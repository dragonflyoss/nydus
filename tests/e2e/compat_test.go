package e2e

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// The cross-version compatibility check builds images with one nydus binary
// and checks and reads them with another, so a change to the on-disk format
// that a released binary cannot read (or that cannot read what a released
// binary wrote) fails loudly. Both default to the in-tree release build; CI
// points one of them at the last released version in each direction.
//
// The images, and the manifest of the trees they must reproduce, can also be
// built and read in separate runs through an images directory, so CI builds
// the released version's images once and caches them.
const (
	// builderEnv names the nydus binary that builds the images.
	builderEnv = "NYDUS_E2E_COMPAT_BUILDER"

	// readerEnv names the nydus binary that checks and reads them.
	readerEnv = "NYDUS_E2E_COMPAT_READER"

	// imagesDirEnv names the images directory of a separate build or read
	// run.
	imagesDirEnv = "NYDUS_E2E_COMPAT_IMAGES"
)

// TestCompatBuildImages builds the compatibility images into
// $NYDUS_E2E_COMPAT_IMAGES with $NYDUS_E2E_COMPAT_BUILDER.
func TestCompatBuildImages(t *testing.T) {
	imagesDir := skipUnlessImagesDir(t)
	builder, err := util.LookupExecutableFromEnv(builderEnv, "nydus")
	assert.NoError(t, err)

	t.Logf("builder: %s (%s)", builder, nydusVersion(t, builder))
	buildImages(t, builder, imagesDir)
}

// TestCompatReadImages checks and reads the compatibility images in
// $NYDUS_E2E_COMPAT_IMAGES with $NYDUS_E2E_COMPAT_READER.
func TestCompatReadImages(t *testing.T) {
	imagesDir := skipUnlessImagesDir(t)
	reader, err := util.LookupExecutableFromEnv(readerEnv, "nydus")
	assert.NoError(t, err)

	readImages(t, reader, imagesDir, loadImagesManifest(t, imagesDir))
}

// TestCrossVersionCompatibility builds the compatibility images with
// $NYDUS_E2E_COMPAT_BUILDER and checks and reads them with $NYDUS_E2E_COMPAT_READER.
func TestCrossVersionCompatibility(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	assert := assert.New(t)
	builder, err := util.LookupExecutableFromEnv(builderEnv, "nydus")
	assert.NoError(err)
	reader, err := util.LookupExecutableFromEnv(readerEnv, "nydus")
	assert.NoError(err)
	t.Logf("builder: %s (%s)", builder, nydusVersion(t, builder))

	// Read only images of a build that went through.
	imagesDir := filepath.Join(t.TempDir(), "images")
	var manifest *imagesManifest
	t.Run("build", func(t *testing.T) {
		manifest = buildImages(t, builder, imagesDir)
	})
	if manifest == nil {
		t.FailNow()
	}

	t.Run("read", func(t *testing.T) {
		readImages(t, reader, imagesDir, manifest)
	})
}

// skipUnlessImagesDir returns the absolute images directory of a separate build
// or read run, skipping the test without root or $NYDUS_E2E_COMPAT_IMAGES.
func skipUnlessImagesDir(t *testing.T) string {
	t.Helper()
	util.SkipUnlessRoot(t, "mounting FUSE")

	imagesDir := os.Getenv(imagesDirEnv)
	if imagesDir == "" {
		t.Skipf("%s is not set", imagesDirEnv)
	}

	imagesDir, err := filepath.Abs(imagesDir)
	assert.NoError(t, err)
	return imagesDir
}

// readImages runs every read path of reader over the images in imagesDir:
// `check` of each blob and of the bootstrap, FUSE mounts through the full blob,
// the bootstrap and the bootstrap with a chunk cache, and `export`. Each must
// reproduce the image's tree exactly.
func readImages(t *testing.T, reader, imagesDir string, manifest *imagesManifest) {
	t.Helper()
	t.Logf("images built by: %s", manifest.Builder)
	t.Logf("reader: %s (%s)", reader, nydusVersion(t, reader))
	workDir := t.TempDir()

	for _, image := range manifest.Images {
		t.Run(image.Name, func(t *testing.T) {
			want, ok := manifest.Trees[image.Tree]
			if !assert.True(t, ok, "no tree %q in the manifest", image.Tree) {
				return
			}

			bootstrap := filepath.Join(imagesDir, image.Bootstrap)
			blobDir := filepath.Join(imagesDir, image.BlobDir)
			var blobs []string
			for _, blob := range image.Blobs {
				blobs = append(blobs, filepath.Join(imagesDir, blob))
			}
			if !assert.NotEmpty(t, blobs, "image %q lists no blobs", image.Name) {
				return
			}
			mountpoint := filepath.Join(workDir, image.Name, "mnt")

			// A merged bootstrap keeps each layer's link count, which a
			// group broken by an upper layer no longer matches.
			opts := compareOptions{compareNlink: !image.Merged}

			t.Run("check", func(t *testing.T) {
				for _, blob := range blobs {
					util.CheckImage(t, reader, "--blob", blob)
				}
				util.CheckImage(t, reader, "--bootstrap", bootstrap, "--blob-dir", blobDir)
			})

			if !image.Merged {
				t.Run("fuse blob", func(t *testing.T) {
					unmount := util.MountNydusBlob(t, reader, blobs[0], mountpoint)
					defer unmount()
					verifyMount(t, mountpoint, want, opts)
				})
			}

			t.Run("fuse bootstrap", func(t *testing.T) {
				unmount := util.MountNydusBootstrap(t, reader, bootstrap, blobDir, "", mountpoint)
				defer unmount()
				verifyMount(t, mountpoint, want, opts)
			})

			if !image.Native {
				t.Run("fuse bootstrap with cache", func(t *testing.T) {
					cacheDir := filepath.Join(workDir, image.Name, "cache")
					unmount := util.MountNydusBootstrap(t, reader, bootstrap, blobDir, cacheDir, mountpoint)
					defer unmount()
					verifyMount(t, mountpoint, want, opts)
				})
			}

			if !image.Merged {
				t.Run("export", func(t *testing.T) {
					verifyExport(t, reader, blobs[0], want)
				})
			}
		})
	}
}

// verifyMount compares the tree under mountpoint with want, including the
// content of every regular file.
func verifyMount(t *testing.T, mountpoint string, want []treeEntry, opts compareOptions) {
	t.Helper()
	compareTrees(t, want, scanTree(t, mountpoint), opts)

	for _, entry := range want {
		if len(entry.Extents) > 0 {
			verifyExtents(t, filepath.Join(mountpoint, string(entry.Path)), entry)
		}
	}
}

// verifyExtents reads the data extents of a large sparse file, and the
// start, middle and end of every gap between them, which must be zeros.
func verifyExtents(t *testing.T, path string, want treeEntry) {
	t.Helper()
	const probe = 64 << 10

	f, err := os.Open(path)
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = f.Close() }()

	readAt := func(off, n int64) []byte {
		buf := make([]byte, n)
		_, err := f.ReadAt(buf, off)
		assert.NoError(t, err, "%q: read %d bytes at %d", want.Path, n, off)
		return buf
	}

	zeros := make([]byte, probe)
	checkGap := func(start, end int64) {
		for _, off := range []int64{start, start + (end-start)/2, end - probe} {
			off = max(start, off)
			n := min(int64(probe), end-off)
			if n > 0 {
				assert.True(t, bytes.Equal(zeros[:n], readAt(off, n)), "%q: hole at %d is not zeros", want.Path, off)
			}
		}
	}

	// Hash each extent and probe the gap before it and the one after the last.
	pos := int64(0)
	for _, extent := range want.Extents {
		checkGap(pos, extent.Offset)
		sum := sha256.Sum256(readAt(extent.Offset, extent.Length))
		assert.Equal(t, extent.SHA256, hex.EncodeToString(sum[:]), "%q: data at %d", want.Path, extent.Offset)
		pos = extent.Offset + extent.Length
	}
	checkGap(pos, want.Size)
}

// verifyExport streams `nydus export` of blob and compares the OCI
// layer with want. A tar has no sockets, no link counts and hardlinks of
// regular files only.
func verifyExport(t *testing.T, reader, blob string, want []treeEntry) {
	t.Helper()
	cmd := exec.Command(reader, "export", blob)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if !assert.NoError(t, err) {
		return
	}
	if !assert.NoError(t, cmd.Start()) {
		return
	}

	// Drain the pipe before waiting, so an export longer than the scan does
	// not block on a full pipe.
	got, scanErr := scanLayerTar(stdout, want)
	_, _ = io.Copy(io.Discard, stdout)
	assert.NoError(t, cmd.Wait(), "nydus export %s: %s", blob, stderr.String())
	assert.NoError(t, scanErr, "reading the exported tar")

	compareTrees(t, withoutSockets(want), got, compareOptions{fromTar: true})
}

// scanLayerTar records the entries of a layer tarball. Large files are
// checked against their extents in want as they stream past.
func scanLayerTar(r io.Reader, want []treeEntry) ([]treeEntry, error) {
	wantByPath := map[byteString]treeEntry{}
	for _, entry := range want {
		wantByPath[entry.Path] = entry
	}

	var entries []treeEntry
	indexByPath := map[string]int{}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		rel := strings.TrimSuffix(strings.TrimPrefix(hdr.Name, "./"), "/")
		if rel == "" || rel == "." {
			continue
		}

		// A link entry copies the entry it points at under its own path.
		if hdr.Typeflag == tar.TypeLink {
			target := strings.TrimPrefix(hdr.Linkname, "./")
			i, ok := indexByPath[target]
			if !ok {
				return nil, fmt.Errorf("%q: hardlink to %q, which is not in the tar before it", rel, target)
			}
			entry := entries[i]
			entry.Path = byteString(rel)
			indexByPath[rel] = len(entries)
			entries = append(entries, entry)

			continue
		}

		// Record the header and the xattrs of its PAX records, less the
		// internal ones.
		entry := treeEntry{
			Path:      byteString(rel),
			Mode:      uint32(hdr.Mode & 0o7777),
			UID:       uint32(hdr.Uid),
			GID:       uint32(hdr.Gid),
			MtimeSec:  hdr.ModTime.Unix(),
			MtimeNsec: int64(hdr.ModTime.Nanosecond()),
			inode:     rel,
		}
		for key, value := range hdr.PAXRecords {
			if name, ok := strings.CutPrefix(key, "SCHILY.xattr."); ok && !util.IsInternalXattr(name) {
				if entry.Xattrs == nil {
					entry.Xattrs = map[string]byteString{}
				}
				entry.Xattrs[name] = byteString(value)
			}
		}

		// Record what the type decides, hashing a regular file in full or
		// checking its extents as it streams past.
		switch hdr.Typeflag {
		case tar.TypeDir:
			entry.Type = "dir"
			entry.inode = ""
		case tar.TypeReg:
			entry.Type = "reg"
			entry.Size = hdr.Size
			if hdr.Size <= maxFullHashSize {
				h := sha256.New()
				if _, err := io.Copy(h, tr); err != nil {
					return nil, err
				}
				entry.SHA256 = hex.EncodeToString(h.Sum(nil))
			} else if err := verifySparseStream(tr, wantByPath[entry.Path]); err != nil {
				return nil, fmt.Errorf("%q: %w", rel, err)
			}
		case tar.TypeSymlink:
			entry.Type = "symlink"
			entry.Target = byteString(hdr.Linkname)
			entry.Size = int64(len(hdr.Linkname))
		case tar.TypeChar, tar.TypeBlock:
			entry.Type = "chr"
			if hdr.Typeflag == tar.TypeBlock {
				entry.Type = "blk"
			}
			entry.Major = uint32(hdr.Devmajor)
			entry.Minor = uint32(hdr.Devminor)
		case tar.TypeFifo:
			entry.Type = "fifo"
		default:
			return nil, fmt.Errorf("%q: unexpected tar entry type %q", rel, hdr.Typeflag)
		}

		indexByPath[rel] = len(entries)
		entries = append(entries, entry)
	}

	assignLinks(entries)
	return entries, nil
}

// verifySparseStream checks a large file's content as it streams: the
// extents of want hash as recorded and everything else is zeros.
func verifySparseStream(r io.Reader, want treeEntry) error {
	if want.Size == 0 || len(want.Extents) == 0 {
		return errors.New("no extents recorded for a large file")
	}

	buf := make([]byte, 1<<20)
	zeros := make([]byte, len(buf))
	extents := want.Extents
	h := sha256.New()
	for pos := int64(0); pos < want.Size; {
		n, err := io.ReadFull(r, buf[:min(int64(len(buf)), want.Size-pos)])
		if err != nil {
			return fmt.Errorf("at %d: %w", pos, err)
		}

		// Feed the part of the buffer inside the current extent to the hash
		// and compare the part before the next extent with zeros.
		for data := buf[:n]; len(data) > 0; {
			if len(extents) > 0 && pos >= extents[0].Offset {
				end := extents[0].Offset + extents[0].Length
				m := min(int64(len(data)), end-pos)
				h.Write(data[:m])
				pos += m
				data = data[m:]
				if pos == end {
					if sum := hex.EncodeToString(h.Sum(nil)); sum != extents[0].SHA256 {
						return fmt.Errorf("data at %d differs", extents[0].Offset)
					}
					h.Reset()
					extents = extents[1:]
				}

				continue
			}

			next := want.Size
			if len(extents) > 0 {
				next = extents[0].Offset
			}
			m := min(int64(len(data)), next-pos)
			if !bytes.Equal(data[:m], zeros[:m]) {
				return fmt.Errorf("hole at %d is not zeros", pos)
			}
			pos += m
			data = data[m:]
		}
	}

	return nil
}

// compareOptions relaxes a comparison for what a read path cannot
// carry.
type compareOptions struct {
	// compareNlink compares the link count of non-directories.
	compareNlink bool

	// fromTar compares an exported layer: no link counts, and hardlinks of
	// regular files only.
	fromTar bool
}

// compareTrees fails the test unless got has exactly the paths of want,
// each with the same attributes and content.
func compareTrees(t *testing.T, want, got []treeEntry, opts compareOptions) {
	t.Helper()
	const maxReported = 20

	normalize := func(entry treeEntry) treeEntry {
		entry.Extents = nil
		entry.inode = ""
		if !opts.compareNlink || opts.fromTar {
			entry.Nlink = 0
		}
		if opts.fromTar && entry.Type != "reg" {
			entry.Link = ""
		}
		return entry
	}

	// Match every wanted path and report the first differences in full.
	gotByPath := make(map[byteString]treeEntry, len(got))
	for _, entry := range got {
		gotByPath[entry.Path] = entry
	}

	var missing, extra []string
	differing := 0
	for _, wantEntry := range want {
		gotEntry, ok := gotByPath[wantEntry.Path]
		if !ok {
			missing = append(missing, strconv.Quote(string(wantEntry.Path)))
			continue
		}
		delete(gotByPath, wantEntry.Path)

		if wantEntry, gotEntry := normalize(wantEntry), normalize(gotEntry); !reflect.DeepEqual(wantEntry, gotEntry) {
			differing++
			if differing <= maxReported {
				assert.Equal(t, wantEntry, gotEntry, "%q differs", wantEntry.Path)
			}
		}
	}

	for path := range gotByPath {
		extra = append(extra, strconv.Quote(string(path)))
	}

	// Summarize, then stop: the extent checks that follow a mismatching
	// tree would only repeat it.
	report := func(what string, paths []string) {
		if len(paths) > 0 {
			shown := paths[:min(len(paths), maxReported)]
			t.Errorf("%d %s paths, including: %s", len(paths), what, strings.Join(shown, ", "))
		}
	}
	report("missing", missing)
	report("unexpected", extra)
	if differing > 0 {
		t.Errorf("%d entries differ", differing)
	}

	if t.Failed() {
		t.FailNow()
	}
}
