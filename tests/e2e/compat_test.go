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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	compatBuilderEnv = "NYDUS_COMPAT_BUILDER"
	compatReaderEnv  = "NYDUS_COMPAT_READER"
	compatImagesEnv  = "NYDUS_COMPAT_IMAGES"
)

// TestCompatBuildImages builds the compatibility images into
// $NYDUS_COMPAT_IMAGES with $NYDUS_COMPAT_BUILDER.
func TestCompatBuildImages(t *testing.T) {
	dir := compatImagesDir(t)
	builder := lookupBinFromEnv(t, compatBuilderEnv, "nydus")
	t.Logf("builder: %s (%s)", builder, compatVersion(t, builder))
	compatBuildImages(t, builder, dir)
}

// TestCompatReadImages checks and reads the compatibility images in
// $NYDUS_COMPAT_IMAGES with $NYDUS_COMPAT_READER.
func TestCompatReadImages(t *testing.T) {
	dir := compatImagesDir(t)
	reader := lookupBinFromEnv(t, compatReaderEnv, "nydus")
	compatReadImages(t, reader, dir, compatLoadManifest(t, dir))
}

// TestCrossVersionCompatibility builds the compatibility images with
// $NYDUS_COMPAT_BUILDER and checks and reads them with $NYDUS_COMPAT_READER.
func TestCrossVersionCompatibility(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	builder := lookupBinFromEnv(t, compatBuilderEnv, "nydus")
	reader := lookupBinFromEnv(t, compatReaderEnv, "nydus")
	t.Logf("builder: %s (%s)", builder, compatVersion(t, builder))

	dir := filepath.Join(t.TempDir(), "images")
	var manifest *compatManifest
	t.Run("Build", func(t *testing.T) {
		manifest = compatBuildImages(t, builder, dir)
	})
	if manifest == nil {
		t.FailNow()
	}
	t.Run("Read", func(t *testing.T) {
		compatReadImages(t, reader, dir, manifest)
	})
}

func compatImagesDir(t *testing.T) string {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	dir := os.Getenv(compatImagesEnv)
	if dir == "" {
		t.Skipf("%s is not set", compatImagesEnv)
	}
	dir, err := filepath.Abs(dir)
	require.NoError(t, err)
	return dir
}

// compatReadImages runs every read path of reader over the images in dir:
// `check` of each blob and of the bootstrap, FUSE mounts through the full blob,
// the bootstrap and the bootstrap with a chunk cache, and `export`. Each must
// reproduce the image's tree exactly.
func compatReadImages(t *testing.T, reader, dir string, manifest *compatManifest) {
	t.Helper()
	t.Logf("images built by: %s", manifest.Builder)
	t.Logf("reader: %s (%s)", reader, compatVersion(t, reader))
	work := t.TempDir()

	for _, image := range manifest.Images {
		image := image
		t.Run(image.Name, func(t *testing.T) {
			want, ok := manifest.Trees[image.Tree]
			require.True(t, ok, "no tree %q in the manifest", image.Tree)
			bootstrap := filepath.Join(dir, image.Bootstrap)
			blobDir := filepath.Join(dir, image.BlobDir)
			var blobs []string
			for _, blob := range image.Blobs {
				blobs = append(blobs, filepath.Join(dir, blob))
			}
			mnt := filepath.Join(work, image.Name, "mnt")
			// A merged bootstrap keeps each layer's link count, which a
			// group broken by an upper layer no longer matches.
			opts := compatCompareOptions{nlink: !image.Merged}

			t.Run("Check", func(t *testing.T) {
				for _, blob := range blobs {
					compatRun(t, reader, "check", "--blob", blob)
				}
				compatRun(t, reader, "check", "--bootstrap", bootstrap, "--blob-dir", blobDir)
			})

			if !image.Merged {
				t.Run("FuseBlob", func(t *testing.T) {
					unmount := mountNydus(t, reader, "", blobs[0], mnt)
					defer unmount()
					compatVerifyMount(t, mnt, want, opts)
				})
			}

			t.Run("FuseBootstrap", func(t *testing.T) {
				unmount := mountNydusBootstrap(t, reader, bootstrap, blobDir, mnt)
				defer unmount()
				compatVerifyMount(t, mnt, want, opts)
			})

			if !image.Native {
				t.Run("FuseBootstrapCache", func(t *testing.T) {
					cacheDir := filepath.Join(work, image.Name, "cache")
					unmount := mountNydusBootstrapWithCache(t, reader, bootstrap, blobDir, cacheDir, mnt)
					defer unmount()
					compatVerifyMount(t, mnt, want, opts)
				})
			}

			if !image.Merged {
				t.Run("Export", func(t *testing.T) {
					compatVerifyExport(t, reader, blobs[0], want)
				})
			}
		})
	}
}

// compatVerifyMount compares the tree under mnt with want, including the
// content of every regular file.
func compatVerifyMount(t *testing.T, mnt string, want []compatEntry, opts compatCompareOptions) {
	t.Helper()
	compatCompareTree(t, want, compatScanTree(t, mnt), opts)
	for _, entry := range want {
		if len(entry.Extents) > 0 {
			compatVerifyExtents(t, filepath.Join(mnt, string(entry.Path)), entry)
		}
	}
}

// compatVerifyExtents reads the data extents of a large sparse file, and the
// start, middle and end of every gap between them, which must be zeros.
func compatVerifyExtents(t *testing.T, path string, want compatEntry) {
	t.Helper()
	const probe = 64 << 10
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	readAt := func(off, n int64) []byte {
		buf := make([]byte, n)
		_, err := f.ReadAt(buf, off)
		require.NoError(t, err, "%q: read %d bytes at %d", want.Path, n, off)
		return buf
	}
	zero := make([]byte, probe)
	gap := func(start, end int64) {
		for _, off := range []int64{start, start + (end-start)/2, end - probe} {
			off = max(start, off)
			n := min(int64(probe), end-off)
			if n > 0 {
				require.True(t, bytes.Equal(zero[:n], readAt(off, n)), "%q: hole at %d is not zeros", want.Path, off)
			}
		}
	}

	pos := int64(0)
	for _, extent := range want.Extents {
		gap(pos, extent.Offset)
		sum := sha256.Sum256(readAt(extent.Offset, extent.Length))
		require.Equal(t, extent.SHA256, hex.EncodeToString(sum[:]), "%q: data at %d", want.Path, extent.Offset)
		pos = extent.Offset + extent.Length
	}
	gap(pos, want.Size)
}

// compatVerifyExport streams `nydus export` of blob and compares the OCI
// layer with want. A tar has no sockets, no link counts and hardlinks of
// regular files only.
func compatVerifyExport(t *testing.T, reader, blob string, want []compatEntry) {
	t.Helper()
	cmd := exec.Command(reader, "export", blob)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	got, scanErr := compatScanTar(stdout, want)
	_, _ = io.Copy(io.Discard, stdout)
	require.NoError(t, cmd.Wait(), "nydus export %s: %s", blob, stderr.String())
	require.NoError(t, scanErr, "reading the exported tar")
	compatCompareTree(t, compatWithoutSockets(want), got, compatCompareOptions{tar: true})
}

// compatScanTar records the entries of a layer tarball. Large files are
// checked against their extents in want as they stream past.
func compatScanTar(r io.Reader, want []compatEntry) ([]compatEntry, error) {
	wantByPath := map[compatBytes]compatEntry{}
	for _, entry := range want {
		wantByPath[entry.Path] = entry
	}

	var entries []compatEntry
	index := map[string]int{}
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

		if hdr.Typeflag == tar.TypeLink {
			target := strings.TrimPrefix(hdr.Linkname, "./")
			i, ok := index[target]
			if !ok {
				return nil, fmt.Errorf("%q: hardlink to %q, which is not in the tar before it", rel, target)
			}
			entry := entries[i]
			entry.Path = compatBytes(rel)
			index[rel] = len(entries)
			entries = append(entries, entry)
			continue
		}

		entry := compatEntry{
			Path:      compatBytes(rel),
			Mode:      uint32(hdr.Mode & 07777),
			UID:       uint32(hdr.Uid),
			GID:       uint32(hdr.Gid),
			MtimeSec:  hdr.ModTime.Unix(),
			MtimeNsec: int64(hdr.ModTime.Nanosecond()),
			inode:     rel,
		}
		for key, value := range hdr.PAXRecords {
			if name, ok := strings.CutPrefix(key, "SCHILY.xattr."); ok && !strings.HasPrefix(name, "trusted.nydus.") {
				if entry.Xattrs == nil {
					entry.Xattrs = map[string]compatBytes{}
				}
				entry.Xattrs[name] = compatBytes(value)
			}
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			entry.Type = "dir"
			entry.inode = ""
		case tar.TypeReg:
			entry.Type = "reg"
			entry.Size = hdr.Size
			if hdr.Size <= compatFullHashLimit {
				h := sha256.New()
				if _, err := io.Copy(h, tr); err != nil {
					return nil, err
				}
				entry.SHA256 = hex.EncodeToString(h.Sum(nil))
			} else if err := compatVerifySparseStream(tr, wantByPath[entry.Path]); err != nil {
				return nil, fmt.Errorf("%q: %w", rel, err)
			}
		case tar.TypeSymlink:
			entry.Type = "symlink"
			entry.Target = compatBytes(hdr.Linkname)
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
		index[rel] = len(entries)
		entries = append(entries, entry)
	}
	compatAssignLinks(entries)
	return entries, nil
}

// compatVerifySparseStream checks a large file's content as it streams: the
// extents of want hash as recorded and everything else is zeros.
func compatVerifySparseStream(r io.Reader, want compatEntry) error {
	if want.Size == 0 || len(want.Extents) == 0 {
		return errors.New("no extents recorded for a large file")
	}
	buf := make([]byte, 1<<20)
	zero := make([]byte, len(buf))
	extents := want.Extents
	h := sha256.New()
	for pos := int64(0); pos < want.Size; {
		n, err := io.ReadFull(r, buf[:min(int64(len(buf)), want.Size-pos)])
		if err != nil {
			return fmt.Errorf("at %d: %w", pos, err)
		}
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
			if !bytes.Equal(data[:m], zero[:m]) {
				return fmt.Errorf("hole at %d is not zeros", pos)
			}
			pos += m
			data = data[m:]
		}
	}
	return nil
}

// compatCompareOptions relaxes a comparison for what a read path cannot
// carry.
type compatCompareOptions struct {
	// nlink compares the link count of non-directories.
	nlink bool
	// tar compares an exported layer: no link counts, and hardlinks of
	// regular files only.
	tar bool
}

// compatCompareTree fails the test unless got has exactly the paths of want,
// each with the same attributes and content.
func compatCompareTree(t *testing.T, want, got []compatEntry, opts compatCompareOptions) {
	t.Helper()
	const maxReported = 20
	normalize := func(entry compatEntry) compatEntry {
		entry.Extents = nil
		entry.inode = ""
		if !opts.nlink || opts.tar {
			entry.Nlink = 0
		}
		if opts.tar && entry.Type != "reg" {
			entry.Link = ""
		}
		return entry
	}

	gotByPath := make(map[compatBytes]compatEntry, len(got))
	for _, entry := range got {
		gotByPath[entry.Path] = entry
	}
	var missing, extra []string
	differ := 0
	for _, w := range want {
		g, ok := gotByPath[w.Path]
		if !ok {
			missing = append(missing, strconv.Quote(string(w.Path)))
			continue
		}
		delete(gotByPath, w.Path)
		if w, g := normalize(w), normalize(g); !reflect.DeepEqual(w, g) {
			differ++
			if differ <= maxReported {
				assert.Equal(t, w, g, "%q differs", w.Path)
			}
		}
	}
	for path := range gotByPath {
		extra = append(extra, strconv.Quote(string(path)))
	}

	report := func(what string, paths []string) {
		if len(paths) > 0 {
			shown := paths[:min(len(paths), maxReported)]
			t.Errorf("%d %s paths, including: %s", len(paths), what, strings.Join(shown, ", "))
		}
	}
	report("missing", missing)
	report("unexpected", extra)
	if differ > 0 {
		t.Errorf("%d entries differ", differ)
	}
	if t.Failed() {
		t.FailNow()
	}
}
