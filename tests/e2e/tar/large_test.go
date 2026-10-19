package tar

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// markedZeros is size bytes of zeros carrying an 8-byte marker at each
// offset in marks: a file too large to hold that still has content to check.
type markedZeros struct {
	// size is the length of the file.
	size int64

	// marks are the offsets of the markers.
	marks []int64

	// offset is the read position.
	offset int64
}

// Read fills p with the next bytes of the file.
func (m *markedZeros) Read(p []byte) (int, error) {
	if m.offset >= m.size {
		return 0, io.EOF
	}

	n := int(min(int64(len(p)), m.size-m.offset))
	m.fill(p[:n], m.offset)
	m.offset += int64(n)

	return n, nil
}

// fill writes the content at offset into p.
func (m *markedZeros) fill(p []byte, offset int64) {
	clear(p)
	for i, mark := range m.marks {
		for j := range int64(8) {
			if at := mark + j - offset; at >= 0 && at < int64(len(p)) {
				p[at] = byte('A' + i)
			}
		}
	}
}

// TestLargeFiles converts files past the 8 GiB reach of the octal size
// field in each header format that can carry one, streaming them rather than
// holding them, and checks the mounted size and content at the chunk and
// 4 GiB boundaries. Zero chunks become holes, so the blob stays small.
func TestLargeFiles(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	if testing.Short() {
		t.Skip("streams several 8 GiB layers")
	}
	t.Parallel()

	for _, tc := range []struct {
		name   string
		size   int64
		format tar.Format
	}{
		{"ustar just under 8 GiB", 1<<33 - 1, tar.FormatUSTAR},
		{"pax 8 GiB", 1 << 33, tar.FormatPAX},
		{"gnu 8 GiB", 1 << 33, tar.FormatGNU},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert := assert.New(t)

			// Stream the archive into the builder through a pipe; closing the
			// read end unblocks the writer if the build stops reading early.
			content := &markedZeros{size: tc.size, marks: []int64{0, 2<<20 - 4, 1<<32 - 4, 1 << 32, tc.size - 8}}
			pr, pw := io.Pipe()
			defer func() { _ = pr.Close() }()
			go func() {
				tw := tar.NewWriter(pw)
				err := tw.WriteHeader(&tar.Header{Name: "big", Typeflag: tar.TypeReg, Mode: 0o644, Size: tc.size,
					ModTime: time.Unix(1700000000, 0), Format: tc.format})
				if err == nil {
					_, err = io.Copy(tw, content)
				}
				if err == nil {
					err = tw.Close()
				}
				_ = pw.CloseWithError(err)
			}()

			// Convert the layer and check the zero chunks became holes.
			workDir := t.TempDir()
			blob := filepath.Join(workDir, "layer.blob")
			assert.NoError(packLayer(t, pr, blob, blobLayout{}))

			st, err := os.Stat(blob)
			if !assert.NoError(err) {
				return
			}
			assert.Less(st.Size(), int64(64<<20), "zero chunks must become holes")

			// Mount the blob and check the file's size.
			mountpoint := filepath.Join(workDir, "mnt")
			defer util.MountNydusBlob(t, nydusBin, blob, mountpoint)()

			f, err := os.Open(filepath.Join(mountpoint, "big"))
			if !assert.NoError(err) {
				return
			}
			defer func() { _ = f.Close() }()
			fi, err := f.Stat()
			assert.NoError(err)
			assert.Equal(tc.size, fi.Size())

			// Check the content around every marker and at a few boundaries.
			for _, mark := range append(content.marks, 3<<30, tc.size/2+1) {
				offset := max(mark-16, 0)
				want, got := make([]byte, 4096), make([]byte, 4096)
				n, err := f.ReadAt(got, offset)
				if !errors.Is(err, io.EOF) {
					assert.NoError(err)
				}
				assert.Equal(int(min(int64(len(got)), tc.size-offset)), n, "short read at %d", offset)
				content.fill(want[:n], offset)
				assert.True(bytes.Equal(want[:n], got[:n]), "content differs at %d", offset)
			}
		})
	}
}

// TestHugeSparseCorpus converts the corpus archives whose sparse files
// declare 60 GB, which Pack expands to zeros on the way to the builder and
// the builder turns back into holes. Set NYDUS_E2E_HUGE_TAR=1 to run it:
// it streams 120 GB of zeros through the builder.
func TestHugeSparseCorpus(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	if os.Getenv("NYDUS_E2E_HUGE_TAR") != "1" {
		t.Skip("set NYDUS_E2E_HUGE_TAR=1 to stream 60 GB sparse files")
	}
	t.Parallel()
	testdata := goTarTestdata(t)

	for _, name := range []string{"gnu-sparse-big.tar", "pax-sparse-big.tar"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Convert the archive.
			data := readCorpusArchive(t, corpusArchivePath(t, testdata, name))
			workDir := t.TempDir()
			blob := filepath.Join(workDir, "layer.blob")
			if !assert.NoError(t, packLayer(t, bytes.NewReader(data), blob, blobLayout{})) {
				return
			}

			// Mount the blob and compare it with the archive.
			mountpoint := filepath.Join(workDir, "mnt")
			defer util.MountNydusBlob(t, nydusBin, blob, mountpoint)()
			compareStreamed(t, data, mountpoint)
		})
	}
}

// compareStreamed checks every regular file of the archive against the
// mount block by block as Go reads it, reading the mount only where Go
// yields data and at every 1024th zero block.
func compareStreamed(t *testing.T, data []byte, mountpoint string) {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	want, got := make([]byte, 1<<20), make([]byte, 1<<20)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return
		}
		if !assert.NoError(t, err) {
			return
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeGNUSparse {
			continue
		}

		// Root the name first, which clamps ".." the way the reference does.
		compareStreamedFile(t, tr, filepath.Join(mountpoint, filepath.Join("/", hdr.Name)), hdr, want, got)
	}
}

// compareStreamedFile checks one member against the mounted file at path,
// closing it before the mount is torn down even when a check fails.
func compareStreamedFile(t *testing.T, tr *tar.Reader, path string, hdr *tar.Header, want, got []byte) {
	t.Helper()
	f, err := os.Open(path)
	if !assert.NoError(t, err) {
		return
	}
	defer func() { _ = f.Close() }()

	// Check the size.
	fi, err := f.Stat()
	assert.NoError(t, err)
	assert.Equal(t, hdr.Size, fi.Size(), "%s: size", hdr.Name)

	// Check the content where Go yields data and at every 1024th zero block.
	for offset, block := int64(0), 0; ; offset, block = offset+int64(len(want)), block+1 {
		n, err := io.ReadFull(tr, want)
		if n == 0 {
			return
		}

		if bytes.Count(want[:n], []byte{0}) != n || block%1024 == 0 {
			m, readErr := f.ReadAt(got[:n], offset)
			if !errors.Is(readErr, io.EOF) {
				assert.NoError(t, readErr)
			}
			assert.Equal(t, n, m, "%s: short read at %d", hdr.Name, offset)
			assert.True(t, bytes.Equal(want[:n], got[:n]), "%s: content differs at %d", hdr.Name, offset)
		}

		if err != nil {
			return
		}
	}
}
