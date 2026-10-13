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

	"github.com/dragonflyoss/nydus/tests/e2e"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// markedZeros is size bytes of zeros carrying an 8-byte marker at each
// offset in marks: a file too large to hold that still has content to check.
type markedZeros struct {
	size  int64
	marks []int64
	pos   int64
}

func (m *markedZeros) Read(p []byte) (int, error) {
	if m.pos >= m.size {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), m.size-m.pos))
	m.fill(p[:n], m.pos)
	m.pos += int64(n)
	return n, nil
}

// fill writes the content at off into p.
func (m *markedZeros) fill(p []byte, off int64) {
	clear(p)
	for i, mark := range m.marks {
		for j := int64(0); j < 8; j++ {
			if at := mark + j - off; at >= 0 && at < int64(len(p)) {
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
	if os.Getuid() != 0 {
		t.Skip("requires root: the mount runs nydus fuse")
	}
	if testing.Short() {
		t.Skip("streams several 8 GiB layers")
	}
	t.Parallel()
	nydusBin := e2e.MustLookupExecutable(t, "nydus")

	for _, c := range []struct {
		name   string
		size   int64
		format tar.Format
	}{
		{"ustar-8GiB-1", 1<<33 - 1, tar.FormatUSTAR},
		{"pax-8GiB", 1 << 33, tar.FormatPAX},
		{"gnu-8GiB", 1 << 33, tar.FormatGNU},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			content := &markedZeros{size: c.size, marks: []int64{0, 2<<20 - 4, 1<<32 - 4, 1 << 32, c.size - 8}}
			pr, pw := io.Pipe()
			// Unblocks the writer if Pack stops reading early.
			defer func() { _ = pr.Close() }()
			go func() {
				tw := tar.NewWriter(pw)
				err := tw.WriteHeader(&tar.Header{Name: "big", Typeflag: tar.TypeReg, Mode: 0o644, Size: c.size,
					ModTime: time.Unix(1700000000, 0), Format: c.format})
				if err == nil {
					_, err = io.Copy(tw, content)
				}
				if err == nil {
					err = tw.Close()
				}
				_ = pw.CloseWithError(err)
			}()

			work := t.TempDir()
			blob := filepath.Join(work, "layer.blob")
			require.NoError(t, packLayer(t, nydusBin, pr, blob, tarLayout{}))
			st, err := os.Stat(blob)
			require.NoError(t, err)
			require.Less(t, st.Size(), int64(64<<20), "zero chunks must become holes")

			mnt := filepath.Join(work, "mnt")
			defer e2e.MountNydus(t, nydusBin, "", blob, mnt)()
			f, err := os.Open(filepath.Join(mnt, "big"))
			require.NoError(t, err)
			defer func() { _ = f.Close() }()
			fi, err := f.Stat()
			require.NoError(t, err)
			require.Equal(t, c.size, fi.Size())
			for _, mark := range append(content.marks, 3<<30, c.size/2+1) {
				off := max(mark-16, 0)
				want, got := make([]byte, 4096), make([]byte, 4096)
				n, err := f.ReadAt(got, off)
				if !errors.Is(err, io.EOF) {
					require.NoError(t, err)
				}
				require.Equal(t, int(min(int64(len(got)), c.size-off)), n, "short read at %d", off)
				content.fill(want[:n], off)
				require.True(t, bytes.Equal(want[:n], got[:n]), "content differs at %d", off)
			}
		})
	}
}

// TestHugeSparseCorpus converts the corpus archives whose sparse files
// declare 60 GB, which Pack expands to zeros on the way to the builder and
// the builder turns back into holes. Set NYDUS_E2E_HUGE_TAR=1 to run it:
// it streams 120 GB of zeros through the builder.
func TestHugeSparseCorpus(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root: the mount runs nydus fuse")
	}
	if os.Getenv("NYDUS_E2E_HUGE_TAR") != "1" {
		t.Skip("set NYDUS_E2E_HUGE_TAR=1 to stream 60 GB sparse files")
	}
	t.Parallel()
	nydusBin := e2e.MustLookupExecutable(t, "nydus")
	testdata := goTarTestdata(t)

	for _, name := range []string{"gnu-sparse-big.tar", "pax-sparse-big.tar"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data := readCorpusArchive(t, corpusArchive(t, testdata, name))
			work := t.TempDir()
			blob := filepath.Join(work, "layer.blob")
			require.NoError(t, packLayer(t, nydusBin, bytes.NewReader(data), blob, tarLayout{}))
			mnt := filepath.Join(work, "mnt")
			defer e2e.MountNydus(t, nydusBin, "", blob, mnt)()
			compareStreamed(t, data, mnt)
		})
	}
}

// compareStreamed checks every regular file of the archive against the
// mount block by block as Go reads it, reading the mount only where Go
// yields data and at every 1024th zero block.
func compareStreamed(t *testing.T, data []byte, mnt string) {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	want, got := make([]byte, 1<<20), make([]byte, 1<<20)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return
		}
		require.NoError(t, err)
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeGNUSparse {
			continue
		}
		// Rooting the name first clamps ".." the way the reference does.
		compareStreamedFile(t, tr, filepath.Join(mnt, filepath.Join("/", hdr.Name)), hdr, want, got)
	}
}

// compareStreamedFile checks one member against the mounted file at path,
// closing it before the mount is torn down even when a check fails.
func compareStreamedFile(t *testing.T, tr *tar.Reader, path string, hdr *tar.Header, want, got []byte) {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	require.NoError(t, unix.Fstat(int(f.Fd()), &st))
	require.Equal(t, hdr.Size, st.Size, "%s: size", hdr.Name)
	for off, block := int64(0), 0; ; off, block = off+int64(len(want)), block+1 {
		n, err := io.ReadFull(tr, want)
		if n == 0 {
			return
		}
		if bytes.Count(want[:n], []byte{0}) != n || block%1024 == 0 {
			m, rerr := f.ReadAt(got[:n], off)
			if !errors.Is(rerr, io.EOF) {
				require.NoError(t, rerr)
			}
			require.Equal(t, n, m, "%s: short read at %d", hdr.Name, off)
			require.True(t, bytes.Equal(want[:n], got[:n]), "%s: content differs at %d", hdr.Name, off)
		}
		if err != nil {
			return
		}
	}
}
