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

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

// TestLargeFiles converts files past the 8 GiB reach of the octal size
// field in each header format that can carry one, streaming them rather than
// holding them, and checks the mounted size and content at the chunk and
// 4 GiB boundaries. Zero chunks become holes, so the blob stays small.
func TestLargeFiles(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)

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
			// Unblocks the writer if the builder stops reading early.
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
			require.NoError(t, packLayer(t, pr, blob, tarLayout{}))
			st, err := os.Stat(blob)
			require.NoError(t, err)
			require.Less(t, st.Size(), int64(64<<20), "zero chunks must become holes")

			mnt := mount.Mount(t, mount.FUSE{}, blobImage(work, blob), mount.Options{Mode: mount.Blob})
			f, err := os.Open(mnt.Path("big"))
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
