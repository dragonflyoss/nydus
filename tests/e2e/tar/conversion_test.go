package tar

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/continuity/fs"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

type tarLayout struct {
	compressor string
	chunkSize  uint32
}

var tarLayouts = map[string]tarLayout{
	"none":       {compressor: "none"},
	"lz4":        {compressor: "lz4"},
	"zstd-64k":   {chunkSize: 64 << 10},
	"erofs-none": {compressor: "erofs-none"},
	"erofs-zstd": {compressor: "erofs-zstd"},
}

type tarOutcome int

const (
	tarConverted tarOutcome = iota
	tarRejected
	tarOverBudget
	tarUnjudged

	tarBudget      = 1 << 30
	typeGNUDumpDir = 'D'
)

func (layout tarLayout) checkTarConversion(t *testing.T, data []byte) tarOutcome {
	t.Helper()
	layer, goErr := gunzipLayer(data)

	var expanded int64
	if goErr == nil {
		expanded, goErr = scanGoTar(layer)
	}

	if goErr == nil && expanded > tarBudget {
		t.Logf("not converted: expands past the %d-byte budget", tarBudget)
		return tarOverBudget
	}

	work := t.TempDir()
	img, packErr := fixture.PackTar(t, bytes.NewReader(data), work, layout.compressor, layout.chunkSize)

	if goErr != nil {
		requireRejected(t, packErr)
		return tarRejected
	}

	reference := filepath.Join(work, "reference")
	if !assert.NoError(t, os.Mkdir(reference, 0o755)) {
		t.FailNow()
	}

	if err := extractReference(layer, reference); err != nil {
		if errors.Is(err, errTarUnsupported) {
			expectNoCrash(t, packErr)
			t.Logf("not judged: %v", err)
			return tarUnjudged
		}

		requireRejected(t, packErr)
		return tarRejected
	}

	if !assert.NoError(t, packErr) {
		t.FailNow()
	}

	mnt := mount.Mount(t, mount.FUSE{}, img, mount.Options{Mode: mount.Blob})
	fstest.DiffTree(t, reference, mnt.Root)

	mnt.Unmount()

	return tarConverted
}

func requireVerdict(t *testing.T, outcome tarOutcome) {
	t.Helper()
	assert.NotEqual(t, tarOverBudget, outcome)
	env.Require(t, outcome != tarUnjudged, "the host filesystem can hold the reference tree")
}

func requireRejected(t *testing.T, packErr error) {
	t.Helper()
	if !assert.Error(t, packErr) {
		t.FailNow()
	}

	expectNoCrash(t, packErr)
}

func expectNoCrash(t *testing.T, packErr error) {
	t.Helper()
	var exitErr *exec.ExitError
	if errors.As(packErr, &exitErr) {
		code := exitErr.ExitCode()
		assert.NotContains(t, []int{101, -1}, code)
	}
}

func scanGoTar(data []byte) (int64, error) {
	tr := tar.NewReader(bytes.NewReader(data))
	var expanded int64

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return expanded, nil
		}
		if err != nil {
			return expanded, err
		}

		switch hdr.Typeflag {
		case tar.TypeLink, tar.TypeSymlink, tar.TypeChar, tar.TypeBlock, tar.TypeDir, tar.TypeFifo:
			continue
		}

		if expanded > tarBudget || hdr.Size > tarBudget-expanded {
			expanded = tarBudget + 1
			continue
		}

		expanded += hdr.Size

		if _, err := io.Copy(io.Discard, tr); err != nil {
			return expanded, err
		}
	}
}

func gunzipLayer(data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		return data, nil
	}

	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	return io.ReadAll(zr)
}

var errTarUnsupported = errors.New("reference depends on the host filesystem")

func extractReference(data []byte, dir string) error {
	explicit := map[string]bool{}

	normalize := func(hdr *tar.Header) (bool, error) {
		switch hdr.Typeflag {
		case tar.TypeGNUSparse, tar.TypeCont:
			hdr.Typeflag = tar.TypeReg

		case typeGNUDumpDir:
			hdr.Typeflag = tar.TypeDir
		}

		if hdr.Typeflag == tar.TypeDir {
			parent, base := filepath.Split(hdr.Name)
			if resolved, err := fs.RootPath(dir, parent); err == nil {
				explicit[filepath.Join(resolved, base)] = true
			}
		}

		return true, nil
	}

	keepWhiteouts := func(*tar.Header, string) (bool, error) { return true, nil }

	_, err := archive.Apply(context.Background(), dir, bytes.NewReader(data),
		archive.WithFilter(normalize), archive.WithConvertWhiteout(keepWhiteouts))

	if err != nil {
		if errors.Is(err, unix.ENOSPC) && strings.Contains(err.Error(), "failed to setxattr") {
			return fmt.Errorf("%w: %v", errTarUnsupported, err)
		}

		return err
	}

	zero := []unix.Timespec{{}, {}}

	return filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || !entry.IsDir() || path == dir || explicit[path] {
			return err
		}

		return unix.UtimesNanoAt(unix.AT_FDCWD, path, zero, unix.AT_SYMLINK_NOFOLLOW)
	})
}

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

			img, err := fixture.PackTar(t, pr, t.TempDir(), "", 0)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			st, err := os.Stat(img.Blob(t))
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.Less(t, st.Size(), int64(64<<20)) {
				t.FailNow()
			}

			mnt := mount.Mount(t, mount.FUSE{}, img, mount.Options{Mode: mount.Blob})
			f, err := os.Open(mnt.Path("big"))
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			defer func() { _ = f.Close() }()
			fi, err := f.Stat()
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.Equal(t, c.size, fi.Size()) {
				t.FailNow()
			}

			for _, mark := range append(content.marks, 3<<30, c.size/2+1) {
				off := max(mark-16, 0)
				want, got := make([]byte, 4096), make([]byte, 4096)
				n, err := f.ReadAt(got, off)
				if !errors.Is(err, io.EOF) {
					assert.NoError(t, err)
				}
				if !assert.Equal(t, int(min(int64(len(got)), c.size-off)), n) {
					t.FailNow()
				}

				content.fill(want[:n], off)
				assert.True(t, bytes.Equal(want[:n], got[:n]))
			}
		})
	}
}

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

func (m *markedZeros) fill(p []byte, off int64) {
	clear(p)

	for i, mark := range m.marks {
		for j := range int64(8) {
			if at := mark + j - off; at >= 0 && at < int64(len(p)) {
				p[at] = byte('A' + i)
			}
		}
	}
}
