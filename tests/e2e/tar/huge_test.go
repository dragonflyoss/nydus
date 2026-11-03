//go:build manual

package tar

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestHugeSparseCorpus(t *testing.T) {
	t.Parallel()
	mount.FUSE{}.Require(t)
	testdata := corpus.GoTarTestdata(t)

	for _, name := range corpus.GoTarHugeArchives {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			data := corpus.ReadGoTarArchive(t, corpus.GoTarArchive(testdata, name))
			img, err := fixture.PackTar(t, bytes.NewReader(data), t.TempDir(), "", 0)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			mnt := mount.Mount(t, mount.FUSE{}, img, mount.Options{Mode: mount.Blob})
			compareStreamed(t, data, mnt.Root)
		})
	}
}

func compareStreamed(t *testing.T, data []byte, mnt string) {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	want, got := make([]byte, 1<<20), make([]byte, 1<<20)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return
		}
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeGNUSparse {
			continue
		}

		compareStreamedFile(t, tr, filepath.Join(mnt, filepath.Join("/", hdr.Name)), hdr, want, got)
	}
}

func compareStreamedFile(t *testing.T, tr *tar.Reader, path string, hdr *tar.Header, want, got []byte) {
	t.Helper()
	f, err := os.Open(path)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if !assert.NoError(t, unix.Fstat(int(f.Fd()), &st)) {
		t.FailNow()
	}
	if !assert.Equal(t, hdr.Size, st.Size) {
		t.FailNow()
	}

	for off, block := int64(0), 0; ; off, block = off+int64(len(want)), block+1 {
		n, err := io.ReadFull(tr, want)
		if n == 0 {
			return
		}

		if bytes.Count(want[:n], []byte{0}) != n || block%1024 == 0 {
			m, rerr := f.ReadAt(got[:n], off)
			if !errors.Is(rerr, io.EOF) {
				assert.NoError(t, rerr)
			}
			if !assert.Equal(t, n, m) {
				t.FailNow()
			}

			assert.True(t, bytes.Equal(want[:n], got[:n]))
		}

		if err != nil {
			return
		}
	}
}
