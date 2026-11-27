package kernel

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/erofs"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const readTimeout = 30 * time.Second

func TestCorruptImage(t *testing.T) {
	t.Parallel()
	layout := fixture.MustLayout(t, "erofs-lz4")
	mount.MustHaveEROFS(t, layout)
	dir := env.WorkDir(t)
	src := filepath.Join(dir, "source")
	if !assert.NoError(t, os.MkdirAll(src, 0o755)) {
		t.FailNow()
	}
	if !assert.NoError(t, os.WriteFile(filepath.Join(src, "victim"), bytes.Repeat([]byte("nydus erofs lz4 "), 1<<16), 0o644)) {
		t.FailNow()
	}

	pristine := fixture.BuildImage(t, dir, src, layout)
	bootstrap, err := os.ReadFile(pristine.Bootstrap)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var victim unix.Stat_t
	if !assert.NoError(t, unix.Stat(filepath.Join(mountEROFS(t, pristine.Bootstrap, pristine.Blobs), "victim"), &victim)) {
		t.FailNow()
	}

	index, err := erofs.LclusterIndexOff(bootstrap, victim.Ino, 1)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	for _, tc := range []struct {
		name string
		blob bool
		off  int64
		n    int
	}{
		{"RootInode", false, erofs.InodeOff(bootstrap, erofs.RootNid(bootstrap)), 32},
		{"LclusterIndex", false, index, 8},
		{"CompressedData", true, 0, 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			img := fixture.Copy(t, pristine)

			path := img.Bootstrap
			if tc.blob {
				path = img.Blob(t)
			}

			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			_, err = f.WriteAt(bytes.Repeat([]byte{0xff}, tc.n), tc.off)
			if !assert.NoError(t, err) || !assert.NoError(t, f.Close()) {
				t.FailNow()
			}

			mnt := filepath.Join(env.WorkDir(t), "mnt")
			if mount.TryEROFS(t, mnt, img.Bootstrap, img.Blobs) != nil {
				return
			}

			for range 2 {
				ctx, cancel := context.WithTimeout(t.Context(), readTimeout)
				err := exec.CommandContext(ctx, "cat", filepath.Join(mnt, "victim")).Run()

				cancel()
				assert.EqualError(t, err, "exit status 1")
			}
		})
	}
}
