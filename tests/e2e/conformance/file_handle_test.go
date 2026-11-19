package conformance

import (
	"io"
	"os"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func testFileHandle(t *testing.T, a mount.Adapter) {
	if _, fuse := a.(mount.FUSE); !fuse {
		t.Skip("a kernel EROFS mount resolves file handles itself")
	}

	m := &mounted{Mounted: mount.Mount(t, a, semanticImage(t), mount.Options{}), adapter: a}
	mountFd := openDir(t, m.Root)

	type target struct {
		rel    string
		handle unix.FileHandle
		ino    uint64
	}
	var targets []target

	for _, rel := range []string{"files/small_100b", "dirs/a/b/c", "dirs/a/b/c/d/e/f/deep_file"} {
		handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, m.Path(rel), 0)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		var st unix.Stat_t
		if !assert.NoError(t, unix.Lstat(m.Path(rel), &st)) {
			t.FailNow()
		}

		targets = append(targets, target{rel: rel, handle: handle, ino: st.Ino})
	}

	evicted := false

	for range 5 {
		unix.Sync()
		if !assert.NoError(t, os.WriteFile("/proc/sys/vm/drop_caches", []byte("2"), 0o644)) {
			t.FailNow()
		}

		before := m.API.Metrics(t).Sum("nydus_fs_op_total", `operation="lookup"`)

		for _, tgt := range targets {
			fd, err := unix.OpenByHandleAt(mountFd, tgt.handle, unix.O_RDONLY|unix.O_CLOEXEC)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			f := os.NewFile(uintptr(fd), tgt.rel)

			var st unix.Stat_t
			if !assert.NoError(t, unix.Fstat(fd, &st)) {
				t.FailNow()
			}

			assert.Equal(t, tgt.ino, st.Ino)

			if st.Mode&unix.S_IFMT == unix.S_IFREG {
				got, err := io.ReadAll(f)
				if !assert.NoError(t, err) {
					t.FailNow()
				}

				assert.Equal(t, m.wantBytes(t, tgt.rel), got)
			}

			_ = f.Close()
		}

		if m.API.Metrics(t).Sum("nydus_fs_op_total", `operation="lookup"`) > before {
			evicted = true
			break
		}
	}

	assert.True(t, evicted)
}
