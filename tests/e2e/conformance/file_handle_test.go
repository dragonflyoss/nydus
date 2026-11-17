package conformance

import (
	"io"
	"os"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// testFileHandle opens files by handle after the kernel evicted their inodes.
// Without FUSE_EXPORT_SUPPORT the kernel resolves a handle only from its inode
// cache and fails with ESTALE; with it the daemon is asked for the inode again,
// which the lookup counter shows.
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

	lookups := func() float64 {
		return m.API.Metrics(t).Sum("nydus_fs_op_total", `operation="lookup"`)
	}

	// The kernel gives a recently used inode a second chance, so one drop may
	// keep it: drop until the daemon sees the kernel ask again.
	evicted := false

	for range 5 {
		unix.Sync()
		if !assert.NoError(t, os.WriteFile("/proc/sys/vm/drop_caches", []byte("2"), 0o644)) {
			t.FailNow()
		}

		before := lookups()

		for _, tgt := range targets {
			fd, err := unix.OpenByHandleAt(mountFd, tgt.handle, unix.O_RDONLY|unix.O_CLOEXEC)
			if !assert.NoError(t, err, tgt.rel) {
				t.FailNow()
			}

			f := os.NewFile(uintptr(fd), tgt.rel)

			var st unix.Stat_t
			if !assert.NoError(t, unix.Fstat(fd, &st), tgt.rel) {
				t.FailNow()
			}

			assert.Equal(t, tgt.ino, st.Ino, tgt.rel)

			if st.Mode&unix.S_IFMT == unix.S_IFREG {
				got, err := io.ReadAll(f)
				if !assert.NoError(t, err, tgt.rel) {
					t.FailNow()
				}

				assert.Equal(t, m.wantBytes(t, tgt.rel), got, tgt.rel)
			}

			_ = f.Close()
		}

		if lookups() > before {
			evicted = true
			break
		}
	}

	assert.True(t, evicted, "the kernel never asked the daemon for an evicted inode")
}
