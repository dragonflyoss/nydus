package conformance

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/proc"
)

func testAttributes(t *testing.T, m *mounted) {
	t.Run("Metadata", func(t *testing.T) {
		t.Parallel()
		metadata(t, m)
	})

	t.Run("InodeIdentity", func(t *testing.T) {
		t.Parallel()
		inodeIdentity(t, m)
	})

	t.Run("Permissions", func(t *testing.T) {
		t.Parallel()
		permissions(t, m)
	})

	t.Run("Statfs", func(t *testing.T) {
		t.Parallel()
		statfs(t, m)
	})

	t.Run("Locks", func(t *testing.T) {
		t.Parallel()
		locks(t, m)
	})

	t.Run("ProcessView", func(t *testing.T) {
		t.Parallel()
		processView(t, m)
	})
}

func metadata(t *testing.T, m *mounted) {
	t.Run("RootMode", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		if !assert.NoError(t, unix.Stat(m.Root, &st)) {
			t.FailNow()
		}
		if !assert.EqualValues(t, unix.S_IFDIR, st.Mode&unix.S_IFMT) {
			t.FailNow()
		}

		want := uint32(0o755)
		if m.isKernelEROFS() {
			var src unix.Stat_t
			if !assert.NoError(t, unix.Stat(m.Image.Source, &src)) {
				t.FailNow()
			}

			want = src.Mode & 0o7777
		}

		assert.Equal(t, want, st.Mode&0o7777)
	})

	t.Run("RootMtimeIsDropped", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		if !assert.NoError(t, unix.Stat(m.Root, &st)) {
			t.FailNow()
		}
		if !assert.Zero(t, st.Mtim.Sec) {
			t.FailNow()
		}

		assert.Zero(t, st.Mtim.Nsec)
	})

	t.Run("DeviceNumbers", func(t *testing.T) {
		t.Parallel()
		for rel, want := range map[string][2]uint32{"special/chardev": {1, 3}, "special/blkdev": {1, 0}} {
			var st unix.Stat_t
			if !assert.NoError(t, unix.Lstat(m.Path(rel), &st)) {
				t.FailNow()
			}
			if !assert.Equal(t, want[0], unix.Major(st.Rdev)) {
				t.FailNow()
			}

			assert.Equal(t, want[1], unix.Minor(st.Rdev))
		}
	})

	t.Run("WideOwners", func(t *testing.T) {
		t.Parallel()
		for rel, want := range map[string][2]uint32{
			"special/large_uid_gid": {70000, 70001},
			"special/uid_65535":     {65535, 65535},
			"special/uid_65536":     {65536, 65536},
		} {
			var st unix.Stat_t
			if !assert.NoError(t, unix.Lstat(m.Path(rel), &st)) {
				t.FailNow()
			}
			if !assert.Equal(t, want[0], st.Uid) {
				t.FailNow()
			}

			assert.Equal(t, want[1], st.Gid)
		}
	})

	t.Run("DirectoryLinkCount", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{".", "dirs", "dirs/a", "dirs/empty_dir", "symlinks", "wide/short"} {
			var st unix.Stat_t
			if !assert.NoError(t, unix.Stat(m.Path(rel), &st)) {
				t.FailNow()
			}

			subdirs := 0

			for _, e := range fstest.ReadDirents(t, m.Path(rel), 32<<10) {
				if e.Type == unix.DT_DIR && e.Name != "." && e.Name != ".." {
					subdirs++
				}
			}

			assert.EqualValues(t, subdirs+2, st.Nlink)
		}
	})

	t.Run("BlocksAccountForData", func(t *testing.T) {
		t.Parallel()
		var empty, big unix.Stat_t
		if !assert.NoError(t, unix.Stat(m.Path("files/empty"), &empty)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Stat(m.Path("files/large_256k"), &big)) {
			t.FailNow()
		}
		if !assert.Zero(t, empty.Blocks) {
			t.FailNow()
		}
		if !assert.GreaterOrEqual(t, big.Blocks*512, big.Size/2) {
			t.FailNow()
		}

		assert.Positive(t, big.Blksize)
	})
}

func inodeIdentity(t *testing.T, m *mounted) {
	t.Run("HardlinksShareInode", func(t *testing.T) {
		t.Parallel()
		group := []string{"hardlinks/original", "hardlinks/link1", "hardlinks/link2", "hardlinks/subdir/link3"}
		var first unix.Stat_t
		if !assert.NoError(t, unix.Stat(m.Path(group[0]), &first)) {
			t.FailNow()
		}
		if !assert.EqualValues(t, len(group), first.Nlink) {
			t.FailNow()
		}

		for _, rel := range group[1:] {
			var st unix.Stat_t
			if !assert.NoError(t, unix.Stat(m.Path(rel), &st)) {
				t.FailNow()
			}
			if !assert.Equal(t, first.Ino, st.Ino) {
				t.FailNow()
			}

			assert.Equal(t, first.Nlink, st.Nlink)
		}

		var many unix.Stat_t
		if !assert.NoError(t, unix.Stat(m.Path("inode/many_links"), &many)) {
			t.FailNow()
		}

		var src unix.Stat_t
		if !assert.NoError(t, unix.Stat(m.src("inode/many_links"), &src)) {
			t.FailNow()
		}
		if !assert.Greater(t, src.Nlink, uint64(255)) {
			t.FailNow()
		}

		assert.Equal(t, src.Nlink, many.Nlink)
	})

	t.Run("DistinctFilesHaveDistinctInodes", func(t *testing.T) {
		t.Parallel()
		var a, b unix.Stat_t
		if !assert.NoError(t, unix.Stat(m.Path("hardlinks/same_content_a"), &a)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Stat(m.Path("hardlinks/same_content_b"), &b)) {
			t.FailNow()
		}
		if !assert.NotEqual(t, a.Ino, b.Ino) {
			t.FailNow()
		}

		assert.EqualValues(t, 1, a.Nlink)
	})

	t.Run("InodesUniqueAndOneDevice", func(t *testing.T) {
		t.Parallel()
		var root unix.Stat_t
		if !assert.NoError(t, unix.Stat(m.Root, &root)) {
			t.FailNow()
		}

		seen := map[uint64]string{}

		assert.NoError(t, filepath.WalkDir(m.Root, func(path string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			var st unix.Stat_t
			if err := unix.Lstat(path, &st); err != nil {
				return err
			}
			if !assert.Equal(t, root.Dev, st.Dev) {
				t.FailNow()
			}
			if st.Nlink > 1 && st.Mode&unix.S_IFMT != unix.S_IFDIR {
				return nil
			}

			_, dup := seen[st.Ino]
			if !assert.False(t, dup) {
				t.FailNow()
			}

			seen[st.Ino] = path

			return nil
		}))
	})
}

func permissions(t *testing.T, m *mounted) {
	t.Run("ModesSurvive", func(t *testing.T) {
		t.Parallel()
		for rel, want := range map[string]uint32{
			"perms/rwx":       0o777,
			"perms/no_perm":   0,
			"perms/setuid":    0o4755,
			"perms/setgid":    0o2755,
			"perms/sticky":    0o1755,
			"perms/suid_sgid": 0o6755,
			"dirs/sticky_dir": 0o1777,
		} {
			var st unix.Stat_t
			if !assert.NoError(t, unix.Stat(m.Path(rel), &st)) {
				t.FailNow()
			}

			assert.Equal(t, want, st.Mode&0o7777)
		}
	})

	openAs := func(t *testing.T, path string) error {
		return asUser(t, func() error { return openErr(path, unix.O_RDONLY, 0) })
	}

	readdirAs := func(t *testing.T, path string) error {
		return asUser(t, func() error {
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}

			defer func() { _ = unix.Close(fd) }()
			_, err = unix.Getdents(fd, make([]byte, 4096))

			return err
		})
	}

	for _, tc := range []struct {
		name, rel string
		want      error
	}{
		{"WorldReadableOpens", "perms/other_owner_r", nil},
		{"ReadOnlyFileOpens", "perms/r_only", nil},
		{"OwnerOnlyDenied", "perms/other_owner_none", unix.EACCES},
		{"ModeZeroDenied", "perms/no_perm", unix.EACCES},
		{"TraverseWithoutList", "perms/x_only_dir/hidden", nil},
		{"ListWithoutTraverse", "perms/r_only_dir/listed", unix.EACCES},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := openAs(t, m.Path(tc.rel))

			if tc.want == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tc.want)
			}
		})
	}

	t.Run("ListingNeedsRead", func(t *testing.T) {
		t.Parallel()
		if !assert.ErrorIs(t, readdirAs(t, m.Path("perms/x_only_dir")), unix.EACCES) {
			t.FailNow()
		}

		assert.NoError(t, readdirAs(t, m.Path("perms/r_only_dir")))
	})

	t.Run("AccessMatchesOpen", func(t *testing.T) {
		t.Parallel()
		env.MustHaveKernel(t, 5, 8, "faccessat2 AT_EACCESS; the userspace fallback checks euid rather than fsuid")

		access := func(rel string, mode uint32) error {
			return asUser(t, func() error {
				return unix.Faccessat(unix.AT_FDCWD, m.Path(rel), mode, unix.AT_EACCESS)
			})
		}

		if !assert.NoError(t, access("perms/other_owner_r", unix.R_OK)) {
			t.FailNow()
		}
		if !assert.ErrorIs(t, access("perms/other_owner_none", unix.R_OK), unix.EACCES) {
			t.FailNow()
		}
		if !assert.ErrorIs(t, access("perms/r_only", unix.X_OK), unix.EACCES) {
			t.FailNow()
		}

		assert.NoError(t, access("perms/r_x", unix.X_OK))
	})
}

func asUser(t *testing.T, fn func() error) error {
	t.Helper()
	runtime.LockOSThread()

	defer func() {
		_ = unix.Setfsuid(0)
		_ = unix.Setfsgid(0)

		if fsuid, fsgid, err := threadFsids(); err == nil && fsuid == 0 && fsgid == 0 {
			runtime.UnlockOSThread()
		}
	}()

	_ = unix.Setfsgid(unprivilegedUID)
	_ = unix.Setfsuid(unprivilegedUID)

	fsuid, fsgid, err := threadFsids()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, unprivilegedUID, fsuid) {
		t.FailNow()
	}
	if !assert.Equal(t, unprivilegedUID, fsgid) {
		t.FailNow()
	}

	return fn()
}

func threadFsids() (fsuid, fsgid int, err error) {
	status, err := proc.Status("/proc/thread-self/status")
	if err != nil {
		return -1, -1, err
	}

	ids := make([]int, 2)

	for i, key := range []string{"Uid", "Gid"} {
		fields := strings.Fields(status[key])
		if len(fields) != 4 {
			return -1, -1, fmt.Errorf("unexpected %s line %q", key, status[key])
		}
		if ids[i], err = strconv.Atoi(fields[3]); err != nil {
			return -1, -1, err
		}
	}

	return ids[0], ids[1], nil
}

func statfs(t *testing.T, m *mounted) {
	var st unix.Statfs_t
	if !assert.NoError(t, unix.Statfs(m.Root, &st)) {
		t.FailNow()
	}

	if m.isKernelEROFS() {
		assert.EqualValues(t, unix.EROFS_SUPER_MAGIC_V1, st.Type)
	} else {
		assert.EqualValues(t, unix.FUSE_SUPER_MAGIC, st.Type)
	}

	if !assert.Positive(t, st.Bsize) {
		t.FailNow()
	}
	if !assert.EqualValues(t, 255, st.Namelen) {
		t.FailNow()
	}
	if !assert.Zero(t, st.Bavail) {
		t.FailNow()
	}
	if !assert.Zero(t, st.Bfree) {
		t.FailNow()
	}
	if !assert.NotZero(t, st.Flags&unix.ST_RDONLY) {
		t.FailNow()
	}

	var sub unix.Statfs_t
	if !assert.NoError(t, unix.Statfs(m.Path("dirs/a/b/c"), &sub)) {
		t.FailNow()
	}
	if !assert.Equal(t, st.Type, sub.Type) {
		t.FailNow()
	}

	assert.Equal(t, st.Fsid, sub.Fsid)
}

func locks(t *testing.T, m *mounted) {
	path := m.Path("files/small_100b")

	t.Run("Flock", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, path)
		if !assert.NoError(t, unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Flock(fd, unix.LOCK_UN)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)) {
			t.FailNow()
		}

		assert.NoError(t, unix.Flock(fd, unix.LOCK_UN))
	})

	t.Run("PosixReadLock", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, path)
		lk := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET}
		if !assert.NoError(t, unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &lk)) {
			t.FailNow()
		}

		probe := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET}
		if !assert.NoError(t, unix.FcntlFlock(uintptr(fd), unix.F_GETLK, &probe)) {
			t.FailNow()
		}
		if !assert.EqualValues(t, unix.F_UNLCK, probe.Type) {
			t.FailNow()
		}

		wlk := unix.Flock_t{Type: unix.F_WRLCK, Whence: unix.SEEK_SET}
		assert.ErrorIs(t, unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &wlk), unix.EBADF)
	})

	t.Run("OFDReadLock", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, path)
		lk := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET}
		if !assert.NoError(t, unix.FcntlFlock(uintptr(fd), unix.F_OFD_SETLK, &lk)) {
			t.FailNow()
		}

		probe := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET}
		if !assert.NoError(t, unix.FcntlFlock(uintptr(fd), unix.F_OFD_GETLK, &probe)) {
			t.FailNow()
		}

		assert.EqualValues(t, unix.F_UNLCK, probe.Type)
	})

	t.Run("Fsync", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, path)
		err := unix.Fsync(fd)
		if m.isKernelEROFS() && errors.Is(err, unix.EINVAL) {
			return
		}

		assert.NoError(t, err)
		assert.NoError(t, unix.Fdatasync(fd))
	})
}

func processView(t *testing.T, m *mounted) {
	root, err := filepath.EvalSymlinks(m.Root)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Run("Getcwd", func(t *testing.T) {
		t.Parallel()
		cmd := exec.Command("sh", "-c", "pwd -P && cd .. && pwd -P")
		cmd.Dir = m.Path("dirs/a/b/c")
		out, err := cmd.CombinedOutput()
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		want := root + "/dirs/a/b/c\n" + root + "/dirs/a/b\n"
		assert.Equal(t, want, string(out))
	})

	t.Run("ProcFdNamesTheFile", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"files/small_100b", "dirs/a/b/c/d/e/f/deep_file", "hardlinks/link2"} {
			fd := openRO(t, m.Path(rel))
			target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.Equal(t, root+"/"+rel, target)
		}
	})

	t.Run("FileHandle", func(t *testing.T) {
		t.Parallel()
		path := m.Path("files/small_100b")

		handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
		if !m.isKernelEROFS() && err != nil {
			assert.Contains(t, []error{unix.EOPNOTSUPP, unix.EPERM, unix.EINVAL}, err)
			return
		}

		if !assert.NoError(t, err) {
			t.FailNow()
		}

		mountFd := openDir(t, m.Root)
		fd, err := unix.OpenByHandleAt(mountFd, handle, unix.O_RDONLY|unix.O_CLOEXEC)
		if !m.isKernelEROFS() && errors.Is(err, unix.ESTALE) {
			return
		}
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		defer func() { _ = unix.Close(fd) }()
		var viaHandle, viaPath unix.Stat_t
		if !assert.NoError(t, unix.Fstat(fd, &viaHandle)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Stat(path, &viaPath)) {
			t.FailNow()
		}

		assert.Equal(t, viaPath.Ino, viaHandle.Ino)
	})
}
