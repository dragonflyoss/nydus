package contract

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

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// C13: attributes and the syscalls built on them: metadata the builder has
// to encode specially, inode identity, permission checks by an unprivileged
// uid, statfs, locks, and how a process sees itself inside the mount.
func init() {
	Register(Case{ID: "C13", Name: "Attributes", Scope: Semantic, Run: runAttributes})
}

func runAttributes(t *testing.T, f *Fixture) {
	t.Run("Metadata", func(t *testing.T) {
		t.Parallel()
		metadata(t, f)
	})
	t.Run("InodeIdentity", func(t *testing.T) {
		t.Parallel()
		inodeIdentity(t, f)
	})
	t.Run("Permissions", func(t *testing.T) {
		t.Parallel()
		permissions(t, f)
	})
	t.Run("Statfs", func(t *testing.T) {
		t.Parallel()
		statfs(t, f)
	})
	t.Run("Locks", func(t *testing.T) {
		t.Parallel()
		locks(t, f)
	})
	t.Run("ProcessView", func(t *testing.T) {
		t.Parallel()
		processView(t, f)
	})
}

func metadata(t *testing.T, f *Fixture) {
	t.Run("RootMode", func(t *testing.T) {
		t.Parallel()
		var st unix.Stat_t
		require.NoError(t, unix.Stat(f.Root, &st))
		require.EqualValues(t, unix.S_IFDIR, st.Mode&unix.S_IFMT)
		// The root's permission bits are the staging tool's umask, not
		// content. The FUSE reader pins them to 0755 so no umask can lock
		// other uids out of a rootfs; the kernel driver reports what the
		// builder recorded, the source root's bits.
		want := uint32(0o755)
		if isKernelEROFS(f) {
			var src unix.Stat_t
			require.NoError(t, unix.Stat(f.Image.Source, &src))
			want = src.Mode & 0o7777
		}
		require.EqualValues(t, want, st.Mode&0o7777, "root permission bits")
	})

	t.Run("RootMtimeIsDropped", func(t *testing.T) {
		t.Parallel()
		// The root's mtime is the build time, not a property of the content,
		// so the builder drops it to keep the bootstrap reproducible.
		var st unix.Stat_t
		require.NoError(t, unix.Stat(f.Root, &st))
		require.Zero(t, st.Mtim.Sec, "the root's mtime should not be carried over")
		require.Zero(t, st.Mtim.Nsec)
	})

	t.Run("DeviceNumbers", func(t *testing.T) {
		t.Parallel()
		for rel, want := range map[string][2]uint32{"special/chardev": {1, 3}, "special/blkdev": {1, 0}} {
			var st unix.Stat_t
			require.NoError(t, unix.Lstat(f.At(rel), &st))
			require.EqualValues(t, want[0], unix.Major(st.Rdev), "%s: major", rel)
			require.EqualValues(t, want[1], unix.Minor(st.Rdev), "%s: minor", rel)
		}
	})

	t.Run("WideOwners", func(t *testing.T) {
		t.Parallel()
		// Past 16 bits the builder has to emit an extended inode.
		for rel, want := range map[string][2]uint32{
			"special/large_uid_gid": {70000, 70001},
			"special/uid_65535":     {65535, 65535},
			"special/uid_65536":     {65536, 65536},
		} {
			var st unix.Stat_t
			require.NoError(t, unix.Lstat(f.At(rel), &st))
			require.EqualValues(t, want[0], st.Uid, "%s: uid", rel)
			require.EqualValues(t, want[1], st.Gid, "%s: gid", rel)
		}
	})

	t.Run("DirectoryLinkCount", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{".", "dirs", "dirs/a", "dirs/empty_dir", "symlinks", "wide/short"} {
			var st unix.Stat_t
			require.NoError(t, unix.Stat(f.At(rel), &st))
			subdirs := 0
			for _, e := range oracle.ReadDirents(t, f.At(rel), 32<<10) {
				if e.Type == unix.DT_DIR && e.Name != "." && e.Name != ".." {
					subdirs++
				}
			}
			require.EqualValues(t, subdirs+2, st.Nlink, "%s: st_nlink should be 2 + subdirectories", rel)
		}
	})

	t.Run("BlocksAccountForData", func(t *testing.T) {
		t.Parallel()
		var empty, big unix.Stat_t
		require.NoError(t, unix.Stat(f.At("files/empty"), &empty))
		require.NoError(t, unix.Stat(f.At("files/large_256k"), &big))
		require.Zero(t, empty.Blocks, "an empty file should not report allocated blocks")
		require.GreaterOrEqual(t, big.Blocks*512, big.Size/2,
			"st_blocks is implausibly small for a %d byte file", big.Size)
		require.Positive(t, big.Blksize, "st_blksize")
	})
}

func inodeIdentity(t *testing.T, f *Fixture) {
	t.Run("HardlinksShareInode", func(t *testing.T) {
		t.Parallel()
		group := []string{"hardlinks/original", "hardlinks/link1", "hardlinks/link2", "hardlinks/subdir/link3"}
		var first unix.Stat_t
		require.NoError(t, unix.Stat(f.At(group[0]), &first))
		require.EqualValues(t, len(group), first.Nlink, "st_nlink does not match the hardlink count")
		for _, rel := range group[1:] {
			var st unix.Stat_t
			require.NoError(t, unix.Stat(f.At(rel), &st))
			require.Equal(t, first.Ino, st.Ino, "%s has a different inode number", rel)
			require.Equal(t, first.Nlink, st.Nlink, "%s has a different link count", rel)
		}
		// A link count past 255 needs more than a byte.
		var many unix.Stat_t
		require.NoError(t, unix.Stat(f.At("inode/many_links"), &many))
		var src unix.Stat_t
		require.NoError(t, unix.Stat(f.Src("inode/many_links"), &src))
		require.True(t, src.Nlink > 255, "source nlink must exceed 255: %d", src.Nlink)
		require.EqualValues(t, src.Nlink, many.Nlink, "inode/many_links: st_nlink")
	})

	t.Run("DistinctFilesHaveDistinctInodes", func(t *testing.T) {
		t.Parallel()
		// Identical content must still be separate inodes: chunk
		// deduplication happens below the metadata layer.
		var a, b unix.Stat_t
		require.NoError(t, unix.Stat(f.At("hardlinks/same_content_a"), &a))
		require.NoError(t, unix.Stat(f.At("hardlinks/same_content_b"), &b))
		require.NotEqual(t, a.Ino, b.Ino)
		require.EqualValues(t, 1, a.Nlink)
	})

	t.Run("InodesUniqueAndOneDevice", func(t *testing.T) {
		t.Parallel()
		var root unix.Stat_t
		require.NoError(t, unix.Stat(f.Root, &root))
		seen := map[uint64]string{}
		require.NoError(t, filepath.WalkDir(f.Root, func(path string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			var st unix.Stat_t
			if err := unix.Lstat(path, &st); err != nil {
				return err
			}
			require.Equal(t, root.Dev, st.Dev, "%s reports a different st_dev", path)
			if st.Nlink > 1 && st.Mode&unix.S_IFMT != unix.S_IFDIR {
				return nil
			}
			prev, dup := seen[st.Ino]
			require.False(t, dup, "inode %d shared by %s and %s without a hardlink", st.Ino, prev, path)
			seen[st.Ino] = path
			return nil
		}))
	})
}

// unprivilegedUID is the fsuid and fsgid permission checks run as.
const unprivilegedUID = 65534

func permissions(t *testing.T, f *Fixture) {
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
			require.NoError(t, unix.Stat(f.At(rel), &st))
			require.EqualValues(t, want, st.Mode&0o7777, "%s lost its mode bits", rel)
		}
	})

	openAs := func(t *testing.T, path string) error {
		return asUser(t, func() error {
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err == nil {
				_ = unix.Close(fd)
			}
			return err
		})
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

	// The mode, uid and gid the mount reports have to gate access: under
	// FUSE through default_permissions, under EROFS natively.
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
			err := openAs(t, f.At(tc.rel))
			if tc.want == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tc.want)
			}
		})
	}

	t.Run("ListingNeedsRead", func(t *testing.T) {
		t.Parallel()
		// 0711 is reachable by name but not listable; 0444 is listable.
		require.ErrorIs(t, readdirAs(t, f.At("perms/x_only_dir")), unix.EACCES)
		require.NoError(t, readdirAs(t, f.At("perms/r_only_dir")))
	})

	t.Run("AccessMatchesOpen", func(t *testing.T) {
		t.Parallel()
		env.RequireKernel(t, 5, 8, "faccessat2 AT_EACCESS; the userspace fallback checks euid rather than fsuid")
		// access(2) consults the real uid, which setfsuid does not change, so
		// this goes through faccessat2's AT_EACCESS, which uses the fsuid.
		access := func(rel string, mode uint32) error {
			return asUser(t, func() error {
				return unix.Faccessat(unix.AT_FDCWD, f.At(rel), mode, unix.AT_EACCESS)
			})
		}
		require.NoError(t, access("perms/other_owner_r", unix.R_OK))
		require.ErrorIs(t, access("perms/other_owner_none", unix.R_OK), unix.EACCES)
		require.ErrorIs(t, access("perms/r_only", unix.X_OK), unix.EACCES)
		require.NoError(t, access("perms/r_x", unix.X_OK))
	})
}

// asUser runs fn on a thread whose filesystem uid and gid are
// unprivilegedUID. setfsuid is per thread and, once the fsuid is non-zero,
// also clears CAP_DAC_OVERRIDE and friends from the effective set, which is
// exactly what is being exercised.
func asUser(t *testing.T, fn func() error) error {
	t.Helper()
	runtime.LockOSThread()
	defer func() {
		_ = unix.Setfsuid(0)
		_ = unix.Setfsgid(0)
		// A thread whose fsuid could not be restored stays locked, so it
		// exits with the goroutine instead of serving other tests.
		if fsuid, err := threadFsuid(); err == nil && fsuid == 0 {
			runtime.UnlockOSThread()
		}
	}()
	require.NoError(t, unix.Setfsgid(unprivilegedUID))
	require.NoError(t, unix.Setfsuid(unprivilegedUID))
	// setfsuid cannot report failure, and running these checks as root
	// would make every one pass, so read the fsuid back first.
	fsuid, err := threadFsuid()
	require.NoError(t, err)
	require.Equal(t, unprivilegedUID, fsuid, "fsuid was not dropped")
	return fn()
}

// threadFsuid returns the calling thread's filesystem uid, the fourth field
// of the Uid line in /proc/thread-self/status.
func threadFsuid() (int, error) {
	status, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return -1, err
	}
	for _, line := range strings.Split(string(status), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			fields := strings.Fields(rest)
			if len(fields) != 4 {
				return -1, fmt.Errorf("unexpected Uid line %q", line)
			}
			return strconv.Atoi(fields[3])
		}
	}
	return -1, errors.New("no Uid line in /proc/thread-self/status")
}

// stRdonly is ST_RDONLY of statfs(2) f_flags, which x/sys does not define.
const stRdonly = 0x1

func statfs(t *testing.T, f *Fixture) {
	var st unix.Statfs_t
	require.NoError(t, unix.Statfs(f.Root, &st))
	if isKernelEROFS(f) {
		require.EqualValues(t, unix.EROFS_SUPER_MAGIC_V1, st.Type, "f_type should be EROFS_SUPER_MAGIC_V1")
	} else {
		require.EqualValues(t, unix.FUSE_SUPER_MAGIC, st.Type, "f_type should be FUSE_SUPER_MAGIC")
	}
	require.Positive(t, st.Bsize, "f_bsize")
	require.EqualValues(t, 255, st.Namelen, "f_namelen should be NAME_MAX")
	// Nothing can ever be written, so there is no free space to report.
	require.Zero(t, st.Bavail, "f_bavail")
	require.Zero(t, st.Bfree, "f_bfree")
	require.NotZero(t, st.Flags&stRdonly, "f_flags lacks ST_RDONLY")

	// Every path on the mount reports the same filesystem.
	var sub unix.Statfs_t
	require.NoError(t, unix.Statfs(f.At("dirs/a/b/c"), &sub))
	require.Equal(t, st.Type, sub.Type)
	require.Equal(t, st.Fsid, sub.Fsid)
}

func locks(t *testing.T, f *Fixture) {
	path := f.At("files/small_100b")

	t.Run("Flock", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, path)
		require.NoError(t, unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB))
		require.NoError(t, unix.Flock(fd, unix.LOCK_UN))
		// flock does not need a writable descriptor even for LOCK_EX.
		require.NoError(t, unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB))
		require.NoError(t, unix.Flock(fd, unix.LOCK_UN))
	})

	t.Run("PosixReadLock", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, path)
		lk := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET}
		require.NoError(t, unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &lk))
		probe := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET}
		require.NoError(t, unix.FcntlFlock(uintptr(fd), unix.F_GETLK, &probe))
		require.EqualValues(t, unix.F_UNLCK, probe.Type, "an unheld range should read back unlocked")
		// A write lock needs a writable descriptor.
		wlk := unix.Flock_t{Type: unix.F_WRLCK, Whence: unix.SEEK_SET}
		require.ErrorIs(t, unix.FcntlFlock(uintptr(fd), unix.F_SETLK, &wlk), unix.EBADF)
	})

	t.Run("OFDReadLock", func(t *testing.T) {
		t.Parallel()
		// OFD locks are what SQLite and systemd use; a read lock must be
		// available even though nothing can ever be written.
		fd := openRO(t, path)
		lk := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET}
		require.NoError(t, unix.FcntlFlock(uintptr(fd), unix.F_OFD_SETLK, &lk))
		probe := unix.Flock_t{Type: unix.F_RDLCK, Whence: unix.SEEK_SET}
		require.NoError(t, unix.FcntlFlock(uintptr(fd), unix.F_OFD_GETLK, &probe))
		require.EqualValues(t, unix.F_UNLCK, probe.Type)
	})

	t.Run("Fsync", func(t *testing.T) {
		t.Parallel()
		fd := openRO(t, path)
		err := unix.Fsync(fd)
		if isKernelEROFS(f) && errors.Is(err, unix.EINVAL) {
			// The kernel driver has no ->fsync, which the VFS reports as
			// EINVAL; there is nothing dirty either way.
			return
		}
		// Nothing is dirty, so this is a no-op rather than an error.
		require.NoError(t, err)
		require.NoError(t, unix.Fdatasync(fd))
	})
}

func processView(t *testing.T, f *Fixture) {
	// Paths the kernel reports are resolved; the mount may sit below a
	// symlink such as a /tmp that is one.
	root, err := filepath.EvalSymlinks(f.Root)
	require.NoError(t, err)

	t.Run("Getcwd", func(t *testing.T) {
		t.Parallel()
		// A child process, because the working directory is per process and
		// the other cases run in parallel.
		cmd := exec.Command("sh", "-c", "pwd -P && cd .. && pwd -P")
		cmd.Dir = f.At("dirs/a/b/c")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
		want := root + "/dirs/a/b/c\n" + root + "/dirs/a/b\n"
		require.Equal(t, want, string(out), "getcwd inside the mount")
	})

	t.Run("ProcFdNamesTheFile", func(t *testing.T) {
		t.Parallel()
		for _, rel := range []string{"files/small_100b", "dirs/a/b/c/d/e/f/deep_file", "hardlinks/link2"} {
			fd := openRO(t, f.At(rel))
			target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
			require.NoError(t, err)
			require.Equal(t, root+"/"+rel, target, "/proc/self/fd should name the open file")
		}
	})

	t.Run("FileHandle", func(t *testing.T) {
		t.Parallel()
		path := f.At("files/small_100b")
		handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
		if !isKernelEROFS(f) && err != nil {
			// The FUSE reader does not offer export support, which it must
			// say rather than hand out a handle it cannot resolve.
			require.True(t, errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EINVAL),
				"name_to_handle_at failed with an unexpected error: %v", err)
			return
		}
		// EROFS supports NFS export, so a handle must round-trip.
		require.NoError(t, err, "name_to_handle_at")
		mountFd := openDir(t, f.Root)
		fd, err := unix.OpenByHandleAt(mountFd, handle, unix.O_RDONLY|unix.O_CLOEXEC)
		if !isKernelEROFS(f) && errors.Is(err, unix.ESTALE) {
			// Without export support FUSE can only resolve inodes it still
			// has cached.
			return
		}
		require.NoError(t, err, "open_by_handle_at")
		defer func() { _ = unix.Close(fd) }()
		var viaHandle, viaPath unix.Stat_t
		require.NoError(t, unix.Fstat(fd, &viaHandle))
		require.NoError(t, unix.Stat(path, &viaPath))
		require.Equal(t, viaPath.Ino, viaHandle.Ino)
	})
}
