package e2e

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// roFullReadLimit is the size above which a file is sampled rather than read
// whole. The corpus deliberately contains multi-gigabyte sparse files to force
// the extended inode encoding, and slurping those into memory would dominate
// the run without testing anything the samples miss.
const roFullReadLimit = 64 << 20

// DiffTree is roDiffTree for the e2e subpackages.
func DiffTree(t *testing.T, src, mnt string, compareMtimeNsec bool) {
	t.Helper()
	roDiffTree(t, src, mnt, compareMtimeNsec)
}

// roDiffTree is the single whole-tree differential: it walks the source and
// asserts the mount reproduces it exactly. Every scenario that produces a mount
// runs this, so a builder change that corrupts metadata is caught the same way
// whether the image came from one blob, a bootstrap, or a merge.
//
// compareMtimeNsec is false when comparing against an image built by
// mkfs.erofs, whose compact inodes carry no sub-second mtime.
func roDiffTree(t *testing.T, src, mnt string, compareMtimeNsec bool) {
	t.Helper()
	// Deliberately serial: callers unmount with a defer, and a parallel subtest
	// would not run until after that defer had already fired.

	t.Run("PathSet", func(t *testing.T) {
		require.Equal(t, roRelativePaths(t, src), roRelativePaths(t, mnt))
	})

	t.Run("Metadata", func(t *testing.T) {
		roWalkPairs(t, src, mnt, func(rel, srcPath, mntPath string) {
			var want, got unix.Stat_t
			require.NoError(t, unix.Lstat(srcPath, &want))
			require.NoError(t, unix.Lstat(mntPath, &got), "lstat %s", rel)

			// The root is deliberately normalised; its own cases cover it.
			if rel == "." {
				return
			}

			require.Equal(t, want.Mode, got.Mode, "%s: st_mode", rel)
			// btrfs, among others, reports 1 for every directory.
			if want.Mode&unix.S_IFMT != unix.S_IFDIR || want.Nlink != 1 {
				require.Equal(t, want.Nlink, got.Nlink, "%s: st_nlink", rel)
			}
			require.Equal(t, want.Uid, got.Uid, "%s: st_uid", rel)
			require.Equal(t, want.Gid, got.Gid, "%s: st_gid", rel)
			require.Equal(t, want.Mtim.Sec, got.Mtim.Sec, "%s: mtime", rel)
			if compareMtimeNsec {
				require.Equal(t, want.Mtim.Nsec, got.Mtim.Nsec, "%s: mtime nsec", rel)
			}
			switch want.Mode & unix.S_IFMT {
			case unix.S_IFREG, unix.S_IFLNK:
				require.Equal(t, want.Size, got.Size, "%s: st_size", rel)
			case unix.S_IFCHR, unix.S_IFBLK:
				require.Equal(t, want.Rdev, got.Rdev, "%s: st_rdev", rel)
			}
		})
	})

	t.Run("Content", func(t *testing.T) {
		roWalkPairs(t, src, mnt, func(rel, srcPath, mntPath string) {
			var st unix.Stat_t
			require.NoError(t, unix.Lstat(srcPath, &st))
			if st.Mode&unix.S_IFMT != unix.S_IFREG {
				return
			}
			if st.Size > roFullReadLimit {
				roCompareSampled(t, srcPath, mntPath, st.Size)
				return
			}
			want, err := os.ReadFile(srcPath)
			require.NoError(t, err)
			if len(want) > 0 {
				roCompareProbes(t, mntPath, want)
			}
			got, err := os.ReadFile(mntPath)
			require.NoError(t, err, "read %s", rel)
			require.True(t, bytes.Equal(want, got), "%s: content differs", rel)
		})
	})

	t.Run("SymlinkTargets", func(t *testing.T) {
		roWalkPairs(t, src, mnt, func(rel, srcPath, mntPath string) {
			var st unix.Stat_t
			require.NoError(t, unix.Lstat(srcPath, &st))
			if st.Mode&unix.S_IFMT != unix.S_IFLNK {
				return
			}
			want, err := os.Readlink(srcPath)
			require.NoError(t, err)
			got, err := os.Readlink(mntPath)
			require.NoError(t, err, "readlink %s", rel)
			require.Equal(t, want, got, "%s: symlink target", rel)
		})
	})

	t.Run("HardlinkGroups", func(t *testing.T) {
		// Names sharing an inode in the source must share one in the mount,
		// and names that do not must not.
		require.Equal(t, roInodeGroups(t, src), roInodeGroups(t, mnt))
	})

	t.Run("Dirents", func(t *testing.T) {
		roWalkPairs(t, src, mnt, func(rel, srcPath, mntPath string) {
			var st unix.Stat_t
			require.NoError(t, unix.Lstat(srcPath, &st))
			if st.Mode&unix.S_IFMT != unix.S_IFDIR {
				return
			}
			want := roSortedDirents(t, srcPath)
			got := roSortedDirents(t, mntPath)

			wantNames := make([]string, 0, len(want))
			for _, e := range want {
				wantNames = append(wantNames, e.Name)
			}
			gotNames := make([]string, 0, len(got))
			for _, e := range got {
				gotNames = append(gotNames, e.Name)
			}
			require.Equal(t, wantNames, gotNames, "%s: directory entries", rel)
			for i, e := range got {
				require.Equal(t, want[i].Type, e.Type, "%s: d_type of %s", rel, e.Name)
				var st unix.Stat_t
				require.NoError(t, unix.Lstat(filepath.Join(mntPath, e.Name), &st))
				require.Equal(t, st.Ino, e.Ino, "%s: d_ino of %s", rel, e.Name)
			}
		})
	})

	t.Run("Xattrs", func(t *testing.T) {
		roWalkPairs(t, src, mnt, func(rel, srcPath, mntPath string) {
			names := roVisibleXattrs(t, srcPath)
			require.Equal(t, names, roVisibleXattrs(t, mntPath), "%s: xattr names", rel)
			for _, name := range names {
				require.Equal(t, roGetXattr(t, srcPath, name), roGetXattr(t, mntPath, name),
					"%s: value of %s", rel, name)
			}
		})
	})
}

// roWalkPairs calls fn for every path in src along with its counterpart in mnt.
func roWalkPairs(t *testing.T, src, mnt string, fn func(rel, srcPath, mntPath string)) {
	t.Helper()
	require.NoError(t, filepath.WalkDir(src, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		require.NoError(t, err)
		fn(rel, path, filepath.Join(mnt, rel))
		return nil
	}))
}

func roRelativePaths(t *testing.T, root string) []string {
	t.Helper()

	var paths []string
	require.NoError(t, filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		require.NoError(t, err)
		if rel != "." {
			paths = append(paths, rel)
		}
		return nil
	}))
	sort.Strings(paths)
	return paths
}

// roInodeGroups returns the sets of paths that share an inode, keyed by the
// smallest path in each set, so the result compares across filesystems even
// though the inode numbers themselves differ.
func roInodeGroups(t *testing.T, root string) map[string][]string {
	t.Helper()

	byIno := map[uint64][]string{}
	require.NoError(t, filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var st unix.Stat_t
		require.NoError(t, unix.Lstat(path, &st))
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		require.NoError(t, err)
		byIno[st.Ino] = append(byIno[st.Ino], rel)
		return nil
	}))

	groups := map[string][]string{}
	for _, paths := range byIno {
		if len(paths) < 2 {
			continue
		}
		sort.Strings(paths)
		groups[paths[0]] = paths
	}
	return groups
}

// roVisibleXattrs lists the xattr names of path, excluding the nydus-internal
// trusted.nydus.* namespace: the builder stamps trusted.nydus.prefetch.blobs
// on the image root, which the nydus FUSE reader hides but a root-privileged
// kernel EROFS mount of the raw device exposes. The internal namespace is not
// part of the reproduced tree contract, so the differential ignores it on
// both sides.
func roVisibleXattrs(t *testing.T, path string) []string {
	t.Helper()
	var names []string
	for _, name := range roListXattr(t, path) {
		if !strings.HasPrefix(name, "trusted.nydus.") {
			names = append(names, name)
		}
	}
	return names
}

// roListXattr lists the xattr names of path itself, not of a symlink target.
func roListXattr(t *testing.T, path string) []string {
	t.Helper()

	size, err := unix.Llistxattr(path, nil)
	// A nydus mount of an image without any xattr answers EOPNOTSUPP.
	if errors.Is(err, unix.EOPNOTSUPP) {
		return nil
	}
	require.NoError(t, err, "listxattr %s", path)
	if size == 0 {
		return nil
	}

	buf := make([]byte, size)
	n, err := unix.Llistxattr(path, buf)
	require.NoError(t, err)

	var names []string
	for _, raw := range bytes.Split(bytes.TrimRight(buf[:n], "\x00"), []byte{0}) {
		if len(raw) > 0 {
			names = append(names, string(raw))
		}
	}
	sort.Strings(names)
	return names
}

// roGetXattr reads an xattr of path itself, not of a symlink target.
func roGetXattr(t *testing.T, path, name string) []byte {
	t.Helper()

	size, err := unix.Lgetxattr(path, name, nil)
	require.NoError(t, err, "getxattr %s %s", path, name)
	if size == 0 {
		return []byte{}
	}

	buf := make([]byte, size)
	n, err := unix.Lgetxattr(path, name, buf)
	require.NoError(t, err)
	return buf[:n]
}

// roCompareProbes reads mntPath at odd offsets straddling page and chunk
// boundaries, past EOF and through mmap, each from a cold page cache, so
// chunks are decoded out of order rather than by one sequential pass.
func roCompareProbes(t *testing.T, mntPath string, want []byte) {
	t.Helper()

	fd, err := unix.Open(mntPath, unix.O_RDONLY, 0)
	require.NoError(t, err, "open %s", mntPath)
	defer func() { _ = unix.Close(fd) }()
	drop := func() { _ = unix.Fadvise(fd, 0, 0, unix.FADV_DONTNEED) }

	size := int64(len(want))
	got := make([]byte, 8191)
	for _, off := range []int64{size - 1, size - 4097, size/2 + 1, 4<<20 - 3, 2<<20 + 1, 2<<20 - 1,
		1<<20 - 1, 65537, 65535, 4097, 4095, 1, 0} {
		if off < 0 || off >= size {
			continue
		}
		drop()
		n, err := unix.Pread(fd, got, off)
		require.NoError(t, err, "pread %s at %d", mntPath, off)
		end := min(off+int64(len(got)), size)
		require.True(t, bytes.Equal(want[off:end], got[:n]), "%s: content differs at %d", mntPath, off)
	}
	n, err := unix.Pread(fd, got, size)
	require.NoError(t, err, "pread %s at EOF", mntPath)
	require.Zero(t, n, "%s: read past EOF", mntPath)

	drop()
	mapped, err := unix.Mmap(fd, 0, len(want), unix.PROT_READ, unix.MAP_SHARED)
	require.NoError(t, err, "mmap %s", mntPath)
	defer func() { _ = unix.Munmap(mapped) }()
	require.True(t, bytes.Equal(want, mapped), "%s: mapped content differs", mntPath)
}

type roDirent struct {
	Name string
	Ino  uint64
	Type uint8
	Off  int64
}

// roSortedDirents lists dir through a buffer small enough to take several
// getdents64 calls, so readdir resumption is exercised, without "." and
// "..", sorted by name.
func roSortedDirents(t *testing.T, dir string) []roDirent {
	t.Helper()
	var entries []roDirent
	for _, e := range roReadDirentsBuf(t, dir, 512) {
		if e.Name != "." && e.Name != ".." {
			entries = append(entries, e)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries
}

func roReadDirentsBuf(t *testing.T, dir string, bufSize int) []roDirent {
	t.Helper()

	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	require.NoError(t, err, "open %s", dir)
	defer func() { _ = unix.Close(fd) }()

	return roDrainDirents(t, fd, bufSize)
}

// roDrainDirents decodes the raw getdents64 stream. unix.ParseDirent would be
// simpler but discards d_type, d_ino and d_off, which is precisely what needs
// checking here.
func roDrainDirents(t *testing.T, fd int, bufSize int) []roDirent {
	t.Helper()

	buf := make([]byte, bufSize)
	var out []roDirent
	for {
		n, err := unix.Getdents(fd, buf)
		require.NoError(t, err)
		if n == 0 {
			return out
		}

		for offset := 0; offset < n; {
			raw := (*unix.Dirent)(unsafe.Pointer(&buf[offset]))
			reclen := int(raw.Reclen)
			require.Greater(t, reclen, 0, "malformed dirent record length")

			nameBytes := unsafe.Slice((*byte)(unsafe.Pointer(&raw.Name[0])), reclen-int(unsafe.Offsetof(raw.Name)))
			if i := bytes.IndexByte(nameBytes, 0); i >= 0 {
				nameBytes = nameBytes[:i]
			}

			out = append(out, roDirent{
				Name: string(nameBytes),
				Ino:  raw.Ino,
				Type: raw.Type,
				Off:  raw.Off,
			})
			offset += reclen
		}
	}
}

// roCompareSampled checks the head, tail and a few interior windows of a file
// too large to compare byte for byte.
func roCompareSampled(t *testing.T, srcPath, mntPath string, size int64) {
	t.Helper()

	src, err := unix.Open(srcPath, unix.O_RDONLY, 0)
	require.NoError(t, err)
	defer func() { _ = unix.Close(src) }()
	mnt, err := unix.Open(mntPath, unix.O_RDONLY, 0)
	require.NoError(t, err, "open %s", mntPath)
	defer func() { _ = unix.Close(mnt) }()

	const window = 64 << 10
	offsets := []int64{0, 4095, 4096, size / 3, size / 2, size - window, size - 1}
	for _, off := range offsets {
		if off < 0 || off >= size {
			continue
		}
		want := make([]byte, window)
		got := make([]byte, window)
		n1, err1 := unix.Pread(src, want, off)
		n2, err2 := unix.Pread(mnt, got, off)
		require.NoError(t, err1)
		require.NoError(t, err2, "pread %s at %d", mntPath, off)
		require.Equal(t, n1, n2, "%s: short read at %d", mntPath, off)
		require.True(t, bytes.Equal(want[:n1], got[:n2]), "%s: content differs at %d", mntPath, off)
	}
}
