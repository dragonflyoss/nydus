// Package oracle holds the judges every e2e suite compares against: the
// whole-tree differential, extent-aware content comparison, raw dirent
// decoding and fsck.erofs.
package oracle

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// FullReadLimit is the size above which a file is compared extent by extent
// rather than read whole: the corpora deliberately contain multi-gigabyte
// sparse files to force the extended inode encoding.
const FullReadLimit = 64 << 20

// Options relaxes DiffTree for images that legitimately differ from their
// source in one respect.
type Options struct {
	// SkipMtimeNsec ignores sub-second mtimes, which compact EROFS inodes
	// written by mkfs.erofs do not carry.
	SkipMtimeNsec bool
	// SkipNlink ignores st_nlink. Only for callers that assert link counts
	// separately, e.g. under a known issue.
	SkipNlink bool
}

// DiffTree asserts that mnt reproduces src exactly: path set, metadata,
// content (including out-of-order and mmap reads), symlink targets, hardlink
// groups, dirents and xattrs. It is the single tree judge of every suite, so
// a builder or reader bug is caught the same way whatever produced the mount.
func DiffTree(t env.TB, src, mnt string, opts Options) {
	t.Helper()

	require.Equal(t, relativePaths(t, src), relativePaths(t, mnt), "path set")

	walkPairs(t, src, mnt, func(rel, srcPath, mntPath string) {
		var want, got unix.Stat_t
		require.NoError(t, unix.Lstat(srcPath, &want))
		require.NoError(t, unix.Lstat(mntPath, &got), "lstat %s", rel)

		// The root is deliberately normalised; the contract cases cover it.
		if rel != "." {
			diffStat(t, rel, &want, &got, opts)
		}

		switch want.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			CompareFile(t, srcPath, mntPath)
		case unix.S_IFLNK:
			wantTarget, err := os.Readlink(srcPath)
			require.NoError(t, err)
			gotTarget, err := os.Readlink(mntPath)
			require.NoError(t, err, "readlink %s", rel)
			require.Equal(t, wantTarget, gotTarget, "%s: symlink target", rel)
		case unix.S_IFDIR:
			diffDirents(t, rel, srcPath, mntPath)
		}

		names := VisibleXattrs(t, srcPath)
		require.Equal(t, names, VisibleXattrs(t, mntPath), "%s: xattr names", rel)
		for _, name := range names {
			require.Equal(t, GetXattr(t, srcPath, name), GetXattr(t, mntPath, name), "%s: value of %s", rel, name)
		}
	})

	// Names sharing an inode in the source must share one in the mount, and
	// names that do not must not.
	require.Equal(t, InodeGroups(t, src), InodeGroups(t, mnt), "hardlink groups")
}

func diffStat(t env.TB, rel string, want, got *unix.Stat_t, opts Options) {
	t.Helper()
	require.Equal(t, want.Mode, got.Mode, "%s: st_mode", rel)
	// btrfs, among others, reports 1 for every directory.
	if !opts.SkipNlink && (want.Mode&unix.S_IFMT != unix.S_IFDIR || want.Nlink != 1) {
		require.Equal(t, want.Nlink, got.Nlink, "%s: st_nlink", rel)
	}
	require.Equal(t, want.Uid, got.Uid, "%s: st_uid", rel)
	require.Equal(t, want.Gid, got.Gid, "%s: st_gid", rel)
	require.Equal(t, want.Mtim.Sec, got.Mtim.Sec, "%s: mtime", rel)
	if !opts.SkipMtimeNsec {
		require.Equal(t, want.Mtim.Nsec, got.Mtim.Nsec, "%s: mtime nsec", rel)
	}
	switch want.Mode & unix.S_IFMT {
	case unix.S_IFREG, unix.S_IFLNK:
		require.Equal(t, want.Size, got.Size, "%s: st_size", rel)
	case unix.S_IFCHR, unix.S_IFBLK:
		require.Equal(t, want.Rdev, got.Rdev, "%s: st_rdev", rel)
	}
}

func diffDirents(t env.TB, rel, srcPath, mntPath string) {
	t.Helper()
	want := SortedDirents(t, srcPath)
	got := SortedDirents(t, mntPath)

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
}

// CompareFile asserts that mntPath holds the same bytes as srcPath. Small
// files are also probed at odd offsets from a cold page cache and through
// mmap; large ones are compared extent by extent.
func CompareFile(t env.TB, srcPath, mntPath string) {
	t.Helper()
	st, err := os.Stat(srcPath)
	require.NoError(t, err)
	if st.Size() > FullReadLimit {
		CompareExtents(t, srcPath, mntPath)
		return
	}
	want, err := os.ReadFile(srcPath)
	require.NoError(t, err)
	if len(want) > 0 {
		compareProbes(t, mntPath, want)
	}
	got, err := os.ReadFile(mntPath)
	require.NoError(t, err, "read %s", mntPath)
	require.True(t, bytes.Equal(want, got), "%s: content differs", mntPath)
}

// compareProbes reads mntPath at offsets straddling page and chunk
// boundaries, past EOF and through mmap, each from a cold page cache, so
// chunks are decoded out of order rather than by one sequential pass.
func compareProbes(t env.TB, mntPath string, want []byte) {
	t.Helper()

	fd, err := unix.Open(mntPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
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

// walkPairs calls fn for every path in src along with its counterpart in mnt.
func walkPairs(t env.TB, src, mnt string, fn func(rel, srcPath, mntPath string)) {
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

func relativePaths(t env.TB, root string) []string {
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

// InodeGroups returns the sets of paths that share an inode, keyed by the
// smallest path in each set, so the result compares across filesystems even
// though the inode numbers themselves differ.
func InodeGroups(t env.TB, root string) map[string][]string {
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

// VisibleXattrs lists the xattr names of path, excluding the nydus-internal
// trusted.nydus.* namespace: the builder stamps trusted.nydus.prefetch.blobs
// on the image root, which the FUSE reader hides but a root-privileged
// kernel EROFS mount exposes. It is not part of the reproduced tree.
func VisibleXattrs(t env.TB, path string) []string {
	t.Helper()
	var names []string
	for _, name := range ListXattr(t, path) {
		if !strings.HasPrefix(name, "trusted.nydus.") {
			names = append(names, name)
		}
	}
	return names
}

// ListXattr lists the xattr names of path itself, not of a symlink target.
func ListXattr(t env.TB, path string) []string {
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

// GetXattr reads an xattr of path itself, not of a symlink target.
func GetXattr(t env.TB, path, name string) []byte {
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
