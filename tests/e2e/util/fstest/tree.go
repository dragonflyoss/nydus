// Package fstest compares a mounted tree with its source: the whole-tree
// differential, manifests, extent-aware content comparison and raw dirent
// decoding.
package fstest

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// fullReadLimit is the size up to which a regular file is read and hashed
// whole; larger ones are compared by their data extents.
const fullReadLimit = 64 << 20

// DiffTree asserts that mnt reproduces src exactly: path set, metadata,
// content (including out-of-order and mmap reads), symlink targets, hardlink
// groups, dirents and xattrs. It is the single tree judge of every suite, so
// a builder or reader bug is caught the same way whatever produced the mount.
func DiffTree(t testing.TB, src, mnt string) {
	t.Helper()
	if !assert.Equal(t, relativePaths(t, src), relativePaths(t, mnt)) {
		t.FailNow()
	}

	walkPairs(t, src, mnt, func(rel, srcPath, mntPath string) {
		var want, got unix.Stat_t
		if !assert.NoError(t, unix.Lstat(srcPath, &want)) {
			t.FailNow()
		}
		if !assert.NoError(t, unix.Lstat(mntPath, &got)) {
			t.FailNow()
		}

		// The root is deliberately normalised; the contract cases cover it.
		if rel != "." {
			diffStat(t, rel, &want, &got)
		}

		switch want.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			compareFile(t, srcPath, mntPath)

		case unix.S_IFLNK:
			wantTarget, err := os.Readlink(srcPath)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			gotTarget, err := os.Readlink(mntPath)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			assert.Equal(t, wantTarget, gotTarget)

		case unix.S_IFDIR:
			diffDirents(t, rel, srcPath, mntPath)
		}

		wantXattrs, err := listXattrs(srcPath)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		gotXattrs, err := listXattrs(mntPath)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.Equal(t, wantXattrs, gotXattrs) {
			t.FailNow()
		}
	})

	// Names sharing an inode in the source must share one in the mount, and
	// names that do not must not.
	assert.Equal(t, inodeGroups(t, src), inodeGroups(t, mnt))
}

func diffStat(t testing.TB, rel string, want, got *unix.Stat_t) {
	t.Helper()
	if !assert.Equal(t, want.Mode, got.Mode) {
		t.FailNow()
	}
	// btrfs, among others, reports 1 for every directory.
	if want.Mode&unix.S_IFMT != unix.S_IFDIR || want.Nlink != 1 {
		assert.Equal(t, want.Nlink, got.Nlink)
	}
	if !assert.Equal(t, want.Uid, got.Uid) {
		t.FailNow()
	}
	if !assert.Equal(t, want.Gid, got.Gid) {
		t.FailNow()
	}
	if !assert.Equal(t, want.Mtim.Sec, got.Mtim.Sec) {
		t.FailNow()
	}

	assert.Equal(t, want.Mtim.Nsec, got.Mtim.Nsec)

	switch want.Mode & unix.S_IFMT {
	case unix.S_IFREG, unix.S_IFLNK:
		assert.Equal(t, want.Size, got.Size)

	case unix.S_IFCHR, unix.S_IFBLK:
		assert.Equal(t, want.Rdev, got.Rdev)
	}
}

func diffDirents(t testing.TB, rel, srcPath, mntPath string) {
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

	if !assert.Equal(t, wantNames, gotNames) {
		t.FailNow()
	}

	for i, e := range got {
		if !assert.Equal(t, want[i].Type, e.Type) {
			t.FailNow()
		}

		var st unix.Stat_t
		if !assert.NoError(t, unix.Lstat(filepath.Join(mntPath, e.Name), &st)) {
			t.FailNow()
		}

		assert.Equal(t, st.Ino, e.Ino)
	}
}

// compareFile asserts that mntPath holds the same bytes as srcPath. Small
// files are also probed at odd offsets from a cold page cache and through
// mmap; large ones are compared extent by extent.
func compareFile(t testing.TB, srcPath, mntPath string) {
	t.Helper()
	st, err := os.Stat(srcPath)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	if st.Size() > fullReadLimit {
		compareExtents(t, srcPath, mntPath)
		return
	}

	want, err := os.ReadFile(srcPath)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if len(want) > 0 {
		compareProbes(t, mntPath, want)
	}

	got, err := os.ReadFile(mntPath)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.True(t, bytes.Equal(want, got))
}

// compareProbes reads mntPath at offsets straddling page and chunk
// boundaries, past EOF and through mmap, each from a cold page cache, so
// chunks are decoded out of order rather than by one sequential pass.
func compareProbes(t testing.TB, mntPath string, want []byte) {
	t.Helper()
	fd, err := unix.Open(mntPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

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
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		end := min(off+int64(len(got)), size)
		assert.True(t, bytes.Equal(want[off:end], got[:n]))
	}

	n, err := unix.Pread(fd, got, size)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Zero(t, n) {
		t.FailNow()
	}

	drop()
	mapped, err := unix.Mmap(fd, 0, len(want), unix.PROT_READ, unix.MAP_SHARED)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = unix.Munmap(mapped) }()
	assert.True(t, bytes.Equal(want, mapped))
}

// walkPairs calls fn for every path in src along with its counterpart in mnt.
func walkPairs(t testing.TB, src, mnt string, fn func(rel, srcPath, mntPath string)) {
	t.Helper()
	assert.NoError(t, filepath.WalkDir(src, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		fn(rel, path, filepath.Join(mnt, rel))

		return nil
	}))
}

func relativePaths(t testing.TB, root string) []string {
	t.Helper()
	var paths []string
	if !assert.NoError(t, filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(root, path)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		if rel != "." {
			paths = append(paths, rel)
		}

		return nil
	})) {
		t.FailNow()
	}

	slices.Sort(paths)

	return paths
}

// inodeGroups returns the sets of paths that share an inode, keyed by the
// smallest path in each set, so the result compares across filesystems even
// though the inode numbers themselves differ.
func inodeGroups(t testing.TB, root string) map[string][]string {
	t.Helper()
	byIno := map[uint64][]string{}
	if !assert.NoError(t, filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		var st unix.Stat_t
		if !assert.NoError(t, unix.Lstat(path, &st)) {
			t.FailNow()
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		byIno[st.Ino] = append(byIno[st.Ino], rel)

		return nil
	})) {
		t.FailNow()
	}

	groups := map[string][]string{}

	for _, paths := range byIno {
		if len(paths) < 2 {
			continue
		}

		slices.Sort(paths)
		groups[paths[0]] = paths
	}

	return groups
}
