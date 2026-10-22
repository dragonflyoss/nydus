package util

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// MaxFullCompareSize is the size above which a file is sampled rather than read
// whole. The corpus deliberately contains multi-gigabyte sparse files to force
// the extended inode encoding, and slurping those into memory would dominate
// the run without testing anything the samples miss.
const MaxFullCompareSize = 64 << 20

// CheckDirectoryEqual walks the source tree and asserts the mount reproduces
// it exactly. Every scenario that produces a mount runs this, so a builder
// change that corrupts metadata is caught the same way whether the image came
// from one blob, a bootstrap, or a merge.
//
// compareMtimeNsec is false when comparing against an image built by
// mkfs.erofs, whose compact inodes carry no sub-second mtime.
func CheckDirectoryEqual(t *testing.T, source, mountpoint string, compareMtimeNsec bool) {
	t.Helper()

	// Compare the path sets first, and the hard link groups as a whole: names
	// sharing an inode in the source must share one in the mount, and names
	// that do not must not.
	assert.Equal(t, relativePaths(t, source), relativePaths(t, mountpoint))
	assert.Equal(t, inodeGroups(t, source), inodeGroups(t, mountpoint))

	walkPairs(t, source, mountpoint, func(rel, sourcePath, mountPath string) {
		var want, got unix.Stat_t
		assert.NoError(t, unix.Lstat(sourcePath, &want))
		assert.NoError(t, unix.Lstat(mountPath, &got), "lstat %s", rel)

		// Compare the metadata, except on the root, which is deliberately
		// normalised and has its own cases.
		if rel != "." {
			assert.Equal(t, want.Mode, got.Mode, "%s: st_mode", rel)
			if want.Mode&unix.S_IFMT != unix.S_IFDIR || want.Nlink != 1 {
				assert.Equal(t, want.Nlink, got.Nlink, "%s: st_nlink", rel)
			}
			assert.Equal(t, want.Uid, got.Uid, "%s: st_uid", rel)
			assert.Equal(t, want.Gid, got.Gid, "%s: st_gid", rel)
			assert.Equal(t, want.Mtim.Sec, got.Mtim.Sec, "%s: mtime", rel)
			if compareMtimeNsec {
				assert.Equal(t, want.Mtim.Nsec, got.Mtim.Nsec, "%s: mtime nsec", rel)
			}
		}

		// Compare what the file type carries: directory entries, content, the
		// symlink target or the device number.
		switch want.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			wantDirents := sortedDirents(t, sourcePath)
			gotDirents := sortedDirents(t, mountPath)
			assert.Equal(t, DirentNames(wantDirents), DirentNames(gotDirents), "%s: directory entries", rel)
			for i, e := range gotDirents {
				assert.Equal(t, wantDirents[i].Type, e.Type, "%s: d_type of %s", rel, e.Name)
				var st unix.Stat_t
				assert.NoError(t, unix.Lstat(filepath.Join(mountPath, e.Name), &st))
				assert.Equal(t, st.Ino, e.Ino, "%s: d_ino of %s", rel, e.Name)
			}
		case unix.S_IFREG:
			assert.Equal(t, want.Size, got.Size, "%s: st_size", rel)
			if want.Size > MaxFullCompareSize {
				compareSampled(t, sourcePath, mountPath, want.Size)
				break
			}

			wantData, err := os.ReadFile(sourcePath)
			assert.NoError(t, err)
			if len(wantData) > 0 {
				compareProbes(t, mountPath, wantData)
			}
			gotData, err := os.ReadFile(mountPath)
			assert.NoError(t, err, "read %s", rel)
			assert.True(t, bytes.Equal(wantData, gotData), "%s: content differs", rel)
		case unix.S_IFLNK:
			assert.Equal(t, want.Size, got.Size, "%s: st_size", rel)
			wantTarget, err := os.Readlink(sourcePath)
			assert.NoError(t, err)
			gotTarget, err := os.Readlink(mountPath)
			assert.NoError(t, err, "readlink %s", rel)
			assert.Equal(t, wantTarget, gotTarget, "%s: symlink target", rel)
		case unix.S_IFCHR, unix.S_IFBLK:
			assert.Equal(t, want.Rdev, got.Rdev, "%s: st_rdev", rel)
		}

		// Compare the xattrs the mount is meant to show.
		names := visibleXattrs(t, sourcePath)
		assert.Equal(t, names, visibleXattrs(t, mountPath), "%s: xattr names", rel)
		for _, name := range names {
			assert.Equal(t, GetXattr(t, sourcePath, name), GetXattr(t, mountPath, name), "%s: value of %s", rel, name)
		}
	})
}

// walkPairs calls fn for every path in source along with its counterpart in mountpoint.
func walkPairs(t *testing.T, source, mountpoint string, fn func(rel, sourcePath, mountPath string)) {
	t.Helper()
	assert.NoError(t, filepath.WalkDir(source, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		assert.NoError(t, err)
		fn(rel, path, filepath.Join(mountpoint, rel))
		return nil
	}))
}

// relativePaths lists every path under root relative to it, sorted, the root
// itself as ".".
func relativePaths(t *testing.T, root string) []string {
	t.Helper()

	var paths []string
	assert.NoError(t, filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		assert.NoError(t, err)
		if rel != "." {
			paths = append(paths, rel)
		}
		return nil
	}))
	slices.Sort(paths)
	return paths
}

// inodeGroups returns the sets of paths that share an inode, keyed by the
// smallest path in each set, so the result compares across filesystems even
// though the inode numbers themselves differ.
func inodeGroups(t *testing.T, root string) map[string][]string {
	t.Helper()

	byIno := map[uint64][]string{}
	assert.NoError(t, filepath.WalkDir(root, func(path string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var st unix.Stat_t
		assert.NoError(t, unix.Lstat(path, &st))
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		assert.NoError(t, err)
		byIno[st.Ino] = append(byIno[st.Ino], rel)
		return nil
	}))

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

// compareProbes reads mountPath at odd offsets straddling page and chunk
// boundaries, past EOF and through mmap, each from a cold page cache, so
// chunks are decoded out of order rather than by one sequential pass.
func compareProbes(t *testing.T, mountPath string, want []byte) {
	t.Helper()

	fd, err := unix.Open(mountPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	assert.NoError(t, err, "open %s", mountPath)
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
		assert.NoError(t, err, "pread %s at %d", mountPath, off)
		end := min(off+int64(len(got)), size)
		assert.True(t, bytes.Equal(want[off:end], got[:n]), "%s: content differs at %d", mountPath, off)
	}
	n, err := unix.Pread(fd, got, size)
	assert.NoError(t, err, "pread %s at EOF", mountPath)
	assert.Zero(t, n, "%s: read past EOF", mountPath)

	drop()
	mapped, err := unix.Mmap(fd, 0, len(want), unix.PROT_READ, unix.MAP_SHARED)
	assert.NoError(t, err, "mmap %s", mountPath)
	defer func() { _ = unix.Munmap(mapped) }()
	assert.True(t, bytes.Equal(want, mapped), "%s: mapped content differs", mountPath)
}

// compareSampled checks the head, tail and a few interior windows of a file
// too large to compare byte for byte.
func compareSampled(t *testing.T, sourcePath, mountPath string, size int64) {
	t.Helper()

	source, err := unix.Open(sourcePath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	assert.NoError(t, err)
	defer func() { _ = unix.Close(source) }()
	mountpoint, err := unix.Open(mountPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	assert.NoError(t, err, "open %s", mountPath)
	defer func() { _ = unix.Close(mountpoint) }()

	const window = 64 << 10
	offsets := []int64{0, 4095, 4096, size / 3, size / 2, size - window, size - 1}
	for _, off := range offsets {
		if off < 0 || off >= size {
			continue
		}
		want := make([]byte, window)
		got := make([]byte, window)
		n1, err1 := unix.Pread(source, want, off)
		n2, err2 := unix.Pread(mountpoint, got, off)
		assert.NoError(t, err1)
		assert.NoError(t, err2, "pread %s at %d", mountPath, off)
		assert.Equal(t, n1, n2, "%s: short read at %d", mountPath, off)
		assert.True(t, bytes.Equal(want[:n1], got[:n2]), "%s: content differs at %d", mountPath, off)
	}
}

// CheckBytesEqual asserts got equals expected and, when it does not, reports the
// first mismatching offset and the total number of wrong bytes so a failure
// can be located precisely.
func CheckBytesEqual(t *testing.T, expected, got []byte, desc string) {
	t.Helper()
	if !assert.Len(t, got, len(expected), "%s: length mismatch", desc) || bytes.Equal(expected, got) {
		return
	}

	first := -1
	wrong := 0
	for i := range expected {
		if expected[i] != got[i] {
			if first < 0 {
				first = i
			}
			wrong++
		}
	}
	assert.Failf(t, "byte mismatch", "%s: %d wrong bytes, first mismatch at offset %#x (expected %#02x, got %#02x)",
		desc, wrong, first, expected[first], got[first])
}
