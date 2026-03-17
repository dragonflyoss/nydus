// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package diff

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/continuity/fs"
	"github.com/stretchr/testify/require"
)

func TestGetOverlayLayers(t *testing.T) {
	t.Run("upper and lower", func(t *testing.T) {
		m := mount.Mount{
			Type:    "overlay",
			Options: []string{"lowerdir=/l2:/l1", "upperdir=/u", "workdir=/w"},
		}
		layers, err := GetOverlayLayers(m)
		require.NoError(t, err)
		require.Equal(t, []string{"/l1", "/l2", "/u"}, layers)
	})

	t.Run("lower only", func(t *testing.T) {
		m := mount.Mount{
			Type:    "overlay",
			Options: []string{"lowerdir=/l2:/l1"},
		}
		layers, err := GetOverlayLayers(m)
		require.NoError(t, err)
		require.Equal(t, []string{"/l1", "/l2"}, layers)
	})

	t.Run("single lower", func(t *testing.T) {
		m := mount.Mount{
			Type:    "overlay",
			Options: []string{"lowerdir=/only", "upperdir=/u"},
		}
		layers, err := GetOverlayLayers(m)
		require.NoError(t, err)
		require.Equal(t, []string{"/only", "/u"}, layers)
	})

	t.Run("known options skipped", func(t *testing.T) {
		m := mount.Mount{
			Type:    "overlay",
			Options: []string{"lowerdir=/l", "upperdir=/u", "workdir=/w", "index=off", "userxattr", "redirect_dir=nofollow"},
		}
		layers, err := GetOverlayLayers(m)
		require.NoError(t, err)
		require.Equal(t, []string{"/l", "/u"}, layers)
	})

	t.Run("unknown option error", func(t *testing.T) {
		m := mount.Mount{
			Type:    "overlay",
			Options: []string{"lowerdir=/l", "unknownopt=foo"},
		}
		_, err := GetOverlayLayers(m)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unknown option")
	})
}

func TestGetUpperdir(t *testing.T) {
	t.Run("bottommost bind", func(t *testing.T) {
		upper := []mount.Mount{{Type: "bind", Source: "/upper/dir"}}
		dir, err := GetUpperdir(nil, upper)
		require.NoError(t, err)
		require.Equal(t, "/upper/dir", dir)
	})

	t.Run("bottommost non-bind error", func(t *testing.T) {
		upper := []mount.Mount{{Type: "overlay", Source: "/x"}}
		_, err := GetUpperdir(nil, upper)
		require.Error(t, err)
		require.Contains(t, err.Error(), "bottommost upper must be bind mount")
	})

	t.Run("overlay with bind lower", func(t *testing.T) {
		lower := []mount.Mount{{Type: "bind", Source: "/layer0"}}
		upper := []mount.Mount{{Type: "overlay", Options: []string{"lowerdir=/layer0", "upperdir=/layer1", "workdir=/w"}}}
		dir, err := GetUpperdir(lower, upper)
		require.NoError(t, err)
		require.Equal(t, "/layer1", dir)
	})

	t.Run("overlay with overlay lower", func(t *testing.T) {
		lower := []mount.Mount{{Type: "overlay", Options: []string{"lowerdir=/l1:/l0", "upperdir=/l2", "workdir=/w"}}}
		upper := []mount.Mount{{Type: "overlay", Options: []string{"lowerdir=/l2:/l1:/l0", "upperdir=/l3", "workdir=/w"}}}
		dir, err := GetUpperdir(lower, upper)
		require.NoError(t, err)
		require.Equal(t, "/l3", dir)
	})

	t.Run("upper not overlay error", func(t *testing.T) {
		lower := []mount.Mount{{Type: "bind", Source: "/layer0"}}
		upper := []mount.Mount{{Type: "bind", Source: "/layer1"}}
		_, err := GetUpperdir(lower, upper)
		require.Error(t, err)
		require.Contains(t, err.Error(), "upper snapshot isn't overlay mounted")
	})

	t.Run("unsupported lower type", func(t *testing.T) {
		lower := []mount.Mount{{Type: "tmpfs"}}
		upper := []mount.Mount{{Type: "overlay"}}
		_, err := GetUpperdir(lower, upper)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot get layer information")
	})

	t.Run("multiple mounts error", func(t *testing.T) {
		lower := []mount.Mount{{Type: "bind"}, {Type: "bind"}}
		upper := []mount.Mount{{Type: "overlay"}}
		_, err := GetUpperdir(lower, upper)
		require.Error(t, err)
		require.Contains(t, err.Error(), "multiple mount configurations")
	})

	t.Run("layer mismatch error", func(t *testing.T) {
		lower := []mount.Mount{{Type: "bind", Source: "/layer0"}}
		upper := []mount.Mount{{Type: "overlay", Options: []string{"lowerdir=/different", "upperdir=/u", "workdir=/w"}}}
		_, err := GetUpperdir(lower, upper)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be common")
	})

	t.Run("too many upper layers", func(t *testing.T) {
		lower := []mount.Mount{{Type: "bind", Source: "/layer0"}}
		upper := []mount.Mount{{Type: "overlay", Options: []string{"lowerdir=/extra:/layer0", "upperdir=/u", "workdir=/w"}}}
		_, err := GetUpperdir(lower, upper)
		require.Error(t, err)
		require.Contains(t, err.Error(), "cannot determine diff")
	})
}

func TestCompareSysStat(t *testing.T) {
	s1 := &syscall.Stat_t{Uid: 1000, Gid: 1000, Mode: 0644, Rdev: 0}
	s2 := &syscall.Stat_t{Uid: 1000, Gid: 1000, Mode: 0644, Rdev: 0}

	same, err := compareSysStat(s1, s2)
	require.NoError(t, err)
	require.True(t, same)

	s2.Uid = 2000
	same, err = compareSysStat(s1, s2)
	require.NoError(t, err)
	require.False(t, same)

	// Non-Stat_t type
	same, err = compareSysStat("not a stat", s2)
	require.NoError(t, err)
	require.False(t, same)
}

func TestCheckDelete(t *testing.T) {
	base := t.TempDir()

	t.Run("regular file is not delete", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "reg")
		require.NoError(t, err)
		f.Close()
		info, err := os.Stat(f.Name())
		require.NoError(t, err)
		isDel, skip, err := checkDelete("", "/foo", base, info)
		require.NoError(t, err)
		require.False(t, isDel)
		require.False(t, skip)
	})
}

func TestCompareCapabilities(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a")
	f2 := filepath.Join(dir, "b")
	require.NoError(t, os.WriteFile(f1, []byte("x"), 0644))
	require.NoError(t, os.WriteFile(f2, []byte("x"), 0644))

	same, err := compareCapabilities(f1, f2)
	require.NoError(t, err)
	require.True(t, same)
}

func TestCompareSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("content"), 0644))

	link1 := filepath.Join(dir, "link1")
	link2 := filepath.Join(dir, "link2")
	link3 := filepath.Join(dir, "link3")
	require.NoError(t, os.Symlink(target, link1))
	require.NoError(t, os.Symlink(target, link2))
	require.NoError(t, os.Symlink("/different", link3))

	same, err := compareSymlinkTarget(link1, link2)
	require.NoError(t, err)
	require.True(t, same)

	same, err = compareSymlinkTarget(link1, link3)
	require.NoError(t, err)
	require.False(t, same)

	_, err = compareSymlinkTarget("/nonexistent", link1)
	require.Error(t, err)
}

func TestCompareFileContent(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "a")
	f2 := filepath.Join(dir, "b")
	f3 := filepath.Join(dir, "c")

	require.NoError(t, os.WriteFile(f1, []byte("hello world"), 0644))
	require.NoError(t, os.WriteFile(f2, []byte("hello world"), 0644))
	require.NoError(t, os.WriteFile(f3, []byte("different"), 0644))

	same, err := compareFileContent(f1, f2)
	require.NoError(t, err)
	require.True(t, same)

	same, err = compareFileContent(f1, f3)
	require.NoError(t, err)
	require.False(t, same)

	_, err = compareFileContent("/nonexistent", f1)
	require.Error(t, err)

	_, err = compareFileContent(f1, "/nonexistent")
	require.Error(t, err)
}

func TestSameDirent(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "same1")
	f2 := filepath.Join(dir, "same2")
	require.NoError(t, os.WriteFile(f1, []byte("content"), 0644))
	require.NoError(t, os.WriteFile(f2, []byte("different"), 0644))

	info1, err := os.Lstat(f1)
	require.NoError(t, err)
	info2, err := os.Lstat(f2)
	require.NoError(t, err)

	// Different size -> not same
	same, err := sameDirent(info1, info2, f1, f2)
	require.NoError(t, err)
	require.False(t, same)

	// Same file -> same
	same, err = sameDirent(info1, info1, f1, f1)
	require.NoError(t, err)
	require.True(t, same)

	// Non-Stat_t
	same, err = compareSysStat("not stat", &syscall.Stat_t{})
	require.NoError(t, err)
	require.False(t, same)
}

func TestCheckRedirect(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "sub")
	require.NoError(t, os.MkdirAll(subdir, 0755))

	info, err := os.Lstat(subdir)
	require.NoError(t, err)
	// Normal dir without redirect xattr
	redirect, err := checkRedirect(dir, "sub", info)
	require.NoError(t, err)
	require.False(t, redirect)

	// Regular file is never redirect
	f := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0644))
	finfo, err := os.Lstat(f)
	require.NoError(t, err)
	redirect, err = checkRedirect(dir, "file", finfo)
	require.NoError(t, err)
	require.False(t, redirect)
}

func TestOverlaySupportIndex(t *testing.T) {
	// Just call to ensure it doesn't panic
	_ = overlaySupportIndex()
}

func TestCheckOpaque(t *testing.T) {
	upper := t.TempDir()
	base := t.TempDir()

	subdir := filepath.Join(upper, "sub")
	require.NoError(t, os.MkdirAll(subdir, 0755))

	info, err := os.Lstat(subdir)
	require.NoError(t, err)

	// No opaque xattr
	isOpaque, err := checkOpaque(upper, "sub", base, info)
	require.NoError(t, err)
	require.False(t, isOpaque)

	// Regular file is not opaque
	f := filepath.Join(upper, "file")
	require.NoError(t, os.WriteFile(f, []byte("x"), 0644))
	finfo, err := os.Lstat(f)
	require.NoError(t, err)
	isOpaque, err = checkOpaque(upper, "file", base, finfo)
	require.NoError(t, err)
	require.False(t, isOpaque)
}

func TestCancellableWriter(t *testing.T) {
	var buf bytes.Buffer
	ctx := context.Background()
	cw := &cancellableWriter{ctx: ctx, w: &buf}

	n, err := cw.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.Equal(t, "hello", buf.String())

	// Cancel context
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	cw2 := &cancellableWriter{ctx: cancelCtx, w: &buf}
	_, err = cw2.Write([]byte("should fail"))
	require.Error(t, err)
}

func TestSameDirentWithTruncatedTimestamps(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "file1")
	f2 := filepath.Join(dir, "file2")

	// Create files with same content
	require.NoError(t, os.WriteFile(f1, []byte("same content"), 0644))
	require.NoError(t, os.WriteFile(f2, []byte("same content"), 0644))

	// Set truncated timestamps (nanosecond = 0)
	truncTime := time.Unix(1000000, 0)
	require.NoError(t, os.Chtimes(f1, truncTime, truncTime))
	require.NoError(t, os.Chtimes(f2, truncTime, truncTime))

	info1, err := os.Lstat(f1)
	require.NoError(t, err)
	info2, err := os.Lstat(f2)
	require.NoError(t, err)

	// Same content, same timestamps → should be same
	same, err := sameDirent(info1, info2, f1, f2)
	require.NoError(t, err)
	require.True(t, same)
}

func TestSameDirentDifferentSizes(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "small")
	f2 := filepath.Join(dir, "big")
	require.NoError(t, os.WriteFile(f1, []byte("x"), 0644))
	require.NoError(t, os.WriteFile(f2, []byte("bigger"), 0644))

	// Set same truncated times
	truncTime := time.Unix(1000000, 0)
	require.NoError(t, os.Chtimes(f1, truncTime, truncTime))
	require.NoError(t, os.Chtimes(f2, truncTime, truncTime))

	info1, err := os.Lstat(f1)
	require.NoError(t, err)
	info2, err := os.Lstat(f2)
	require.NoError(t, err)

	same, err := sameDirent(info1, info2, f1, f2)
	require.NoError(t, err)
	require.False(t, same)
}

func TestSameDirentDirectories(t *testing.T) {
	dir := t.TempDir()
	d1 := filepath.Join(dir, "d1")
	d2 := filepath.Join(dir, "d2")
	require.NoError(t, os.MkdirAll(d1, 0755))
	require.NoError(t, os.MkdirAll(d2, 0755))

	info1, err := os.Lstat(d1)
	require.NoError(t, err)
	info2, err := os.Lstat(d2)
	require.NoError(t, err)

	same, err := sameDirent(info1, info2, d1, d2)
	require.NoError(t, err)
	// Directories with same mode/uid/gid should be same
	require.True(t, same)
}

func TestSameDirentSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("x"), 0644))

	link1 := filepath.Join(dir, "link1")
	link2 := filepath.Join(dir, "link2")
	link3 := filepath.Join(dir, "link3")
	require.NoError(t, os.Symlink(target, link1))
	require.NoError(t, os.Symlink(target, link2))
	require.NoError(t, os.Symlink("/different", link3))

	// Set truncated timestamps
	truncTime := time.Unix(1000000, 0)
	require.NoError(t, os.Chtimes(link1, truncTime, truncTime))
	require.NoError(t, os.Chtimes(link2, truncTime, truncTime))

	info1, err := os.Lstat(link1)
	require.NoError(t, err)
	info2, err := os.Lstat(link2)
	require.NoError(t, err)

	same, err := sameDirent(info1, info2, link1, link2)
	require.NoError(t, err)
	require.True(t, same)
}

func TestCompareFileContentEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	f1 := filepath.Join(dir, "empty1")
	f2 := filepath.Join(dir, "empty2")
	require.NoError(t, os.WriteFile(f1, nil, 0644))
	require.NoError(t, os.WriteFile(f2, nil, 0644))

	same, err := compareFileContent(f1, f2)
	require.NoError(t, err)
	require.True(t, same)
}

func TestChangesAddedFile(t *testing.T) {
	base := t.TempDir()
	upper := t.TempDir()
	upperdirView := upper

	// Create a new file in upper that doesn't exist in base
	require.NoError(t, os.WriteFile(filepath.Join(upper, "newfile.txt"), []byte("hello"), 0644))

	type change struct {
		kind int
		path string
	}
	var changes []change
	changeFn := func(kind fs.ChangeKind, path string, f os.FileInfo, err error) error {
		changes = append(changes, change{kind: int(kind), path: path})
		return nil
	}

	err := Changes(context.Background(), func(path string) {}, nil, nil, changeFn, upper, upperdirView, base)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	require.Equal(t, "/newfile.txt", changes[0].path)
	require.Equal(t, int(fs.ChangeKindAdd), changes[0].kind)
}

func TestChangesModifiedFile(t *testing.T) {
	base := t.TempDir()
	upper := t.TempDir()

	// Create the same file in both directories with different content (different sizes to trigger mismatch)
	require.NoError(t, os.WriteFile(filepath.Join(base, "file.txt"), []byte("old content"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(upper, "file.txt"), []byte("new content that is longer"), 0644))

	type change struct {
		kind int
		path string
	}
	var changes []change
	changeFn := func(kind fs.ChangeKind, path string, f os.FileInfo, err error) error {
		changes = append(changes, change{kind: int(kind), path: path})
		return nil
	}

	err := Changes(context.Background(), func(path string) {}, nil, nil, changeFn, upper, upper, base)
	require.NoError(t, err)
	require.Len(t, changes, 1)
	require.Equal(t, "/file.txt", changes[0].path)
	require.Equal(t, int(fs.ChangeKindModify), changes[0].kind)
}

func TestChangesContextCanceled(t *testing.T) {
	base := t.TempDir()
	upper := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(upper, "file.txt"), []byte("data"), 0644))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	changeFn := func(kind fs.ChangeKind, path string, f os.FileInfo, err error) error {
		return nil
	}

	err := Changes(ctx, func(path string) {}, nil, nil, changeFn, upper, upper, base)
	require.Error(t, err)
	require.ErrorIs(t, err, context.Canceled)
}

func TestChangesWithoutPaths(t *testing.T) {
	base := t.TempDir()
	upper := t.TempDir()

	// Create files in upper
	require.NoError(t, os.MkdirAll(filepath.Join(upper, "skip"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(upper, "skip", "file.txt"), []byte("skip me"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(upper, "keep.txt"), []byte("keep me"), 0644))

	type change struct {
		kind int
		path string
	}
	var changes []change
	changeFn := func(kind fs.ChangeKind, path string, f os.FileInfo, err error) error {
		changes = append(changes, change{kind: int(kind), path: path})
		return nil
	}

	// Filter out /skip and its children
	err := Changes(context.Background(), func(path string) {}, nil, []string{"/skip"}, changeFn, upper, upper, base)
	require.NoError(t, err)

	// Only /keep.txt should appear (not /skip or /skip/file.txt)
	for _, c := range changes {
		require.NotEqual(t, "/skip", c.path)
		require.NotEqual(t, "/skip/file.txt", c.path)
	}
	found := false
	for _, c := range changes {
		if c.path == "/keep.txt" {
			found = true
		}
	}
	require.True(t, found, "should find /keep.txt")
}

func TestChangesWithPaths(t *testing.T) {
	base := t.TempDir()
	upper := t.TempDir()

	type change struct {
		kind int
		path string
	}
	var changes []change
	changeFn := func(kind fs.ChangeKind, path string, f os.FileInfo, err error) error {
		changes = append(changes, change{kind: int(kind), path: path})
		return nil
	}

	// withPaths should generate delete entries at the end
	err := Changes(context.Background(), func(path string) {}, []string{"/lower-file1", "/lower-file2"}, nil, changeFn, upper, upper, base)
	require.NoError(t, err)
	require.Len(t, changes, 2)
	require.Equal(t, "/lower-file1", changes[0].path)
	require.Equal(t, int(fs.ChangeKindDelete), changes[0].kind)
	require.Equal(t, "/lower-file2", changes[1].path)
	require.Equal(t, int(fs.ChangeKindDelete), changes[1].kind)
}

func TestChangesUnmodifiedDir(t *testing.T) {
	base := t.TempDir()
	upper := t.TempDir()

	// Create same directory and file in both
	require.NoError(t, os.MkdirAll(filepath.Join(base, "dir"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(base, "dir", "file.txt"), []byte("same"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(upper, "dir"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(upper, "dir", "file.txt"), []byte("same"), 0644))

	type change struct {
		kind int
		path string
	}
	var changes []change
	changeFn := func(kind fs.ChangeKind, path string, f os.FileInfo, err error) error {
		changes = append(changes, change{kind: int(kind), path: path})
		return nil
	}

	err := Changes(context.Background(), func(path string) {}, nil, nil, changeFn, upper, upper, base)
	require.NoError(t, err)
	// Both dir and file are identical - should be skipped
	require.Empty(t, changes)
}
