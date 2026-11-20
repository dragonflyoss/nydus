/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/testsuite"
	"github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"

	nydusfs "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/util/testutil"
)

var (
	mockBlobID = strings.Repeat("aa", 32)

	mockBlobChainID = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	mockBootstrapChainID = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	mockImageRef = "registry.example.com/team/app:v1-nydus-v3"

	mockMountpoint = "/var/lib/nydus-snapshotter/nydusd/2222/mnt"

	mockBlobLabels = map[string]string{
		labelSnapshotRef: mockBlobChainID,
		labelNydusBlob:   labelTrue,
	}

	mockBootstrapLabels = map[string]string{
		labelSnapshotRef:            mockBootstrapChainID,
		labelNydusBootstrap:         labelTrue,
		labelNydusFSVersion:         nydusfs.Version,
		snapshotters.TargetRefLabel: mockImageRef,
	}
)

func TestSnapshotter_Suite(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("overlay mounts need root")
	}

	testsuite.SnapshotterSuite(t, "overlayfs", func(ctx context.Context, root string) (snapshots.Snapshotter, func() error, error) {
		sn, err := New(root, nil)
		if err != nil {
			return nil, nil, err
		}

		return sn, sn.Close, nil
	})
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, root string)
		expect  func(t *testing.T, root string, sn Snapshotter, err error)
	}{
		{
			name:    "create the snapshots directory",
			prepare: func(t *testing.T, root string) {},
			expect: func(t *testing.T, root string, sn Snapshotter, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.DirExists(filepath.Join(root, snapshotsDirName))
				assert.NoError(sn.Close())
			},
		},
		{
			name: "root that cannot be created",
			prepare: func(t *testing.T, root string) {
				assert.NoError(t, os.WriteFile(root, nil, 0o644))
			},
			expect: func(t *testing.T, root string, sn Snapshotter, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, syscall.ENOTDIR)
				assert.Nil(sn)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "root")
			tc.prepare(t, root)
			sn, err := New(root, nil)
			tc.expect(t, root, sn, err)
		})
	}
}

func TestSnapshotter_Prepare(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, sn Snapshotter)
	}{
		{
			name: "commit nydus data layer and report it exists",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "k8s.io/1/extract-1 "+mockBlobChainID, "", snapshots.WithLabels(mockBlobLabels))
				assert.ErrorIs(err, errdefs.ErrAlreadyExists)

				info, err := sn.Stat(ctx, mockBlobChainID)
				assert.NoError(err)
				assert.Equal(snapshots.KindCommitted, info.Kind)
				assert.Equal(mockBlobChainID, info.Labels[labelSnapshotRef])
			},
		},
		{
			name: "drop a duplicate commit of the same layer",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "k8s.io/1/extract-1 "+mockBlobChainID, "", snapshots.WithLabels(mockBlobLabels))
				assert.ErrorIs(err, errdefs.ErrAlreadyExists)
				_, err = sn.Prepare(ctx, "default/2/extract-2 "+mockBlobChainID, "", snapshots.WithLabels(mockBlobLabels))
				assert.ErrorIs(err, errdefs.ErrAlreadyExists)

				_, err = sn.Stat(ctx, "default/2/extract-2 "+mockBlobChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "ignore a bootstrap label committed from a container key",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "k8s.io/9/container", "", snapshots.WithLabels(mockBootstrapLabels))
				assert.NoError(err)
				assert.NoError(sn.Commit(ctx, "k8s.io/10/forged", "k8s.io/9/container", snapshots.WithLabels(mockBootstrapLabels)))

				info, err := sn.Stat(ctx, "k8s.io/10/forged")
				assert.NoError(err)
				assert.NotContains(info.Labels, labelNydusBootstrap)

				mounts, err := sn.Prepare(ctx, "k8s.io/11/child", "k8s.io/10/forged")
				assert.NoError(err)
				assert.Equal("overlay", mounts[0].Type)
			},
		},
		{
			name: "ignore remote labels on a container key",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				mounts, err := sn.Prepare(ctx, "k8s.io/3/container", "", snapshots.WithLabels(mockBlobLabels))
				assert.NoError(err)
				assert.Equal("bind", mounts[0].Type)

				_, err = sn.Stat(ctx, mockBlobChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "nydus data layer on a parent that does not exist",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "k8s.io/1/extract-1 "+mockBlobChainID, "missing", snapshots.WithLabels(mockBlobLabels))
				assert.ErrorIs(err, errdefs.ErrNotFound)
				_, err = sn.Stat(ctx, mockBlobChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "uid mapping label that does not parse",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "container", "", snapshots.WithLabels(map[string]string{snapshots.LabelSnapshotUIDMapping: "root"}))
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
				_, err = sn.Stat(ctx, "container")
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "option that fails",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "container", "", func(*snapshots.Info) error { return errors.New("foo") })
				assert.EqualError(err, "foo")
				_, err = sn.Stat(ctx, "container")
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "parent that does not exist",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "container", "missing")
				assert.ErrorIs(err, errdefs.ErrNotFound)
				_, err = sn.View(ctx, "view", "missing")
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "key that exists",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "container", "")
				assert.NoError(err)
				_, err = sn.Prepare(ctx, "container", "")
				assert.ErrorIs(err, errdefs.ErrAlreadyExists)
			},
		},
		{
			name: "mounts, usage and commit of a snapshot that does not exist",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Mounts(ctx, "missing")
				assert.ErrorIs(err, errdefs.ErrNotFound)
				_, err = sn.Usage(ctx, "missing")
				assert.ErrorIs(err, errdefs.ErrNotFound)
				assert.ErrorIs(sn.Commit(ctx, "layer", "missing"), errdefs.ErrNotFound)
				assert.ErrorIs(sn.Remove(ctx, "missing"), errdefs.ErrNotFound)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sn := newTestSnapshotter(t, t.TempDir(), nil)
			tc.expect(t, sn)
		})
	}
}

func TestSnapshotter_Cleanup(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, sn Snapshotter, root string)
	}{
		{
			name: "remove directories of removed snapshots only",
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "removed", "")
				assert.NoError(err)
				_, err = sn.Prepare(ctx, "kept", "")
				assert.NoError(err)
				assert.NoError(sn.Remove(ctx, "removed"))
				assert.Len(snapshotDirs(t, root), 2)

				assert.NoError(sn.Cleanup(ctx))
				assert.Len(snapshotDirs(t, root), 1)
				_, err = sn.Mounts(ctx, "kept")
				assert.NoError(err)
			},
		},
		{
			name: "snapshots directory that cannot be read",
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "active", "")
				assert.NoError(err)
				assert.NoError(os.RemoveAll(filepath.Join(root, snapshotsDirName)))
				assert.ErrorIs(sn.Cleanup(ctx), os.ErrNotExist)
			},
		},
		{
			name: "metadata store that holds no snapshot yet",
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				assert.ErrorIs(sn.Cleanup(t.Context()), errdefs.ErrNotFound)
			},
		},
		{
			name: "keep going past a directory that cannot be removed",
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				ctx := t.Context()
				mounts, err := sn.Prepare(ctx, "busy", "")
				assert.NoError(err)
				_, err = sn.Prepare(ctx, "removed", "")
				assert.NoError(err)
				testutil.MountTmpfs(t, mounts[0].Source, "")
				assert.NoError(sn.Remove(ctx, "busy"))
				assert.NoError(sn.Remove(ctx, "removed"))

				assert.NoError(sn.Cleanup(ctx))
				assert.Len(snapshotDirs(t, root), 1)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			sn := newTestSnapshotter(t, root, nil)
			tc.expect(t, sn, root)
		})
	}
}

func TestSnapshotter_Usage(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, sn Snapshotter)
	}{
		{
			name: "measure an active snapshot and keep a committed one's",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				mounts, err := sn.Prepare(ctx, "active", "")
				assert.NoError(err)
				assert.NoError(os.WriteFile(filepath.Join(mounts[0].Source, "file"), make([]byte, 8192), 0o644))

				usage, err := sn.Usage(ctx, "active")
				assert.NoError(err)
				assert.Positive(usage.Inodes)
				assert.Positive(usage.Size)

				assert.NoError(sn.Commit(ctx, "committed", "active"))
				committed, err := sn.Usage(ctx, "committed")
				assert.NoError(err)
				assert.Equal(usage, committed)
			},
		},
		{
			name: "active snapshot whose directory is gone",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				mounts, err := sn.Prepare(ctx, "active", "")
				assert.NoError(err)
				assert.NoError(os.RemoveAll(filepath.Dir(mounts[0].Source)))

				_, err = sn.Usage(ctx, "active")
				assert.ErrorIs(err, os.ErrNotExist)
				assert.ErrorIs(sn.Commit(ctx, "committed", "active"), os.ErrNotExist)
			},
		},
		{
			name: "child of a parent whose directory is gone",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				mounts, err := sn.Prepare(ctx, "active", "")
				assert.NoError(err)
				assert.NoError(sn.Commit(ctx, "parent", "active"))
				assert.NoError(os.RemoveAll(filepath.Dir(mounts[0].Source)))

				_, err = sn.Prepare(ctx, "child", "parent")
				assert.ErrorContains(err, "stat parent")
				_, err = sn.Stat(ctx, "child")
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "snapshots directory that is gone",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				mounts, err := sn.Prepare(ctx, "active", "")
				assert.NoError(err)
				assert.NoError(os.RemoveAll(filepath.Dir(filepath.Dir(mounts[0].Source))))

				_, err = sn.Prepare(ctx, "other", "")
				assert.ErrorContains(err, "create snapshot directory")
			},
		},
		{
			name: "directory of the snapshot that is taken",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				mounts, err := sn.Prepare(ctx, "first", "")
				assert.NoError(err)
				snapshotsDir := filepath.Dir(filepath.Dir(mounts[0].Source))
				assert.NoError(os.MkdirAll(filepath.Join(snapshotsDir, "2", "taken"), 0o755))

				_, err = sn.Prepare(ctx, "second", "")
				assert.ErrorContains(err, "rename snapshot directory")
				entries, err := os.ReadDir(snapshotsDir)
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sn := newTestSnapshotter(t, t.TempDir(), nil)
			tc.expect(t, sn)
		})
	}
}

func snapshotDirs(t *testing.T, root string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, snapshotsDirName))
	assert.NoError(t, err)
	return entries
}

func newTestSnapshotter(t *testing.T, root string, fileSystem nydusfs.FileSystem) Snapshotter {
	t.Helper()
	sn, err := New(root, fileSystem)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { assert.NoError(t, sn.Close()) })
	return sn
}
