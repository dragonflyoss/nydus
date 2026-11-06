/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"context"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/core/snapshots/testsuite"
	"github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	nydusfs "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs/mocks"
)

var (
	mockBlobID = strings.Repeat("aa", 32)

	mockBlobChainID = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

	mockBootstrapChainID = "sha256:2222222222222222222222222222222222222222222222222222222222222222"

	mockImageRef = "registry.example.com/team/app:v1-nydus-v3"

	mockMountpoint = "/var/lib/containerd-nydus-v3/nydusd/2222/mnt"

	mockBlobLabels = map[string]string{
		labelSnapshotRef: mockBlobChainID,
		labelNydusBlob:   labelTrue,
	}

	mockBootstrapLabels = map[string]string{
		labelSnapshotRef:            mockBootstrapChainID,
		labelNydusBootstrap:         labelTrue,
		labelNydusFSVersion:         "7",
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sn, err := New(t.TempDir(), nil)
			assert.NoError(t, err)
			defer sn.Close()
			tc.expect(t, sn)
		})
	}
}

func TestSnapshotter_Mounts(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(m *mocks.MockFileSystemMockRecorder)
		expect func(t *testing.T, sn Snapshotter, root string)
	}{
		{
			name: "mount container on the nydus daemon",
			mock: func(m *mocks.MockFileSystemMockRecorder) {
				m.Mount(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, image *nydusfs.Image) (string, error) {
					if image.ChainID != mockBootstrapChainID || image.Ref != mockImageRef || !strings.HasSuffix(image.BootstrapDir, "/fs") {
						return "", errdefs.ErrInvalidArgument
					}

					return mockMountpoint, nil
				}).Times(2)
			},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				ctx := t.Context()
				parent := pullNydusImage(t, sn, mockBootstrapLabels)

				mounts, err := sn.Prepare(ctx, "container", parent)
				assert.NoError(err)
				assert.Equal("overlay", mounts[0].Type)
				assert.Contains(mounts[0].Options, "lowerdir="+mockMountpoint)

				mounts, err = sn.Mounts(ctx, "container")
				assert.NoError(err)
				assert.Contains(mounts[0].Options, "lowerdir="+mockMountpoint)
			},
		},
		{
			name: "bind a view of the nydus daemon read only",
			mock: func(m *mocks.MockFileSystemMockRecorder) {
				m.Mount(gomock.Any(), gomock.Any()).Return(mockMountpoint, nil).Times(1)
			},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				parent := pullNydusImage(t, sn, mockBootstrapLabels)

				mounts, err := sn.View(t.Context(), "view", parent)
				assert.NoError(err)
				assert.Equal([]mount.Mount{{Type: "bind", Source: mockMountpoint, Options: []string{"ro", "rbind"}}}, mounts)
			},
		},
		{
			name: "remove a container snapshot whose daemon fails",
			mock: func(m *mocks.MockFileSystemMockRecorder) {
				m.Mount(gomock.Any(), gomock.Any()).Return("", errdefs.ErrUnavailable).Times(1)
			},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				ctx := t.Context()
				parent := pullNydusImage(t, sn, mockBootstrapLabels)

				_, err := sn.Prepare(ctx, "container", parent)
				assert.ErrorIs(err, errdefs.ErrUnavailable)
				_, err = sn.Stat(ctx, "container")
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "reject bootstrap without image reference",
			mock: func(m *mocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				labels := map[string]string{}
				maps.Copy(labels, mockBootstrapLabels)
				delete(labels, snapshotters.TargetRefLabel)
				parent := pullNydusImage(t, sn, labels)

				_, err := sn.Prepare(t.Context(), "container", parent)
				assert.ErrorIs(t, err, errdefs.ErrFailedPrecondition)
			},
		},
		{
			name: "reject unsupported nydus format",
			mock: func(m *mocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				labels := map[string]string{}
				maps.Copy(labels, mockBootstrapLabels)
				labels[labelNydusFSVersion] = "6"
				parent := pullNydusImage(t, sn, labels)

				_, err := sn.Prepare(t.Context(), "container", parent)
				assert.ErrorIs(t, err, errdefs.ErrNotImplemented)
			},
		},
		{
			name: "reject nydus data layers without a labelled bootstrap",
			mock: func(m *mocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "k8s.io/1/extract-1 "+mockBlobChainID, "", snapshots.WithLabels(mockBlobLabels))
				assert.ErrorIs(err, errdefs.ErrAlreadyExists)
				_, err = sn.Prepare(ctx, "k8s.io/2/extract-2 "+mockBootstrapChainID, mockBlobChainID)
				assert.ErrorIs(err, errdefs.ErrFailedPrecondition)
				_, err = sn.Stat(ctx, "k8s.io/2/extract-2 "+mockBootstrapChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "chown the upper dir to the user namespace root",
			mock: func(m *mocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				if os.Getuid() != 0 {
					t.Skip("chown needs root")
				}

				mounts, err := sn.Prepare(t.Context(), "userns", "", snapshots.WithLabels(map[string]string{
					snapshots.LabelSnapshotUIDMapping: "0:100000:65536",
					snapshots.LabelSnapshotGIDMapping: "0:200000:65536",
				}))
				assert.NoError(err)
				info, err := os.Stat(mounts[0].Source)
				assert.NoError(err)
				stat := info.Sys().(*syscall.Stat_t)
				assert.Equal(uint32(100000), stat.Uid)
				assert.Equal(uint32(200000), stat.Gid)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			fileSystem := mocks.NewMockFileSystem(ctl)
			tc.mock(fileSystem.EXPECT())

			root := t.TempDir()
			sn, err := New(root, map[string]nydusfs.FileSystem{"7": fileSystem})
			assert.NoError(t, err)
			defer sn.Close()
			tc.expect(t, sn, root)
		})
	}
}

func TestSnapshotter_usedImages(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(m *mocks.MockFileSystemMockRecorder)
		expect func(t *testing.T, sn *snapshotter)
	}{
		{
			name: "image used by a container",
			mock: func(m *mocks.MockFileSystemMockRecorder) {
				m.Mount(gomock.Any(), gomock.Any()).Return(mockMountpoint, nil).Times(1)
			},
			expect: func(t *testing.T, sn *snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				parent := pullNydusImage(t, sn, mockBootstrapLabels)
				_, err := sn.Prepare(ctx, "container", parent)
				assert.NoError(err)

				used, err := sn.usedImages(ctx)
				assert.NoError(err)
				assert.Contains(used, mockBootstrapChainID)

				assert.NoError(sn.Remove(ctx, "container"))
				used, err = sn.usedImages(ctx)
				assert.NoError(err)
				assert.NotContains(used, mockBootstrapChainID)
			},
		},
		{
			name: "image used by a container of another namespace",
			mock: func(m *mocks.MockFileSystemMockRecorder) {
				m.Mount(gomock.Any(), gomock.Any()).Return(mockMountpoint, nil).Times(1)
			},
			expect: func(t *testing.T, sn *snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				first := pullNydusImageAs(t, sn, mockBootstrapLabels, "k8s.io/1/")
				second := pullNydusImageAs(t, sn, mockBootstrapLabels, "default/5/")
				_, err := sn.Prepare(ctx, "default/3/container", second)
				assert.NoError(err)
				assert.NoError(sn.Remove(ctx, first))

				used, err := sn.usedImages(ctx)
				assert.NoError(err)
				assert.Contains(used, mockBootstrapChainID)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			fileSystem := mocks.NewMockFileSystem(ctl)
			tc.mock(fileSystem.EXPECT())

			sn, err := New(t.TempDir(), map[string]nydusfs.FileSystem{"7": fileSystem})
			assert.NoError(t, err)
			defer sn.Close()
			tc.expect(t, sn.(*snapshotter))
		})
	}
}

func TestSnapshotter_CommittedBlobs(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, sn Snapshotter)
	}{
		{
			name: "no blobs in a fresh metastore",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				blobs, err := sn.CommittedBlobs(t.Context())
				assert.NoError(err)
				assert.Empty(blobs)
				used, err := sn.(*snapshotter).usedImages(t.Context())
				assert.NoError(err)
				assert.Empty(used)
			},
		},
		{
			name: "list blobs of committed bootstraps",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				pullNydusImage(t, sn, mockBootstrapLabels)
				blobs, err := sn.CommittedBlobs(t.Context())
				assert.NoError(err)
				assert.Equal(map[string]struct{}{mockBlobID: {}}, blobs)
			},
		},
		{
			name: "skip a bootstrap layer without an image dir",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				pullNydusImage(t, sn, mockBootstrapLabels)
				key := "extract-3 sha256:" + strings.Repeat("cc", 32)
				_, err := sn.Prepare(t.Context(), key, "", snapshots.WithLabels(mockBootstrapLabels))
				assert.NoError(err)
				assert.NoError(sn.Commit(t.Context(), "forged", key, snapshots.WithLabels(mockBootstrapLabels)))

				blobs, err := sn.CommittedBlobs(t.Context())
				assert.NoError(err)
				assert.Equal(map[string]struct{}{mockBlobID: {}}, blobs)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sn, err := New(t.TempDir(), nil)
			assert.NoError(t, err)
			defer sn.Close()
			tc.expect(t, sn)
		})
	}
}

func pullNydusImage(t *testing.T, sn Snapshotter, bootstrapLabels map[string]string) string {
	t.Helper()
	return pullNydusImageAs(t, sn, bootstrapLabels, "k8s.io/1/")
}

func pullNydusImageAs(t *testing.T, sn Snapshotter, bootstrapLabels map[string]string, prefix string) string {
	t.Helper()
	assert := assert.New(t)
	ctx := t.Context()

	_, err := sn.Prepare(ctx, prefix+"extract-1 "+mockBlobChainID, "", snapshots.WithLabels(mockBlobLabels))
	assert.ErrorIs(err, errdefs.ErrAlreadyExists)

	key := prefix + "extract-2 " + mockBootstrapChainID
	_, err = sn.Prepare(ctx, key, mockBlobChainID, snapshots.WithLabels(bootstrapLabels))
	assert.NoError(err)

	mounts, err := sn.Mounts(ctx, key)
	assert.NoError(err)
	assert.Equal("bind", mounts[0].Type)
	imageDir := filepath.Join(mounts[0].Source, "image")
	assert.NoError(os.MkdirAll(imageDir, 0o755))
	assert.NoError(os.WriteFile(filepath.Join(imageDir, "image.boot"), nil, 0o644))
	assert.NoError(os.WriteFile(filepath.Join(imageDir, mockBlobID+".blob.meta"), nil, 0o644))

	name := prefix + mockBootstrapChainID
	assert.NoError(sn.Commit(ctx, name, key, snapshots.WithLabels(bootstrapLabels)))

	return name
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			sn, err := New(root, nil)
			assert.NoError(t, err)
			defer sn.Close()
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sn, err := New(t.TempDir(), nil)
			assert.NoError(t, err)
			defer sn.Close()
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
