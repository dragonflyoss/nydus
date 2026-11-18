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
	"github.com/containerd/containerd/v2/pkg/snapshotters"
	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	nydusfs "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs/mocks"
)

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
				assert := assert.New(t)
				labels := map[string]string{}
				maps.Copy(labels, mockBootstrapLabels)
				delete(labels, snapshotters.TargetRefLabel)
				parent := pullNydusImage(t, sn, labels)

				_, err := sn.Prepare(t.Context(), "container", parent)
				assert.ErrorIs(err, errdefs.ErrFailedPrecondition)
			},
		},
		{
			name: "reject bootstrap without chain id",
			mock: func(m *mocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				labels := maps.Clone(mockBootstrapLabels)
				delete(labels, labelSnapshotRef)
				parent := pullNydusImage(t, sn, labels)

				_, err := sn.Prepare(t.Context(), "container", parent)
				assert.ErrorIs(err, errdefs.ErrFailedPrecondition)
				assert.ErrorContains(err, labelSnapshotRef)
			},
		},
		{
			name: "reject bootstrap with an unknown prefetch scope",
			mock: func(m *mocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				labels := maps.Clone(mockBootstrapLabels)
				labels[labelNydusPrefetch] = "some"
				parent := pullNydusImage(t, sn, labels)

				_, err := sn.Prepare(t.Context(), "container", parent)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
			},
		},
		{
			name: "reject unsupported nydus format",
			mock: func(m *mocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				labels := map[string]string{}
				maps.Copy(labels, mockBootstrapLabels)
				labels[labelNydusFSVersion] = "6"
				parent := pullNydusImage(t, sn, labels)

				_, err := sn.Prepare(t.Context(), "container", parent)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
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
			sn := newTestSnapshotter(t, root, fileSystem)
			tc.expect(t, sn, root)
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
