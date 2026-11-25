/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"context"
	"os"
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
		labels map[string]string
		mock   func(m *mocks.MockFileSystemMockRecorder)
		expect func(t *testing.T, sn Snapshotter, root string)
	}{
		{
			name:   "mount container on the nydus daemon",
			labels: mockBootstrapLabels,
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
				mounts, err := sn.Prepare(ctx, "container", mockBootstrapSnapshot)
				assert.NoError(err)
				assert.Equal("overlay", mounts[0].Type)
				assert.Contains(mounts[0].Options, "lowerdir="+mockMountpoint)

				mounts, err = sn.Mounts(ctx, "container")
				assert.NoError(err)
				assert.Contains(mounts[0].Options, "lowerdir="+mockMountpoint)
			},
		},
		{
			name:   "bind a view of the nydus daemon read only",
			labels: mockBootstrapLabels,
			mock: func(m *mocks.MockFileSystemMockRecorder) {
				m.Mount(gomock.Any(), gomock.Any()).Return(mockMountpoint, nil).Times(1)
			},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				mounts, err := sn.View(t.Context(), "view", mockBootstrapSnapshot)
				assert.NoError(err)
				assert.Equal([]mount.Mount{{Type: "bind", Source: mockMountpoint, Options: []string{"ro", "rbind"}}}, mounts)
			},
		},
		{
			name:   "remove a container snapshot whose daemon fails",
			labels: mockBootstrapLabels,
			mock: func(m *mocks.MockFileSystemMockRecorder) {
				m.Mount(gomock.Any(), gomock.Any()).Return("", errdefs.ErrUnavailable).Times(1)
			},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "container", mockBootstrapSnapshot)
				assert.ErrorIs(err, errdefs.ErrUnavailable)
				_, err = sn.Stat(ctx, "container")
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "reject bootstrap without image reference",
			labels: map[string]string{
				labelSnapshotRef:    mockBootstrapChainID,
				labelNydusBootstrap: labelTrue,
				labelNydusFSVersion: nydusfs.Version,
			},
			mock: func(m *mocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				_, err := sn.Prepare(t.Context(), "container", mockBootstrapSnapshot)
				assert.ErrorIs(err, errdefs.ErrFailedPrecondition)
			},
		},
		{
			name: "reject bootstrap without chain id",
			labels: map[string]string{
				labelNydusBootstrap:         labelTrue,
				labelNydusFSVersion:         nydusfs.Version,
				snapshotters.TargetRefLabel: mockImageRef,
			},
			mock: func(m *mocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				_, err := sn.Prepare(t.Context(), "container", mockBootstrapSnapshot)
				assert.ErrorIs(err, errdefs.ErrFailedPrecondition)
				assert.ErrorContains(err, labelSnapshotRef)
			},
		},
		{
			name: "reject bootstrap with an unknown prefetch scope",
			labels: map[string]string{
				labelSnapshotRef:            mockBootstrapChainID,
				labelNydusBootstrap:         labelTrue,
				labelNydusFSVersion:         nydusfs.Version,
				labelNydusPrefetch:          "some",
				snapshotters.TargetRefLabel: mockImageRef,
			},
			mock: func(m *mocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				_, err := sn.Prepare(t.Context(), "container", mockBootstrapSnapshot)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
			},
		},
		{
			name: "reject unsupported nydus format",
			labels: map[string]string{
				labelSnapshotRef:            mockBootstrapChainID,
				labelNydusBootstrap:         labelTrue,
				labelNydusFSVersion:         "6",
				snapshotters.TargetRefLabel: mockImageRef,
			},
			mock: func(m *mocks.MockFileSystemMockRecorder) {},
			expect: func(t *testing.T, sn Snapshotter, root string) {
				assert := assert.New(t)
				_, err := sn.Prepare(t.Context(), "container", mockBootstrapSnapshot)
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
			sn, err := New(root, fileSystem)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			defer func() { assert.NoError(t, sn.Close()) }()
			if tc.labels != nil {
				_, err := sn.Prepare(t.Context(), mockBlobExtractKey, "", snapshots.WithLabels(mockBlobLabels))
				assert.ErrorIs(t, err, errdefs.ErrAlreadyExists)
				_, err = sn.Prepare(t.Context(), mockBootstrapExtractKey, mockBlobChainID, snapshots.WithLabels(tc.labels))
				assert.NoError(t, err)
				mounts, err := sn.Mounts(t.Context(), mockBootstrapExtractKey)
				assert.NoError(t, err)
				assert.Equal(t, "bind", mounts[0].Type)
				assert.NoError(t, os.CopyFS(mounts[0].Source, mockBootstrapLayer))
				assert.NoError(t, sn.Commit(t.Context(), mockBootstrapSnapshot, mockBootstrapExtractKey, snapshots.WithLabels(tc.labels)))
			}

			tc.expect(t, sn, root)
		})
	}
}
