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
	"testing"
	"testing/synctest"
	"time"

	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	nydusfs "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs/mocks"
)

func TestSnapshotter_Run(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, ctl *gomock.Controller, fileSystem *mocks.MockFileSystem)
	}{
		{
			name: "release at start and on removal",
			expect: func(t *testing.T, ctl *gomock.Controller, fileSystem *mocks.MockFileSystem) {
				assert := assert.New(t)
				released := make(chan struct{})
				fileSystem.EXPECT().Release(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, _ nydusfs.UsedFunc) error {
					select {
					case released <- struct{}{}:
					case <-ctx.Done():
					}
					return nil
				}).MinTimes(2)

				sn, err := New(t.TempDir(), fileSystem)
				if !assert.NoError(err) {
					t.FailNow()
				}
				defer func() { assert.NoError(sn.Close()) }()

				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan struct{})
				go func() {
					sn.Run(ctx)
					close(done)
				}()

				<-released
				_, err = sn.Prepare(t.Context(), "container", "")
				assert.NoError(err)
				assert.NoError(sn.Remove(t.Context(), "container"))
				<-released

				cancel()
				<-done
			},
		},
		{
			name: "release on every tick, past a pass that failed",
			expect: func(t *testing.T, ctl *gomock.Controller, fileSystem *mocks.MockFileSystem) {
				synctest.Test(t, func(t *testing.T) {
					assert := assert.New(t)
					gomock.InOrder(
						fileSystem.EXPECT().Release(gomock.Any(), gomock.Any()).Return(errors.New("foo")).Times(1),
						fileSystem.EXPECT().Release(gomock.Any(), gomock.Any()).Return(nil).Times(2),
					)

					sn, err := New(t.TempDir(), fileSystem)
					if !assert.NoError(err) {
						t.FailNow()
					}
					defer func() { assert.NoError(sn.Close()) }()

					ctx, cancel := context.WithCancel(t.Context())
					go sn.Run(ctx)
					synctest.Wait()
					time.Sleep(2 * releaseInterval)
					synctest.Wait()
					cancel()
					synctest.Wait()
					assert.True(ctl.Satisfied())
				})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			tc.expect(t, ctl, mocks.NewMockFileSystem(ctl))
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
				_, err := sn.Prepare(ctx, "container", mockBootstrapSnapshot)
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
				_, err := sn.Prepare(ctx, "default/5/extract-1 "+mockBlobChainID, "", snapshots.WithLabels(mockBlobLabels))
				assert.ErrorIs(err, errdefs.ErrAlreadyExists)
				_, err = sn.Prepare(ctx, "default/5/extract-2 "+mockBootstrapChainID, mockBlobChainID, snapshots.WithLabels(mockBootstrapLabels))
				assert.NoError(err)
				mounts, err := sn.Mounts(ctx, "default/5/extract-2 "+mockBootstrapChainID)
				assert.NoError(err)
				assert.Equal("bind", mounts[0].Type)
				assert.NoError(os.CopyFS(mounts[0].Source, mockBootstrapLayer))
				assert.NoError(sn.Commit(ctx, "default/5/"+mockBootstrapChainID, "default/5/extract-2 "+mockBootstrapChainID, snapshots.WithLabels(mockBootstrapLabels)))

				_, err = sn.Prepare(ctx, "default/3/container", "default/5/"+mockBootstrapChainID)
				assert.NoError(err)
				assert.NoError(sn.Remove(ctx, mockBootstrapSnapshot))

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

			sn, err := New(t.TempDir(), fileSystem)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			defer func() { assert.NoError(t, sn.Close()) }()

			_, err = sn.Prepare(t.Context(), mockBlobExtractKey, "", snapshots.WithLabels(mockBlobLabels))
			assert.ErrorIs(t, err, errdefs.ErrAlreadyExists)
			_, err = sn.Prepare(t.Context(), mockBootstrapExtractKey, mockBlobChainID, snapshots.WithLabels(mockBootstrapLabels))
			assert.NoError(t, err)
			mounts, err := sn.Mounts(t.Context(), mockBootstrapExtractKey)
			assert.NoError(t, err)
			assert.Equal(t, "bind", mounts[0].Type)
			assert.NoError(t, os.CopyFS(mounts[0].Source, mockBootstrapLayer))
			assert.NoError(t, sn.Commit(t.Context(), mockBootstrapSnapshot, mockBootstrapExtractKey, snapshots.WithLabels(mockBootstrapLabels)))

			tc.expect(t, sn.(*snapshotter))
		})
	}
}
