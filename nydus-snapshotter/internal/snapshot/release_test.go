/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	nydusfs "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs/mocks"
)

func TestSnapshotter_Run(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, sn Snapshotter, released chan struct{})
	}{
		{
			name: "tear down at start and on removal",
			expect: func(t *testing.T, sn Snapshotter, released chan struct{}) {
				assert := assert.New(t)
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan struct{})
				go func() {
					sn.Run(ctx)
					close(done)
				}()

				<-released
				_, err := sn.Prepare(t.Context(), "container", "")
				assert.NoError(err)
				assert.NoError(sn.Remove(t.Context(), "container"))
				<-released

				cancel()
				<-done
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			released := make(chan struct{})
			fileSystem := mocks.NewMockFileSystem(ctl)
			fileSystem.EXPECT().Release(gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, _ nydusfs.UsedFunc) error {
				select {
				case released <- struct{}{}:
				case <-ctx.Done():
				}
				return nil
			}).MinTimes(2)

			sn, err := New(t.TempDir(), map[string]nydusfs.FileSystem{"7": fileSystem})
			assert.NoError(t, err)
			defer sn.Close()
			tc.expect(t, sn, released)
		})
	}
}
