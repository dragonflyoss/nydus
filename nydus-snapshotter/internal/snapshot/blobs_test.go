/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
)

func TestSnapshotter_CommittedBlobs(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
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
			name:   "list blobs of committed bootstraps",
			labels: mockBootstrapLabels,
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				blobs, err := sn.CommittedBlobs(t.Context())
				assert.NoError(err)
				assert.Equal(map[string]struct{}{mockBlobID: {}}, blobs)
			},
		},
		{
			name: "metadata store that cannot be opened",
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
				ctx := t.Context()
				_, err := sn.Prepare(ctx, "active", "")
				assert.NoError(err)
				assert.NoError(sn.Close())
				metadata := filepath.Join(sn.(*snapshotter).root, "metadata.db")
				assert.NoError(os.Remove(metadata))
				assert.NoError(os.Mkdir(metadata, 0o755))

				_, err = sn.CommittedBlobs(ctx)
				assert.Error(err)
				_, err = sn.(*snapshotter).usedImages(ctx)
				assert.Error(err)
				_, err = sn.Mounts(ctx, "active")
				assert.Error(err)
				assert.Error(sn.Cleanup(ctx))
			},
		},
		{
			name:   "skip a bootstrap layer without an image dir",
			labels: mockBootstrapLabels,
			expect: func(t *testing.T, sn Snapshotter) {
				assert := assert.New(t)
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

			tc.expect(t, sn)
		})
	}
}
