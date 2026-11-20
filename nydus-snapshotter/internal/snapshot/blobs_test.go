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
	"github.com/stretchr/testify/assert"
)

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
			sn := newTestSnapshotter(t, t.TempDir(), nil)
			tc.expect(t, sn)
		})
	}
}
