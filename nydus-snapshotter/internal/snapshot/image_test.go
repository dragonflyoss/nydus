/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"maps"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"

	nydusfs "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
)

func TestSnapshotter_NydusImage(t *testing.T) {
	tests := []struct {
		name     string
		labels   map[string]string
		chainIDs []string
		expect   func(t *testing.T, image *nydusfs.Image, err error)
	}{
		{
			name:     "find the bootstrap layer among the layers of the image",
			labels:   mockBootstrapLabels,
			chainIDs: []string{mockBlobChainID, mockBootstrapChainID},
			expect: func(t *testing.T, image *nydusfs.Image, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockBootstrapChainID, image.ChainID)
				assert.Empty(image.Ref)
				blobs, err := nydusfs.NewBootstrapLayer(image.BootstrapDir).Blobs()
				assert.NoError(err)
				assert.Equal([]string{mockBlobID}, blobs)
			},
		},
		{
			name:     "image without a layer this snapshotter unpacked",
			labels:   mockBootstrapLabels,
			chainIDs: []string{mockBlobChainID},
			expect: func(t *testing.T, image *nydusfs.Image, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotFound)
				assert.Nil(image)
			},
		},
		{
			name: "bootstrap layer of another format version",
			labels: func() map[string]string {
				labels := maps.Clone(mockBootstrapLabels)
				labels[labelNydusFSVersion] = "6"
				return labels
			}(),
			chainIDs: []string{mockBootstrapChainID},
			expect: func(t *testing.T, image *nydusfs.Image, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
				assert.Nil(image)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sn := newTestSnapshotter(t, t.TempDir(), nil)
			pullNydusImage(t, sn, tc.labels)
			image, err := sn.NydusImage(t.Context(), tc.chainIDs)
			tc.expect(t, image, err)
		})
	}
}
