/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package snapshot

import (
	"testing"

	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
)

func TestSnapshotKey_isUnpack(t *testing.T) {
	tests := []struct {
		name   string
		key    snapshotKey
		expect func(t *testing.T, unpack bool)
	}{
		{
			name: "unpack key of the metadata store",
			key:  "default/12/extract-123-sha256:ab",
			expect: func(t *testing.T, unpack bool) {
				assert.True(t, unpack)
			},
		},
		{
			name: "bare unpack key",
			key:  "extract-123-sha256:ab",
			expect: func(t *testing.T, unpack bool) {
				assert.True(t, unpack)
			},
		},
		{
			name: "container key",
			key:  "default/13/container",
			expect: func(t *testing.T, unpack bool) {
				assert.False(t, unpack)
			},
		},
		{
			name: "container key named like an unpack key below the prefix",
			key:  "default/14/app/extract-123",
			expect: func(t *testing.T, unpack bool) {
				assert.False(t, unpack)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, tc.key.isUnpack())
		})
	}
}

func TestLabels_prefetchScope(t *testing.T) {
	tests := []struct {
		name   string
		labels labels
		expect func(t *testing.T, scope string, err error)
	}{
		{
			name:   "configured default",
			labels: labels{},
			expect: func(t *testing.T, scope string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(scope)
			},
		},
		{
			name:   "scope of the label",
			labels: labels{labelNydusPrefetch: "none"},
			expect: func(t *testing.T, scope string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("none", scope)
			},
		},
		{
			name:   "unknown scope",
			labels: labels{labelNydusPrefetch: "some"},
			expect: func(t *testing.T, scope string, err error) {
				assert.ErrorIs(t, err, errdefs.ErrInvalidArgument)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scope, err := tc.labels.prefetchScope()
			tc.expect(t, scope, err)
		})
	}
}

func TestLabels_rootPair(t *testing.T) {
	tests := []struct {
		name   string
		labels labels
		expect func(t *testing.T, uid, gid int, ok bool, err error)
	}{
		{
			name:   "no mapping",
			labels: labels{},
			expect: func(t *testing.T, uid, gid int, ok bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(ok)
			},
		},
		{
			name: "mapping with several ranges",
			labels: labels{
				snapshots.LabelSnapshotUIDMapping: "1:300000:10,0:100000:1",
				snapshots.LabelSnapshotGIDMapping: "0:200000:65536",
			},
			expect: func(t *testing.T, uid, gid int, ok bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(ok)
				assert.Equal(100000, uid)
				assert.Equal(200000, gid)
			},
		},
		{
			name:   "mapping without container root",
			labels: labels{snapshots.LabelSnapshotUIDMapping: "1:100000:10"},
			expect: func(t *testing.T, uid, gid int, ok bool, err error) {
				assert.ErrorIs(t, err, errdefs.ErrInvalidArgument)
			},
		},
		{
			name:   "unparsable mapping",
			labels: labels{snapshots.LabelSnapshotUIDMapping: "root"},
			expect: func(t *testing.T, uid, gid int, ok bool, err error) {
				assert.ErrorIs(t, err, errdefs.ErrInvalidArgument)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uid, gid, ok, err := tc.labels.rootPair()
			tc.expect(t, uid, gid, ok, err)
		})
	}
}
