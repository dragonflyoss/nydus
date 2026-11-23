/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"strings"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
)

func TestDaemonIDFromUnit(t *testing.T) {
	tests := []struct {
		name   string
		unit   string
		expect func(t *testing.T, id daemonID, ok bool)
	}{
		{
			name: "daemon unit",
			unit: mockUnit,
			expect: func(t *testing.T, id daemonID, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
				assert.Equal(mockChainID, id.ChainID())
				assert.Equal(mockUnit, id.Unit())
				assert.Equal(mockPreheatUnit, id.PreheatUnit())
				assert.Equal("abababababab", id.Short())
				parsed, err := daemonIDFromChainID(mockChainID)
				assert.NoError(err)
				assert.Equal(id, parsed)
			},
		},
		{
			name: "other unit",
			unit: "nydusd-abc.service",
			expect: func(t *testing.T, id daemonID, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
			},
		},
		{
			name: "unit without the daemon prefix",
			unit: "containerd.service",
			expect: func(t *testing.T, id daemonID, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
				assert.Empty(id)
			},
		},
		{
			name: "unit of another type",
			unit: strings.TrimSuffix(mockUnit, ".service") + ".scope",
			expect: func(t *testing.T, id daemonID, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
				assert.Empty(id)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := daemonIDFromUnit(tc.unit)
			tc.expect(t, id, ok)
		})
	}
}

func TestDaemonIDFromChainID(t *testing.T) {
	tests := []struct {
		name    string
		chainID string
		expect  func(t *testing.T, id daemonID, err error)
	}{
		{
			name:    "sha256 chain id",
			chainID: mockChainID,
			expect: func(t *testing.T, id daemonID, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockChainID, id.ChainID())
			},
		},
		{
			name:    "chain id of another algorithm",
			chainID: "sha512:" + strings.Repeat("ab", 64),
			expect: func(t *testing.T, id daemonID, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
				assert.Empty(id)
			},
		},
		{
			name:    "no digest",
			chainID: "../../etc",
			expect: func(t *testing.T, id daemonID, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
				assert.Empty(id)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, err := daemonIDFromChainID(tc.chainID)
			tc.expect(t, id, err)
		})
	}
}
