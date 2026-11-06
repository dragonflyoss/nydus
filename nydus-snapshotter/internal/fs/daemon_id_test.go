/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDaemonID_Unit(t *testing.T) {
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
				assert.Equal("abababababab", id.Short())
				parsed, err := parseDaemonID(mockChainID)
				assert.NoError(err)
				assert.Equal(id, parsed)
			},
		},
		{
			name: "other unit",
			unit: "nydusd-abc.service",
			expect: func(t *testing.T, id daemonID, ok bool) {
				assert.False(t, ok)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, ok := daemonIDOfUnit(tc.unit)
			tc.expect(t, id, ok)
		})
	}
}
