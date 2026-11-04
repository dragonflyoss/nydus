/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsNydusCompressor(t *testing.T) {
	tests := []struct {
		name       string
		compressor string
		expect     func(t *testing.T, ok bool)
	}{
		{
			name:       "chunk layout",
			compressor: "lz4",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
			},
		},
		{
			name:       "native erofs layout",
			compressor: "erofs-zstd",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.True(ok)
			},
		},
		{
			name:       "unsupported compressor",
			compressor: "gzip",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
			},
		},
		{
			name: "empty compressor",
			expect: func(t *testing.T, ok bool) {
				assert := assert.New(t)
				assert.False(ok)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, IsNydusCompressor(tc.compressor))
		})
	}
}
