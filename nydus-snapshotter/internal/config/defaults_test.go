/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, cfg *Config)
	}{
		{
			name: "defaults validate",
			expect: func(t *testing.T, cfg *Config) {
				assert := assert.New(t)
				assert.NoError(cfg.Validate())
			},
		},
		{
			name: "shipped config states the defaults",
			expect: func(t *testing.T, cfg *Config) {
				assert := assert.New(t)
				shipped, err := Load("../../deploy/nydus-snapshotter/config.yaml")
				assert.NoError(err)
				assert.Equal(cfg, shipped)
			},
		},
		{
			name: "every call returns a config of its own",
			expect: func(t *testing.T, cfg *Config) {
				assert := assert.New(t)
				cfg.RootDir = "/var/lib/other"
				assert.Equal(DefaultRootDir, New().RootDir)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, New())
		})
	}
}
