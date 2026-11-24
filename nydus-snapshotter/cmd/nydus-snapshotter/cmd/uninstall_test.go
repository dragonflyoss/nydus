/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUninstallCmd(t *testing.T) {
	tests := []struct {
		name   string
		config string
		args   []string
		expect func(t *testing.T, err error)
	}{
		{
			name:   "pod without an api server",
			config: "log:\n  level: debug\n",
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
			},
		},
		{
			name: "config that is missing",
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, fs.ErrNotExist)
			},
		},
		{
			name:   "invalid config",
			config: "log:\n  level: loud\n",
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid log.level")
			},
		},
		{
			name: "refuse an argument",
			args: []string{"now"},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unknown command")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", "")
			path := filepath.Join(t.TempDir(), "config.yaml")
			if tc.config != "" {
				assert.NoError(t, os.WriteFile(path, []byte(tc.config), 0o644))
			}

			_, err := executeCommand(t, append([]string{"uninstall", "--config", path}, tc.args...)...)
			tc.expect(t, err)
		})
	}
}
