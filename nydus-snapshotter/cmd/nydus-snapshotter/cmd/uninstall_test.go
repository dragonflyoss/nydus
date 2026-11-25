/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
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
			name:   "refuse an argument",
			config: "log:\n  level: debug\n",
			args:   []string{"now"},
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

			out := &bytes.Buffer{}
			rootCmd.SetOut(out)
			rootCmd.SetErr(out)
			rootCmd.SetArgs(append([]string{"uninstall", "--config", path}, tc.args...))
			t.Cleanup(func() {
				for _, cmd := range []*cobra.Command{rootCmd, installCmd, uninstallCmd} {
					for _, name := range []string{"config", "help", "version"} {
						if flag := cmd.Flags().Lookup(name); flag != nil {
							assert.NoError(t, flag.Value.Set(flag.DefValue))
							flag.Changed = false
						}
					}
				}
			})

			tc.expect(t, rootCmd.ExecuteContext(t.Context()))
		})
	}
}
