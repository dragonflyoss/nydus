/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"bytes"
	"context"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/util/testutil"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/version"
)

func executeCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out := &bytes.Buffer{}
	rootCmd.SetOut(out)
	rootCmd.SetErr(out)
	rootCmd.SetArgs(args)
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

	err := rootCmd.ExecuteContext(t.Context())
	return out.String(), err
}

func TestRootCmd(t *testing.T) {
	tests := []struct {
		name   string
		config string
		args   []string
		expect func(t *testing.T, out string, err error)
	}{
		{
			name: "print the version",
			args: []string{"--version"},
			expect: func(t *testing.T, out string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Contains(out, version.String())
			},
		},
		{
			name: "describe the install command",
			args: []string{"install", "--help"},
			expect: func(t *testing.T, out string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Contains(out, "--config")
			},
		},
		{
			name: "refuse an argument",
			args: []string{"serve"},
			expect: func(t *testing.T, out string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unknown command")
			},
		},
		{
			name: "refuse an unknown flag",
			args: []string{"--root", "/var/lib/other"},
			expect: func(t *testing.T, out string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unknown flag")
			},
		},
		{
			name: "config that is missing",
			args: []string{"--config", "testdata/missing.yaml"},
			expect: func(t *testing.T, out string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, fs.ErrNotExist)
			},
		},
		{
			name:   "invalid config",
			config: "log:\n  level: loud\n",
			expect: func(t *testing.T, out string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid log.level")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.config != "" {
				configPath = filepath.Join(t.TempDir(), "config.yaml")
				assert.NoError(t, os.WriteFile(configPath, []byte(tc.config), 0o644))
			}

			out, err := executeCommand(t, tc.args...)
			tc.expect(t, out, err)
		})
	}
}

func TestRunSnapshotter(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, cfg *config.Config)
		expect  func(t *testing.T, cfg *config.Config, cancel context.CancelFunc, done <-chan error)
	}{
		{
			name:    "serve until the context is done",
			prepare: func(t *testing.T, cfg *config.Config) {},
			expect: func(t *testing.T, cfg *config.Config, cancel context.CancelFunc, done <-chan error) {
				assert := assert.New(t)
				assert.Eventually(func() bool {
					conn, err := net.Dial("unix", cfg.GRPC.Addr)
					if err == nil {
						conn.Close()
					}

					return err == nil
				}, 10*time.Second, 10*time.Millisecond)
				cancel()
				assert.NoError(<-done)
			},
		},
		{
			name: "server that cannot be built",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(cfg.RootDir, nil, 0o644))
			},
			expect: func(t *testing.T, cfg *config.Config, cancel context.CancelFunc, done <-chan error) {
				assert := assert.New(t)
				assert.ErrorContains(<-done, "create "+cfg.RootDir)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testutil.NewConfig(t)
			tc.prepare(t, cfg)

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			path := filepath.Join(t.TempDir(), "config.yaml")
			go func() { done <- runSnapshotter(ctx, cfg, path) }()
			tc.expect(t, cfg, cancel, done)
		})
	}
}
