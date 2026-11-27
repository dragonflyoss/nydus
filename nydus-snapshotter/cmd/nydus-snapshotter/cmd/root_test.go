/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package cmd

import (
	"bytes"
	"context"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/version"
)

var (
	mockConfigPathEnvVar = "NYDUS_SNAPSHOTTER_TEST_CONFIG_PATH"
)

func TestRootCmd(t *testing.T) {
	tests := []struct {
		name   string
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			assert.NoError(t, os.WriteFile(path, []byte("log:\n  level: debug\n"), 0o644))

			out := &bytes.Buffer{}
			rootCmd.SetOut(out)
			rootCmd.SetErr(out)
			rootCmd.SetArgs(append([]string{"--config", path}, tc.args...))
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
			tc.expect(t, out.String(), err)
		})
	}
}

func TestInitConfig(t *testing.T) {
	if path := os.Getenv(mockConfigPathEnvVar); path != "" {
		configPath = path
		initConfig()
		return
	}

	tests := []struct {
		name   string
		config string
		expect func(t *testing.T, out string, err error)
	}{
		{
			name:   "config that loads",
			config: "log:\n  level: debug\n",
			expect: func(t *testing.T, out string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "config that is missing",
			expect: func(t *testing.T, out string, err error) {
				assert := assert.New(t)
				var exitErr *exec.ExitError
				if assert.ErrorAs(err, &exitErr) {
					assert.Equal(1, exitErr.ExitCode())
				}

				assert.Contains(out, "no such file or directory")
			},
		},
		{
			name:   "invalid config",
			config: "log:\n  level: loud\n",
			expect: func(t *testing.T, out string, err error) {
				assert := assert.New(t)
				var exitErr *exec.ExitError
				if assert.ErrorAs(err, &exitErr) {
					assert.Equal(1, exitErr.ExitCode())
				}

				assert.Contains(out, "invalid log.level")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if tc.config != "" {
				assert.NoError(t, os.WriteFile(path, []byte(tc.config), 0o644))
			}

			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestInitConfig$")
			cmd.Env = append(os.Environ(), mockConfigPathEnvVar+"="+path)
			out, err := cmd.CombinedOutput()
			tc.expect(t, string(out), err)
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
			if os.Geteuid() != 0 {
				t.Skip("talks to systemd as root")
			}

			if _, err := os.Stat("/run/systemd/system"); err != nil {
				t.Skip("needs systemd as init")
			}

			dir := t.TempDir()
			cfg := config.New()
			cfg.RootDir = filepath.Join(dir, "lib")
			cfg.RuntimeDir = filepath.Join(dir, "run")
			cfg.GRPC.Addr = filepath.Join(cfg.RuntimeDir, "s.sock")
			cfg.Metrics.Addr = "127.0.0.1:0"
			cfg.Cgroup.Slice = "nydustest" + strconv.Itoa(os.Getpid()) + strconv.Itoa(rand.IntN(1<<30)) + ".slice"
			t.Cleanup(func() { _ = exec.Command("systemctl", "stop", cfg.Cgroup.Slice).Run() })
			tc.prepare(t, cfg)

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- runNydusSnapshotter(ctx, cfg) }()
			tc.expect(t, cfg, cancel, done)
		})
	}
}
