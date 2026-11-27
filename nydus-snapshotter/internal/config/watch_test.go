/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConfig_Watch(t *testing.T) {
	tests := []struct {
		name   string
		update string
		err    error
		expect func(t *testing.T, reloaded []*Config)
	}{
		{
			name:   "reload a changed config",
			update: "cgroup:\n  memory_max: \"4GiB\"\n",
			expect: func(t *testing.T, reloaded []*Config) {
				assert := assert.New(t)
				assert.Len(reloaded, 1)
				assert.Equal(Size(4<<30), reloaded[0].Cgroup.MemoryMax)
			},
		},
		{
			name:   "pass a config that fails to apply once",
			update: "cgroup:\n  memory_max: \"4GiB\"\n",
			err:    errors.New("foo"),
			expect: func(t *testing.T, reloaded []*Config) {
				assert := assert.New(t)
				assert.Len(reloaded, 1)
				assert.Equal(Size(4<<30), reloaded[0].Cgroup.MemoryMax)
			},
		},
		{
			name:   "keep the running config on an invalid change",
			update: "cgroup:\n  memory_max: \"lots\"\n",
			expect: func(t *testing.T, reloaded []*Config) {
				assert := assert.New(t)
				assert.Empty(reloaded)
			},
		},
		{
			name:   "leave a change that needs a restart to the restart",
			update: "log:\n  level: debug\n",
			expect: func(t *testing.T, reloaded []*Config) {
				assert := assert.New(t)
				assert.Empty(reloaded)
			},
		},
		{
			name:   "ignore a rewrite of the running config",
			update: "log:\n  level: info\n",
			expect: func(t *testing.T, reloaded []*Config) {
				assert := assert.New(t)
				assert.Empty(reloaded)
			},
		},
		{
			name: "keep the running config while the file is missing",
			expect: func(t *testing.T, reloaded []*Config) {
				assert := assert.New(t)
				assert.Empty(reloaded)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			assert.NoError(t, os.WriteFile(path, nil, 0o644))
			cfg := New()
			assert.NoError(t, cfg.Load(path))
			if tc.update == "" {
				assert.NoError(t, os.Remove(path))
			} else {
				assert.NoError(t, os.WriteFile(path, []byte(tc.update), 0o644))
			}

			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				var reloaded []*Config
				go cfg.Watch(ctx, func(_ context.Context, cfg *Config) error {
					reloaded = append(reloaded, cfg)
					return tc.err
				})

				time.Sleep(3 * watchInterval)
				synctest.Wait()
				cancel()
				synctest.Wait()
				tc.expect(t, reloaded)
			})
		})
	}
}
