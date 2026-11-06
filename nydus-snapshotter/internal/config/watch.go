/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"time"

	"github.com/containerd/log"
)

// DefaultWatchInterval is the interval of polling the config file.
const DefaultWatchInterval = 10 * time.Second

// Watcher polls a config file for changes. Polling survives the symlink swap
// of a ConfigMap update, which fsnotify watches miss, as Dragonfly's config
// watcher does, refer to
// https://github.com/dragonflyoss/dragonfly/blob/main/cmd/dependency/dependency.go.
type Watcher struct {
	// path is the config file.
	path string

	// interval is the polling interval.
	interval time.Duration

	// last is the config of the last change reported, the running one.
	last *Config

	// lastData is the file content last read, so an unchanged invalid file
	// is reported once.
	lastData []byte

	// lastErr is the last read error, so a lasting one is reported once.
	lastErr string
}

// NewWatcher returns a watcher of the config file at path, whose running
// config is current.
func NewWatcher(path string, interval time.Duration, current *Config) *Watcher {
	return &Watcher{path: path, interval: interval, last: current}
}

// Run calls fn with every config that decodes, validates and differs from
// the last one, until ctx is done. A config that fails keeps the running one.
func (w *Watcher) Run(ctx context.Context, fn func(context.Context, *Config)) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		data, err := os.ReadFile(w.path)
		if err != nil {
			if err.Error() != w.lastErr {
				log.G(ctx).WithError(err).Warn("read config, keeping the running one")
				w.lastErr = err.Error()
			}

			continue
		}
		w.lastErr = ""

		// An empty read is a file caught mid-write, not a config.
		if len(data) == 0 || bytes.Equal(data, w.lastData) {
			continue
		}
		w.lastData = data

		cfg, err := Parse(data)
		if err != nil {
			log.G(ctx).WithError(err).Warn("reload config, keeping the running one")
			continue
		}

		if reflect.DeepEqual(cfg, w.last) {
			continue
		}
		w.last = cfg

		log.G(ctx).Info("config changed, reloading")
		fn(ctx, cfg)
	}
}

// Merge returns the running config with the settings of next that apply
// without a restart: the cgroup limits and the dragonfly section. It reports
// whether next changes anything else, which applies on the next restart; a
// new cgroup slice would hide the running daemons, so it is one of those.
func (c *Config) Merge(next *Config) (*Config, bool) {
	merged := *c
	merged.Cgroup = next.Cgroup
	merged.Cgroup.Slice = c.Cgroup.Slice
	merged.Nydusd.Dragonfly = next.Nydusd.Dragonfly

	return &merged, !reflect.DeepEqual(c.restartOnly(), next.restartOnly())
}

// restartOnly returns a copy holding only the settings that apply on a
// restart.
func (c *Config) restartOnly() *Config {
	restartOnly := *c
	restartOnly.Cgroup = CgroupConfig{Slice: c.Cgroup.Slice}
	restartOnly.Nydusd.Dragonfly = DragonflyConfig{}
	return &restartOnly
}
