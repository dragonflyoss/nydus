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

// watchInterval is the interval of polling the config file.
const watchInterval = 10 * time.Second

// Watcher polls a config file for changes. Polling survives the symlink swap
// of a ConfigMap update, which fsnotify watches miss, as Dragonfly's config
// watcher does, refer to
// https://github.com/dragonflyoss/dragonfly/blob/main/cmd/dependency/dependency.go.
type Watcher struct {
	// path is the config file.
	path string

	// last is the config last passed to fn, at first the one the snapshotter
	// started with.
	last *Config

	// lastData is the file content last read, so an unchanged invalid file
	// is reported once.
	lastData []byte

	// lastErr is the last read error, so a lasting one is reported once.
	lastErr string
}

// NewWatcher returns a watcher of the config file at path, whose running
// config is current.
func NewWatcher(path string, current *Config) *Watcher {
	return &Watcher{path: path, last: current}
}

// Run calls fn with every config that decodes, validates and differs from
// the last one, until ctx is done. A config that fails keeps the running one.
func (w *Watcher) Run(ctx context.Context, fn func(context.Context, *Config)) {
	ticker := time.NewTicker(watchInterval)
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
