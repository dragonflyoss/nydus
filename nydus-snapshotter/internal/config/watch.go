/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"context"
	"time"

	"github.com/containerd/log"
)

// watchInterval is the interval of polling the config file.
const watchInterval = 10 * time.Second

// Watch polls the file c was loaded from and calls fn with every reloaded
// config that differs from the running one, until ctx is done. A file that
// fails to load keeps the running config, and a config fn fails to apply is
// logged and not passed again. Polling survives the symlink swap of a
// ConfigMap update, which fsnotify watches miss.
func (c *Config) Watch(ctx context.Context, fn func(context.Context, *Config) error) {
	var (
		// running is the config last passed to fn, at first c.
		running = c

		// lastErr is the last reload error, so a lasting one is reported once.
		lastErr string

		// lastRestartOnly is whether the last reload left settings to a
		// restart, so lasting ones are reported once.
		lastRestartOnly bool
	)

	ticker := time.NewTicker(watchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		cfg, changed, restartOnly, err := running.Reload()
		if err != nil {
			if err.Error() != lastErr {
				log.G(ctx).WithError(err).Warn("reload config, keeping the running one")
				lastErr = err.Error()
			}

			continue
		}
		lastErr = ""

		if restartOnly && !lastRestartOnly {
			log.G(ctx).Warn("config changes outside cgroup and nydusd.config apply after a restart")
		}
		lastRestartOnly = restartOnly

		if !changed {
			continue
		}
		running = cfg

		log.G(ctx).Info("config changed, reloading")
		if err := fn(ctx, cfg); err != nil {
			log.G(ctx).WithError(err).Error("apply reloaded config")
		}
	}
}
