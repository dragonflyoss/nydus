/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package stargz

import (
	"errors"
	"fmt"
	"os"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/config"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/meta"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/process"
)

func WithMeta(root string) NewFSOpt {
	return func(d *filesystem) error {
		if root == "" {
			return errors.New("rootDir is required")
		}
		d.FileSystemMeta = meta.FileSystemMeta{
			RootDir: root,
		}
		return nil
	}
}

func WithNydusdBinaryPath(p string) NewFSOpt {
	return func(d *filesystem) error {
		if p == "" {
			return errors.New("nydusd binary path is required")
		}
		d.nydusdBinaryPath = p
		return nil
	}
}

func WithProcessManager(pm *process.Manager) NewFSOpt {
	return func(d *filesystem) error {
		if pm == nil {
			return errors.New("process manager cannot be nil")
		}

		d.manager = pm
		return nil
	}
}

func WithNydusImageBinaryPath(p string) NewFSOpt {
	return func(d *filesystem) error {
		if p == "" {
			return errors.New("nydus image binary path is required")
		}
		d.nydusdImageBinaryPath = p
		return nil
	}
}

func WithDaemonConfig(cfg config.DaemonConfig) NewFSOpt {
	return func(d *filesystem) error {
		if (config.DaemonConfig{}) == cfg {
			return errors.New("daemon config is empty")
		}
		d.daemonCfg = cfg
		return nil
	}
}

func WithLogLevel(logLevel string) NewFSOpt {
	return func(d *filesystem) error {
		if logLevel == "" {
			d.logLevel = config.DefaultLogLevel
		} else {
			d.logLevel = logLevel
		}
		return nil
	}
}

func WithLogDir(dir string) NewFSOpt {
	return func(d *filesystem) error {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return errors.New(fmt.Sprintf("failed to create logDir %s: %v", dir, err))
		}
		d.logDir = dir
		return nil
	}
}

type NewFSOpt func(d *filesystem) error
