/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"errors"
	"strings"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/config"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/cache"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/fs"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/meta"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/process"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/signature"
)

type NewFSOpt func(d *filesystem) error

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

func WithCacheManager(cm *cache.Manager) NewFSOpt {
	return func(d *filesystem) error {
		if cm == nil {
			return errors.New("cache manager cannot be nil")
		}

		d.cacheMgr = cm
		return nil
	}
}

func WithVerifier(verifier *signature.Verifier) NewFSOpt {
	return func(d *filesystem) error {
		d.verifier = verifier
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

func WithVPCRegistry(vpcRegistry bool) NewFSOpt {
	return func(d *filesystem) error {
		d.vpcRegistry = vpcRegistry
		return nil
	}
}

func WithDaemonMode(daemonMode string) NewFSOpt {
	return func(d *filesystem) error {
		mode := strings.ToLower(daemonMode)
		switch mode {
		case config.DaemonModeNone:
			d.mode = fs.NoneInstance
		case config.DaemonModeShared, config.DaemonModeSingle:
			d.mode = fs.SingleInstance
		case config.DaemonModeMultiple:
			fallthrough
		default:
			d.mode = fs.MultiInstance
		}
		return nil
	}
}
