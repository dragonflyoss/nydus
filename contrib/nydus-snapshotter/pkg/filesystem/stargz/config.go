/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package stargz

import (
	"errors"

	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/filesystem/meta"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/filesystem/nydus"
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

func WithNydusImageBinaryPath(p string) NewFSOpt {
	return func(d *filesystem) error {
		if p == "" {
			return errors.New("nydus image binary path is required")
		}
		d.nydusdImageBinaryPath = p
		return nil
	}
}

func WithDaemonConfig(cfg nydus.DaemonConfig) NewFSOpt {
	return func(d *filesystem) error {
		if (nydus.DaemonConfig{}) == cfg {
			return errors.New("daemon config is empty")
		}
		d.daemonCfg = cfg
		return nil
	}
}

type NewFSOpt func(d *filesystem) error

