/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"errors"

	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/filesystem/meta"
	"gitlab.alipay-inc.com/antsys/nydus-snapshotter/pkg/signature"
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

func WithVerifier(verifier *signature.Verifier) NewFSOpt {
	return func(d *filesystem) error {
		d.verifier = verifier
		return nil
	}
}

func WithDaemonConfig(cfg DaemonConfig) NewFSOpt {
	return func(d *filesystem) error {
		if (DaemonConfig{}) == cfg {
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

func WithSharedDaemon(sharedDaemon bool) NewFSOpt {
	return func(d *filesystem) error {
		if sharedDaemon {
			d.mode = SingleInstance
		} else {
			d.mode = MultiInstance
		}
		return nil
	}
}
