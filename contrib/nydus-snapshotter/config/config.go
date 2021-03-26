/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/filesystem/nydus"
	"github.com/pkg/errors"
)

const (
	defaultNydusDaemonConfigPath string = "/etc/nydus/config.json"
	defaultNydusdBinaryPath      string = "/usr/local/bin/nydusd"
)

type Config struct {
	Address              string             `toml:"-"`
	ConvertVpcRegistry   bool               `toml:"-"`
	DaemonCfgPath        string             `toml:"daemon_cfg_path"`
	DaemonCfg            nydus.DaemonConfig `toml:"-"`
	PublicKeyFile        string             `toml:"-"`
	RootDir              string             `toml:"-"`
	ValidateSignature    bool               `toml:"validate_signature"`
	NydusdBinaryPath     string             `toml:"nydusd_binary_path"`
	NydusImageBinaryPath string             `toml:"-"`
	SharedDaemon         bool               `toml:"shared_daemon"`
	AsyncRemove          bool               `toml:"async_remove"`
	EnableMetrics        bool               `toml:"enable_metrics"`
}

func (c *Config) FillupWithDefaults() error {
	if c.DaemonCfgPath == "" {
		c.DaemonCfgPath = defaultNydusDaemonConfigPath
	}

	if c.NydusdBinaryPath == "" {
		c.NydusdBinaryPath = defaultNydusdBinaryPath
	}

	var daemonCfg nydus.DaemonConfig
	if err := nydus.LoadConfig(c.DaemonCfgPath, &daemonCfg); err != nil {
		return errors.Wrapf(err, "failed to load config file %q", c.DaemonCfgPath)
	}
	c.DaemonCfg = daemonCfg

	return nil
}
