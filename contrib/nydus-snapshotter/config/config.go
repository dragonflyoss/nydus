/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"github.com/pkg/errors"
)

const (
	defaultNydusDaemonConfigPath string = "/etc/nydus/config.json"
	defaultNydusdBinaryPath      string = "/usr/local/bin/nydusd"
	defaultNydusImageBinaryPath  string = "/usr/local/bin/nydus-image"
)

type Config struct {
	Address              string             `toml:"-"`
	ConvertVpcRegistry   bool               `toml:"-"`
	DaemonCfgPath        string             `toml:"daemon_cfg_path"`
	DaemonCfg            DaemonConfig       `toml:"-"`
	PublicKeyFile        string             `toml:"-"`
	RootDir              string             `toml:"-"`
	ValidateSignature    bool               `toml:"validate_signature"`
	NydusdBinaryPath     string             `toml:"nydusd_binary_path"`
	NydusImageBinaryPath string             `toml:"nydus_image_binary"`
	DaemonMode           string             `toml:"daemon_mode"`
	AsyncRemove          bool               `toml:"async_remove"`
	EnableMetrics        bool               `toml:"enable_metrics"`
	MetricsFile          string             `toml:"metrics_file"`
	EnableStargz         bool               `toml:"enable_stargz"`
}

func (c *Config) FillupWithDefaults() error {
	if c.DaemonCfgPath == "" {
		c.DaemonCfgPath = defaultNydusDaemonConfigPath
	}

	if c.NydusdBinaryPath == "" {
		c.NydusdBinaryPath = defaultNydusdBinaryPath
	}

	if c.NydusImageBinaryPath == "" {
		c.NydusImageBinaryPath = defaultNydusImageBinaryPath
	}

	if c.DaemonMode == "" {
		c.DaemonMode = "multiple"
	}

	var daemonCfg DaemonConfig
	if err := LoadConfig(c.DaemonCfgPath, &daemonCfg); err != nil {
		return errors.Wrapf(err, "failed to load config file %q", c.DaemonCfgPath)
	}
	c.DaemonCfg = daemonCfg

	return nil
}
