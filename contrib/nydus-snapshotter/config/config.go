/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"path/filepath"
	"time"

	"github.com/pkg/errors"
)

const (
	DefaultDaemonMode  string = "multiple"
	DaemonModeMultiple string = "multiple"
	DaemonModeShared   string = "shared"
	DaemonModeSingle   string = "single"
	DaemonModeNone     string = "none"
	defaultGCPeriod           = 24 * time.Hour

	defaultNydusDaemonConfigPath string = "/etc/nydus/config.json"
	defaultNydusdBinaryPath      string = "/usr/local/bin/nydusd"
	defaultNydusImageBinaryPath  string = "/usr/local/bin/nydus-image"
)

type Config struct {
	Address              string        `toml:"-"`
	ConvertVpcRegistry   bool          `toml:"-"`
	DaemonCfgPath        string        `toml:"daemon_cfg_path"`
	DaemonCfg            DaemonConfig  `toml:"-"`
	PublicKeyFile        string        `toml:"-"`
	RootDir              string        `toml:"-"`
	CacheDir             string        `toml:"cache_dir"`
	GCPeriod             time.Duration `toml:"gc_period"`
	ValidateSignature    bool          `toml:"validate_signature"`
	NydusdBinaryPath     string        `toml:"nydusd_binary_path"`
	NydusImageBinaryPath string        `toml:"nydus_image_binary"`
	DaemonMode           string        `toml:"daemon_mode"`
	AsyncRemove          bool          `toml:"async_remove"`
	EnableMetrics        bool          `toml:"enable_metrics"`
	MetricsFile          string        `toml:"metrics_file"`
	EnableStargz         bool          `toml:"enable_stargz"`
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
		c.DaemonMode = DefaultDaemonMode
	}

	if c.GCPeriod == 0 {
		c.GCPeriod = defaultGCPeriod
	}

	if len(c.CacheDir) == 0 {
		c.CacheDir = filepath.Join(c.RootDir, "cache")
	}
	var daemonCfg DaemonConfig
	if err := LoadConfig(c.DaemonCfgPath, &daemonCfg); err != nil {
		return errors.Wrapf(err, "failed to load config file %q", c.DaemonCfgPath)
	}
	c.DaemonCfg = daemonCfg
	return nil
}
