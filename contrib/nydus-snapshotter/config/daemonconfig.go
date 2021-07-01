/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"fmt"

	"encoding/json"
	"io/ioutil"

	"github.com/pkg/errors"

	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/auth"
	"github.com/dragonflyoss/image-service/contrib/nydus-snapshotter/pkg/utils/registry"
)

const (
	backendTypeLocalfs  = "localfs"
	backendTypeOss      = "oss"
	backendTypeRegistry = "registry"
)

type DaemonConfig struct {
	Device         DeviceConfig `json:"device"`
	Mode           string       `json:"mode"`
	DigestValidate bool         `json:"digest_validate"`
	IOStatsFiles   bool         `json:"iostats_files,omitempty"`
	EnableXattr    bool         `json:"enable_xattr,omitempty"`
	FSPrefetch     struct {
		Enable       bool `json:"enable"`
		ThreadsCount int  `json:"threads_count"`
		MergingSize  int  `json:"merging_size"`
	} `json:"fs_prefetch,omitempty"`
}

type DeviceConfig struct {
	Backend struct {
		BackendType string `json:"type"`
		Config      struct {
			// Localfs backend configs
			BlobFile      string `json:"blob_file,omitempty"`
			Dir           string `json:"dir,omitempty"`
			ReadAhead     bool   `json:"readahead"`
			ReadAheadSec  int    `json:"readahead_sec,omitempty"`

			// Registry backend configs
			Host          string `json:"host,omitempty"`
			Repo          string `json:"repo,omitempty"`
			Auth          string `json:"auth,omitempty"`
			RegistryToken string `json:"registry_token,omitempty"`
			BlobUrlScheme string `json:"blob_url_scheme,omitempty"`

			// OSS backend configs
			EndPoint        string `json:"endpoint,omitempty"`
			AccessKeyId     string `json:"access_key_id,omitempty"`
			AccessKeySecret string `json:"access_key_secret,omitempty"`
			BucketName      string `json:"bucket_name,omitempty"`
			ObjectPrefix    string `json:"object_prefix,omitempty"`

			// Shared by registry and oss backend
			Scheme        string `json:"scheme,omitempty"`

			// Below configs are common configs shared by all backends
			Proxy         struct {
				URL           string `json:"url,omitempty"`
				Fallback      bool   `json:"fallback"`
				PingURL       string `json:"ping_url,omitempty"`
				CheckInterval int    `json:"check_interval,omitempty"`
			} `json:"proxy,omitempty"`
			Timeout        int `json:"timeout,omitempty"`
			ConnectTimeout int `json:"connect_timeout,omitempty"`
			RetryLimit     int `json:"retry_limit,omitempty"`
		} `json:"config"`
	} `json:"backend"`
	Cache struct {
		CacheType  string `json:"type"`
		Compressed bool   `json:"compressed,omitempty"`
		Config     struct {
			WorkDir string `json:"work_dir"`
		} `json:"config"`
	} `json:"cache"`
}

func LoadConfig(configFile string, cfg *DaemonConfig) error {
	b, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return err
	}
	return nil
}

func SaveConfig(c DaemonConfig, configFile string) error {
	b, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	return ioutil.WriteFile(configFile, b, 0755)
}

func NewDaemonConfig(cfg DaemonConfig, imageID string, vpcRegistry bool, labels map[string]string) (DaemonConfig, error) {
	image, err := registry.ParseImage(imageID)
	if err != nil {
		return DaemonConfig{}, errors.Wrapf(err, "failed to parse image %s", imageID)
	}

	switch backend := cfg.Device.Backend.BackendType; backend {
	case backendTypeRegistry:
		registryHost := image.Host
		if vpcRegistry {
			registryHost = registry.ConvertToVPCHost(registryHost)
		}
		keyChain := auth.FromLabels(labels)
		if keyChain.TokenBase() {
			cfg.Device.Backend.Config.RegistryToken = keyChain.Password
		} else {
			cfg.Device.Backend.Config.Auth = keyChain.ToBase64()
		}
		cfg.Device.Backend.Config.Host = registryHost
		cfg.Device.Backend.Config.Repo = image.Repo
	// Localfs and OSS backends don't need any update, just use the provided config in template
	case backendTypeLocalfs:
	case backendTypeOss:
	default:
		return DaemonConfig{}, errors.New(fmt.Sprintf("unknown backend type %s", backend))
	}

	return cfg, nil
}
