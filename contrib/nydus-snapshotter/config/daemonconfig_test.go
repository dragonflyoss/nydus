/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	buf := []byte(`{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "scheme": "https",
        "host": "acr-nydus-registry-vpc.cn-hangzhou.cr.aliyuncs.com",
        "repo": "test/myserver",
        "auth": "",
        "blob_url_scheme": "http",
        "proxy": {
          "url": "http://p2p-proxy:65001",
          "fallback": true,
          "ping_url": "http://p2p-proxy:40901/server/ping",
          "check_interval": 5
        },
        "timeout": 5,
        "connect_timeout": 5,
        "retry_limit": 0
      }
    },
    "cache": {
      "type": "blobcache",
      "config": {
        "work_dir": "/cache"
      }
    }
  },
  "mode": "direct",
  "digest_validate": true,
  "iostats_files": true,
  "enable_xattr": true,
  "fs_prefetch": {
    "enable": true,
    "threads_count": 10,
    "merging_size": 131072
  }
}`)
	var cfg DaemonConfig
	err := json.Unmarshal(buf, &cfg)
	require.Nil(t, err)
	require.Equal(t, cfg.FSPrefetch.Enable, true)
	require.Equal(t, cfg.FSPrefetch.MergingSize, 131072)
	require.Equal(t, cfg.FSPrefetch.ThreadsCount, 10)
	require.Equal(t, cfg.Device.Backend.Config.BlobUrlScheme, "http")
	require.Equal(t, cfg.Device.Backend.Config.Proxy.CheckInterval, 5)
}
