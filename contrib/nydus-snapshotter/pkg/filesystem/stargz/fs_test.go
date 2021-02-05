/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package stargz

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"contrib/nydus-snapshotter/pkg/filesystem/meta"
	"contrib/nydus-snapshotter/pkg/filesystem/nydus"
	"contrib/nydus-snapshotter/pkg/label"
	"contrib/nydus-snapshotter/pkg/process"
)

func ensureExists(path string) error {
	_, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s not exists", path)
	}
	return nil
}

func Test_filesystem_createNewDaemon(t *testing.T) {
	snapshotRoot := "testdata/snapshot"
	err := os.MkdirAll(snapshotRoot, 0755)
	require.Nil(t, err)
	defer func() {
		_ = os.RemoveAll(snapshotRoot)
	}()
	f := filesystem{
		FileSystemMeta: meta.FileSystemMeta{
			RootDir: snapshotRoot,
		},
		manager: process.NewManager(process.Opt{
			NydusdBinaryPath: "",
		}),
		daemonCfg:   nydus.DaemonConfig{},
		resolver:    nil,
		vpcRegistry: false,
	}
	_, err = f.createNewDaemon("1", "example.com/test/testimage:0.1")
	require.Nil(t, err)
}

func Test_filesystem_generateDaemonConfig(t *testing.T) {
	snapshotRoot := "testdata/snapshot"
	err := os.MkdirAll(snapshotRoot, 0755)
	require.Nil(t, err)
	defer func() {
		_ = os.RemoveAll(snapshotRoot)
	}()

	content, err := ioutil.ReadFile("testdata/config/nydus.json")
	require.Nil(t, err)
	var cfg nydus.DaemonConfig
	err = json.Unmarshal(content, &cfg)
	require.Nil(t, err)
	f := filesystem{
		FileSystemMeta: meta.FileSystemMeta{
			RootDir: snapshotRoot,
		},
		manager: process.NewManager(process.Opt{
			NydusdBinaryPath: "",
		}),
		daemonCfg:   cfg,
		resolver:    nil,
		vpcRegistry: false,
	}
	d, err := f.createNewDaemon("1", "example.com/test/testimage:0.1")
	err = f.generateDaemonConfig(d, map[string]string{
		label.ImagePullUsername: "mock",
		label.ImagePullSecret:   "mock",
	})
	require.Nil(t, err)
	assert.Nil(t, ensureExists(filepath.Join(snapshotRoot, "config", d.ID, "config.json")))
	assert.Nil(t, ensureExists(filepath.Join(snapshotRoot, "cache")))
	assert.Nil(t, ensureExists(filepath.Join(snapshotRoot, "logs", d.ID)))
	assert.Nil(t, ensureExists(filepath.Join(snapshotRoot, "socket", d.ID)))
}
