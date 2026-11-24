/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/util/testutil"
)

func TestInstaller_nydusVersion(t *testing.T) {
	tests := []struct {
		name   string
		script string
		expect func(t *testing.T, version string, err error)
	}{
		{
			name:   "version the payload's nydus prints",
			script: nydusScript("3.0.0"),
			expect: func(t *testing.T, version string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("3.0.0", version)
			},
		},
		{
			name:   "prerelease version with build metadata",
			script: nydusScript("3.0.0-beta.3+build_1"),
			expect: func(t *testing.T, version string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("3.0.0-beta.3+build_1", version)
			},
		},
		{
			name:   "output without a version",
			script: "#!/bin/sh\necho nydus\n",
			expect: func(t *testing.T, version string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unexpected")
				assert.Empty(version)
			},
		},
		{
			name:   "version that is no directory name",
			script: nydusScript("../current"),
			expect: func(t *testing.T, version string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unexpected")
				assert.Empty(version)
			},
		},
		{
			name:   "binary that fails",
			script: "#!/bin/sh\nexit 1\n",
			expect: func(t *testing.T, version string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "--version")
				assert.Empty(version)
			},
		},
		{
			name: "missing binary",
			expect: func(t *testing.T, version string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.Empty(version)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newConfig(t)
			if tc.script == "" {
				assert.NoError(t, os.Remove(filepath.Join(cfg.Installer.PayloadDir, payloadNydusBinary)))
			} else {
				writeFiles(t, cfg.Installer.PayloadDir, map[string]string{payloadNydusBinary: tc.script})
			}

			version, err := newInstaller(cfg, nil).nydusVersion(t.Context())
			tc.expect(t, version, err)
		})
	}
}

func TestInstaller_switchVersion(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, binDir string)
		expect  func(t *testing.T, binDir string, err error)
	}{
		{
			name:    "point current at the first version",
			prepare: func(t *testing.T, binDir string) {},
			expect: func(t *testing.T, binDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				target, err := os.Readlink(filepath.Join(binDir, "current"))
				assert.NoError(err)
				assert.Equal(mockVersion, target)
			},
		},
		{
			name: "keep a link that points at the version",
			prepare: func(t *testing.T, binDir string) {
				assert.NoError(t, os.Symlink(mockVersion, filepath.Join(binDir, "current")))
				assert.NoError(t, os.Mkdir(filepath.Join(binDir, "3.0.0-old"), 0o755))
			},
			expect: func(t *testing.T, binDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.DirExists(filepath.Join(binDir, "3.0.0-old"))
			},
		},
		{
			name: "keep the previous version and remove older ones",
			prepare: func(t *testing.T, binDir string) {
				for _, version := range []string{"3.0.0-older", "3.0.0-previous"} {
					assert.NoError(t, os.Mkdir(filepath.Join(binDir, version), 0o755))
				}

				assert.NoError(t, os.Symlink("3.0.0-previous", filepath.Join(binDir, "current")))
			},
			expect: func(t *testing.T, binDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				target, err := os.Readlink(filepath.Join(binDir, "current"))
				assert.NoError(err)
				assert.Equal(mockVersion, target)
				assert.DirExists(filepath.Join(binDir, "3.0.0-previous"))
				assert.NoDirExists(filepath.Join(binDir, "3.0.0-older"))
			},
		},
		{
			name: "keep what is no version directory",
			prepare: func(t *testing.T, binDir string) {
				assert.NoError(t, os.Mkdir(filepath.Join(binDir, ".cache"), 0o755))
				writeFiles(t, binDir, map[string]string{"3.0.0-file": "no directory"})
			},
			expect: func(t *testing.T, binDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.DirExists(filepath.Join(binDir, ".cache"))
				assert.FileExists(filepath.Join(binDir, "3.0.0-file"))
			},
		},
		{
			name: "replace the temporary link of a switch that died",
			prepare: func(t *testing.T, binDir string) {
				assert.NoError(t, os.Symlink("3.0.0-died", filepath.Join(binDir, "current"+temporarySuffix)))
			},
			expect: func(t *testing.T, binDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				target, err := os.Readlink(filepath.Join(binDir, "current"))
				assert.NoError(err)
				assert.Equal(mockVersion, target)
				assert.NoFileExists(filepath.Join(binDir, "current"+temporarySuffix))
			},
		},
		{
			name: "current that is no link",
			prepare: func(t *testing.T, binDir string) {
				assert.NoError(t, os.Mkdir(filepath.Join(binDir, "current"), 0o755))
			},
			expect: func(t *testing.T, binDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read "+filepath.Join(binDir, "current"))
				assert.DirExists(filepath.Join(binDir, "current"))
			},
		},
		{
			name: "host path that cannot be resolved",
			prepare: func(t *testing.T, binDir string) {
				assert.NoError(t, os.RemoveAll(binDir))
				assert.NoError(t, os.Symlink(filepath.Base(binDir), binDir))
			},
			expect: func(t *testing.T, binDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve host path")
			},
		},
		{
			name: "temporary name held by a directory",
			prepare: func(t *testing.T, binDir string) {
				assert.NoError(t, os.MkdirAll(filepath.Join(binDir, "current"+temporarySuffix, "busy"), 0o755))
			},
			expect: func(t *testing.T, binDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "remove "+filepath.Join(binDir, "current"+temporarySuffix))
				assert.NoFileExists(filepath.Join(binDir, "current"))
			},
		},
		{
			name: "missing bin directory",
			prepare: func(t *testing.T, binDir string) {
				assert.NoError(t, os.RemoveAll(binDir))
			},
			expect: func(t *testing.T, binDir string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create symlink "+filepath.Join(binDir, "current"+temporarySuffix))
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
		{
			name: "keep a version that cannot be removed",
			prepare: func(t *testing.T, binDir string) {
				testutil.MountTmpfs(t, filepath.Join(binDir, "1.0.0"), "")
			},
			expect: func(t *testing.T, binDir string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				target, err := os.Readlink(filepath.Join(binDir, "current"))
				assert.NoError(err)
				assert.Equal(mockVersion, target)
				assert.DirExists(filepath.Join(binDir, "1.0.0"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newConfig(t)
			binDir := filepath.Dir(hostPath(t, cfg, filepath.Dir(config.DefaultNydusdBinary)))
			assert.NoError(t, os.MkdirAll(filepath.Join(binDir, mockVersion), 0o755))
			tc.prepare(t, binDir)
			tc.expect(t, binDir, newInstaller(cfg, nil).switchVersion(t.Context(), mockVersion))
		})
	}
}
