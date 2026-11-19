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
	"go.uber.org/mock/gomock"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/util/testutil"
)

func TestFile_installed(t *testing.T) {
	tests := []struct {
		name    string
		file    *file
		prepare func(t *testing.T, target string)
		expect  func(t *testing.T, installed bool, err error)
	}{
		{
			name: "file holding the content with the mode",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				assert.NoError(t, os.WriteFile(target, []byte("data"), 0o644))
				assert.NoError(t, os.Chmod(target, 0o644))
			},
			expect: func(t *testing.T, installed bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(installed)
			},
		},
		{
			name: "file holding the content of the source file",
			file: &file{perm: 0o755, src: "testdata/payload"},
			prepare: func(t *testing.T, target string) {
				assert.NoError(t, os.WriteFile(target, []byte("payload\n"), 0o755))
				assert.NoError(t, os.Chmod(target, 0o755))
			},
			expect: func(t *testing.T, installed bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(installed)
			},
		},
		{
			name: "file holding other content",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				assert.NoError(t, os.WriteFile(target, []byte("atad"), 0o644))
			},
			expect: func(t *testing.T, installed bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(installed)
			},
		},
		{
			name: "file with another mode",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				assert.NoError(t, os.WriteFile(target, []byte("data"), 0o600))
			},
			expect: func(t *testing.T, installed bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(installed)
			},
		},
		{
			name: "directory in place of the file",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				assert.NoError(t, os.Mkdir(target, 0o755))
			},
			expect: func(t *testing.T, installed bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(installed)
			},
		},
		{
			name:    "missing file",
			file:    &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {},
			expect: func(t *testing.T, installed bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(installed)
			},
		},
		{
			name:    "missing source file",
			file:    &file{perm: 0o644, src: "testdata/missing"},
			prepare: func(t *testing.T, target string) {},
			expect: func(t *testing.T, installed bool, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.False(installed)
			},
		},
		{
			name:    "source that cannot be read",
			file:    &file{perm: 0o644, src: "testdata"},
			prepare: func(t *testing.T, target string) {},
			expect: func(t *testing.T, installed bool, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read payload")
				assert.ErrorIs(err, unix.EISDIR)
				assert.False(installed)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "file")
			tc.prepare(t, target)

			tc.file.target = target
			installed, err := tc.file.installed()
			tc.expect(t, installed, err)
		})
	}
}

func TestFile_write(t *testing.T) {
	tests := []struct {
		name    string
		file    *file
		prepare func(t *testing.T, target string)
		expect  func(t *testing.T, target string, err error)
	}{
		{
			name:    "write a file and its directory",
			file:    &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, target, "data", 0o644)
			},
		},
		{
			name:    "copy the source file",
			file:    &file{perm: 0o755, src: "testdata/payload"},
			prepare: func(t *testing.T, target string) {},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, target, "payload\n", 0o755)
			},
		},
		{
			name: "replace a file with another mode",
			file: &file{perm: 0o600, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				writeFiles(t, filepath.Dir(target), map[string]string{filepath.Base(target): "previous"})
			},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, target, "data", 0o600)
			},
		},
		{
			name: "give the file its mode whatever the umask",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				umask := unix.Umask(0o077)
				t.Cleanup(func() { unix.Umask(umask) })
			},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, target, "data", 0o644)
			},
		},
		{
			name: "replace the temporary file of a write that died",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				writeFiles(t, filepath.Dir(target), map[string]string{filepath.Base(target) + temporarySuffix: "a partial write longer than the data"})
			},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, target, "data", 0o644)
				entries, err := os.ReadDir(filepath.Dir(target))
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
		{
			name: "write through no link left under the temporary name",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				writeFiles(t, filepath.Dir(target), map[string]string{"other": "other"})
				assert.NoError(t, os.Symlink("other", target+temporarySuffix))
			},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, target, "data", 0o644)
				assert.Equal("other", readFile(t, filepath.Join(filepath.Dir(target), "other")))
			},
		},
		{
			name: "leave no temporary file when the write fails",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				assert.NoError(t, os.MkdirAll(filepath.Join(target, "busy"), 0o755))
			},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write "+target)
				entries, err := os.ReadDir(filepath.Dir(target))
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
		{
			name:    "missing source file",
			file:    &file{perm: 0o644, src: "testdata/missing"},
			prepare: func(t *testing.T, target string) {},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.NoFileExists(target)
			},
		},
		{
			name: "directory that cannot be created",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				assert.NoError(t, os.WriteFile(filepath.Dir(target), nil, 0o644))
			},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir of "+target)
			},
		},
		{
			name: "temporary name held by a directory",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				assert.NoError(t, os.MkdirAll(filepath.Join(target+temporarySuffix, "busy"), 0o755))
			},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "remove "+target+temporarySuffix)
				assert.NoFileExists(target)
			},
		},
		{
			name:    "source that cannot be read",
			file:    &file{perm: 0o644, src: "testdata"},
			prepare: func(t *testing.T, target string) {},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write "+target)
				assert.ErrorIs(err, unix.EISDIR)
				assert.NoFileExists(target + temporarySuffix)
				assert.NoFileExists(target)
			},
		},
		{
			name: "file system without a free inode",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				testutil.MountTmpfs(t, filepath.Dir(target), "nr_inodes=1")
			},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write "+target)
				assert.ErrorIs(err, unix.ENOSPC)
				assert.NoFileExists(target)
			},
		},
		{
			name: "leave no temporary file when the file system is full",
			file: &file{perm: 0o644, data: make([]byte, 1<<20)},
			prepare: func(t *testing.T, target string) {
				testutil.MountTmpfs(t, filepath.Dir(target), "size=4k")
			},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write "+target)
				assert.ErrorIs(err, unix.ENOSPC)
				entries, err := os.ReadDir(filepath.Dir(target))
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "dir", "file")
			tc.prepare(t, target)
			tc.file.target = target
			tc.expect(t, target, tc.file.write())
		})
	}
}

func TestInstaller_syncConfig(t *testing.T) {
	tests := []struct {
		name   string
		update map[string]string
		expect func(t *testing.T, cfg *Config, previous os.FileInfo, err error)
	}{
		{
			name:   "copy a changed config without restarting",
			update: map[string]string{"config/config.yaml": "cgroup:\n  memory_max: \"4GiB\"\n"},
			expect: func(t *testing.T, cfg *Config, previous os.FileInfo, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, hostPath(t, cfg, config.DefaultPath), "cgroup:\n  memory_max: \"4GiB\"\n", 0o644)
				assertFile(t, hostPath(t, cfg, restartPending), mockServiceRestart, 0o644)
			},
		},
		{
			name:   "copy a changed hosts.toml without a pending restart",
			update: map[string]string{"config/certs.d/registry.example.com/hosts.toml": mockMirrorHostsTOML},
			expect: func(t *testing.T, cfg *Config, previous os.FileInfo, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, hostPath(t, cfg, config.DefaultRegistryConfigPath+"/registry.example.com/hosts.toml"), mockMirrorHostsTOML, 0o644)
				assert.NoFileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name: "copy nothing when the config is unchanged",
			expect: func(t *testing.T, cfg *Config, previous os.FileInfo, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				current, err := os.Stat(hostPath(t, cfg, config.DefaultPath))
				assert.NoError(err)
				assert.True(os.SameFile(previous, current))
				assert.NoFileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name:   "keep the host config when the new one is invalid",
			update: map[string]string{"config/config.yaml": mockInvalidConfig},
			expect: func(t *testing.T, cfg *Config, previous os.FileInfo, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid log.level")
				assertFile(t, hostPath(t, cfg, config.DefaultPath), readFile(t, "../../deploy/nydus-snapshotter/config.yaml"), 0o644)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newConfig(t)
			install(t, cfg)
			writeFiles(t, cfg.PayloadDir, tc.update)
			previous, err := os.Stat(hostPath(t, cfg, config.DefaultPath))
			assert.NoError(t, err)

			ctl := gomock.NewController(t)
			defer ctl.Finish()
			tc.expect(t, cfg, previous, New(cfg, mocks.NewMockManager(ctl)).syncConfig(t.Context()))
		})
	}
}

func TestInstaller_clearRestarts(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, cfg *Config)
		expect  func(t *testing.T, cfg *Config, err error)
	}{
		{
			name: "forget the pending units",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.HostRoot, map[string]string{restartPending: mockServiceRestart})
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name:    "nothing pending",
			prepare: func(t *testing.T, cfg *Config) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "marker that cannot be removed",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.MkdirAll(filepath.Join(hostPath(t, cfg, restartPending), "busy"), 0o755))
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "remove "+hostPath(t, cfg, restartPending))
			},
		},
		{
			name: "host path that cannot be resolved",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.Symlink("run", filepath.Join(cfg.HostRoot, "run")))
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve host path "+restartPending)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newConfig(t)
			tc.prepare(t, cfg)
			tc.expect(t, cfg, New(cfg, nil).clearRestarts())
		})
	}
}
