/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
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
			file: &file{perm: 0o755, src: "testdata/source"},
			prepare: func(t *testing.T, target string) {
				assert.NoError(t, os.WriteFile(target, []byte("source\n"), 0o755))
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
				assert.ErrorContains(err, "read source")
				assert.ErrorIs(err, unix.EISDIR)
				assert.False(installed)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target := filepath.Join(t.TempDir(), "file")
			tc.prepare(t, target)

			installed, err := tc.file.installed(target)
			tc.expect(t, installed, err)
		})
	}
}

func TestFile_write(t *testing.T) {
	tests := []struct {
		name    string
		file    *file
		tmpfs   string
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
				data, err := os.ReadFile(target)
				assert.NoError(err)
				assert.Equal("data", string(data))
				info, err := os.Stat(target)
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o644), info.Mode())
				}
			},
		},
		{
			name:    "copy the source file",
			file:    &file{perm: 0o755, src: "testdata/source"},
			prepare: func(t *testing.T, target string) {},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(target)
				assert.NoError(err)
				assert.Equal("source\n", string(data))
				info, err := os.Stat(target)
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o755), info.Mode())
				}
			},
		},
		{
			name: "replace a file with another mode",
			file: &file{perm: 0o600, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				assert.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
				assert.NoError(t, os.WriteFile(target, []byte("previous"), 0o755))
			},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(target)
				assert.NoError(err)
				assert.Equal("data", string(data))
				info, err := os.Stat(target)
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o600), info.Mode())
				}
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
				data, err := os.ReadFile(target)
				assert.NoError(err)
				assert.Equal("data", string(data))
				info, err := os.Stat(target)
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o644), info.Mode())
				}
			},
		},
		{
			name: "replace the temporary file of a write that died",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				assert.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
				assert.NoError(t, os.WriteFile(target+temporarySuffix, []byte("a partial write longer than the data"), 0o755))
			},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(target)
				assert.NoError(err)
				assert.Equal("data", string(data))
				info, err := os.Stat(target)
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o644), info.Mode())
				}

				entries, err := os.ReadDir(filepath.Dir(target))
				assert.NoError(err)
				assert.Len(entries, 1)
			},
		},
		{
			name: "write through no link left under the temporary name",
			file: &file{perm: 0o644, data: []byte("data")},
			prepare: func(t *testing.T, target string) {
				assert.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
				assert.NoError(t, os.WriteFile(filepath.Join(filepath.Dir(target), "other"), []byte("other"), 0o755))
				assert.NoError(t, os.Symlink("other", target+temporarySuffix))
			},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(target)
				assert.NoError(err)
				assert.Equal("data", string(data))
				info, err := os.Stat(target)
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o644), info.Mode())
				}

				other, err := os.ReadFile(filepath.Join(filepath.Dir(target), "other"))
				assert.NoError(err)
				assert.Equal("other", string(other))
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
			name:    "file system without a free inode",
			file:    &file{perm: 0o644, data: []byte("data")},
			tmpfs:   "nr_inodes=1",
			prepare: func(t *testing.T, target string) {},
			expect: func(t *testing.T, target string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "write "+target)
				assert.ErrorIs(err, unix.ENOSPC)
				assert.NoFileExists(target)
			},
		},
		{
			name:    "leave no temporary file when the file system is full",
			file:    &file{perm: 0o644, data: make([]byte, 1<<20)},
			tmpfs:   "size=4k",
			prepare: func(t *testing.T, target string) {},
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
			if tc.tmpfs != "" {
				if os.Geteuid() != 0 {
					t.Skip("mounts as root")
				}

				assert.NoError(t, os.MkdirAll(filepath.Dir(target), 0o755))
				err := unix.Mount("tmpfs", filepath.Dir(target), "tmpfs", 0, tc.tmpfs)
				if errors.Is(err, unix.EPERM) {
					t.Skip("mounts with CAP_SYS_ADMIN")
				}

				if err != nil {
					t.Fatal(err)
				}

				t.Cleanup(func() { assert.NoError(t, unix.Unmount(filepath.Dir(target), unix.MNT_DETACH)) })
			}

			tc.prepare(t, target)
			tc.expect(t, target, tc.file.write(target))
		})
	}
}

func TestInstaller_syncConfig(t *testing.T) {
	tests := []struct {
		name   string
		update map[string]string
		expect func(t *testing.T, previous os.FileInfo, err error)
	}{
		{
			name:   "copy a changed config without restarting",
			update: map[string]string{config.DefaultPath: "cgroup:\n  memory_max: \"4GiB\"\n"},
			expect: func(t *testing.T, previous os.FileInfo, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				for path, file := range map[string]fstest.MapFile{
					config.DefaultPath:  {Data: []byte("cgroup:\n  memory_max: \"4GiB\"\n"), Mode: 0o644},
					restartRequiredFile: {Data: []byte{}, Mode: 0o644},
				} {
					data, err := os.ReadFile(filepath.Join(hostRootMount, path))
					assert.NoError(err)
					assert.Equal(string(file.Data), string(data))
					info, err := os.Stat(filepath.Join(hostRootMount, path))
					if assert.NoError(err) {
						assert.Equal(file.Mode, info.Mode())
					}
				}
			},
		},
		{
			name:   "copy a changed hosts.toml without a pending restart",
			update: map[string]string{mockHostsPath: mockMirrorHostsTOML},
			expect: func(t *testing.T, previous os.FileInfo, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(filepath.Join(hostRootMount, mockHostsPath))
				assert.NoError(err)
				assert.Equal(mockMirrorHostsTOML, string(data))
				info, err := os.Stat(filepath.Join(hostRootMount, mockHostsPath))
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o644), info.Mode())
				}

				assert.NoFileExists(filepath.Join(hostRootMount, restartRequiredFile))
			},
		},
		{
			name: "copy nothing when the config is unchanged",
			expect: func(t *testing.T, previous os.FileInfo, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				current, err := os.Stat(filepath.Join(hostRootMount, config.DefaultPath))
				assert.NoError(err)
				assert.True(os.SameFile(previous, current))
				assert.NoFileExists(filepath.Join(hostRootMount, restartRequiredFile))
			},
		},
		{
			name:   "keep the host config when the new one is invalid",
			update: map[string]string{config.DefaultPath: mockInvalidConfig},
			expect: func(t *testing.T, previous os.FileInfo, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid log.level")
				expected, err := os.ReadFile("../../deploy/nydus-snapshotter/config.yaml")
				assert.NoError(err)
				data, err := os.ReadFile(filepath.Join(hostRootMount, config.DefaultPath))
				assert.NoError(err)
				assert.Equal(string(expected), string(data))
				info, err := os.Stat(filepath.Join(hostRootMount, config.DefaultPath))
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o644), info.Mode())
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if os.Getuid() != 0 {
				t.Skip("needs root for a root filesystem of its own")
			}

			for _, path := range mockResetPaths {
				assert.NoError(t, os.RemoveAll(path))
			}

			assert.NoError(t, os.MkdirAll(hostRootMount, 0o755))
			assert.NoError(t, os.CopyFS("/", mockImage))
			assert.NoError(t, os.CopyFS(unitDir, os.DirFS("../../deploy/systemd")))
			assert.NoError(t, os.CopyFS(filepath.Dir(config.DefaultPath), os.DirFS("../../deploy/nydus-snapshotter")))
			cfg := config.New()
			cfg.Installer.Registries.Enable = true

			ctl := gomock.NewController(t)
			defer ctl.Finish()
			mockSystemd := mocks.NewMockSystemd(ctl)
			mockSystemd.EXPECT().EnableUnitFiles(gomock.Any(), gomock.Any()).Return(nil).Times(1)
			mockSystemd.EXPECT().RestartUnit(gomock.Any(), gomock.Any()).Return(nil).Times(1)
			i, err := New(cfg, config.DefaultPath, mockSystemd)
			if err != nil {
				t.Fatal(err)
			}

			assert.NoError(t, i.install(t.Context()))
			for path, data := range tc.update {
				assert.NoError(t, os.WriteFile(path, []byte(data), 0o644))
			}

			previous, err := os.Stat(filepath.Join(hostRootMount, config.DefaultPath))
			assert.NoError(t, err)

			tc.expect(t, previous, i.syncConfig(t.Context()))
		})
	}
}

func TestInstaller_removeRestartRequiredFile(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T)
		expect  func(t *testing.T, err error)
	}{
		{
			name: "remove the restart-required file",
			prepare: func(t *testing.T) {
				assert.NoError(t, os.MkdirAll(filepath.Join(hostRootMount, filepath.Dir(restartRequiredFile)), 0o755))
				assert.NoError(t, os.WriteFile(filepath.Join(hostRootMount, restartRequiredFile), nil, 0o644))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(filepath.Join(hostRootMount, restartRequiredFile))
			},
		},
		{
			name:    "nothing pending",
			prepare: func(t *testing.T) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "restart-required file that cannot be removed",
			prepare: func(t *testing.T) {
				assert.NoError(t, os.MkdirAll(filepath.Join(hostRootMount, restartRequiredFile, "busy"), 0o755))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "remove "+filepath.Join(hostRootMount, restartRequiredFile))
			},
		},
		{
			name: "host path that cannot be resolved",
			prepare: func(t *testing.T) {
				assert.NoError(t, os.Symlink("run", filepath.Join(hostRootMount, "run")))
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve host path "+restartRequiredFile)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if os.Getuid() != 0 {
				t.Skip("needs root for a root filesystem of its own")
			}

			assert.NoError(t, os.RemoveAll(hostRootMount))
			assert.NoError(t, os.MkdirAll(hostRootMount, 0o755))
			tc.prepare(t)

			i, err := New(config.New(), config.DefaultPath, nil)
			if err != nil {
				t.Fatal(err)
			}

			tc.expect(t, i.removeRestartRequiredFile())
		})
	}
}
