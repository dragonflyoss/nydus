/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
)

func TestInstaller_nydusBinaryVersion(t *testing.T) {
	tests := []struct {
		name   string
		script string
		expect func(t *testing.T, version string, err error)
	}{
		{
			name:   "version the image's nydus prints",
			script: fmt.Sprintf(mockNydusScript, "3.0.0"),
			expect: func(t *testing.T, version string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("3.0.0", version)
			},
		},
		{
			name:   "prerelease version with build metadata",
			script: fmt.Sprintf(mockNydusScript, "3.0.0-beta.3+build.1"),
			expect: func(t *testing.T, version string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("3.0.0-beta.3+build.1", version)
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
			name:   "version that is no semantic version",
			script: fmt.Sprintf(mockNydusScript, "../current"),
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
			if !testRoot {
				t.Skip("needs root for a root filesystem of its own")
			}

			assert.NoError(t, os.RemoveAll(nydusBinary))
			if tc.script != "" {
				assert.NoError(t, os.WriteFile(nydusBinary, []byte(tc.script), 0o755))
			}

			i, err := New(config.New(), config.DefaultPath, nil)
			if err != nil {
				t.Fatal(err)
			}

			version, err := i.nydusBinaryVersion(t.Context())
			tc.expect(t, version, err)
		})
	}
}

func TestInstaller_switchNydusBinaryVersion(t *testing.T) {
	tests := []struct {
		name    string
		binary  string
		prepare func(t *testing.T, versionsDir, link string)
		expect  func(t *testing.T, versionsDir, link string, err error)
	}{
		{
			name:    "link the binary to the first version",
			prepare: func(t *testing.T, versionsDir, link string) {},
			expect: func(t *testing.T, versionsDir, link string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				target, err := os.Readlink(link)
				assert.NoError(err)
				assert.Equal(mockNydusTarget, target)
			},
		},
		{
			name:    "link a binary at another path",
			binary:  "/usr/local/bin/nydus",
			prepare: func(t *testing.T, versionsDir, link string) {},
			expect: func(t *testing.T, versionsDir, link string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(filepath.Join(hostRootMount, "usr/local/bin/nydus"), link)
				target, err := os.Readlink(link)
				assert.NoError(err)
				assert.Equal(mockNydusTarget, target)
			},
		},
		{
			name: "keep a link to the version",
			prepare: func(t *testing.T, versionsDir, link string) {
				assert.NoError(t, os.MkdirAll(filepath.Dir(link), 0o755))
				assert.NoError(t, os.Symlink(mockNydusTarget, link))
				assert.NoError(t, os.Mkdir(filepath.Join(versionsDir, "3.0.0-old"), 0o755))
			},
			expect: func(t *testing.T, versionsDir, link string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.DirExists(filepath.Join(versionsDir, "3.0.0-old"))
			},
		},
		{
			name: "keep the previous version and remove older ones",
			prepare: func(t *testing.T, versionsDir, link string) {
				for _, version := range []string{"3.0.0-older", "3.0.0-previous"} {
					assert.NoError(t, os.Mkdir(filepath.Join(versionsDir, version), 0o755))
				}

				assert.NoError(t, os.MkdirAll(filepath.Dir(link), 0o755))
				assert.NoError(t, os.Symlink(nydusBinaryVersionsDir+"/3.0.0-previous/nydus", link))
			},
			expect: func(t *testing.T, versionsDir, link string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				target, err := os.Readlink(link)
				assert.NoError(err)
				assert.Equal(mockNydusTarget, target)
				assert.DirExists(filepath.Join(versionsDir, "3.0.0-previous"))
				assert.NoDirExists(filepath.Join(versionsDir, "3.0.0-older"))
			},
		},
		{
			name: "keep what is no version directory",
			prepare: func(t *testing.T, versionsDir, link string) {
				assert.NoError(t, os.Mkdir(filepath.Join(versionsDir, ".cache"), 0o755))
				assert.NoError(t, os.WriteFile(filepath.Join(versionsDir, "3.0.0-file"), []byte("no directory"), 0o644))
			},
			expect: func(t *testing.T, versionsDir, link string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.DirExists(filepath.Join(versionsDir, ".cache"))
				assert.FileExists(filepath.Join(versionsDir, "3.0.0-file"))
			},
		},
		{
			name: "replace the temporary link of a switch that died",
			prepare: func(t *testing.T, versionsDir, link string) {
				assert.NoError(t, os.MkdirAll(filepath.Dir(link), 0o755))
				assert.NoError(t, os.Symlink("3.0.0-died", link+temporarySuffix))
			},
			expect: func(t *testing.T, versionsDir, link string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				target, err := os.Readlink(link)
				assert.NoError(err)
				assert.Equal(mockNydusTarget, target)
				assert.NoFileExists(link + temporarySuffix)
			},
		},
		{
			name: "replace a binary that is no link",
			prepare: func(t *testing.T, versionsDir, link string) {
				assert.NoError(t, os.MkdirAll(filepath.Dir(link), 0o755))
				assert.NoError(t, os.WriteFile(link, []byte("nydus"), 0o755))
			},
			expect: func(t *testing.T, versionsDir, link string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				target, err := os.Readlink(link)
				assert.NoError(err)
				assert.Equal(mockNydusTarget, target)
			},
		},
		{
			name: "binary path held by a directory",
			prepare: func(t *testing.T, versionsDir, link string) {
				assert.NoError(t, os.MkdirAll(link, 0o755))
			},
			expect: func(t *testing.T, versionsDir, link string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "rename "+link+temporarySuffix)
				assert.DirExists(link)
			},
		},
		{
			name: "host path that cannot be resolved",
			prepare: func(t *testing.T, versionsDir, link string) {
				assert.NoError(t, os.RemoveAll(filepath.Join(hostRootMount, "opt")))
				assert.NoError(t, os.Symlink("opt", filepath.Join(hostRootMount, "opt")))
			},
			expect: func(t *testing.T, versionsDir, link string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve host path")
			},
		},
		{
			name: "temporary name held by a directory",
			prepare: func(t *testing.T, versionsDir, link string) {
				assert.NoError(t, os.MkdirAll(filepath.Join(link+temporarySuffix, "busy"), 0o755))
			},
			expect: func(t *testing.T, versionsDir, link string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "remove "+link+temporarySuffix)
				assert.NoFileExists(link)
			},
		},
		{
			name: "directory of the binary that cannot be created",
			prepare: func(t *testing.T, versionsDir, link string) {
				assert.NoError(t, os.MkdirAll(filepath.Dir(filepath.Dir(link)), 0o755))
				assert.NoError(t, os.WriteFile(filepath.Dir(link), nil, 0o644))
			},
			expect: func(t *testing.T, versionsDir, link string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir of "+link)
			},
		},
		{
			name: "keep a version that cannot be removed",
			prepare: func(t *testing.T, versionsDir, link string) {
				assert.NoError(t, os.Mkdir(filepath.Join(versionsDir, "1.0.0"), 0o755))
				err := unix.Mount("tmpfs", filepath.Join(versionsDir, "1.0.0"), "tmpfs", 0, "")
				if errors.Is(err, unix.EPERM) {
					t.Skip("mounts with CAP_SYS_ADMIN")
				}

				if err != nil {
					t.Fatal(err)
				}

				t.Cleanup(func() { assert.NoError(t, unix.Unmount(filepath.Join(versionsDir, "1.0.0"), unix.MNT_DETACH)) })
			},
			expect: func(t *testing.T, versionsDir, link string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				target, err := os.Readlink(link)
				assert.NoError(err)
				assert.Equal(mockNydusTarget, target)
				assert.DirExists(filepath.Join(versionsDir, "1.0.0"))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !testRoot {
				t.Skip("needs root for a root filesystem of its own")
			}

			assert.NoError(t, os.RemoveAll(hostRootMount))
			cfg := config.New()
			cfg.Nydusd.Binary = cmp.Or(tc.binary, config.DefaultNydusdBinary)
			versionsDir, link := filepath.Join(hostRootMount, nydusBinaryVersionsDir), filepath.Join(hostRootMount, cfg.Nydusd.Binary)
			assert.NoError(t, os.MkdirAll(filepath.Join(versionsDir, mockVersion), 0o755))
			tc.prepare(t, versionsDir, link)

			i, err := New(cfg, config.DefaultPath, nil)
			if err != nil {
				t.Fatal(err)
			}

			tc.expect(t, versionsDir, link, i.switchNydusBinaryVersion(t.Context(), mockVersion))
		})
	}
}
