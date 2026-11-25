/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

var (
	mockVersion          = "3.0.0-test"
	mockNydusTarget      = nydusBinaryVersionsDir + "/" + mockVersion + "/nydus"
	mockNydusScript      = "#!/bin/sh\necho 'nydus %s (1a2b3c4d5, 2026-01-02)'\n"
	mockHostsPath        = config.DefaultRegistryConfigPath + "/registry.example.com/hosts.toml"
	mockHostsTOML        = "server = \"https://registry.example.com\"\n"
	mockMirrorHostsTOML  = "server = \"https://mirror.example.com\"\n"
	mockToken            = "token"
	mockHostTokenPath    = "/run/nydus-snapshotter/kubernetes/token"
	mockCA               = "ca"
	mockKubeSecretConfig = "auth:\n  kube_secret:\n    enable: true\n"
	mockInvalidConfig    = "log:\n  level: loud\n"
	mockUnitPath         = filepath.Join(unitDir, nydusSnapshotterServiceUnit)
	mockResetPaths       = []string{hostRootMount, nydusBinary, nydusSnapshotterBinary, mockUnitPath, filepath.Dir(config.DefaultPath)}

	mockImage = fstest.MapFS{
		"usr/local/bin/nydus":                                           {Data: []byte(fmt.Sprintf(mockNydusScript, mockVersion)), Mode: 0o755},
		"usr/local/bin/nydus-snapshotter":                               {Data: []byte("nydus-snapshotter"), Mode: 0o755},
		"etc/nydus-snapshotter/certs.d/registry.example.com/hosts.toml": {Data: []byte(mockHostsTOML), Mode: 0o644},
	}

	mockServiceAccount = fstest.MapFS{
		"token":  {Data: []byte(mockToken), Mode: 0o600},
		"ca.crt": {Data: []byte(mockCA), Mode: 0o644},
	}
)

func TestMain(m *testing.M) {
	if os.Getuid() != 0 {
		os.Exit(m.Run())
	}

	flag.Parse()
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		dir, err := os.MkdirTemp("", "nydus-installer-")
		if err != nil {
			log.Fatal(err)
		}

		cmd := exec.Command("/proc/self/exe", append(os.Args[1:], dir)...)
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS}
		err = cmd.Run()
		_ = os.RemoveAll(dir)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}

		if err != nil {
			log.Fatal(err)
		}

		return
	}

	dir := flag.Arg(flag.NArg() - 1)
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	executable, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}

	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		log.Fatalf("mount tmpfs: %v", err)
	}

	upper, work, root := filepath.Join(dir, "upper"), filepath.Join(dir, "work"), filepath.Join(dir, "root")
	for _, path := range []string{upper, work, root} {
		if err := os.Mkdir(path, 0o755); err != nil {
			log.Fatal(err)
		}
	}

	if err := syscall.Mount("overlay", root, "overlay", 0, "lowerdir=/,upperdir="+upper+",workdir="+work); err != nil {
		log.Fatalf("mount overlay: %v", err)
	}

	for _, path := range []string{"/proc", "/dev", os.TempDir(), filepath.Dir(executable), filepath.Join(wd, "../..")} {
		target := filepath.Join(root, path)
		if err := os.MkdirAll(target, 0o755); err != nil {
			log.Fatal(err)
		}

		if err := syscall.Mount(path, target, "", syscall.MS_BIND, ""); err != nil {
			log.Fatalf("bind %s: %v", path, err)
		}
	}

	if err := syscall.Chroot(root); err != nil {
		log.Fatal(err)
	}

	if err := os.Chdir(wd); err != nil {
		log.Fatal(err)
	}

	os.Exit(m.Run())
}

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		nodeLabel bool
		nodeName  string
		host      string
		expect    func(t *testing.T, i *Installer, err error)
	}{
		{
			name: "installer without node label",
			expect: func(t *testing.T, i *Installer, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(config.DefaultPath, i.configPath)
				assert.Empty(i.nodeName)
				assert.Nil(i.kubeClient)
			},
		},
		{
			name:      "installer labeling the node of the pod",
			nodeLabel: true,
			nodeName:  mockNodeName,
			host:      "10.96.0.1",
			expect: func(t *testing.T, i *Installer, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockNodeName, i.nodeName)
				assert.NotNil(i.kubeClient)
			},
		},
		{
			name:      "node label without an api server",
			nodeLabel: true,
			nodeName:  mockNodeName,
			expect: func(t *testing.T, i *Installer, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.Nil(i)
			},
		},
		{
			name:      "node label without the node of the pod",
			nodeLabel: true,
			expect: func(t *testing.T, i *Installer, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "NODE_NAME must name the node when installer.node_label.enable is set")
				assert.Nil(i)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(NodeNameEnvVar, tc.nodeName)
			t.Setenv("KUBERNETES_SERVICE_HOST", tc.host)
			t.Setenv("KUBERNETES_SERVICE_PORT", "443")
			cfg := config.New()
			cfg.Installer.NodeLabel.Enable = tc.nodeLabel
			cfg.Installer.ServiceAccountPath = filepath.Join("testdata", "serviceaccount")

			i, err := New(cfg, config.DefaultPath, nil)
			tc.expect(t, i, err)
		})
	}
}

func TestInstaller_Run(t *testing.T) {
	tests := []struct {
		name       string
		files      map[string]string
		kubeSecret bool
		mock       func(t *testing.T, cfg *config.Config, m *mocks.MockSystemdMockRecorder, cancel context.CancelFunc)
		expect     func(t *testing.T, err error)
	}{
		{
			name: "install and sync until done",
			mock: func(t *testing.T, cfg *config.Config, m *mocks.MockSystemdMockRecorder, cancel context.CancelFunc) {
				gomock.InOrder(
					m.Ping(gomock.Any()).Return(nil).Times(1),
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Do(func(context.Context, string) { cancel() }).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(filepath.Join(hostRootMount, config.DefaultAuthKubeconfig))
				assert.FileExists(filepath.Join(hostRootMount, nydusSnapshotterBinary))
			},
		},
		{
			name:       "sync the kubeconfig with kube secret",
			files:      map[string]string{config.DefaultPath: mockKubeSecretConfig},
			kubeSecret: true,
			mock: func(t *testing.T, cfg *config.Config, m *mocks.MockSystemdMockRecorder, cancel context.CancelFunc) {
				gomock.InOrder(
					m.Ping(gomock.Any()).Return(nil).Times(1),
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Do(func(context.Context, string) { cancel() }).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(hostRootMount, config.DefaultAuthKubeconfig))
			},
		},
		{
			name:       "keep the token and the config in sync after the install",
			files:      map[string]string{config.DefaultPath: mockKubeSecretConfig},
			kubeSecret: true,
			mock: func(t *testing.T, cfg *config.Config, m *mocks.MockSystemdMockRecorder, cancel context.CancelFunc) {
				gomock.InOrder(
					m.Ping(gomock.Any()).Return(nil).Times(1),
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Do(func(context.Context, string) {
						assert.NoError(t, os.WriteFile(filepath.Join(cfg.Installer.ServiceAccountPath, "token"), []byte("rotated"), 0o600))
						assert.NoError(t, os.WriteFile(mockHostsPath, []byte(mockMirrorHostsTOML), 0o644))
						go func() {
							defer cancel()
							assert.Eventually(t, func() bool {
								token, tokenErr := os.ReadFile(filepath.Join(hostRootMount, mockHostTokenPath))
								hosts, hostsErr := os.ReadFile(filepath.Join(hostRootMount, mockHostsPath))
								return tokenErr == nil && hostsErr == nil && string(token) == "rotated" && string(hosts) == mockMirrorHostsTOML
							}, 5*time.Second, 10*time.Millisecond)
						}()
					}).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				for path, file := range map[string]fstest.MapFile{
					mockHostTokenPath: {Data: []byte("rotated"), Mode: 0o600},
					mockHostsPath:     {Data: []byte(mockMirrorHostsTOML), Mode: 0o644},
				} {
					data, err := os.ReadFile(filepath.Join(hostRootMount, path))
					assert.NoError(err)
					assert.Equal(string(file.Data), string(data))
					info, err := os.Stat(filepath.Join(hostRootMount, path))
					if assert.NoError(err) {
						assert.Equal(file.Mode, info.Mode())
					}
				}

				assert.NoFileExists(filepath.Join(hostRootMount, restartRequiredFile))
			},
		},
		{
			name:       "write nothing to a host whose systemd cannot be used",
			files:      map[string]string{config.DefaultPath: mockKubeSecretConfig},
			kubeSecret: true,
			mock: func(t *testing.T, cfg *config.Config, m *mocks.MockSystemdMockRecorder, cancel context.CancelFunc) {
				m.Ping(gomock.Any()).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				entries, err := os.ReadDir(hostRootMount)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:  "install that fails",
			files: map[string]string{nydusBinary: "#!/bin/sh\nexit 1\n"},
			mock: func(t *testing.T, cfg *config.Config, m *mocks.MockSystemdMockRecorder, cancel context.CancelFunc) {
				m.Ping(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.NoFileExists(filepath.Join(hostRootMount, nydusSnapshotterBinary))
			},
		},
		{
			name:       "keep the host as it is while a sync fails",
			files:      map[string]string{config.DefaultPath: mockKubeSecretConfig},
			kubeSecret: true,
			mock: func(t *testing.T, cfg *config.Config, m *mocks.MockSystemdMockRecorder, cancel context.CancelFunc) {
				gomock.InOrder(
					m.Ping(gomock.Any()).Return(nil).Times(1),
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Do(func(context.Context, string) {
						assert.NoError(t, os.WriteFile(config.DefaultPath, []byte(mockInvalidConfig), 0o644))
						assert.NoError(t, os.Remove(filepath.Join(cfg.Installer.ServiceAccountPath, "token")))
						go func() {
							defer cancel()
							assert.Never(t, func() bool {
								data, err := os.ReadFile(filepath.Join(hostRootMount, config.DefaultPath))
								return err != nil || string(data) != mockKubeSecretConfig
							}, 100*time.Millisecond, 10*time.Millisecond)
						}()
					}).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				for path, file := range map[string]fstest.MapFile{
					config.DefaultPath: {Data: []byte(mockKubeSecretConfig), Mode: 0o644},
					mockHostTokenPath:  {Data: []byte(mockToken), Mode: 0o600},
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
			name:       "credentials that cannot be synced",
			kubeSecret: true,
			mock: func(t *testing.T, cfg *config.Config, m *mocks.MockSystemdMockRecorder, cancel context.CancelFunc) {
				assert.NoError(t, os.Remove(filepath.Join(cfg.Installer.ServiceAccountPath, "token")))
				m.Ping(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read service account token")
				assert.NoFileExists(filepath.Join(hostRootMount, nydusSnapshotterBinary))
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
			for path, data := range tc.files {
				assert.NoError(t, os.WriteFile(path, []byte(data), 0o755))
			}

			t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
			t.Setenv("KUBERNETES_SERVICE_PORT", "443")
			cfg := config.New()
			cfg.Installer.ServiceAccountPath = t.TempDir()
			cfg.Installer.SyncInterval = config.Duration(10 * time.Millisecond)
			cfg.Installer.Registries.Enable = true
			cfg.Auth.KubeSecret.Enable = tc.kubeSecret
			assert.NoError(t, os.CopyFS(cfg.Installer.ServiceAccountPath, mockServiceAccount))

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			mockSystemd := mocks.NewMockSystemd(ctl)
			tc.mock(t, cfg, mockSystemd.EXPECT(), cancel)

			i, err := New(cfg, config.DefaultPath, mockSystemd)
			if err != nil {
				t.Fatal(err)
			}

			tc.expect(t, i.Run(ctx))
		})
	}
}

func TestInstaller_install(t *testing.T) {
	tests := []struct {
		name              string
		installedVersions []string
		prepare           func(t *testing.T, cfg *config.Config)
		mock              func(m *mocks.MockSystemdMockRecorder)
		expect            func(t *testing.T, err error)
	}{
		{
			name:    "install onto an empty host",
			prepare: func(t *testing.T, cfg *config.Config) {},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				for path, file := range map[string]struct {
					src  string
					perm os.FileMode
				}{
					nydusSnapshotterBinary: {src: nydusSnapshotterBinary, perm: 0o755},
					mockNydusTarget:        {src: nydusBinary, perm: 0o755},
					config.DefaultPath:     {src: "../../deploy/nydus-snapshotter/config.yaml", perm: 0o644},
					mockUnitPath:           {src: "../../deploy/systemd/" + nydusSnapshotterServiceUnit, perm: 0o644},
					mockHostsPath:          {src: mockHostsPath, perm: 0o644},
				} {
					expected, err := os.ReadFile(file.src)
					assert.NoError(err)
					data, err := os.ReadFile(filepath.Join(hostRootMount, path))
					assert.NoError(err)
					assert.Equal(string(expected), string(data))
					info, err := os.Stat(filepath.Join(hostRootMount, path))
					if assert.NoError(err) {
						assert.Equal(file.perm, info.Mode())
					}
				}

				link, err := os.Readlink(filepath.Join(hostRootMount, config.DefaultNydusdBinary))
				assert.NoError(err)
				assert.Equal(mockNydusTarget, link)
				assert.NoFileExists(filepath.Join(hostRootMount, restartRequiredFile))
				info, err := os.Stat(filepath.Join(hostRootMount, filepath.Dir(restartRequiredFile)))
				if assert.NoError(err) {
					assert.Equal(os.ModeDir|0o700, info.Mode())
				}
			},
		},
		{
			name:              "start the units of an unchanged host",
			installedVersions: []string{mockVersion},
			prepare:           func(t *testing.T, cfg *config.Config) {},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(filepath.Join(hostRootMount, restartRequiredFile))
			},
		},
		{
			name:              "restart the service when the config changes",
			installedVersions: []string{mockVersion},
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(config.DefaultPath, []byte("log:\n  level: \"debug\"\n"), 0o644))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(filepath.Join(hostRootMount, config.DefaultPath))
				assert.NoError(err)
				assert.Equal("log:\n  level: \"debug\"\n", string(data))
				info, err := os.Stat(filepath.Join(hostRootMount, config.DefaultPath))
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o644), info.Mode())
				}
			},
		},
		{
			name:              "switch to a new nydus version",
			installedVersions: []string{mockVersion},
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(nydusBinary, []byte(fmt.Sprintf(mockNydusScript, "3.0.1-test")), 0o755))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				link, err := os.Readlink(filepath.Join(hostRootMount, config.DefaultNydusdBinary))
				assert.NoError(err)
				assert.Equal(nydusBinaryVersionsDir+"/3.0.1-test/nydus", link)
				assert.FileExists(filepath.Join(hostRootMount, mockNydusTarget))
				assert.NoFileExists(filepath.Join(hostRootMount, config.DefaultNydusdBinary) + temporarySuffix)
			},
		},
		{
			name:              "prune versions older than the previous one",
			installedVersions: []string{mockVersion, "3.0.1-test"},
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(nydusBinary, []byte(fmt.Sprintf(mockNydusScript, "3.0.2-test")), 0o755))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(hostRootMount, nydusBinaryVersionsDir, "3.0.2-test/nydus"))
				assert.FileExists(filepath.Join(hostRootMount, nydusBinaryVersionsDir, "3.0.1-test/nydus"))
				assert.NoDirExists(filepath.Join(hostRootMount, nydusBinaryVersionsDir, mockVersion))
			},
		},
		{
			name:              "restart the service when its binary changes",
			installedVersions: []string{mockVersion},
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(nydusSnapshotterBinary, []byte("nydus-snapshotter v2"), 0o755))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:              "restart the service when its unit changes",
			installedVersions: []string{mockVersion},
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(mockUnitPath, []byte("[Service]\n"), 0o644))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:              "keep the snapshotter running when certs.d changes",
			installedVersions: []string{mockVersion},
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(mockHostsPath, []byte(mockMirrorHostsTOML), 0o644))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "resolve an absolute host symlink within the host root",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.MkdirAll(filepath.Join(hostRootMount, "data/opt"), 0o755))
				assert.NoError(t, os.Symlink("/data/opt", filepath.Join(hostRootMount, "opt")))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(hostRootMount, "data", mockNydusTarget))
			},
		},
		{
			name:              "finish a required restart",
			installedVersions: []string{mockVersion},
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(filepath.Join(hostRootMount, restartRequiredFile), nil, 0o644))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(filepath.Join(hostRootMount, restartRequiredFile))
			},
		},
		{
			name:    "keep the restart pending when it fails",
			prepare: func(t *testing.T, cfg *config.Config) {},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(errors.New("foo")).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.FileExists(filepath.Join(hostRootMount, restartRequiredFile))
			},
		},
		{
			name:              "restart-required file that cannot be checked",
			installedVersions: []string{mockVersion},
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.RemoveAll(filepath.Join(hostRootMount, filepath.Dir(restartRequiredFile))))
				assert.NoError(t, os.WriteFile(filepath.Join(hostRootMount, filepath.Dir(restartRequiredFile)), nil, 0o644))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "stat "+filepath.Join(hostRootMount, restartRequiredFile))
			},
		},
		{
			name:              "service that cannot be started",
			installedVersions: []string{mockVersion},
			prepare:           func(t *testing.T, cfg *config.Config) {},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(errors.New("foo")).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
			},
		},
		{
			name:              "enable unit files failed",
			installedVersions: []string{mockVersion},
			prepare:           func(t *testing.T, cfg *config.Config) {},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
			},
		},
		{
			name: "invalid config",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(config.DefaultPath, []byte(mockInvalidConfig), 0o644))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid log.level")
				assert.NoFileExists(filepath.Join(hostRootMount, nydusSnapshotterBinary))
				assert.NoFileExists(filepath.Join(hostRootMount, restartRequiredFile))
			},
		},
		{
			name: "install certs.d where the config says",
			prepare: func(t *testing.T, cfg *config.Config) {
				cfg.Registry.ConfigPath = "/etc/registry/certs.d"
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				data, err := os.ReadFile(filepath.Join(hostRootMount, "etc/registry/certs.d/registry.example.com/hosts.toml"))
				assert.NoError(err)
				assert.Equal(mockHostsTOML, string(data))
				info, err := os.Stat(filepath.Join(hostRootMount, "etc/registry/certs.d/registry.example.com/hosts.toml"))
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o644), info.Mode())
				}

				assert.NoDirExists(filepath.Join(hostRootMount, config.DefaultRegistryConfigPath))
			},
		},
		{
			name: "invalid nydus version",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(nydusBinary, []byte(fmt.Sprintf(mockNydusScript, "../current")), 0o755))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unexpected")
				assert.NoFileExists(filepath.Join(hostRootMount, nydusSnapshotterBinary))
			},
		},
		{
			name: "missing binary",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.Remove(nydusSnapshotterBinary))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.NoFileExists(filepath.Join(hostRootMount, restartRequiredFile))
			},
		},
		{
			name: "invalid hosts.toml",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(mockHostsPath, []byte("server = \n"), 0o644))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "registry.example.com/hosts.toml")
				assert.NoFileExists(filepath.Join(hostRootMount, nydusSnapshotterBinary))
			},
		},
		{
			name: "hosts.toml a daemon cannot use",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(mockHostsPath, []byte("client = [[\"client.cert\", \"client.key\"]]\n"), 0o644))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
				assert.NoFileExists(filepath.Join(hostRootMount, nydusSnapshotterBinary))
			},
		},
		{
			name: "certs.d file that cannot be read",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.Symlink("missing", filepath.Join(config.DefaultRegistryConfigPath, "dangling")))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "walk certs.d")
				assert.NoFileExists(filepath.Join(hostRootMount, nydusSnapshotterBinary))
			},
		},
		{
			name: "host path that cannot be resolved",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.Symlink("opt", filepath.Join(hostRootMount, "opt")))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve host path")
				assert.NoFileExists(filepath.Join(hostRootMount, nydusSnapshotterBinary))
			},
		},
		{
			name: "restart-required file whose host path cannot be resolved",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.Symlink("run", filepath.Join(hostRootMount, "run")))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve host path "+restartRequiredFile)
				assert.NoFileExists(filepath.Join(hostRootMount, nydusSnapshotterBinary))
			},
		},
		{
			name: "host directory that cannot be created",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.CopyFS(hostRootMount, fstest.MapFS{"usr/local/bin": {}}))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir of "+filepath.Join(hostRootMount, nydusSnapshotterBinary))
				assert.FileExists(filepath.Join(hostRootMount, restartRequiredFile))
			},
		},
		{
			name: "link the nydus binary where the config says",
			prepare: func(t *testing.T, cfg *config.Config) {
				cfg.Nydusd.Binary = "/usr/local/bin/nydus"
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				link, err := os.Readlink(filepath.Join(hostRootMount, "usr/local/bin/nydus"))
				assert.NoError(err)
				assert.Equal(mockNydusTarget, link)
				data, err := os.ReadFile(filepath.Join(hostRootMount, mockNydusTarget))
				assert.NoError(err)
				assert.Equal(fmt.Sprintf(mockNydusScript, mockVersion), string(data))
				info, err := os.Stat(filepath.Join(hostRootMount, mockNydusTarget))
				if assert.NoError(err) {
					assert.Equal(os.FileMode(0o755), info.Mode())
				}
			},
		},
		{
			name: "nydus binary path held by a directory",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.MkdirAll(filepath.Join(hostRootMount, config.DefaultNydusdBinary), 0o755))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "rename "+filepath.Join(hostRootMount, config.DefaultNydusdBinary)+temporarySuffix)
			},
		},
		{
			name: "image without certs.d",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.RemoveAll(config.DefaultRegistryConfigPath))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoDirExists(filepath.Join(hostRootMount, config.DefaultRegistryConfigPath))
			},
		},
		{
			name: "certs.d the installer is not told to install",
			prepare: func(t *testing.T, cfg *config.Config) {
				cfg.Installer.Registries.Enable = false
				assert.NoError(t, os.WriteFile(mockHostsPath, []byte("server = \n"), 0o644))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{nydusSnapshotterServiceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), nydusSnapshotterServiceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoDirExists(filepath.Join(hostRootMount, config.DefaultRegistryConfigPath))
			},
		},
		{
			name: "missing config",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.Remove(config.DefaultPath))
			},
			mock: func(m *mocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read config")
				assert.NoFileExists(filepath.Join(hostRootMount, nydusSnapshotterBinary))
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
			for _, version := range tc.installedVersions {
				assert.NoError(t, os.WriteFile(nydusBinary, []byte(fmt.Sprintf(mockNydusScript, version)), 0o755))
				mockSystemd := mocks.NewMockSystemd(ctl)
				mockSystemd.EXPECT().EnableUnitFiles(gomock.Any(), gomock.Any()).Return(nil).Times(1)
				mockSystemd.EXPECT().RestartUnit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				mockSystemd.EXPECT().StartUnit(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				i, err := New(cfg, config.DefaultPath, mockSystemd)
				if err != nil {
					t.Fatal(err)
				}

				assert.NoError(t, i.install(t.Context()))
			}

			tc.prepare(t, cfg)
			mockSystemd := mocks.NewMockSystemd(ctl)
			tc.mock(mockSystemd.EXPECT())
			i, err := New(cfg, config.DefaultPath, mockSystemd)
			if err != nil {
				t.Fatal(err)
			}

			tc.expect(t, i.install(t.Context()))
		})
	}
}
