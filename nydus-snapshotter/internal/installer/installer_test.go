/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package installer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

var (
	mockVersion = "3.0.0-test"

	mockHostsTOML = "server = \"https://registry.example.com\"\n"

	mockMirrorHostsTOML = "server = \"https://mirror.example.com\"\n"

	mockToken = "token"

	mockCA = "ca"

	mockKubeSecretConfig = "auth:\n  kube_secret:\n    enable: true\n"

	mockInvalidConfig = "log:\n  level: loud\n"

	mockServiceRestart = serviceUnit + "\n"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		expect   func(t *testing.T, err error)
	}{
		{
			name:     "valid config",
			interval: DefaultSyncInterval,
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name:     "invalid sync interval",
			interval: 0,
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "invalid sync interval 0s")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{SyncInterval: tc.interval}
			tc.expect(t, cfg.Validate())
		})
	}
}

func TestInstaller_Run(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]string
		mock    func(t *testing.T, cfg *Config, m *mocks.MockManagerMockRecorder, cancel context.CancelFunc)
		expect  func(t *testing.T, cfg *Config, err error)
	}{
		{
			name: "install and sync until done",
			mock: func(t *testing.T, cfg *Config, m *mocks.MockManagerMockRecorder, cancel context.CancelFunc) {
				gomock.InOrder(
					m.Ping(gomock.Any()).Return(nil).Times(1),
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Do(func(context.Context, string) { cancel() }).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(hostPath(t, cfg, config.DefaultAuthKubeconfig))
				assert.FileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
		{
			name:    "sync the kubeconfig with kube secret",
			payload: map[string]string{"config/config.yaml": mockKubeSecretConfig},
			mock: func(t *testing.T, cfg *Config, m *mocks.MockManagerMockRecorder, cancel context.CancelFunc) {
				gomock.InOrder(
					m.Ping(gomock.Any()).Return(nil).Times(1),
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Do(func(context.Context, string) { cancel() }).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(hostPath(t, cfg, config.DefaultAuthKubeconfig))
			},
		},
		{
			name:    "keep the token and the config in sync after the install",
			payload: map[string]string{"config/config.yaml": mockKubeSecretConfig},
			mock: func(t *testing.T, cfg *Config, m *mocks.MockManagerMockRecorder, cancel context.CancelFunc) {
				gomock.InOrder(
					m.Ping(gomock.Any()).Return(nil).Times(1),
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Do(func(context.Context, string) {
						writeFiles(t, cfg.TokenDir, map[string]string{"token": "rotated"})
						writeFiles(t, cfg.PayloadDir, map[string]string{"config/certs.d/registry.example.com/hosts.toml": mockMirrorHostsTOML})
						go func() {
							defer cancel()
							assert.Eventually(t, func() bool {
								token, tokenErr := os.ReadFile(hostPath(t, cfg, "/run/nydus-snapshotter/kubernetes/token"))
								hosts, hostsErr := os.ReadFile(hostPath(t, cfg, config.DefaultRegistryConfigPath+"/registry.example.com/hosts.toml"))
								return tokenErr == nil && hostsErr == nil && string(token) == "rotated" && string(hosts) == mockMirrorHostsTOML
							}, 5*time.Second, 10*time.Millisecond)
						}()
					}).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, hostPath(t, cfg, "/run/nydus-snapshotter/kubernetes/token"), "rotated", 0o600)
				assertFile(t, hostPath(t, cfg, config.DefaultRegistryConfigPath+"/registry.example.com/hosts.toml"), mockMirrorHostsTOML, 0o644)
				assert.NoFileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name:    "write nothing to a host whose systemd cannot be used",
			payload: map[string]string{"config/config.yaml": mockKubeSecretConfig},
			mock: func(t *testing.T, cfg *Config, m *mocks.MockManagerMockRecorder, cancel context.CancelFunc) {
				m.Ping(gomock.Any()).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				entries, err := os.ReadDir(cfg.RootfsDir)
				assert.NoError(err)
				assert.Empty(entries)
			},
		},
		{
			name:    "install that fails",
			payload: map[string]string{"bin/nydus": "#!/bin/sh\nexit 1\n"},
			mock: func(t *testing.T, cfg *Config, m *mocks.MockManagerMockRecorder, cancel context.CancelFunc) {
				m.Ping(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
		{
			name:    "keep the host as it is while a sync fails",
			payload: map[string]string{"config/config.yaml": mockKubeSecretConfig},
			mock: func(t *testing.T, cfg *Config, m *mocks.MockManagerMockRecorder, cancel context.CancelFunc) {
				gomock.InOrder(
					m.Ping(gomock.Any()).Return(nil).Times(1),
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Do(func(context.Context, string) {
						writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.yaml": mockInvalidConfig})
						assert.NoError(t, os.Remove(filepath.Join(cfg.TokenDir, "token")))
						go func() {
							defer cancel()
							assert.Never(t, func() bool {
								return readFile(t, hostPath(t, cfg, config.DefaultPath)) != mockKubeSecretConfig
							}, 100*time.Millisecond, 10*time.Millisecond)
						}()
					}).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, hostPath(t, cfg, config.DefaultPath), mockKubeSecretConfig, 0o644)
				assertFile(t, hostPath(t, cfg, "/run/nydus-snapshotter/kubernetes/token"), mockToken, 0o600)
			},
		},
		{
			name:    "credentials that cannot be synced",
			payload: map[string]string{"config/config.yaml": mockInvalidConfig},
			mock: func(t *testing.T, cfg *Config, m *mocks.MockManagerMockRecorder, cancel context.CancelFunc) {
				m.Ping(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse payload config")
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
			t.Setenv("KUBERNETES_SERVICE_PORT", "443")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			manager := mocks.NewMockManager(ctl)
			cfg := newConfig(t)
			cfg.SyncInterval = 10 * time.Millisecond
			writeFiles(t, cfg.PayloadDir, tc.payload)
			tc.mock(t, cfg, manager.EXPECT(), cancel)

			tc.expect(t, cfg, New(cfg, manager).Run(ctx))
		})
	}
}

func TestInstaller_install(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, cfg *Config)
		mock    func(m *mocks.MockManagerMockRecorder)
		expect  func(t *testing.T, cfg *Config, err error)
	}{
		{
			name:    "install onto an empty host",
			prepare: func(t *testing.T, cfg *Config) {},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, hostPath(t, cfg, snapshotterBinary), readFile(t, cfg.payload("bin/nydus-snapshotter")), 0o755)
				assertFile(t, hostPath(t, cfg, "/opt/nydus-snapshotter/bin/"+mockVersion+"/nydus"), readFile(t, cfg.payload("bin/nydus")), 0o755)
				assertFile(t, hostPath(t, cfg, config.DefaultPath), readFile(t, "../../deploy/nydus-snapshotter/config.yaml"), 0o644)
				assertFile(t, hostPath(t, cfg, "/etc/systemd/system/"+socketUnit), readFile(t, "../../deploy/systemd/"+socketUnit), 0o644)
				assertFile(t, hostPath(t, cfg, "/etc/systemd/system/"+serviceUnit), readFile(t, "../../deploy/systemd/"+serviceUnit), 0o644)
				assertFile(t, hostPath(t, cfg, config.DefaultRegistryConfigPath+"/registry.example.com/hosts.toml"), mockHostsTOML, 0o644)
				link, err := os.Readlink(hostPath(t, cfg, "/opt/nydus-snapshotter/bin/current"))
				assert.NoError(err)
				assert.Equal(mockVersion, link)
				assert.FileExists(hostPath(t, cfg, config.DefaultNydusdBinary))
				assert.NoFileExists(hostPath(t, cfg, restartPending))
				info, err := os.Stat(filepath.Dir(hostPath(t, cfg, restartPending)))
				assert.NoError(err)
				assert.Equal(os.ModeDir|0o700, info.Mode())
			},
		},
		{
			name:    "start the units of an unchanged host",
			prepare: install,
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name: "restart the service when the config changes",
			prepare: func(t *testing.T, cfg *Config) {
				install(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.yaml": "log:\n  level: \"debug\"\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, hostPath(t, cfg, config.DefaultPath), "log:\n  level: \"debug\"\n", 0o644)
			},
		},
		{
			name: "switch to a new nydus version",
			prepare: func(t *testing.T, cfg *Config) {
				install(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"bin/nydus": nydusScript("3.0.1-test")})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				link, err := os.Readlink(hostPath(t, cfg, "/opt/nydus-snapshotter/bin/current"))
				assert.NoError(err)
				assert.Equal("3.0.1-test", link)
				assert.FileExists(hostPath(t, cfg, "/opt/nydus-snapshotter/bin/"+mockVersion+"/nydus"))
				assert.NoFileExists(hostPath(t, cfg, "/opt/nydus-snapshotter/bin/current"+temporarySuffix))
			},
		},
		{
			name: "prune versions older than the previous one",
			prepare: func(t *testing.T, cfg *Config) {
				install(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"bin/nydus": nydusScript("3.0.1-test")})
				install(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"bin/nydus": nydusScript("3.0.2-test")})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(hostPath(t, cfg, "/opt/nydus-snapshotter/bin/3.0.2-test/nydus"))
				assert.FileExists(hostPath(t, cfg, "/opt/nydus-snapshotter/bin/3.0.1-test/nydus"))
				assert.NoDirExists(hostPath(t, cfg, "/opt/nydus-snapshotter/bin/"+mockVersion))
			},
		},
		{
			name: "restart the service when its binary changes",
			prepare: func(t *testing.T, cfg *Config) {
				install(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"bin/nydus-snapshotter": "nydus-snapshotter v2"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "restart only the service when its unit changes",
			prepare: func(t *testing.T, cfg *Config) {
				install(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"systemd/" + serviceUnit: "[Service]\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "keep the snapshotter running when certs.d changes",
			prepare: func(t *testing.T, cfg *Config) {
				install(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/certs.d/registry.example.com/hosts.toml": "server = \"https://mirror.example.com\"\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "restart the service once, with the socket, when the socket changes",
			prepare: func(t *testing.T, cfg *Config) {
				install(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"systemd/" + socketUnit: "[Socket]\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "resolve an absolute host symlink within the host root",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.MkdirAll(filepath.Join(cfg.RootfsDir, "data/opt"), 0o755))
				assert.NoError(t, os.Symlink("/data/opt", filepath.Join(cfg.RootfsDir, "opt")))
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(cfg.RootfsDir, "data/opt/nydus-snapshotter/bin", mockVersion, "nydus"))
			},
		},
		{
			name: "finish a pending restart",
			prepare: func(t *testing.T, cfg *Config) {
				install(t, cfg)
				writeFiles(t, cfg.RootfsDir, map[string]string{restartPending: mockServiceRestart})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name:    "keep the restart pending when it fails",
			prepare: func(t *testing.T, cfg *Config) {},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Return(errors.New("foo")).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.FileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name: "restart marker that cannot be read",
			prepare: func(t *testing.T, cfg *Config) {
				install(t, cfg)
				assert.NoError(t, os.MkdirAll(hostPath(t, cfg, restartPending), 0o755))
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read "+hostPath(t, cfg, restartPending))
			},
		},
		{
			name: "socket that cannot be started",
			prepare: func(t *testing.T, cfg *Config) {
				install(t, cfg)
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), socketUnit).Return(errors.New("foo")).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
			},
		},
		{
			name: "enable unit files failed",
			prepare: func(t *testing.T, cfg *Config) {
				install(t, cfg)
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
			},
		},
		{
			name: "invalid config",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.yaml": mockInvalidConfig})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "invalid log.level")
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
				assert.NoFileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name: "config naming a nydus binary the installer does not write",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.yaml": "nydusd:\n  binary: /usr/bin/nydus\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "nydusd.binary must be "+config.DefaultNydusdBinary)
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
		{
			name: "config naming a kubeconfig the installer does not write",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.yaml": "auth:\n  kube_secret:\n    enable: true\n    kubeconfig: /etc/kubernetes/kubeconfig\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "auth.kube_secret.kubeconfig must be "+config.DefaultAuthKubeconfig)
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
		{
			name: "certs.d the config does not read",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.yaml": "registry:\n  config_path: /etc/containerd/certs.d\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "registry.config_path must hold "+config.DefaultRegistryConfigPath)
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
		{
			name: "invalid nydus version",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"bin/nydus": nydusScript("../current")})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unexpected")
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
		{
			name: "missing payload",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.Remove(cfg.payload("bin/nydus-snapshotter")))
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.NoFileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name: "invalid hosts.toml",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/certs.d/registry.example.com/hosts.toml": "server = \n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "registry.example.com/hosts.toml")
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
		{
			name: "hosts.toml a daemon cannot use",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/certs.d/registry.example.com/hosts.toml": "client = [[\"client.cert\", \"client.key\"]]\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
		{
			name: "certs.d file that cannot be read",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.Symlink("missing", filepath.Join(cfg.PayloadDir, "config/certs.d/dangling")))
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "walk payload certs.d")
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
		{
			name: "host path that cannot be resolved",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.Symlink("opt", filepath.Join(cfg.RootfsDir, "opt")))
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve host path")
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
		{
			name: "restart marker whose host path cannot be resolved",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.Symlink("run", filepath.Join(cfg.RootfsDir, "run")))
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve host path "+restartPending)
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
		{
			name: "host directory that cannot be created",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.RootfsDir, map[string]string{filepath.Dir(snapshotterBinary): ""})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create dir of "+hostPath(t, cfg, snapshotterBinary))
				assert.FileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name: "current that is no link",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.MkdirAll(hostPath(t, cfg, filepath.Dir(config.DefaultNydusdBinary)), 0o755))
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read "+hostPath(t, cfg, filepath.Dir(config.DefaultNydusdBinary)))
			},
		},
		{
			name: "payload without certs.d",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.RemoveAll(cfg.payload("config/certs.d")))
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.StartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoDirExists(hostPath(t, cfg, config.DefaultRegistryConfigPath))
			},
		},
		{
			name: "missing payload config",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.Remove(cfg.payload("config/config.yaml")))
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "read payload config")
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newConfig(t)
			tc.prepare(t, cfg)
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			manager := mocks.NewMockManager(ctl)
			tc.mock(manager.EXPECT())

			tc.expect(t, cfg, New(cfg, manager).install(t.Context()))
		})
	}
}

func hostPath(t *testing.T, cfg *Config, path string) string {
	t.Helper()
	path, err := cfg.host(path)
	assert.NoError(t, err)
	return path
}

func newConfig(t *testing.T) *Config {
	t.Helper()
	cfg := &Config{
		RootfsDir:    t.TempDir(),
		PayloadDir:   t.TempDir(),
		TokenDir:     t.TempDir(),
		SyncInterval: DefaultSyncInterval,
	}

	writeFiles(t, cfg.PayloadDir, map[string]string{
		"bin/nydus":                                      nydusScript(mockVersion),
		"bin/nydus-snapshotter":                          "nydus-snapshotter",
		"systemd/" + socketUnit:                          readFile(t, "../../deploy/systemd/"+socketUnit),
		"systemd/" + serviceUnit:                         readFile(t, "../../deploy/systemd/"+serviceUnit),
		"config/config.yaml":                             readFile(t, "../../deploy/nydus-snapshotter/config.yaml"),
		"config/certs.d/registry.example.com/hosts.toml": mockHostsTOML,
	})
	writeFiles(t, cfg.TokenDir, map[string]string{
		"token":  mockToken,
		"ca.crt": mockCA,
	})

	return cfg
}

func install(t *testing.T, cfg *Config) {
	t.Helper()
	ctl := gomock.NewController(t)
	defer ctl.Finish()
	manager := mocks.NewMockManager(ctl)
	manager.EXPECT().EnableUnitFiles(gomock.Any(), gomock.Any()).AnyTimes()
	manager.EXPECT().RestartUnit(gomock.Any(), gomock.Any()).AnyTimes()
	manager.EXPECT().StartUnit(gomock.Any(), gomock.Any()).AnyTimes()
	assert.NoError(t, New(cfg, manager).install(t.Context()))
}

func nydusScript(version string) string {
	return "#!/bin/sh\necho 'nydus " + version + " (1a2b3c4d5, 2026-01-02)'\n"
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for path, data := range files {
		path = filepath.Join(dir, path)
		assert.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		assert.NoError(t, os.WriteFile(path, []byte(data), 0o755))
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	assert.NoError(t, err)
	return string(data)
}

func assertFile(t *testing.T, path, data string, perm os.FileMode) {
	t.Helper()
	assert := assert.New(t)
	info, err := os.Stat(path)
	if !assert.NoError(err) {
		return
	}

	assert.Equal(perm, info.Mode())
	assert.Equal(data, readFile(t, path))
}
