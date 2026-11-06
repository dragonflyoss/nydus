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

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

var (
	mockVersion = "3.0.0-test"

	mockHostsTOML = "server = \"https://registry.example.com\"\n"

	mockToken = "token"

	mockCA = "ca"

	mockKubeSecretConfig = "version = 1\n[auth.kubesecret]\nenable = true\n"

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
				assert.NoError(t, err)
			},
		},
		{
			name:     "invalid sync interval",
			interval: 0,
			expect: func(t *testing.T, err error) {
				assert.EqualError(t, err, "invalid sync interval 0s")
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
		mock    func(m *mocks.MockManagerMockRecorder, cancel context.CancelFunc)
		expect  func(t *testing.T, cfg *Config, err error)
	}{
		{
			name: "install and sync until done",
			mock: func(m *mocks.MockManagerMockRecorder, cancel context.CancelFunc) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), serviceUnit).Do(func(context.Context, string) { cancel() }).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(hostPath(t, cfg, config.DefaultKubeconfig))
				assert.FileExists(hostPath(t, cfg, snapshotterBinary))
			},
		},
		{
			name:    "sync the kubeconfig with kubesecret",
			payload: map[string]string{"config/config.toml": mockKubeSecretConfig},
			mock: func(m *mocks.MockManagerMockRecorder, cancel context.CancelFunc) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), serviceUnit).Do(func(context.Context, string) { cancel() }).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(hostPath(t, cfg, config.DefaultKubeconfig))
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
			tc.mock(manager.EXPECT(), cancel)

			cfg := newConfig(t)
			writeFiles(t, cfg.PayloadDir, tc.payload)
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
					m.RestartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assertFile(t, hostPath(t, cfg, snapshotterBinary), readFile(t, cfg.payload("bin/nydus-snapshotter")), 0o755)
				assertFile(t, hostPath(t, cfg, "/opt/nydus-v3/bin/"+mockVersion+"/nydus"), readFile(t, cfg.payload("bin/nydus")), 0o755)
				assertFile(t, hostPath(t, cfg, config.DefaultPath), readFile(t, "../../deploy/nydus-snapshotter/config.toml"), 0o644)
				assertFile(t, hostPath(t, cfg, config.DefaultNydusdTemplate), readFile(t, "../../deploy/nydus-snapshotter/nydusd.template.yaml"), 0o644)
				assertFile(t, hostPath(t, cfg, "/etc/systemd/system/"+socketUnit), readFile(t, "../../deploy/systemd/"+socketUnit), 0o644)
				assertFile(t, hostPath(t, cfg, "/etc/systemd/system/"+serviceUnit), readFile(t, "../../deploy/systemd/"+serviceUnit), 0o644)
				assertFile(t, hostPath(t, cfg, config.DefaultRegistryConfigPath+"/registry.example.com/hosts.toml"), mockHostsTOML, 0o644)
				link, err := os.Readlink(hostPath(t, cfg, "/opt/nydus-v3/bin/current"))
				assert.NoError(err)
				assert.Equal(mockVersion, link)
				assert.FileExists(hostPath(t, cfg, config.DefaultNydusdBinary))
				assert.NoFileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name:    "keep an unchanged host",
			prepare: installed,
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.ActiveState(gomock.Any(), socketUnit).Return(systemd.ActiveStateActive, nil).Times(1),
					m.ActiveState(gomock.Any(), serviceUnit).Return(systemd.ActiveStateActive, nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name:    "start inactive units",
			prepare: installed,
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.ActiveState(gomock.Any(), socketUnit).Return("inactive", nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.ActiveState(gomock.Any(), serviceUnit).Return("failed", nil).Times(1),
					m.RestartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "restart the service when the config changes",
			prepare: func(t *testing.T, cfg *Config) {
				installed(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.toml": "version = 1\n[log]\nlevel = \"debug\"\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.ActiveState(gomock.Any(), socketUnit).Return(systemd.ActiveStateActive, nil).Times(1),
					m.RestartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.NoError(t, err)
				assertFile(t, hostPath(t, cfg, config.DefaultPath), "version = 1\n[log]\nlevel = \"debug\"\n", 0o644)
			},
		},
		{
			name: "switch to a new nydus version",
			prepare: func(t *testing.T, cfg *Config) {
				installed(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"bin/nydus": nydusScript("3.0.1-test")})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.ActiveState(gomock.Any(), socketUnit).Return(systemd.ActiveStateActive, nil).Times(1),
					m.ActiveState(gomock.Any(), serviceUnit).Return(systemd.ActiveStateActive, nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				link, err := os.Readlink(hostPath(t, cfg, "/opt/nydus-v3/bin/current"))
				assert.NoError(err)
				assert.Equal("3.0.1-test", link)
				assert.FileExists(hostPath(t, cfg, "/opt/nydus-v3/bin/"+mockVersion+"/nydus"))
				assert.NoFileExists(hostPath(t, cfg, "/opt/nydus-v3/bin/current.tmp"))
			},
		},
		{
			name: "prune versions older than the previous one",
			prepare: func(t *testing.T, cfg *Config) {
				installed(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"bin/nydus": nydusScript("3.0.1-test")})
				installed(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"bin/nydus": nydusScript("3.0.2-test")})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.ActiveState(gomock.Any(), socketUnit).Return(systemd.ActiveStateActive, nil).Times(1),
					m.ActiveState(gomock.Any(), serviceUnit).Return(systemd.ActiveStateActive, nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(hostPath(t, cfg, "/opt/nydus-v3/bin/3.0.2-test/nydus"))
				assert.FileExists(hostPath(t, cfg, "/opt/nydus-v3/bin/3.0.1-test/nydus"))
				assert.NoDirExists(hostPath(t, cfg, "/opt/nydus-v3/bin/"+mockVersion))
			},
		},
		{
			name: "restart the service when its binary changes",
			prepare: func(t *testing.T, cfg *Config) {
				installed(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"bin/nydus-snapshotter": "nydus-snapshotter v2"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.ActiveState(gomock.Any(), socketUnit).Return(systemd.ActiveStateActive, nil).Times(1),
					m.RestartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "restart only the service when its unit changes",
			prepare: func(t *testing.T, cfg *Config) {
				installed(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"systemd/" + serviceUnit: "[Service]\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.ActiveState(gomock.Any(), socketUnit).Return(systemd.ActiveStateActive, nil).Times(1),
					m.RestartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "keep the snapshotter running when certs.d changes",
			prepare: func(t *testing.T, cfg *Config) {
				installed(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/certs.d/registry.example.com/hosts.toml": "server = \"https://mirror.example.com\"\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.ActiveState(gomock.Any(), socketUnit).Return(systemd.ActiveStateActive, nil).Times(1),
					m.ActiveState(gomock.Any(), serviceUnit).Return(systemd.ActiveStateActive, nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "keep the snapshotter running when the template changes",
			prepare: func(t *testing.T, cfg *Config) {
				installed(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/nydusd.template.yaml": "backend: {}\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.ActiveState(gomock.Any(), socketUnit).Return(systemd.ActiveStateActive, nil).Times(1),
					m.ActiveState(gomock.Any(), serviceUnit).Return(systemd.ActiveStateActive, nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.NoError(t, err)
				assertFile(t, hostPath(t, cfg, config.DefaultNydusdTemplate), "backend: {}\n", 0o644)
			},
		},
		{
			name: "restart the socket and the service when the socket changes",
			prepare: func(t *testing.T, cfg *Config) {
				installed(t, cfg)
				writeFiles(t, cfg.PayloadDir, map[string]string{"systemd/" + socketUnit: "[Socket]\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "resolve an absolute host symlink within the host root",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.MkdirAll(filepath.Join(cfg.HostRoot, "data/opt"), 0o755))
				assert.NoError(t, os.Symlink("/data/opt", filepath.Join(cfg.HostRoot, "opt")))
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), socketUnit).Return(nil).Times(1),
					m.RestartUnit(gomock.Any(), serviceUnit).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.FileExists(filepath.Join(cfg.HostRoot, "data/opt/nydus-v3/bin", mockVersion, "nydus"))
			},
		},
		{
			name: "finish a pending restart",
			prepare: func(t *testing.T, cfg *Config) {
				installed(t, cfg)
				writeFiles(t, cfg.HostRoot, map[string]string{restartPending: mockServiceRestart})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				gomock.InOrder(
					m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(nil).Times(1),
					m.ActiveState(gomock.Any(), socketUnit).Return(systemd.ActiveStateActive, nil).Times(1),
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
					m.RestartUnit(gomock.Any(), serviceUnit).Return(errors.New("foo")).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.FileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name: "enable unit files failed",
			prepare: func(t *testing.T, cfg *Config) {
				installed(t, cfg)
			},
			mock: func(m *mocks.MockManagerMockRecorder) {
				m.EnableUnitFiles(gomock.Any(), []string{socketUnit, serviceUnit}).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.EqualError(t, err, "foo")
			},
		},
		{
			name: "invalid config",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.toml": "version = 2\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unsupported config version 2")
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
				assert.NoFileExists(hostPath(t, cfg, restartPending))
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
			name: "invalid nydusd template",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/nydusd.template.yaml": "backend: [\n"})
			},
			mock: func(m *mocks.MockManagerMockRecorder) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "payload nydusd template")
				assert.NoFileExists(hostPath(t, cfg, snapshotterBinary))
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

func TestInstaller_syncKubeconfig(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		prepare func(t *testing.T, cfg *Config)
		expect  func(t *testing.T, cfg *Config, err error)
	}{
		{
			name:    "write kubeconfig",
			host:    "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				info, err := os.Stat(hostPath(t, cfg, "/run/containerd-nydus-v3/kubernetes"))
				assert.NoError(err)
				assert.Equal(os.ModeDir|0o700, info.Mode())
				assertFile(t, hostPath(t, cfg, "/run/containerd-nydus-v3/kubernetes/token"), mockToken, 0o600)
				assertFile(t, hostPath(t, cfg, "/run/containerd-nydus-v3/kubernetes/ca.crt"), mockCA, 0o644)
				info, err = os.Stat(hostPath(t, cfg, config.DefaultKubeconfig))
				assert.NoError(err)
				assert.Equal(os.FileMode(0o600), info.Mode())
				kubeconfig, err := clientcmd.LoadFromFile(hostPath(t, cfg, config.DefaultKubeconfig))
				assert.NoError(err)
				current := kubeconfig.Contexts[kubeconfig.CurrentContext]
				assert.Equal("https://10.96.0.1:443", kubeconfig.Clusters[current.Cluster].Server)
				assert.Equal("/run/containerd-nydus-v3/kubernetes/ca.crt", kubeconfig.Clusters[current.Cluster].CertificateAuthority)
				assert.Equal("/run/containerd-nydus-v3/kubernetes/token", kubeconfig.AuthInfos[current.AuthInfo].TokenFile)
			},
		},
		{
			name: "rotate token",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, New(cfg, nil).syncKubeconfig())
				writeFiles(t, cfg.TokenDir, map[string]string{"token": "rotated"})
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert.NoError(t, err)
				assertFile(t, hostPath(t, cfg, "/run/containerd-nydus-v3/kubernetes/token"), "rotated", 0o600)
			},
		},
		{
			name:    "ipv6 service host",
			host:    "fd00::1",
			prepare: func(t *testing.T, cfg *Config) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				kubeconfig, err := clientcmd.LoadFromFile(hostPath(t, cfg, config.DefaultKubeconfig))
				assert.NoError(err)
				assert.Equal("https://[fd00::1]:443", kubeconfig.Clusters["default"].Server)
			},
		},
		{
			name:    "not in cluster",
			host:    "",
			prepare: func(t *testing.T, cfg *Config) {},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
				assert.NoFileExists(hostPath(t, cfg, config.DefaultKubeconfig))
			},
		},
		{
			name: "skip without kubesecret",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.toml": readFile(t, "../../deploy/nydus-snapshotter/config.toml")})
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoFileExists(hostPath(t, cfg, config.DefaultKubeconfig))
			},
		},
		{
			name: "missing token",
			host: "10.96.0.1",
			prepare: func(t *testing.T, cfg *Config) {
				assert.NoError(t, os.Remove(filepath.Join(cfg.TokenDir, "token")))
			},
			expect: func(t *testing.T, cfg *Config, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, os.ErrNotExist)
				assert.NoFileExists(hostPath(t, cfg, config.DefaultKubeconfig))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KUBERNETES_SERVICE_HOST", tc.host)
			t.Setenv("KUBERNETES_SERVICE_PORT", "443")
			cfg := newConfig(t)
			writeFiles(t, cfg.PayloadDir, map[string]string{"config/config.toml": mockKubeSecretConfig})
			tc.prepare(t, cfg)

			tc.expect(t, cfg, New(cfg, nil).syncKubeconfig())
		})
	}
}

func TestInstaller_syncConfig(t *testing.T) {
	tests := []struct {
		name   string
		update map[string]string
		expect func(t *testing.T, cfg *Config, changed []string, err error)
	}{
		{
			name:   "copy a changed config without restarting",
			update: map[string]string{"config/config.toml": "version = 1\n[cgroup]\nmemory_max = \"4GiB\"\n"},
			expect: func(t *testing.T, cfg *Config, changed []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{config.DefaultPath}, changed)
				assertFile(t, hostPath(t, cfg, config.DefaultPath), "version = 1\n[cgroup]\nmemory_max = \"4GiB\"\n", 0o644)
				assertFile(t, hostPath(t, cfg, restartPending), mockServiceRestart, 0o644)
			},
		},
		{
			name:   "copy a changed template without a pending restart",
			update: map[string]string{"config/nydusd.template.yaml": "backend: {}\n"},
			expect: func(t *testing.T, cfg *Config, changed []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal([]string{config.DefaultNydusdTemplate}, changed)
				assert.NoFileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name: "copy nothing when the config is unchanged",
			expect: func(t *testing.T, cfg *Config, changed []string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(changed)
				assert.NoFileExists(hostPath(t, cfg, restartPending))
			},
		},
		{
			name:   "keep the host config when the new one is invalid",
			update: map[string]string{"config/config.toml": "version = 2\n"},
			expect: func(t *testing.T, cfg *Config, changed []string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "unsupported config version 2")
				assertFile(t, hostPath(t, cfg, config.DefaultPath), readFile(t, "../../deploy/nydus-snapshotter/config.toml"), 0o644)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newConfig(t)
			installed(t, cfg)
			writeFiles(t, cfg.PayloadDir, tc.update)
			for path := range tc.update {
				assert.NoError(t, os.Chmod(filepath.Join(cfg.PayloadDir, path), 0o644))
			}

			ctl := gomock.NewController(t)
			defer ctl.Finish()
			changed, err := New(cfg, mocks.NewMockManager(ctl)).syncConfig(t.Context())
			tc.expect(t, cfg, changed, err)
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
		HostRoot:     t.TempDir(),
		PayloadDir:   t.TempDir(),
		TokenDir:     t.TempDir(),
		SyncInterval: DefaultSyncInterval,
	}

	writeFiles(t, cfg.PayloadDir, map[string]string{
		"bin/nydus":                                      nydusScript(mockVersion),
		"bin/nydus-snapshotter":                          "nydus-snapshotter",
		"systemd/" + socketUnit:                          readFile(t, "../../deploy/systemd/"+socketUnit),
		"systemd/" + serviceUnit:                         readFile(t, "../../deploy/systemd/"+serviceUnit),
		"config/config.toml":                             readFile(t, "../../deploy/nydus-snapshotter/config.toml"),
		"config/nydusd.template.yaml":                    readFile(t, "../../deploy/nydus-snapshotter/nydusd.template.yaml"),
		"config/certs.d/registry.example.com/hosts.toml": mockHostsTOML,
	})
	writeFiles(t, cfg.TokenDir, map[string]string{
		"token":  mockToken,
		"ca.crt": mockCA,
	})

	return cfg
}

func installed(t *testing.T, cfg *Config) {
	t.Helper()
	ctl := gomock.NewController(t)
	defer ctl.Finish()
	manager := mocks.NewMockManager(ctl)
	manager.EXPECT().EnableUnitFiles(gomock.Any(), gomock.Any()).AnyTimes()
	manager.EXPECT().RestartUnit(gomock.Any(), gomock.Any()).AnyTimes()
	manager.EXPECT().ActiveState(gomock.Any(), gomock.Any()).Return(systemd.ActiveStateActive, nil).AnyTimes()
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
