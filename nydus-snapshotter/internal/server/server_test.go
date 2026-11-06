/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package server

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	authmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	fsmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs/mocks"
)

func TestServer_listen(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, address string)
		expect  func(t *testing.T, address string, listener net.Listener, err error)
	}{
		{
			name:    "bind a new socket",
			prepare: func(t *testing.T, address string) {},
			expect: func(t *testing.T, address string, listener net.Listener, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				info, err := os.Stat(address)
				assert.NoError(err)
				assert.Equal(os.ModeSocket|0o600, info.Mode())
				assert.NoError(listener.Close())
			},
		},
		{
			name: "replace a stale socket",
			prepare: func(t *testing.T, address string) {
				assert.NoError(t, os.MkdirAll(filepath.Dir(address), 0o700))
				listener, err := net.Listen("unix", address)
				assert.NoError(t, err)
				listener.(*net.UnixListener).SetUnlinkOnClose(false)
				assert.NoError(t, listener.Close())
			},
			expect: func(t *testing.T, address string, listener net.Listener, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.NoError(listener.Close())
			},
		},
		{
			name: "keep a socket another process serves",
			prepare: func(t *testing.T, address string) {
				assert.NoError(t, os.MkdirAll(filepath.Dir(address), 0o700))
				listener, err := net.Listen("unix", address)
				assert.NoError(t, err)
				t.Cleanup(func() { assert.NoError(t, listener.Close()) })
			},
			expect: func(t *testing.T, address string, listener net.Listener, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is served by another process")
				assert.FileExists(address)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.New()
			cfg.Address = filepath.Join(t.TempDir(), "run", "s.sock")
			tc.prepare(t, cfg.Address)

			s := &Server{cfg: cfg}
			listener, err := s.listen(t.Context())
			tc.expect(t, cfg.Address, listener, err)
		})
	}
}

func TestServer_ready(t *testing.T) {
	tests := []struct {
		name    string
		serving bool
		mock    func(m *authmocks.MockKeychainMockRecorder)
		expect  func(t *testing.T, err error)
	}{
		{
			name:    "ready",
			serving: true,
			mock: func(m *authmocks.MockKeychainMockRecorder) {
				m.Synced().Return(true).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert.NoError(t, err)
			},
		},
		{
			name: "grpc not serving",
			mock: func(m *authmocks.MockKeychainMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert.EqualError(t, err, "grpc is not serving")
			},
		},
		{
			name:    "credentials not synced",
			serving: true,
			mock: func(m *authmocks.MockKeychainMockRecorder) {
				m.Synced().Return(false).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert.EqualError(t, err, "registry credentials are not synced")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			keychain := authmocks.NewMockKeychain(ctl)
			tc.mock(keychain.EXPECT())

			s := &Server{keychain: keychain}
			s.serving.Store(tc.serving)
			tc.expect(t, s.ready())
		})
	}
}

func TestServer_reload(t *testing.T) {
	tests := []struct {
		name   string
		next   func(cfg config.Config) *config.Config
		mock   func(m *fsmocks.MockFileSystemMockRecorder)
		expect func(t *testing.T, running *config.Config)
	}{
		{
			name: "apply new cgroup limits",
			next: func(cfg config.Config) *config.Config {
				cfg.Cgroup.MemoryMax = 4 << 30
				return &cfg
			},
			mock: func(m *fsmocks.MockFileSystemMockRecorder) {
				m.Reload(gomock.Any(), gomock.Cond(func(cfg *config.Config) bool {
					return cfg.Cgroup.MemoryMax == 4<<30
				})).Return(nil).Times(1)
			},
			expect: func(t *testing.T, running *config.Config) {
				assert.Zero(t, running.Cgroup.MemoryMax)
			},
		},
		{
			name: "keep restart only changes for a restart",
			next: func(cfg config.Config) *config.Config {
				cfg.Cgroup.Slice = "other.slice"
				cfg.Nydusd.MountTimeout = config.Duration(0)
				return &cfg
			},
			mock: func(m *fsmocks.MockFileSystemMockRecorder) {
				m.Reload(gomock.Any(), gomock.Cond(func(cfg *config.Config) bool {
					return cfg.Cgroup.Slice == config.DefaultSlice && cfg.Nydusd.MountTimeout != 0
				})).Return(nil).Times(1)
			},
			expect: func(t *testing.T, running *config.Config) {
				assert.Equal(t, config.DefaultSlice, running.Cgroup.Slice)
			},
		},
		{
			name: "survive a failed reload",
			next: func(cfg config.Config) *config.Config {
				return &cfg
			},
			mock: func(m *fsmocks.MockFileSystemMockRecorder) {
				m.Reload(gomock.Any(), gomock.Any()).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, running *config.Config) {
				assert.Equal(t, config.New(), running)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			fileSystem := fsmocks.NewMockFileSystem(ctl)
			tc.mock(fileSystem.EXPECT())

			s := &Server{cfg: config.New(), fileSystem: fileSystem}
			s.reload(t.Context(), tc.next(*config.New()))
			tc.expect(t, s.cfg)
		})
	}
}
