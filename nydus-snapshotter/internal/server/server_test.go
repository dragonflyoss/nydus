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
	"time"

	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	authmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	fsmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/util/testutil"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, cfg *config.Config)
		expect  func(t *testing.T, cfg *config.Config, s *Server, err error)
	}{
		{
			name:    "serve the snapshot API until stopped",
			prepare: func(t *testing.T, cfg *config.Config) {},
			expect: func(t *testing.T, cfg *config.Config, s *Server, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					return
				}

				served := make(chan error, 1)
				go func() { served <- s.Serve() }()
				conn, err := grpc.NewClient("unix://"+cfg.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
				assert.NoError(err)
				defer conn.Close()

				_, err = snapshotsapi.NewSnapshotsClient(conn).Stat(t.Context(), &snapshotsapi.StatSnapshotRequest{Key: "missing"}, grpc.WaitForReady(true))
				assert.Equal(codes.NotFound, status.Code(err))
				assert.NoError(s.ready())

				s.Stop()
				assert.NoError(<-served)
				assert.ErrorContains(s.ready(), "grpc is not serving")
				_, err = os.Stat(cfg.Address)
				assert.ErrorIs(err, os.ErrNotExist)
			},
		},
		{
			name: "root that cannot be created",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(cfg.Root, nil, 0o644))
			},
			expect: func(t *testing.T, cfg *config.Config, s *Server, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create "+cfg.Root)
				assert.Nil(s)
			},
		},
		{
			name: "store that cannot be opened",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.MkdirAll(filepath.Join(cfg.Root, "nydusd.db"), 0o755))
			},
			expect: func(t *testing.T, cfg *config.Config, s *Server, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "open store")
				assert.Nil(s)
			},
		},
		{
			name: "file system that cannot be built",
			prepare: func(t *testing.T, cfg *config.Config) {
				cfg.Nydusd.Driver = "ublk"
			},
			expect: func(t *testing.T, cfg *config.Config, s *Server, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "init nydus file system")
				assert.Nil(s)
			},
		},
		{
			name: "snapshotter that cannot be built",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.MkdirAll(cfg.Root, 0o700))
				assert.NoError(t, os.WriteFile(filepath.Join(cfg.Root, "snapshots"), nil, 0o644))
			},
			expect: func(t *testing.T, cfg *config.Config, s *Server, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "init snapshotter")
				assert.Nil(s)
			},
		},
		{
			name: "metrics address that cannot be bound",
			prepare: func(t *testing.T, cfg *config.Config) {
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				assert.NoError(t, err)
				t.Cleanup(func() { assert.NoError(t, listener.Close()) })
				cfg.Metrics.Address = listener.Addr().String()
			},
			expect: func(t *testing.T, cfg *config.Config, s *Server, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "listen metrics")
				assert.Nil(s)
			},
		},
		{
			name: "socket that another process serves",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.MkdirAll(filepath.Dir(cfg.Address), 0o700))
				listener, err := net.Listen("unix", cfg.Address)
				assert.NoError(t, err)
				t.Cleanup(func() { assert.NoError(t, listener.Close()) })
			},
			expect: func(t *testing.T, cfg *config.Config, s *Server, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is served by another process")
				assert.Nil(s)
				reopened, err := store.New(filepath.Join(cfg.Root, "nydusd.db"), time.Second)
				assert.NoError(err)
				assert.NoError(reopened.Close())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testutil.NewConfig(t)
			tc.prepare(t, cfg)
			s, err := New(t.Context(), cfg, filepath.Join(cfg.Root, "config.yaml"))
			tc.expect(t, cfg, s, err)
		})
	}
}

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
		{
			name: "socket directory that cannot be created",
			prepare: func(t *testing.T, address string) {
				assert.NoError(t, os.WriteFile(filepath.Dir(address), nil, 0o644))
			},
			expect: func(t *testing.T, address string, listener net.Listener, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create socket dir")
				assert.Nil(listener)
			},
		},
		{
			name: "stale socket that cannot be removed",
			prepare: func(t *testing.T, address string) {
				assert.NoError(t, os.MkdirAll(filepath.Join(address, "busy"), 0o700))
			},
			expect: func(t *testing.T, address string, listener net.Listener, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "remove stale socket")
				assert.Nil(listener)
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
				assert := assert.New(t)
				assert.NoError(err)
			},
		},
		{
			name: "grpc not serving",
			mock: func(m *authmocks.MockKeychainMockRecorder) {},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "grpc is not serving")
			},
		},
		{
			name:    "credentials not synced",
			serving: true,
			mock: func(m *authmocks.MockKeychainMockRecorder) {
				m.Synced().Return(false).Times(1)
			},
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "registry credentials are not synced")
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
				assert := assert.New(t)
				assert.Equal(config.DefaultCgroupMemoryMax, running.Cgroup.MemoryMax)
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
					return cfg.Cgroup.Slice == config.DefaultCgroupSlice && cfg.Nydusd.MountTimeout != 0
				})).Return(nil).Times(1)
			},
			expect: func(t *testing.T, running *config.Config) {
				assert := assert.New(t)
				assert.Equal(config.DefaultCgroupSlice, running.Cgroup.Slice)
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
				assert := assert.New(t)
				assert.Equal(config.New(), running)
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
