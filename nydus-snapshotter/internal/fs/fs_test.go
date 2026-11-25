/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"testing/synctest"
	"time"

	"github.com/containerd/errdefs"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	authmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/cache"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/kmutex"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/metrics"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd"
	nydusdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
	systemdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

var (
	mockID = strings.Repeat("ab", 32)

	mockChainID = "sha256:" + mockID

	mockUnit = "nydusd-" + mockID + ".service"

	mockOtherID = strings.Repeat("cd", 32)

	mockOtherUnit = "nydusd-" + mockOtherID + ".service"

	mockInvalidRef = "Registry.example.com/APP"

	mockCredential = "dXNlcjpwYXNz"

	mockRotatedCredential = "dXNlcjpyb3RhdGVk"

	mockDaemonInfo = &nydusd.Info{
		Version:      "3.0.0",
		GitCommit:    "1a2b3c4d5",
		PID:          42,
		Capabilities: []string{nydusd.CapabilityBackendAuthBasic},
	}

	mockInstance = &store.Instance{
		ChainID:      mockChainID,
		ImageRef:     "registry.example.com/team/app",
		RegistryHost: "registry.example.com",
		Unit:         mockUnit,
		APISocket:    "/run/nydus-snapshotter/nydusd/ab.sock",
		CreatedAt:    time.Unix(1700000000, 0).UTC(),
		Version:      "3.0.0",
		Capabilities: []string{nydusd.CapabilityBackendAuthBasic},
	}

	mockOtherInstance = &store.Instance{
		ChainID:      "sha256:" + mockOtherID,
		ImageRef:     "registry.example.com/team/other",
		RegistryHost: "registry.example.com",
		Unit:         mockOtherUnit,
		APISocket:    "/run/nydus-snapshotter/nydusd/cd.sock",
		CreatedAt:    time.Unix(1700000000, 0).UTC(),
		Version:      "3.0.0",
		Capabilities: []string{nydusd.CapabilityBackendAuthBasic},
	}

	mockBlobID = strings.Repeat("aa", 32)

	mockOtherBlobID = strings.Repeat("bb", 32)

	mockImageRef = "registry.example.com/team/app:v1-nydus-v3"

	mockRootFS = fstest.MapFS{
		"nydus":                               {Mode: 0o755},
		"bootstrap/fs/image/" + bootstrapFile: {Data: []byte("boot"), Mode: 0o644},
		"bootstrap/fs/image/" + mockBlobID + cache.BlobMetaSuffix: {Data: []byte("meta"), Mode: 0o644},
	}

	mockUsed = func(context.Context) (map[string]struct{}, error) {
		return map[string]struct{}{mockChainID: {}}, nil
	}

	mockUnused = func(context.Context) (map[string]struct{}, error) {
		return map[string]struct{}{}, nil
	}
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, cfg *config.Config)
		mock    func(m *systemdmocks.MockSystemdMockRecorder)
		expect  func(t *testing.T, cfg *config.Config, f FileSystem, err error)
	}{
		{
			name:    "start the slice and limit the daemons left running",
			prepare: func(t *testing.T, cfg *config.Config) {},
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				gomock.InOrder(
					m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(uint64(math.MaxUint64), nil).Times(1),
					m.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, systemd.Resources{MemoryMax: 8 << 30, MemoryHigh: 6 << 30, CPUQuotaPerSecUSec: 4_000_000}).Return(nil).Times(1),
					m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1),
					m.SetResources(gomock.Any(), mockUnit, systemd.Resources{MemoryHigh: 1 << 30, CPUQuotaPerSecUSec: 1_000_000}).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, cfg *config.Config, f FileSystem, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(f.(*fileSystem).limitsDeferred.Load())
				for _, dir := range []string{cfg.CacheDir(), cfg.DaemonInstancesDir(), cfg.DaemonRuntimesDir()} {
					info, err := os.Stat(dir)
					assert.NoError(err)
					assert.Equal(os.ModeDir|0o700, info.Mode())
				}
			},
		},
		{
			name:    "defer slice limits below the current usage",
			prepare: func(t *testing.T, cfg *config.Config) {},
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(uint64(9<<30), nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(nil, nil).Times(1)
			},
			expect: func(t *testing.T, cfg *config.Config, f FileSystem, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(f.(*fileSystem).limitsDeferred.Load())
			},
		},
		{
			name:    "retry daemon limits that fail on release",
			prepare: func(t *testing.T, cfg *config.Config) {},
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(uint64(math.MaxUint64), nil).Times(1)
				m.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, gomock.Any()).Return(nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, cfg *config.Config, f FileSystem, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(f.(*fileSystem).limitsDeferred.Load())
			},
		},
		{
			name:    "slice that cannot be started",
			prepare: func(t *testing.T, cfg *config.Config) {},
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(uint64(math.MaxUint64), nil).Times(1)
				m.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, gomock.Any()).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, cfg *config.Config, f FileSystem, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.Nil(f)
			},
		},
		{
			name: "unsupported driver",
			prepare: func(t *testing.T, cfg *config.Config) {
				cfg.Nydusd.Driver = "virtiofs"
			},
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, cfg *config.Config, f FileSystem, err error) {
				assert := assert.New(t)
				assert.EqualError(err, `unsupported driver "virtiofs"`)
				assert.Nil(f)
				assert.NoDirExists(cfg.CacheDir())
			},
		},
		{
			name: "dir that cannot be created",
			prepare: func(t *testing.T, cfg *config.Config) {
				assert.NoError(t, os.WriteFile(cfg.RootDir, nil, 0o644))
			},
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, cfg *config.Config, f FileSystem, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "create "+cfg.CacheDir())
				assert.Nil(f)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			mockSystemd := systemdmocks.NewMockSystemd(ctl)
			tc.mock(mockSystemd.EXPECT())

			root := t.TempDir()
			cfg := config.New()
			cfg.RootDir = filepath.Join(root, "lib")
			cfg.RuntimeDir = filepath.Join(root, "run")
			tc.prepare(t, cfg)

			s, err := store.New(filepath.Join(root, "nydusd.db"), store.DefaultOpenTimeout)
			assert.NoError(t, err)
			t.Cleanup(func() { s.Close() })

			f, err := New(t.Context(), cfg, mockSystemd, s, authmocks.NewMockKeychain(ctl), &sync.Mutex{})
			tc.expect(t, cfg, f, err)
		})
	}
}

func TestFileSystem_Mount(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit])
		expect func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit])
	}{
		{
			name: "start a daemon",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				mk.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(1)
				ms.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, unit *systemd.Unit) error {
					started.Store(unit)
					mounted.Store(true)
					return nil
				}).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
				mc.Info(gomock.Any()).Return(mockDaemonInfo, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				cfg := f.cfg.Load()
				id := mockID
				starts, failures := testutil.ToFloat64(metrics.DaemonStartsTotal), testutil.ToFloat64(metrics.DaemonStartFailuresTotal)
				mountpoint, err := f.Mount(t.Context(), image)
				assert.NoError(err)
				assert.Equal(filepath.Join(cfg.DaemonInstanceDir(id), "mnt"), mountpoint)
				assert.Equal(starts+1, testutil.ToFloat64(metrics.DaemonStartsTotal))
				assert.Equal(failures, testutil.ToFloat64(metrics.DaemonStartFailuresTotal))

				instance, err := f.store.GetInstance(mockChainID)
				assert.NoError(err)
				assert.Equal("registry.example.com", instance.RegistryHost)
				assert.Equal([]string{mockBlobID}, instance.Blobs)
				assert.Equal(mockDaemonInfo.Version, instance.Version)
				assert.Equal(mockDaemonInfo.Capabilities, instance.Capabilities)
				assert.FileExists(instance.Bootstrap)
				assert.FileExists(filepath.Join(cfg.CacheDir(), mockBlobID+cache.BlobMetaSuffix))

				rendered, err := os.ReadFile(filepath.Join(cfg.DaemonRuntimeDir(id), "config.yaml"))
				assert.NoError(err)
				assert.Contains(string(rendered), "auth: dXNlcjpwYXNz")
				assert.Contains(string(rendered), "repository: team/app")
				assert.Contains(string(rendered), "scope: all")
				info, err := os.Stat(filepath.Join(cfg.DaemonRuntimeDir(id), "config.yaml"))
				assert.NoError(err)
				assert.Equal(os.FileMode(0o600), info.Mode().Perm())

				unit := started.Load()
				assert.Equal(mockUnit, unit.Name)
				assert.Equal(config.DefaultCgroupSlice, unit.Slice)
				assert.Equal(cfg.Nydusd.Binary, unit.ExecStart[0])
				assert.Contains(unit.Before, "containerd.service")
				assert.True(unit.Notify)
				assert.Equal(time.Duration(cfg.Nydusd.MountTimeout), unit.TimeoutStart)
				assert.Equal(time.Duration(config.DefaultNydusdWatchdogTimeout), unit.Watchdog)
				assert.NotContains(strings.Join(unit.ExecStart, " "), mockCredential)
			},
		},
		{
			name: "reuse a ready daemon",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				mounted.Store(true)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
				mc.Info(gomock.Any()).Return(mockDaemonInfo, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.NoError(err)
				instance, err := f.store.GetInstance(mockChainID)
				assert.NoError(err)
				assert.Equal(mockUnit, instance.Unit)
				assert.Equal(mockDaemonInfo.Version, instance.Version)
			},
		},
		{
			name: "reuse a recorded daemon without asking it again",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				mounted.Store(true)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				assert.NoError(f.store.PutInstance(&store.Instance{ChainID: mockChainID, Unit: mockUnit, Version: "2.9.0"}))
				_, err := f.Mount(t.Context(), image)
				assert.NoError(err)
				instance, err := f.store.GetInstance(mockChainID)
				assert.NoError(err)
				assert.Equal("2.9.0", instance.Version)
			},
		},
		{
			name: "complete the record of a running daemon whose version is unknown",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				mounted.Store(true)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
				mc.Info(gomock.Any()).Return(mockDaemonInfo, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				assert.NoError(f.store.PutInstance(&store.Instance{ChainID: mockChainID, Unit: mockUnit}))
				_, err := f.Mount(t.Context(), image)
				assert.NoError(err)
				instance, err := f.store.GetInstance(mockChainID)
				assert.NoError(err)
				assert.Equal(mockDaemonInfo.Version, instance.Version)
				assert.Equal(mockDaemonInfo.Capabilities, instance.Capabilities)
			},
		},
		{
			name: "refuse a daemon of another api version",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				mk.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(2)
				ms.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					mounted.Store(true)
					return nil
				}).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
				mc.Info(gomock.Any()).Return(nil, fmt.Errorf("GET /api/v1/daemon: %w", errdefs.ErrNotImplemented)).Times(1)
				ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.ErrorIs(err, errdefs.ErrFailedPrecondition)
				assert.NotErrorIs(err, errdefs.ErrNotImplemented)
				assert.ErrorContains(err, "must be of one release")
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "report a running daemon that does not answer as unavailable",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				mounted.Store(true)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				mc.Ready(gomock.Any()).Return(errors.New("busy")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.ErrorIs(err, errdefs.ErrUnavailable)
			},
		},
		{
			name: "fail fast before credentials sync",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(false).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				starts := testutil.ToFloat64(metrics.DaemonStartsTotal)
				_, err := f.Mount(t.Context(), image)
				assert.ErrorIs(err, errdefs.ErrUnavailable)
				assert.NoDirExists(f.cfg.Load().DaemonInstanceDir(mockID))
				assert.Equal(starts, testutil.ToFloat64(metrics.DaemonStartsTotal))
			},
		},
		{
			name: "fail fast on an invalid image reference",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				image.Ref = mockInvalidRef
				_, err := f.Mount(t.Context(), image)
				assert.Error(err)
				assert.NoDirExists(f.cfg.Load().DaemonInstanceDir(mockID))
			},
		},
		{
			name: "clean up a daemon that fails to start",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				mk.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(2)
				ms.StartTransientUnit(gomock.Any(), gomock.Any()).Return(errors.New("job failed")).Times(1)
				ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				starts, failures := testutil.ToFloat64(metrics.DaemonStartsTotal), testutil.ToFloat64(metrics.DaemonStartFailuresTotal)
				_, err := f.Mount(t.Context(), image)
				assert.ErrorContains(err, "job failed, see journalctl -u "+mockUnit)
				assert.Equal(starts+1, testutil.ToFloat64(metrics.DaemonStartsTotal))
				assert.Equal(failures+1, testutil.ToFloat64(metrics.DaemonStartFailuresTotal))
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "stop a daemon that reports ready without its mount",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				mk.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(2)
				ms.StartTransientUnit(gomock.Any(), gomock.Any()).Return(nil).Times(1)
				ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.ErrorContains(err, "is not mounted")
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "stop a daemon that reports ready without its api",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				mk.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(2)
				ms.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					mounted.Store(true)
					return nil
				}).Times(1)
				mc.Ready(gomock.Any()).Return(errors.New("foo")).Times(1)
				ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.ErrorContains(err, "reported ready but is not: foo")
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "bound the wait for another start of the image",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				cfg := *f.cfg.Load()
				cfg.Nydusd.MountTimeout = config.Duration(100 * time.Millisecond)
				f.cfg.Store(&cfg)
				id := mockID
				assert.NoError(f.locker.Lock(t.Context(), id))
				defer f.locker.Unlock(id)

				_, err := f.Mount(t.Context(), image)
				assert.ErrorIs(err, context.DeadlineExceeded)
				assert.ErrorContains(err, "lock daemon")
			},
		},
		{
			name: "start one daemon for concurrent mounts",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).DoAndReturn(func(context.Context, string) (systemd.ActiveState, error) {
					if mounted.Load() {
						return systemd.ActiveStateActive, nil
					}

					return systemd.ActiveStateInactive, nil
				}).AnyTimes()
				mk.Synced().Return(true).Times(1)
				mk.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(1)
				ms.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					mounted.Store(true)
					return nil
				}).Times(1)
				mc.Ready(gomock.Any()).Return(nil).AnyTimes()
				mc.Info(gomock.Any()).Return(mockDaemonInfo, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				var wg sync.WaitGroup
				errs := make(chan error, 50)
				for range 50 {
					wg.Go(func() {
						_, err := f.Mount(t.Context(), image)
						errs <- err
					})
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					assert.NoError(err)
				}
			},
		},
		{
			name: "invalid chain id",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				image.ChainID = "sha512:" + strings.Repeat("ab", 64)
				_, err := f.Mount(t.Context(), image)
				assert.ErrorIs(err, errdefs.ErrInvalidArgument)
			},
		},
		{
			name: "unit state cannot be read",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveState(""), errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.EqualError(err, "wait for unit "+mockUnit+" to settle: foo")
			},
		},
		{
			name: "request done while a running daemon is checked",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				mounted.Store(true)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				mc.Ready(gomock.Any()).DoAndReturn(func(ctx context.Context) error {
					<-ctx.Done()
					return ctx.Err()
				}).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
				defer cancel()
				_, err := f.Mount(ctx, image)
				assert.ErrorIs(err, context.DeadlineExceeded)
				assert.ErrorContains(err, "check daemon "+mockUnit)
				assert.NotErrorIs(err, errdefs.ErrUnavailable)
			},
		},
		{
			name: "running daemon whose image reference is invalid",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				mounted.Store(true)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				image.Ref = mockInvalidRef
				_, err := f.Mount(t.Context(), image)
				assert.Error(err)
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "running daemon whose bootstrap layer is gone",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				mounted.Store(true)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				assert.NoError(os.RemoveAll(image.BootstrapDir))
				_, err := f.Mount(t.Context(), image)
				assert.ErrorIs(err, os.ErrNotExist)
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "running daemon that cannot be identified",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				mounted.Store(true)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
				mc.Info(gomock.Any()).Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.EqualError(err, "identify daemon "+mockUnit+": foo")
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "running daemon whose record cannot be read",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				mounted.Store(true)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				assert.NoError(f.store.Close())
				_, err := f.Mount(t.Context(), image)
				assert.Error(err)
				assert.NotErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "stale mount that cannot be detached",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				gomock.InOrder(
					md.Unmount(gomock.Any()).Return(errors.New("foo")).Times(1),
					ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1),
					md.Unmount(gomock.Any()).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.EqualError(err, "foo")
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "stale api socket that cannot be removed",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(2)
				ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				socket := f.cfg.Load().APISocket(mockID)
				assert.NoError(os.MkdirAll(filepath.Join(socket, "child"), 0o700))
				_, err := f.Mount(t.Context(), image)
				assert.ErrorContains(err, "remove stale api socket")
				assert.NoDirExists(socket)
			},
		},
		{
			name: "daemon dir that cannot be created",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(2)
				ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				cfg := f.cfg.Load()
				dir := cfg.DaemonRuntimeDir(mockID)
				assert.NoError(os.MkdirAll(filepath.Dir(dir), 0o700))
				assert.NoError(os.WriteFile(dir, nil, 0o644))
				_, err := f.Mount(t.Context(), image)
				assert.ErrorContains(err, "create "+dir)
				assert.NoDirExists(cfg.DaemonInstanceDir(mockID))
			},
		},
		{
			name: "bootstrap layer without a bootstrap",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(2)
				ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				assert.NoError(os.Remove(filepath.Join(image.BootstrapDir, "image", bootstrapFile)))
				_, err := f.Mount(t.Context(), image)
				assert.ErrorIs(err, os.ErrNotExist)
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "record that cannot be written",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(2)
				ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				assert.NoError(f.store.Close())
				_, err := f.Mount(t.Context(), image)
				assert.ErrorContains(err, "record instance")
			},
		},
		{
			name: "credential that cannot be resolved",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(2)
				ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
				mk.Resolve(gomock.Any(), gomock.Any()).Return("", errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.ErrorContains(err, "resolve credential of")
				assert.NoFileExists(filepath.Join(f.cfg.Load().DaemonRuntimeDir(mockID), "config.yaml"))
			},
		},
		{
			name: "nydus binary that is missing",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(2)
				ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
				mk.Resolve(gomock.Any(), gomock.Any()).Return(mockCredential, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				cfg := f.cfg.Load()
				assert.NoError(os.Remove(cfg.Nydusd.Binary))
				_, err := f.Mount(t.Context(), image)
				assert.ErrorContains(err, "resolve nydus binary")
				assert.NoDirExists(cfg.DaemonRuntimeDir(mockID))
			},
		},
		{
			name: "stop a daemon that cannot be identified after its start",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(2)
				ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
				mk.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
				ms.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					mounted.Store(true)
					return nil
				}).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
				mc.Info(gomock.Any()).Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.EqualError(err, "identify daemon "+mockUnit+": foo")
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "report the start failure when the cleanup fails too",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				mk.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(1)
				ms.StartTransientUnit(gomock.Any(), gomock.Any()).Return(errors.New("job failed")).Times(1)
				ms.StopUnit(gomock.Any(), mockUnit).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.ErrorContains(err, "job failed")
				assert.NotContains(err.Error(), "foo")
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
			},
		},
		{
			name: "blob cache dir that is gone",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(2)
				ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				assert.NoError(os.Remove(f.cfg.Load().CacheDir()))
				_, err := f.Mount(t.Context(), image)
				assert.ErrorContains(err, "link ")
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "apply the limits of a config reloaded while the daemon started",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				mk.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(1)
				ms.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					cfg := *f.cfg.Load()
					cfg.Cgroup.Daemon.MemoryHigh = 2 << 30
					f.cfg.Store(&cfg)
					mounted.Store(true)
					return nil
				}).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
				mc.Info(gomock.Any()).Return(mockDaemonInfo, nil).Times(1)
				ms.SetResources(gomock.Any(), mockUnit, systemd.Resources{MemoryHigh: 2 << 30}).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.NoError(err)
			},
		},
		{
			name: "keep a daemon whose reloaded limits cannot be applied",
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, mk *authmocks.MockKeychainMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, f *fileSystem, mounted *atomic.Bool, started *atomic.Pointer[systemd.Unit]) {
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				mk.Synced().Return(true).Times(1)
				mk.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
				md.Unmount(gomock.Any()).Return(nil).Times(1)
				ms.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					cfg := *f.cfg.Load()
					f.cfg.Store(&cfg)
					mounted.Store(true)
					return nil
				}).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
				mc.Info(gomock.Any()).Return(mockDaemonInfo, nil).Times(1)
				ms.SetResources(gomock.Any(), mockUnit, gomock.Any()).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.NoError(err)
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			mockSystemd := systemdmocks.NewMockSystemd(ctl)
			keychain := authmocks.NewMockKeychain(ctl)
			driver := NewMockDriver(ctl)
			client := nydusdmocks.NewMockClient(ctl)
			var (
				mounted atomic.Bool
				started atomic.Pointer[systemd.Unit]
			)
			driver.EXPECT().Name().Return(config.DriverFUSE).AnyTimes()
			driver.EXPECT().Args(gomock.Any()).Return([]string{"fuse"}).AnyTimes()
			driver.EXPECT().Mounted(gomock.Any()).DoAndReturn(func(*Daemon) (bool, error) { return mounted.Load(), nil }).AnyTimes()

			root := t.TempDir()
			cfg := config.New()
			cfg.RootDir = filepath.Join(root, "lib")
			cfg.RuntimeDir = filepath.Join(root, "run")
			cfg.Registry.ConfigPath = ""
			cfg.Nydusd.Binary = filepath.Join(root, "nydus")
			cfg.Nydusd.MountTimeout = config.Duration(2 * time.Second)
			cfg.Cgroup = config.CgroupConfig{Slice: config.DefaultCgroupSlice}
			assert.NoError(t, os.CopyFS(root, mockRootFS))
			assert.NoError(t, os.MkdirAll(cfg.CacheDir(), 0o700))

			s, err := store.New(filepath.Join(root, "nydusd.db"), store.DefaultOpenTimeout)
			assert.NoError(t, err)
			t.Cleanup(func() { s.Close() })

			f := &fileSystem{
				systemd:   mockSystemd,
				store:     s,
				keychain:  keychain,
				hosts:     registry.NewHosts(""),
				driver:    driver,
				newClient: func(string) nydusd.Client { return client },
				locker:    kmutex.New(),
				startLock: &sync.Mutex{},
				preheats:  newPreheatQueue(cfg.Preheat.MaxConcurrentImages),
			}
			f.cfg.Store(cfg)
			image := &Image{ChainID: mockChainID, Ref: mockImageRef, BootstrapDir: filepath.Join(root, "bootstrap", "fs"), PrefetchScope: "all"}

			tc.mock(mockSystemd.EXPECT(), keychain.EXPECT(), driver.EXPECT(), client.EXPECT(), f, &mounted, &started)
			tc.expect(t, f, image, &started)
		})
	}
}

func TestFileSystem_Release(t *testing.T) {
	tests := []struct {
		name         string
		used         []UsedFunc
		runtimeDir   bool
		deferred     bool
		unresponsive bool
		canceled     bool
		prepare      func(t *testing.T, f *fileSystem, d *Daemon)
		mock         func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc)
		expect       func(t *testing.T, f *fileSystem, d *Daemon, err error)
	}{
		{
			name: "stop an unused daemon",
			used: []UsedFunc{mockUnused},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				gomock.InOrder(
					ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1),
					md.Unmount(gomock.Any()).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "keep a used daemon without asking systemd again",
			used: []UsedFunc{mockUsed},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
			},
		},
		{
			name:       "keep the record of a used daemon that exited",
			used:       []UsedFunc{mockUsed},
			runtimeDir: true,
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{}, nil).Times(1)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
				_, counted := f.exited.Load(d.id)
				assert.True(counted)
			},
		},
		{
			name: "keep the record of a used daemon gone with a reboot",
			used: []UsedFunc{mockUsed},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{}, nil).Times(1)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
				_, counted := f.exited.Load(d.id)
				assert.False(counted)
			},
		},
		{
			name: "forget an unused daemon gone with a reboot",
			used: []UsedFunc{mockUnused},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{}, nil).Times(1)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				gomock.InOrder(
					ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1),
					md.Unmount(gomock.Any()).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name:       "count a used daemon that exited once across passes",
			used:       []UsedFunc{mockUsed},
			runtimeDir: true,
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{}, nil).Times(2)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(2)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				exits := testutil.ToFloat64(metrics.DaemonUnexpectedExitsTotal)
				assert.NoError(f.Release(t.Context(), mockUsed))
				assert.Equal(exits, testutil.ToFloat64(metrics.DaemonUnexpectedExitsTotal))
			},
		},
		{
			name: "report a used daemon that does not answer",
			used: []UsedFunc{mockUsed},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				mc.Ready(gomock.Any()).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, reported := f.unresponsive.Load(d.id)
				assert.True(reported)
				assert.Equal(float64(1), testutil.ToFloat64(metrics.UnresponsiveDaemons))
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
			},
		},
		{
			name:         "forget a used daemon that answers again",
			used:         []UsedFunc{mockUsed},
			unresponsive: true,
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, reported := f.unresponsive.Load(d.id)
				assert.False(reported)
				assert.Zero(testutil.ToFloat64(metrics.UnresponsiveDaemons))
			},
		},
		{
			name:         "forget an unresponsive daemon that is gone",
			used:         []UsedFunc{mockUnused},
			unresponsive: true,
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{}, nil).Times(1)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				gomock.InOrder(
					ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1),
					md.Unmount(gomock.Any()).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, reported := f.unresponsive.Load(d.id)
				assert.False(reported)
				assert.Zero(testutil.ToFloat64(metrics.UnresponsiveDaemons))
			},
		},
		{
			name:     "retry deferred limits",
			used:     []UsedFunc{mockUsed},
			deferred: true,
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, gomock.Any()).Return(nil).Times(1)
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(2)
				ms.SetResources(gomock.Any(), mockUnit, gomock.Any()).Return(nil).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(f.limitsDeferred.Load())
			},
		},
		{
			name:     "keep limits deferred while they fail",
			used:     []UsedFunc{mockUsed},
			deferred: true,
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, gomock.Any()).Return(errors.New("foo")).Times(1)
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				mc.Ready(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(f.limitsDeferred.Load())
			},
		},
		{
			name: "report a failing usage check",
			used: []UsedFunc{func(context.Context) (map[string]struct{}, error) {
				return map[string]struct{}{}, errors.New("metadata unavailable")
			}},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{}, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "metadata unavailable")
			},
		},
		{
			name: "units cannot be listed",
			used: []UsedFunc{mockUnused},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
			},
		},
		{
			name: "records cannot be listed",
			used: []UsedFunc{mockUnused},
			prepare: func(t *testing.T, f *fileSystem, d *Daemon) {
				assert.NoError(t, f.store.Close())
			},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
		{
			name: "daemon state cannot be read",
			used: []UsedFunc{mockUnused},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveState(""), errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "release "+mockUnit+": foo")
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
			},
		},
		{
			name: "keep a daemon a container took while the pass ran",
			used: []UsedFunc{mockUnused, mockUsed},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
			},
		},
		{
			name: "usage cannot be told under the lock of the daemon",
			used: []UsedFunc{mockUnused, func(context.Context) (map[string]struct{}, error) {
				return map[string]struct{}{}, errors.New("foo")
			}},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "release "+mockUnit+": foo")
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
			},
		},
		{
			name:     "pass that ended before the lock of the daemon",
			used:     []UsedFunc{mockUnused},
			canceled: true,
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
			},
		},
		{
			name:     "pass that ended probes no daemon in use",
			used:     []UsedFunc{mockUsed},
			canceled: true,
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				_, reported := f.unresponsive.Load(d.id)
				assert.False(reported)
			},
		},
		{
			name: "pass that ended during a probe tells nothing about the daemon",
			used: []UsedFunc{mockUsed},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				mc.Ready(gomock.Any()).DoAndReturn(func(context.Context) error {
					cancel()
					return context.Canceled
				}).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, context.Canceled)
				_, reported := f.unresponsive.Load(d.id)
				assert.False(reported)
			},
		},
		{
			name: "keep the record of a daemon that cannot be stopped",
			used: []UsedFunc{mockUnused},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				ms.StopUnit(gomock.Any(), mockUnit).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "release "+mockUnit+": foo")
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
			},
		},
		{
			name: "keep the record of a daemon whose mount cannot be detached",
			used: []UsedFunc{mockUnused},
			mock: func(ms *systemdmocks.MockSystemdMockRecorder, md *MockDriverMockRecorder, mc *nydusdmocks.MockClientMockRecorder, cancel context.CancelFunc) {
				ms.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				ms.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				gomock.InOrder(
					ms.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1),
					md.Unmount(gomock.Any()).Return(errors.New("foo")).Times(1),
				)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "release "+mockUnit+": foo")
				_, err = f.store.GetInstance(mockChainID)
				assert.NoError(err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			mockSystemd := systemdmocks.NewMockSystemd(ctl)
			driver := NewMockDriver(ctl)
			client := nydusdmocks.NewMockClient(ctl)
			mounted := &atomic.Bool{}
			mounted.Store(true)
			driver.EXPECT().Name().Return(config.DriverFUSE).AnyTimes()
			driver.EXPECT().Args(gomock.Any()).Return([]string{"fuse"}).AnyTimes()
			driver.EXPECT().Mounted(gomock.Any()).DoAndReturn(func(*Daemon) (bool, error) { return mounted.Load(), nil }).AnyTimes()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			tc.mock(mockSystemd.EXPECT(), driver.EXPECT(), client.EXPECT(), cancel)

			root := t.TempDir()
			cfg := config.New()
			cfg.RootDir = filepath.Join(root, "lib")
			cfg.RuntimeDir = filepath.Join(root, "run")
			cfg.Registry.ConfigPath = ""
			cfg.Nydusd.Binary = filepath.Join(root, "nydus")
			cfg.Nydusd.MountTimeout = config.Duration(2 * time.Second)
			cfg.Cgroup = config.CgroupConfig{Slice: config.DefaultCgroupSlice}
			assert.NoError(t, os.CopyFS(root, mockRootFS))
			assert.NoError(t, os.MkdirAll(cfg.CacheDir(), 0o700))

			s, err := store.New(filepath.Join(root, "nydusd.db"), store.DefaultOpenTimeout)
			assert.NoError(t, err)
			t.Cleanup(func() { s.Close() })

			f := &fileSystem{
				systemd:   mockSystemd,
				store:     s,
				keychain:  authmocks.NewMockKeychain(ctl),
				hosts:     registry.NewHosts(""),
				driver:    driver,
				newClient: func(string) nydusd.Client { return client },
				locker:    kmutex.New(),
				startLock: &sync.Mutex{},
				preheats:  newPreheatQueue(cfg.Preheat.MaxConcurrentImages),
			}
			f.cfg.Store(cfg)

			id, err := daemonIDFromChainID(mockChainID)
			assert.NoError(t, err)
			if tc.unresponsive {
				f.unresponsive.Store(id, struct{}{})
			}

			d := f.daemon(f.cfg.Load(), id)
			assert.NoError(t, f.store.PutInstance(d.Instance))
			if tc.runtimeDir {
				assert.NoError(t, os.MkdirAll(d.RuntimeDir, 0o700))
			}

			f.limitsDeferred.Store(tc.deferred)
			if tc.prepare != nil {
				tc.prepare(t, f, d)
			}

			if tc.canceled {
				cancel()
			}

			calls := 0
			tc.expect(t, f, d, f.Release(ctx, func(ctx context.Context) (map[string]struct{}, error) {
				calls++
				return tc.used[min(calls, len(tc.used))-1](ctx)
			}))
		})
	}
}

func TestFileSystem_MountRelease(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, f *fileSystem, image *Image, starting chan struct{}, proceed chan struct{})
	}{
		{
			name: "keep a daemon a concurrent mount is starting",
			expect: func(t *testing.T, f *fileSystem, image *Image, starting chan struct{}, proceed chan struct{}) {
				assert := assert.New(t)
				mounted := make(chan error, 1)
				go func() {
					_, err := f.Mount(t.Context(), image)
					mounted <- err
				}()

				<-starting
				released := make(chan error, 1)
				go func() {
					released <- f.Release(t.Context(), func(context.Context) (map[string]struct{}, error) {
						return map[string]struct{}{mockChainID: {}}, nil
					})
				}()

				close(proceed)
				assert.NoError(<-mounted)
				assert.NoError(<-released)
				_, err := f.store.GetInstance(mockChainID)
				assert.NoError(err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			mockSystemd := systemdmocks.NewMockSystemd(ctl)
			keychain := authmocks.NewMockKeychain(ctl)
			driver := NewMockDriver(ctl)
			client := nydusdmocks.NewMockClient(ctl)
			var mounted atomic.Bool
			driver.EXPECT().Name().Return(config.DriverFUSE).AnyTimes()
			driver.EXPECT().Args(gomock.Any()).Return([]string{"fuse"}).AnyTimes()
			driver.EXPECT().Mounted(gomock.Any()).DoAndReturn(func(*Daemon) (bool, error) { return mounted.Load(), nil }).AnyTimes()

			starting, proceed := make(chan struct{}), make(chan struct{})
			state := func(context.Context, string) (systemd.ActiveState, error) {
				if mounted.Load() {
					return systemd.ActiveStateActive, nil
				}

				return systemd.ActiveStateInactive, nil
			}
			mockSystemd.EXPECT().ActiveState(gomock.Any(), mockUnit).DoAndReturn(state).AnyTimes()
			mockSystemd.EXPECT().ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).DoAndReturn(func(ctx context.Context, _, _ string) (map[string]systemd.ActiveState, error) {
				active, err := state(ctx, mockUnit)
				return map[string]systemd.ActiveState{mockUnit: active}, err
			}).AnyTimes()
			mockSystemd.EXPECT().StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
				close(starting)
				<-proceed
				mounted.Store(true)
				return nil
			}).Times(1)
			mockSystemd.EXPECT().StopUnit(gomock.Any(), gomock.Any()).Times(0)
			keychain.EXPECT().Synced().Return(true).AnyTimes()
			keychain.EXPECT().Resolve(gomock.Any(), gomock.Any()).Return("", nil).AnyTimes()
			driver.EXPECT().Unmount(gomock.Any()).Return(nil).AnyTimes()
			client.EXPECT().Ready(gomock.Any()).Return(nil).AnyTimes()
			client.EXPECT().Info(gomock.Any()).Return(mockDaemonInfo, nil).Times(1)

			root := t.TempDir()
			cfg := config.New()
			cfg.RootDir = filepath.Join(root, "lib")
			cfg.RuntimeDir = filepath.Join(root, "run")
			cfg.Registry.ConfigPath = ""
			cfg.Nydusd.Binary = filepath.Join(root, "nydus")
			cfg.Nydusd.MountTimeout = config.Duration(2 * time.Second)
			cfg.Cgroup = config.CgroupConfig{Slice: config.DefaultCgroupSlice}
			assert.NoError(t, os.CopyFS(root, mockRootFS))
			assert.NoError(t, os.MkdirAll(cfg.CacheDir(), 0o700))

			s, err := store.New(filepath.Join(root, "nydusd.db"), store.DefaultOpenTimeout)
			assert.NoError(t, err)
			t.Cleanup(func() { s.Close() })

			f := &fileSystem{
				systemd:   mockSystemd,
				store:     s,
				keychain:  keychain,
				hosts:     registry.NewHosts(""),
				driver:    driver,
				newClient: func(string) nydusd.Client { return client },
				locker:    kmutex.New(),
				startLock: &sync.Mutex{},
				preheats:  newPreheatQueue(cfg.Preheat.MaxConcurrentImages),
			}
			f.cfg.Store(cfg)
			image := &Image{ChainID: mockChainID, Ref: mockImageRef, BootstrapDir: filepath.Join(root, "bootstrap", "fs"), PrefetchScope: "all"}

			tc.expect(t, f, image, starting, proceed)
		})
	}
}

func TestFileSystem_ReleaseConcurrent(t *testing.T) {
	tests := []struct {
		name   string
		count  int
		mock   func(m *systemdmocks.MockSystemdMockRecorder, ids []daemonID, stopping *atomic.Int32, proceed <-chan struct{})
		expect func(t *testing.T, f *fileSystem, ids []daemonID, stopping int32, err error)
	}{
		{
			name:  "stop unused daemons at once within the limit",
			count: 2 * daemonConcurrency,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, ids []daemonID, stopping *atomic.Int32, proceed <-chan struct{}) {
				m.StopUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, string) error {
					stopping.Add(1)
					<-proceed
					return nil
				}).Times(len(ids))
			},
			expect: func(t *testing.T, f *fileSystem, ids []daemonID, stopping int32, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.EqualValues(daemonConcurrency, stopping)
				instances, err := f.store.ListInstances()
				assert.NoError(err)
				assert.Empty(instances)
			},
		},
		{
			name:  "report every daemon that fails to stop and stop the others",
			count: 3,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, ids []daemonID, stopping *atomic.Int32, proceed <-chan struct{}) {
				m.StopUnit(gomock.Any(), ids[0].Unit()).Return(errors.New("foo")).Times(1)
				m.StopUnit(gomock.Any(), ids[1].Unit()).Return(errors.New("bar")).Times(1)
				m.StopUnit(gomock.Any(), ids[2].Unit()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, ids []daemonID, stopping int32, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, fmt.Sprintf("release %s: foo", ids[0].Unit()))
				assert.ErrorContains(err, fmt.Sprintf("release %s: bar", ids[1].Unit()))
				instances, err := f.store.ListInstances()
				assert.NoError(err)
				assert.Len(instances, 2)
				_, err = f.store.GetInstance(ids[2].ChainID())
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctl := gomock.NewController(t)
				defer ctl.Finish()
				mockSystemd := systemdmocks.NewMockSystemd(ctl)
				driver := NewMockDriver(ctl)
				driver.EXPECT().Name().Return(config.DriverFUSE).AnyTimes()
				driver.EXPECT().Args(gomock.Any()).Return([]string{"fuse"}).AnyTimes()
				driver.EXPECT().Mounted(gomock.Any()).Return(false, nil).AnyTimes()
				driver.EXPECT().Unmount(gomock.Any()).Return(nil).AnyTimes()

				ids := make([]daemonID, tc.count)
				units := make(map[string]systemd.ActiveState, tc.count)
				for i := range ids {
					id, err := daemonIDFromChainID(fmt.Sprintf("sha256:%064x", i))
					assert.NoError(t, err)
					ids[i] = id
					units[id.Unit()] = systemd.ActiveStateActive
				}

				stopping, proceed := &atomic.Int32{}, make(chan struct{})
				mockSystemd.EXPECT().ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(units, nil).Times(1)
				mockSystemd.EXPECT().ActiveState(gomock.Any(), gomock.Any()).Return(systemd.ActiveStateActive, nil).Times(tc.count)
				tc.mock(mockSystemd.EXPECT(), ids, stopping, proceed)

				root := t.TempDir()
				cfg := config.New()
				cfg.RootDir = filepath.Join(root, "lib")
				cfg.RuntimeDir = filepath.Join(root, "run")
				cfg.Registry.ConfigPath = ""
				cfg.Nydusd.Binary = filepath.Join(root, "nydus")
				cfg.Nydusd.MountTimeout = config.Duration(2 * time.Second)
				cfg.Cgroup = config.CgroupConfig{Slice: config.DefaultCgroupSlice}
				assert.NoError(t, os.CopyFS(root, mockRootFS))
				assert.NoError(t, os.MkdirAll(cfg.CacheDir(), 0o700))

				s, err := store.New(filepath.Join(root, "nydusd.db"), store.DefaultOpenTimeout)
				assert.NoError(t, err)
				t.Cleanup(func() { s.Close() })

				f := &fileSystem{
					systemd:   mockSystemd,
					store:     s,
					keychain:  authmocks.NewMockKeychain(ctl),
					hosts:     registry.NewHosts(""),
					driver:    driver,
					newClient: func(string) nydusd.Client { return nydusdmocks.NewMockClient(ctl) },
					locker:    kmutex.New(),
					startLock: &sync.Mutex{},
					preheats:  newPreheatQueue(cfg.Preheat.MaxConcurrentImages),
				}
				f.cfg.Store(cfg)

				for _, id := range ids {
					assert.NoError(t, f.store.PutInstance(f.daemon(f.cfg.Load(), id).Instance))
				}

				released := make(chan error, 1)
				go func() {
					released <- f.Release(t.Context(), mockUnused)
				}()

				synctest.Wait()
				blocked := stopping.Load()
				close(proceed)
				tc.expect(t, f, ids, blocked, <-released)
			})
		})
	}
}

func TestFileSystem_RunningBlobs(t *testing.T) {
	tests := []struct {
		name      string
		instances []*store.Instance
		closed    bool
		mock      func(m *systemdmocks.MockSystemdMockRecorder)
		expect    func(t *testing.T, blobs map[string]struct{}, err error)
	}{
		{
			name:      "blobs of every recorded daemon",
			instances: []*store.Instance{{ChainID: mockChainID, Unit: mockUnit, Blobs: []string{"aaaa", "bbbb"}}},
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
			},
			expect: func(t *testing.T, blobs map[string]struct{}, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[string]struct{}{"aaaa": {}, "bbbb": {}}, blobs)
			},
		},
		{
			name: "no blobs without records",
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{}, nil).Times(1)
			},
			expect: func(t *testing.T, blobs map[string]struct{}, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(blobs)
			},
		},
		{
			name: "daemon running without a record",
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
			},
			expect: func(t *testing.T, blobs map[string]struct{}, err error) {
				assert := assert.New(t)
				assert.ErrorIs(err, errdefs.ErrFailedPrecondition)
				assert.Nil(blobs)
			},
		},
		{
			name: "stopped unit without a record",
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateFailed}, nil).Times(1)
			},
			expect: func(t *testing.T, blobs map[string]struct{}, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(blobs)
			},
		},
		{
			name: "units cannot be listed",
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, blobs map[string]struct{}, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.Nil(blobs)
			},
		},
		{
			name:      "records cannot be read",
			instances: []*store.Instance{{ChainID: mockChainID, Unit: mockUnit, Blobs: []string{"aaaa"}}},
			closed:    true,
			mock:      func(m *systemdmocks.MockSystemdMockRecorder) {},
			expect: func(t *testing.T, blobs map[string]struct{}, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.Nil(blobs)
			},
		},
		{
			name:      "unit that is no daemon",
			instances: []*store.Instance{{ChainID: mockChainID, Unit: mockUnit, Blobs: []string{"aaaa"}}},
			mock: func(m *systemdmocks.MockSystemdMockRecorder) {
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive, "nydusd-helper.service": systemd.ActiveStateActive}, nil).Times(1)
			},
			expect: func(t *testing.T, blobs map[string]struct{}, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[string]struct{}{"aaaa": {}}, blobs)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			mockSystemd := systemdmocks.NewMockSystemd(ctl)
			tc.mock(mockSystemd.EXPECT())

			root := t.TempDir()
			cfg := config.New()
			cfg.RootDir = filepath.Join(root, "lib")
			cfg.RuntimeDir = filepath.Join(root, "run")
			cfg.Registry.ConfigPath = ""
			cfg.Nydusd.Binary = filepath.Join(root, "nydus")
			cfg.Nydusd.MountTimeout = config.Duration(2 * time.Second)
			cfg.Cgroup = config.CgroupConfig{Slice: config.DefaultCgroupSlice}
			assert.NoError(t, os.CopyFS(root, mockRootFS))
			assert.NoError(t, os.MkdirAll(cfg.CacheDir(), 0o700))

			s, err := store.New(filepath.Join(root, "nydusd.db"), store.DefaultOpenTimeout)
			assert.NoError(t, err)
			t.Cleanup(func() { s.Close() })

			f := &fileSystem{
				systemd:   mockSystemd,
				store:     s,
				keychain:  authmocks.NewMockKeychain(ctl),
				hosts:     registry.NewHosts(""),
				driver:    NewMockDriver(ctl),
				newClient: func(string) nydusd.Client { return nydusdmocks.NewMockClient(ctl) },
				locker:    kmutex.New(),
				startLock: &sync.Mutex{},
				preheats:  newPreheatQueue(cfg.Preheat.MaxConcurrentImages),
			}
			f.cfg.Store(cfg)

			for _, instance := range tc.instances {
				assert.NoError(t, f.store.PutInstance(instance))
			}

			if tc.closed {
				assert.NoError(t, f.store.Close())
			}

			blobs, err := f.RunningBlobs(t.Context())
			tc.expect(t, blobs, err)
		})
	}
}
