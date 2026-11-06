/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	authmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth/mocks"
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
	mockChainID = "sha256:" + strings.Repeat("ab", 32)

	mockUnit = "nydusd-" + strings.Repeat("ab", 32) + ".service"

	mockBlobID = strings.Repeat("aa", 32)

	mockOtherBlobID = strings.Repeat("bb", 32)

	mockTemplate = `
storage:
  dir: /ignored
prefetch:
  concurrent_blob_count: 4
backend:
  type: registry
  config:
    http:
      request_timeout: 5s
`
)

type mockRecorders struct {
	systemd  *systemdmocks.MockManagerMockRecorder
	keychain *authmocks.MockKeychainMockRecorder
	driver   *MockDriverMockRecorder
	client   *nydusdmocks.MockClientMockRecorder
	started  *atomic.Pointer[systemd.Unit]
}

func TestFileSystem_Mount(t *testing.T) {
	tests := []struct {
		name   string
		mock   func(m mockRecorders, mounted *atomic.Bool)
		expect func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit])
	}{
		{
			name: "start a daemon",
			mock: func(m mockRecorders, mounted *atomic.Bool) {
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				m.keychain.Synced().Return(true).Times(1)
				m.keychain.Resolve(gomock.Any(), gomock.Any()).Return("dXNlcjpwYXNz", nil).Times(1)
				m.driver.Unmount(gomock.Any()).Return(nil).Times(1)
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, unit *systemd.Unit) error {
					m.started.Store(unit)
					mounted.Store(true)
					return nil
				}).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				m.client.Ready(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				cfg := f.cfg.Load()
				id := strings.Repeat("ab", 32)
				mountpoint, err := f.Mount(t.Context(), image)
				assert.NoError(err)
				assert.Equal(filepath.Join(cfg.InstanceDir(id), "mnt"), mountpoint)

				instance, err := f.store.GetInstance(mockChainID)
				assert.NoError(err)
				assert.Equal("registry.example.com", instance.RegistryHost)
				assert.Equal([]string{mockBlobID}, instance.Blobs)
				assert.FileExists(instance.Bootstrap)
				assert.FileExists(filepath.Join(cfg.CacheDir(), mockBlobID+blobMetaSuffix))

				rendered, err := os.ReadFile(filepath.Join(cfg.RuntimeDir(id), "config.yaml"))
				assert.NoError(err)
				assert.Contains(string(rendered), "auth: dXNlcjpwYXNz")
				assert.Contains(string(rendered), "repository: team/app")
				assert.Contains(string(rendered), "scope: all")
				info, err := os.Stat(filepath.Join(cfg.RuntimeDir(id), "config.yaml"))
				assert.NoError(err)
				assert.Equal(os.FileMode(0o600), info.Mode().Perm())

				unit := started.Load()
				assert.Equal(mockUnit, unit.Name)
				assert.Equal(config.DefaultSlice, unit.Slice)
				assert.Equal(cfg.Nydusd.Binary, unit.ExecStart[0])
				assert.Contains(unit.Before, "containerd.service")
				assert.NotContains(strings.Join(append(unit.ExecStart, unit.Environment...), " "), "dXNlcjpwYXNz")
			},
		},
		{
			name: "reuse a ready daemon",
			mock: func(m mockRecorders, mounted *atomic.Bool) {
				mounted.Store(true)
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				m.client.Ready(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.NoError(err)
				instance, err := f.store.GetInstance(mockChainID)
				assert.NoError(err)
				assert.Equal(mockUnit, instance.Unit)
			},
		},
		{
			name: "report a running daemon that does not answer as unavailable",
			mock: func(m mockRecorders, mounted *atomic.Bool) {
				mounted.Store(true)
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				m.client.Ready(gomock.Any()).Return(errors.New("busy")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				_, err := f.Mount(t.Context(), image)
				assert.ErrorIs(t, err, errdefs.ErrUnavailable)
			},
		},
		{
			name: "fail fast before credentials sync",
			mock: func(m mockRecorders, mounted *atomic.Bool) {
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				m.keychain.Synced().Return(false).Times(1)
				m.systemd.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
				m.driver.Unmount(gomock.Any()).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				_, err := f.Mount(t.Context(), image)
				assert.ErrorIs(t, err, errdefs.ErrUnavailable)
			},
		},
		{
			name: "clean up a daemon that fails to start",
			mock: func(m mockRecorders, mounted *atomic.Bool) {
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				m.keychain.Synced().Return(true).Times(1)
				m.keychain.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
				m.driver.Unmount(gomock.Any()).Return(nil).Times(2)
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).Return(nil).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateFailed, nil).Times(1)
				m.systemd.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				_, err := f.Mount(t.Context(), image)
				assert.ErrorContains(err, "is failed")
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
				assert.DirExists(filepath.Join(f.cfg.Load().Nydusd.LogDir, strings.Repeat("ab", 32)))
			},
		},
		{
			name: "stop a daemon that never gets ready",
			mock: func(m mockRecorders, mounted *atomic.Bool) {
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				m.keychain.Synced().Return(true).Times(1)
				m.keychain.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
				m.driver.Unmount(gomock.Any()).Return(nil).Times(2)
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).Return(nil).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActivating, nil).AnyTimes()
				m.systemd.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				cfg := *f.cfg.Load()
				cfg.Nydusd.MountTimeout = config.Duration(200 * time.Millisecond)
				f.cfg.Store(&cfg)

				_, err := f.Mount(t.Context(), image)
				assert.ErrorIs(err, context.DeadlineExceeded)
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "bound the wait for another start of the image",
			mock: func(m mockRecorders, mounted *atomic.Bool) {},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
				assert := assert.New(t)
				cfg := *f.cfg.Load()
				cfg.Nydusd.MountTimeout = config.Duration(100 * time.Millisecond)
				f.cfg.Store(&cfg)
				id := strings.Repeat("ab", 32)
				assert.NoError(f.locker.Lock(t.Context(), id))
				defer f.locker.Unlock(id)

				_, err := f.Mount(t.Context(), image)
				assert.ErrorIs(err, context.DeadlineExceeded)
				assert.ErrorContains(err, "lock daemon")
			},
		},
		{
			name: "start one daemon for concurrent mounts",
			mock: func(m mockRecorders, mounted *atomic.Bool) {
				m.systemd.ActiveState(gomock.Any(), mockUnit).DoAndReturn(func(context.Context, string) (string, error) {
					if mounted.Load() {
						return systemd.ActiveStateActive, nil
					}

					return systemd.ActiveStateInactive, nil
				}).AnyTimes()
				m.keychain.Synced().Return(true).Times(1)
				m.keychain.Resolve(gomock.Any(), gomock.Any()).Return("", nil).Times(1)
				m.driver.Unmount(gomock.Any()).Return(nil).Times(1)
				m.systemd.StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
					mounted.Store(true)
					return nil
				}).Times(1)
				m.client.Ready(gomock.Any()).Return(nil).AnyTimes()
			},
			expect: func(t *testing.T, f *fileSystem, image *Image, started *atomic.Pointer[systemd.Unit]) {
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
					assert.NoError(t, err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			manager := systemdmocks.NewMockManager(ctl)
			keychain := authmocks.NewMockKeychain(ctl)
			driver := NewMockDriver(ctl)
			client := nydusdmocks.NewMockClient(ctl)
			var (
				mounted atomic.Bool
				started atomic.Pointer[systemd.Unit]
			)
			expectDriver(driver, &mounted)
			tc.mock(mockRecorders{systemd: manager.EXPECT(), keychain: keychain.EXPECT(), driver: driver.EXPECT(), client: client.EXPECT(), started: &started}, &mounted)

			f, image := newTestFileSystem(t, manager, keychain, driver, client)
			tc.expect(t, f, image, &started)
		})
	}
}

func TestFileSystem_Release(t *testing.T) {
	tests := []struct {
		name       string
		used       UsedFunc
		runtimeDir bool
		mock       func(m mockRecorders)
		expect     func(t *testing.T, f *fileSystem, d *Daemon, err error)
	}{
		{
			name: "stop an unused daemon",
			used: usedFunc(false, nil),
			mock: func(m mockRecorders) {
				m.systemd.ListUnits(gomock.Any(), config.DefaultSlice, unitPattern).Return(map[string]string{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateActive, nil).Times(1)
				gomock.InOrder(
					m.systemd.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1),
					m.driver.Unmount(gomock.Any()).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
				assert.NoDirExists(d.LogDir)
			},
		},
		{
			name: "keep a used daemon without asking systemd again",
			used: usedFunc(true, nil),
			mock: func(m mockRecorders) {
				m.systemd.ListUnits(gomock.Any(), config.DefaultSlice, unitPattern).Return(map[string]string{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
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
			used:       usedFunc(true, nil),
			runtimeDir: true,
			mock: func(m mockRecorders) {
				m.systemd.ListUnits(gomock.Any(), config.DefaultSlice, unitPattern).Return(map[string]string{}, nil).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
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
			used: usedFunc(true, nil),
			mock: func(m mockRecorders) {
				m.systemd.ListUnits(gomock.Any(), config.DefaultSlice, unitPattern).Return(map[string]string{}, nil).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
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
			used: usedFunc(false, nil),
			mock: func(m mockRecorders) {
				m.systemd.ListUnits(gomock.Any(), config.DefaultSlice, unitPattern).Return(map[string]string{}, nil).Times(1)
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(1)
				gomock.InOrder(
					m.systemd.StopUnit(gomock.Any(), mockUnit).Return(nil).Times(1),
					m.driver.Unmount(gomock.Any()).Return(nil).Times(1),
				)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, err = f.store.GetInstance(mockChainID)
				assert.ErrorIs(err, errdefs.ErrNotFound)
				assert.NoDirExists(d.LogDir)
			},
		},
		{
			name:       "count a used daemon that exited once across passes",
			used:       usedFunc(true, nil),
			runtimeDir: true,
			mock: func(m mockRecorders) {
				m.systemd.ListUnits(gomock.Any(), config.DefaultSlice, unitPattern).Return(map[string]string{}, nil).Times(2)
				m.systemd.ActiveState(gomock.Any(), mockUnit).Return(systemd.ActiveStateInactive, nil).Times(2)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				exits := exitCount(t)
				assert.NoError(f.Release(t.Context(), usedFunc(true, nil)))
				assert.Equal(exits, exitCount(t))
			},
		},
		{
			name: "report a failing usage check",
			used: usedFunc(false, errors.New("metadata unavailable")),
			mock: func(m mockRecorders) {
				m.systemd.ListUnits(gomock.Any(), config.DefaultSlice, unitPattern).Return(map[string]string{}, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, d *Daemon, err error) {
				assert.ErrorContains(t, err, "metadata unavailable")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			manager := systemdmocks.NewMockManager(ctl)
			driver := NewMockDriver(ctl)
			expectDriver(driver, &atomic.Bool{})
			tc.mock(mockRecorders{systemd: manager.EXPECT(), driver: driver.EXPECT()})

			f, _ := newTestFileSystem(t, manager, authmocks.NewMockKeychain(ctl), driver, nydusdmocks.NewMockClient(ctl))
			id, err := parseDaemonID(mockChainID)
			assert.NoError(t, err)
			d := f.daemon(f.cfg.Load(), id)
			assert.NoError(t, f.store.PutInstance(d.Instance))
			assert.NoError(t, os.MkdirAll(d.LogDir, 0o700))
			if tc.runtimeDir {
				assert.NoError(t, os.MkdirAll(filepath.Dir(d.Config), 0o700))
			}

			tc.expect(t, f, d, f.Release(t.Context(), tc.used))
		})
	}
}

func TestFileSystem_Reload(t *testing.T) {
	tests := []struct {
		name   string
		usage  uint64
		mock   func(m *systemdmocks.MockManagerMockRecorder, usage uint64)
		expect func(t *testing.T, f *fileSystem, err error)
	}{
		{
			name:  "apply limits",
			usage: 1 << 30,
			mock: func(m *systemdmocks.MockManagerMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), "system-nydus.slice").Return(usage, nil).Times(1)
				m.StartSlice(gomock.Any(), "system-nydus.slice", systemd.Resources{MemoryMax: 4 << 30, CPUQuotaPerSecUSec: 2_000_000}).Return(nil).Times(1)
				m.StartSlice(gomock.Any(), "system-nydus-v3.slice", systemd.Resources{}).Return(nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultSlice, unitPattern).Return(map[string]string{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				m.SetResources(gomock.Any(), mockUnit, systemd.Resources{MemoryHigh: 1 << 30}).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(f.limitsDeferred.Load())
			},
		},
		{
			name:  "defer memory max below usage",
			usage: 5 << 30,
			mock: func(m *systemdmocks.MockManagerMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), "system-nydus.slice").Return(usage, nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultSlice, unitPattern).Return(map[string]string{}, nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(f.limitsDeferred.Load())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			manager := systemdmocks.NewMockManager(ctl)
			tc.mock(manager.EXPECT(), tc.usage)

			f, _ := newTestFileSystem(t, manager, authmocks.NewMockKeychain(ctl), NewMockDriver(ctl), nydusdmocks.NewMockClient(ctl))
			cfg := *f.cfg.Load()
			cfg.Cgroup.MemoryMax = 4 << 30
			cfg.Cgroup.CPUQuota = 200
			cfg.Cgroup.Daemon.MemoryHigh = 1 << 30
			tc.expect(t, f, f.Reload(t.Context(), &cfg))
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
			manager := systemdmocks.NewMockManager(ctl)
			keychain := authmocks.NewMockKeychain(ctl)
			driver := NewMockDriver(ctl)
			client := nydusdmocks.NewMockClient(ctl)
			var mounted atomic.Bool
			expectDriver(driver, &mounted)

			starting, proceed := make(chan struct{}), make(chan struct{})
			state := func(context.Context, string) (string, error) {
				if mounted.Load() {
					return systemd.ActiveStateActive, nil
				}

				return systemd.ActiveStateInactive, nil
			}
			manager.EXPECT().ActiveState(gomock.Any(), mockUnit).DoAndReturn(state).AnyTimes()
			manager.EXPECT().ListUnits(gomock.Any(), config.DefaultSlice, unitPattern).DoAndReturn(func(ctx context.Context, _, _ string) (map[string]string, error) {
				active, err := state(ctx, mockUnit)
				return map[string]string{mockUnit: active}, err
			}).AnyTimes()
			manager.EXPECT().StartTransientUnit(gomock.Any(), gomock.Any()).DoAndReturn(func(context.Context, *systemd.Unit) error {
				close(starting)
				<-proceed
				mounted.Store(true)
				return nil
			}).Times(1)
			manager.EXPECT().StopUnit(gomock.Any(), gomock.Any()).Times(0)
			keychain.EXPECT().Synced().Return(true).AnyTimes()
			keychain.EXPECT().Resolve(gomock.Any(), gomock.Any()).Return("", nil).AnyTimes()
			driver.EXPECT().Unmount(gomock.Any()).Return(nil).AnyTimes()
			client.EXPECT().Ready(gomock.Any()).Return(nil).AnyTimes()

			f, image := newTestFileSystem(t, manager, keychain, driver, client)
			tc.expect(t, f, image, starting, proceed)
		})
	}
}

func TestFileSystem_RunningBlobs(t *testing.T) {
	tests := []struct {
		name      string
		instances []*store.Instance
		expect    func(t *testing.T, blobs map[string]struct{}, err error)
	}{
		{
			name:      "blobs of every recorded daemon",
			instances: []*store.Instance{{ChainID: mockChainID, Unit: mockUnit, Blobs: []string{"aaaa", "bbbb"}}},
			expect: func(t *testing.T, blobs map[string]struct{}, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[string]struct{}{"aaaa": {}, "bbbb": {}}, blobs)
			},
		},
		{
			name: "no blobs without records",
			expect: func(t *testing.T, blobs map[string]struct{}, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(blobs)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctl := gomock.NewController(t)
			defer ctl.Finish()
			f, _ := newTestFileSystem(t, systemdmocks.NewMockManager(ctl), authmocks.NewMockKeychain(ctl), NewMockDriver(ctl), nydusdmocks.NewMockClient(ctl))
			for _, instance := range tc.instances {
				assert.NoError(t, f.store.PutInstance(instance))
			}

			blobs, err := f.RunningBlobs(t.Context())
			tc.expect(t, blobs, err)
		})
	}
}

func exitCount(t *testing.T) float64 {
	t.Helper()
	var m dto.Metric
	assert.NoError(t, metrics.DaemonUnexpectedExitTotal.Write(&m))
	return m.GetCounter().GetValue()
}

func usedFunc(used bool, err error) UsedFunc {
	return func(context.Context) (map[string]struct{}, error) {
		if !used {
			return map[string]struct{}{}, err
		}

		return map[string]struct{}{mockChainID: {}}, err
	}
}

func expectDriver(driver *MockDriver, mounted *atomic.Bool) {
	driver.EXPECT().Name().Return(config.DriverFuse).AnyTimes()
	driver.EXPECT().Args(gomock.Any()).Return([]string{"fuse"}).AnyTimes()
	driver.EXPECT().Environment().Return(nil).AnyTimes()
	driver.EXPECT().Mounted(gomock.Any()).DoAndReturn(func(*Daemon) (bool, error) { return mounted.Load(), nil }).AnyTimes()
}

func newTestFileSystem(t *testing.T, manager systemd.Manager, keychain *authmocks.MockKeychain, driver Driver, client nydusd.Client) (*fileSystem, *Image) {
	t.Helper()
	root := t.TempDir()
	cfg := config.New()
	cfg.Root = filepath.Join(root, "lib")
	cfg.RunDir = filepath.Join(root, "run")
	cfg.Registry.ConfigPath = ""
	cfg.Nydusd.Template = filepath.Join(root, "nydusd.template.yaml")
	cfg.Nydusd.Binary = filepath.Join(root, "nydus")
	cfg.Nydusd.LogDir = filepath.Join(root, "log")
	cfg.Nydusd.MountTimeout = config.Duration(2 * time.Second)
	assert.NoError(t, os.WriteFile(cfg.Nydusd.Template, []byte(mockTemplate), 0o644))
	assert.NoError(t, os.WriteFile(cfg.Nydusd.Binary, nil, 0o755))
	assert.NoError(t, os.MkdirAll(cfg.CacheDir(), 0o700))

	imageDir := filepath.Join(root, "bootstrap", "fs", "image")
	assert.NoError(t, os.MkdirAll(imageDir, 0o755))
	assert.NoError(t, os.WriteFile(filepath.Join(imageDir, bootstrapFile), []byte("boot"), 0o644))
	assert.NoError(t, os.WriteFile(filepath.Join(imageDir, mockBlobID+blobMetaSuffix), []byte("meta"), 0o644))

	s, err := store.New(filepath.Join(root, "nydusd.db"), store.DefaultOpenTimeout)
	assert.NoError(t, err)
	t.Cleanup(func() { s.Close() })

	f := &fileSystem{
		systemd:   manager,
		store:     s,
		keychain:  keychain,
		hosts:     registry.NewHosts(""),
		driver:    driver,
		newClient: func(string) nydusd.Client { return client },
		locker:    kmutex.New(),
		startLock: &sync.Mutex{},
	}
	f.cfg.Store(cfg)

	return f, &Image{
		ChainID:       mockChainID,
		Ref:           "registry.example.com/team/app:v1-nydus-v3",
		BootstrapDir:  filepath.Join(root, "bootstrap", "fs"),
		PrefetchScope: "all",
	}
}
