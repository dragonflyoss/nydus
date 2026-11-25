/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	authmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/kmutex"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd"
	nydusdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/store"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
	systemdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

func TestFileSystem_Reload(t *testing.T) {
	tests := []struct {
		name   string
		usage  uint64
		mock   func(m *systemdmocks.MockSystemdMockRecorder, usage uint64)
		expect func(t *testing.T, f *fileSystem, err error)
	}{
		{
			name:  "apply limits",
			usage: 1 << 30,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(usage, nil).Times(1)
				m.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, systemd.Resources{MemoryMax: 4 << 30, CPUQuotaPerSecUSec: 2_000_000}).Return(nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				m.SetResources(gomock.Any(), mockUnit, systemd.Resources{MemoryHigh: 1 << 30}).Return(nil).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(f.limitsDeferred.Load())
			},
		},
		{
			name:  "defer daemon limits that fail to apply",
			usage: 1 << 30,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(usage, nil).Times(1)
				m.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, gomock.Any()).Return(nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
				m.SetResources(gomock.Any(), mockUnit, gomock.Any()).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.True(f.limitsDeferred.Load())
			},
		},
		{
			name: "defer limits while the slice usage cannot be read",
			mock: func(m *systemdmocks.MockSystemdMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(uint64(0), errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.True(f.limitsDeferred.Load())
			},
		},
		{
			name:  "defer limits while the slice cannot be started",
			usage: 1 << 30,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(usage, nil).Times(1)
				m.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, gomock.Any()).Return(errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.True(f.limitsDeferred.Load())
			},
		},
		{
			name:  "defer limits while the daemons cannot be listed",
			usage: 1 << 30,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(usage, nil).Times(1)
				m.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, gomock.Any()).Return(nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(nil, errors.New("foo")).Times(1)
			},
			expect: func(t *testing.T, f *fileSystem, err error) {
				assert := assert.New(t)
				assert.EqualError(err, "foo")
				assert.True(f.limitsDeferred.Load())
			},
		},
		{
			name:  "leave a unit that is no daemon alone",
			usage: 1 << 30,
			mock: func(m *systemdmocks.MockSystemdMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(usage, nil).Times(1)
				m.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, gomock.Any()).Return(nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive, "nydusd-helper.service": systemd.ActiveStateActive}, nil).Times(1)
				m.SetResources(gomock.Any(), mockUnit, gomock.Any()).Return(nil).Times(1)
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
			mock: func(m *systemdmocks.MockSystemdMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(usage, nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, daemonUnitPattern).Return(map[string]systemd.ActiveState{}, nil).Times(1)
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
			mockSystemd := systemdmocks.NewMockSystemd(ctl)
			tc.mock(mockSystemd.EXPECT(), tc.usage)

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

			next := *cfg
			next.Cgroup.MemoryMax = 4 << 30
			next.Cgroup.CPUQuota = 200
			next.Cgroup.Daemon.MemoryHigh = 1 << 30
			tc.expect(t, f, f.Reload(t.Context(), &next))
		})
	}
}
