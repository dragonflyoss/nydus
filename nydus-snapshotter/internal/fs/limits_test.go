/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package fs

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	authmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/auth/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/config"
	nydusdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/nydusd/mocks"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd"
	systemdmocks "github.com/dragonflyoss/nydus/nydus-snapshotter/internal/systemd/mocks"
)

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
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(usage, nil).Times(1)
				m.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, systemd.Resources{MemoryMax: 4 << 30, CPUQuotaPerSecUSec: 2_000_000}).Return(nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, unitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
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
			mock: func(m *systemdmocks.MockManagerMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(usage, nil).Times(1)
				m.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, gomock.Any()).Return(nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, unitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive}, nil).Times(1)
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
			mock: func(m *systemdmocks.MockManagerMockRecorder, usage uint64) {
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
			mock: func(m *systemdmocks.MockManagerMockRecorder, usage uint64) {
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
			mock: func(m *systemdmocks.MockManagerMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(usage, nil).Times(1)
				m.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, gomock.Any()).Return(nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, unitPattern).Return(nil, errors.New("foo")).Times(1)
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
			mock: func(m *systemdmocks.MockManagerMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(usage, nil).Times(1)
				m.StartSlice(gomock.Any(), config.DefaultCgroupSlice, sliceDescription, gomock.Any()).Return(nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, unitPattern).Return(map[string]systemd.ActiveState{mockUnit: systemd.ActiveStateActive, "nydusd-helper.service": systemd.ActiveStateActive}, nil).Times(1)
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
			mock: func(m *systemdmocks.MockManagerMockRecorder, usage uint64) {
				m.MemoryCurrent(gomock.Any(), config.DefaultCgroupSlice).Return(usage, nil).Times(1)
				m.ListUnits(gomock.Any(), config.DefaultCgroupSlice, unitPattern).Return(map[string]systemd.ActiveState{}, nil).Times(1)
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
