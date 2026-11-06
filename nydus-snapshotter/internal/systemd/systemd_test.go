/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package systemd

import (
	"context"
	"math"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	systemddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

var mockUnit = &Unit{
	Name:             "nydusd-ab.service",
	Description:      "nydus daemon",
	Slice:            "system-nydus-v3.slice",
	ExecStart:        []string{"/opt/nydus-v3/bin/3.0.0/nydus", "fuse"},
	Environment:      []string{"NYDUS_FUSE_CONSOLE=false"},
	Before:           []string{"containerd.service"},
	TimeoutStop:      10 * time.Second,
	OOMScoreAdjust:   -999,
	LimitNOFILE:      1048576,
	SyslogIdentifier: "nydusd",
	LogExtraFields:   []string{"NYDUS_CHAIN_ID=sha256:ab"},
	Resources:        Resources{MemoryHigh: 1 << 30},
}

func TestUnit_properties(t *testing.T) {
	tests := []struct {
		name   string
		unit   *Unit
		expect func(t *testing.T, properties map[string]any)
	}{
		{
			name: "transient service properties",
			unit: mockUnit,
			expect: func(t *testing.T, properties map[string]any) {
				assert := assert.New(t)
				assert.Equal("exec", properties["Type"])
				assert.Equal("no", properties["Restart"])
				assert.Equal("inactive-or-failed", properties["CollectMode"])
				assert.Equal(int32(unix.SIGTERM), properties["KillSignal"])
				assert.Equal(uint64(10_000_000), properties["TimeoutStopUSec"])
				assert.Equal(uint64(1048576), properties["LimitNOFILE"])
				assert.Equal(uint64(1048576), properties["LimitNOFILESoft"])
				assert.Equal(uint64(0), properties["LimitCORE"])
				assert.Equal(uint64(0), properties["LimitCORESoft"])
				assert.Equal("nydusd", properties["SyslogIdentifier"])
				assert.Equal(int32(-999), properties["OOMScoreAdjust"])
				assert.Equal("system-nydus-v3.slice", properties["Slice"])
				assert.Equal([]string{"NYDUS_FUSE_CONSOLE=false"}, properties["Environment"])
				assert.Equal([][]byte{[]byte("NYDUS_CHAIN_ID=sha256:ab")}, properties["LogExtraFields"])
				assert.Equal(uint64(1<<30), properties["MemoryHigh"])
				assert.Equal(uint64(math.MaxUint64), properties["MemoryMax"])
				assert.Equal(uint64(math.MaxUint64), properties["CPUQuotaPerSecUSec"])
			},
		},
		{
			name: "keep systemd defaults for zero values",
			unit: &Unit{Name: "nydusd-ab.service", ExecStart: []string{"/bin/true"}},
			expect: func(t *testing.T, properties map[string]any) {
				assert := assert.New(t)
				assert.NotContains(properties, "Environment")
				assert.NotContains(properties, "Before")
				assert.NotContains(properties, "TimeoutStopUSec")
				assert.NotContains(properties, "LimitNOFILE")
				assert.NotContains(properties, "SyslogIdentifier")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, propertyValues(tc.unit.properties()))
		})
	}
}

func TestResources_properties(t *testing.T) {
	tests := []struct {
		name      string
		resources *Resources
		expect    func(t *testing.T, properties map[string]any)
	}{
		{
			name:      "zero is no limit",
			resources: &Resources{},
			expect: func(t *testing.T, properties map[string]any) {
				assert := assert.New(t)
				assert.Equal(uint64(math.MaxUint64), properties["MemoryMax"])
				assert.Equal(uint64(math.MaxUint64), properties["MemoryHigh"])
				assert.Equal(uint64(math.MaxUint64), properties["CPUQuotaPerSecUSec"])
			},
		},
		{
			name:      "limits pass through",
			resources: &Resources{MemoryMax: 8 << 30, MemoryHigh: 6 << 30, CPUQuotaPerSecUSec: 4_000_000},
			expect: func(t *testing.T, properties map[string]any) {
				assert := assert.New(t)
				assert.Equal(uint64(8<<30), properties["MemoryMax"])
				assert.Equal(uint64(6<<30), properties["MemoryHigh"])
				assert.Equal(uint64(4_000_000), properties["CPUQuotaPerSecUSec"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, propertyValues(tc.resources.properties()))
		})
	}
}

func TestIsDBusError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		expect func(t *testing.T, matched bool)
	}{
		{
			name: "named error",
			err:  dbus.Error{Name: dbusUnitExists},
			expect: func(t *testing.T, matched bool) {
				assert.True(t, matched)
			},
		},
		{
			name: "other error",
			err:  dbus.Error{Name: dbusNoSuchUnit},
			expect: func(t *testing.T, matched bool) {
				assert.False(t, matched)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, isDBusError(tc.err, dbusUnitExists))
		})
	}
}

func propertyValues(properties []systemddbus.Property) map[string]any {
	values := make(map[string]any, len(properties))
	for _, p := range properties {
		values[p.Name] = p.Value.Value()
	}

	return values
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name   string
		value  string
		expect func(t *testing.T, version int, err error)
	}{
		{
			name:  "quoted with a v prefix and a distro suffix",
			value: `"v245.4-1.fc32"`,
			expect: func(t *testing.T, version int, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(245, version)
			},
		},
		{
			name:  "debian style",
			value: `"255.4-1ubuntu8.18"`,
			expect: func(t *testing.T, version int, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(255, version)
			},
		},
		{
			name:  "plain number",
			value: "239",
			expect: func(t *testing.T, version int, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(239, version)
			},
		},
		{
			name:  "no number",
			value: `"unknown"`,
			expect: func(t *testing.T, version int, err error) {
				assert.Error(t, err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			version, err := parseVersion(tc.value)
			tc.expect(t, version, err)
		})
	}
}

func TestManager_StartTransientUnit(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s Manager, unit *Unit)
	}{
		{
			name: "start, list and stop a unit",
			expect: func(t *testing.T, s Manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.StartTransientUnit(t.Context(), unit))
				state, err := s.ActiveState(t.Context(), unit.Name)
				assert.NoError(err)
				assert.Equal(ActiveStateActive, state)

				units, err := s.ListUnits(t.Context(), unit.Slice, "nydus-test-*.service")
				assert.NoError(err)
				assert.Equal(map[string]string{unit.Name: ActiveStateActive}, units)

				assert.NoError(s.StopUnit(t.Context(), unit.Name))
				state, err = s.ActiveState(t.Context(), unit.Name)
				assert.NoError(err)
				assert.Equal(ActiveStateInactive, state)
			},
		},
		{
			name: "refuse a running unit",
			expect: func(t *testing.T, s Manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.StartTransientUnit(t.Context(), unit))
				assert.ErrorIs(s.StartTransientUnit(t.Context(), unit), errdefs.ErrAlreadyExists)
			},
		},
		{
			name: "leave units of other slices out",
			expect: func(t *testing.T, s Manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.StartTransientUnit(t.Context(), unit))
				units, err := s.ListUnits(t.Context(), "other-"+unit.Slice, "nydus-test-*.service")
				assert.NoError(err)
				assert.Empty(units)
			},
		},
		{
			name: "stop an unknown unit",
			expect: func(t *testing.T, s Manager, unit *Unit) {
				assert.NoError(t, s.StopUnit(t.Context(), unit.Name))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestManager(t)
			tc.expect(t, s, newTestUnit(t))
		})
	}
}

func TestManager_StartSlice(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s Manager, slice string)
	}{
		{
			name: "start a slice and change its limits",
			expect: func(t *testing.T, s Manager, slice string) {
				assert := assert.New(t)
				assert.NoError(s.StartSlice(t.Context(), slice, Resources{MemoryHigh: 1 << 30}))
				_, err := s.MemoryCurrent(t.Context(), slice)
				assert.NoError(err)
				assert.NoError(s.StartSlice(t.Context(), slice, Resources{MemoryHigh: 2 << 30, CPUQuotaPerSecUSec: 500_000}))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestManager(t)
			slice := "nydustest" + strconv.Itoa(os.Getpid()) + ".slice"
			t.Cleanup(func() { assert.NoError(t, s.StopUnit(context.Background(), slice)) })
			tc.expect(t, s, slice)
		})
	}
}

func TestManager_connection(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s *manager)
	}{
		{
			name: "keep the connection after the dialing request ends",
			expect: func(t *testing.T, s *manager) {
				assert := assert.New(t)
				ctx, cancel := context.WithCancel(t.Context())
				_, err := s.ActiveState(ctx, "nydus-test-unknown.service")
				assert.NoError(err)
				cancel()

				conn := s.conn
				assert.Never(func() bool { return !conn.Connected() }, 200*time.Millisecond, 10*time.Millisecond)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, newTestManager(t).(*manager))
		})
	}
}

func newTestManager(t *testing.T) Manager {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("talks to systemd as root")
	}

	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("needs systemd as init")
	}

	s := New(30 * time.Second)
	t.Cleanup(s.Close)
	return s
}

func newTestUnit(t *testing.T) *Unit {
	t.Helper()
	sleep, err := exec.LookPath("sleep")
	assert.NoError(t, err)

	unit := &Unit{
		Name:        "nydus-test-" + strconv.Itoa(os.Getpid()) + ".service",
		Description: "nydus-snapshotter unit test",
		Slice:       "nydustest" + strconv.Itoa(os.Getpid()) + "units.slice",
		ExecStart:   []string{sleep, "300"},
		TimeoutStop: 10 * time.Second,
	}

	t.Cleanup(func() {
		s := New(30 * time.Second)
		defer s.Close()
		assert.NoError(t, s.StopUnit(context.Background(), unit.Name))
		assert.NoError(t, s.StopUnit(context.Background(), unit.Slice))
	})

	return unit
}
