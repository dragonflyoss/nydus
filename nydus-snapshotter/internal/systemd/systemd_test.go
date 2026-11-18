/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package systemd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/util/testutil"
)

var (
	mockJobTimeout = 30 * time.Second

	mockUnknownUnit = "nydus-test-unknown.service"

	mockInvalidUnit = "nydus test.service"
)

func TestActiveState_Running(t *testing.T) {
	tests := []struct {
		name   string
		state  ActiveState
		expect func(t *testing.T, running bool)
	}{
		{
			name:  "active",
			state: ActiveStateActive,
			expect: func(t *testing.T, running bool) {
				assert := assert.New(t)
				assert.True(running)
			},
		},
		{
			name:  "activating",
			state: ActiveStateActivating,
			expect: func(t *testing.T, running bool) {
				assert := assert.New(t)
				assert.True(running)
			},
		},
		{
			name:  "deactivating",
			state: ActiveStateDeactivating,
			expect: func(t *testing.T, running bool) {
				assert := assert.New(t)
				assert.False(running)
			},
		},
		{
			name:  "inactive",
			state: ActiveStateInactive,
			expect: func(t *testing.T, running bool) {
				assert := assert.New(t)
				assert.False(running)
			},
		},
		{
			name:  "failed",
			state: ActiveStateFailed,
			expect: func(t *testing.T, running bool) {
				assert := assert.New(t)
				assert.False(running)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, tc.state.Running())
		})
	}
}

func TestActiveState_Stopped(t *testing.T) {
	tests := []struct {
		name   string
		state  ActiveState
		expect func(t *testing.T, stopped bool)
	}{
		{
			name:  "active",
			state: ActiveStateActive,
			expect: func(t *testing.T, stopped bool) {
				assert := assert.New(t)
				assert.False(stopped)
			},
		},
		{
			name:  "activating",
			state: ActiveStateActivating,
			expect: func(t *testing.T, stopped bool) {
				assert := assert.New(t)
				assert.False(stopped)
			},
		},
		{
			name:  "deactivating",
			state: ActiveStateDeactivating,
			expect: func(t *testing.T, stopped bool) {
				assert := assert.New(t)
				assert.False(stopped)
			},
		},
		{
			name:  "inactive",
			state: ActiveStateInactive,
			expect: func(t *testing.T, stopped bool) {
				assert := assert.New(t)
				assert.True(stopped)
			},
		},
		{
			name:  "failed",
			state: ActiveStateFailed,
			expect: func(t *testing.T, stopped bool) {
				assert := assert.New(t)
				assert.True(stopped)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, tc.state.Stopped())
		})
	}
}

func TestManager_StartTransientUnit(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m Manager, unit *Unit)
	}{
		{
			name: "start a unit",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(m.StartTransientUnit(t.Context(), unit))
				state, err := m.ActiveState(t.Context(), unit.Name)
				assert.NoError(err)
				assert.Equal(ActiveStateActive, state)
			},
		},
		{
			name: "refuse a running unit",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(m.StartTransientUnit(t.Context(), unit))
				assert.ErrorIs(m.StartTransientUnit(t.Context(), unit), errdefs.ErrAlreadyExists)
			},
		},
		{
			name: "unit without a command",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				unit.ExecStart = nil
				assert.ErrorIs(m.StartTransientUnit(t.Context(), unit), errdefs.ErrInvalidArgument)
			},
		},
		{
			name: "unit whose command is missing",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				unit.ExecStart = []string{"/nonexistent/nydus-test"}
				assert.EqualError(m.StartTransientUnit(t.Context(), unit), fmt.Sprintf("start unit %s: job finished with %q", unit.Name, "failed"))
			},
		},
		{
			name: "notify unit that never reports ready",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				unit.Notify = true
				unit.TimeoutStart = 300 * time.Millisecond
				assert.ErrorContains(m.StartTransientUnit(t.Context(), unit), "finished with")
				state, err := m.ActiveState(t.Context(), unit.Name)
				assert.NoError(err)
				assert.NotEqual(ActiveStateActive, state)
			},
		},
		{
			name: "unit file holding the name",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				unit.Name = newSocketActivated(t).service
				assert.ErrorContains(m.StartTransientUnit(t.Context(), unit), "start unit "+unit.Name)
				state, err := m.ActiveState(t.Context(), unit.Name)
				assert.NoError(err)
				assert.Equal(ActiveStateInactive, state)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t)
			tc.expect(t, m, newTestUnit(t))
		})
	}
}

func TestManager_StopUnit(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m Manager, unit *Unit)
	}{
		{
			name: "stop a running unit",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(m.StartTransientUnit(t.Context(), unit))
				assert.NoError(m.StopUnit(t.Context(), unit.Name))
				state, err := m.ActiveState(t.Context(), unit.Name)
				assert.NoError(err)
				assert.Equal(ActiveStateInactive, state)
			},
		},
		{
			name: "stop an unknown unit",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(m.StopUnit(t.Context(), unit.Name))
			},
		},
		{
			name: "stop a unit with an invalid name",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				assert.ErrorContains(m.StopUnit(t.Context(), mockInvalidUnit), "stop unit "+mockInvalidUnit)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, newTestManager(t), newTestUnit(t))
		})
	}
}

func TestManager_confirmStopped(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m *manager, unit *Unit)
	}{
		{
			name: "unit a failed stop job left running",
			expect: func(t *testing.T, m *manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(m.StartTransientUnit(t.Context(), unit))
				assert.ErrorContains(m.confirmStopped(t.Context(), unit.Name, &jobError{result: "canceled"}), "left it active")
			},
		},
		{
			name: "unit a failed stop job stopped",
			expect: func(t *testing.T, m *manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(m.confirmStopped(t.Context(), unit.Name, &jobError{result: "failed"}))
			},
		},
		{
			name: "unit whose state cannot be read",
			expect: func(t *testing.T, m *manager, unit *Unit) {
				assert := assert.New(t)
				assert.ErrorContains(m.confirmStopped(t.Context(), mockInvalidUnit, &jobError{result: "failed"}), "get unit "+mockInvalidUnit+" state")
			},
		},
		{
			name: "unit that cannot be reset",
			expect: func(t *testing.T, m *manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(m.Ping(t.Context()))
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				assert.ErrorContains(m.confirmStopped(ctx, unit.Name, &jobError{result: "failed"}), "reset failed unit "+unit.Name)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, newTestManager(t).(*manager), newTestUnit(t))
		})
	}
}

func TestManager_StartUnit(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m Manager, units *socketActivated)
	}{
		{
			name: "start a unit and leave it alone once it runs",
			expect: func(t *testing.T, m Manager, units *socketActivated) {
				assert := assert.New(t)
				assert.NoError(m.StartUnit(t.Context(), units.socket))
				assert.NoError(m.StartUnit(t.Context(), units.service))
				assert.NoError(m.StartUnit(t.Context(), units.service))
				state, err := m.ActiveState(t.Context(), units.service)
				assert.NoError(err)
				assert.Equal(ActiveStateActive, state)
				assert.Equal(1, units.starts(t))
			},
		},
		{
			name: "wait for the restart a restarted socket gives its running service",
			expect: func(t *testing.T, m Manager, units *socketActivated) {
				assert := assert.New(t)
				assert.NoError(m.StartUnit(t.Context(), units.socket))
				assert.NoError(m.StartUnit(t.Context(), units.service))
				assert.NoError(m.RestartUnit(t.Context(), units.socket))
				assert.NoError(m.StartUnit(t.Context(), units.service))
				state, err := m.ActiveState(t.Context(), units.service)
				assert.NoError(err)
				assert.Equal(ActiveStateActive, state)
				assert.Equal(2, units.starts(t))
			},
		},
		{
			name: "leave a service alone that its restarted socket is starting again",
			expect: func(t *testing.T, m Manager, units *socketActivated) {
				assert := assert.New(t)
				assert.NoError(m.StartUnit(t.Context(), units.socket))
				assert.NoError(m.StartUnit(t.Context(), units.service))
				assert.NoError(m.RestartUnit(t.Context(), units.socket))
				assert.Eventually(func() bool { return units.starts(t) == 2 }, 5*time.Second, 10*time.Millisecond)
				assert.NoError(m.StartUnit(t.Context(), units.service))
				state, err := m.ActiveState(t.Context(), units.service)
				assert.NoError(err)
				assert.Equal(ActiveStateActive, state)
				assert.Equal(2, units.starts(t))
			},
		},
		{
			name: "unknown unit",
			expect: func(t *testing.T, m Manager, units *socketActivated) {
				assert := assert.New(t)
				assert.ErrorContains(m.StartUnit(t.Context(), mockUnknownUnit), "start unit "+mockUnknownUnit)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t)
			tc.expect(t, m, newSocketActivated(t))
		})
	}
}

func TestManager_RestartUnit(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m Manager, units *socketActivated)
	}{
		{
			name: "restart a running unit",
			expect: func(t *testing.T, m Manager, units *socketActivated) {
				assert := assert.New(t)
				assert.NoError(m.StartUnit(t.Context(), units.service))
				assert.NoError(m.RestartUnit(t.Context(), units.service))
				assert.Equal(2, units.starts(t))
			},
		},
		{
			name: "unknown unit",
			expect: func(t *testing.T, m Manager, units *socketActivated) {
				assert := assert.New(t)
				assert.ErrorContains(m.RestartUnit(t.Context(), mockUnknownUnit), "restart unit "+mockUnknownUnit)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t)
			tc.expect(t, m, newSocketActivated(t))
		})
	}
}

func TestManager_ActiveState(t *testing.T) {
	tests := []struct {
		name   string
		unit   string
		expect func(t *testing.T, state ActiveState, err error)
	}{
		{
			name: "unknown unit is inactive",
			unit: mockUnknownUnit,
			expect: func(t *testing.T, state ActiveState, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(ActiveStateInactive, state)
			},
		},
		{
			name: "invalid unit name",
			unit: mockInvalidUnit,
			expect: func(t *testing.T, state ActiveState, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "get unit "+mockInvalidUnit+" state")
				assert.Empty(state)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state, err := newTestManager(t).ActiveState(t.Context(), tc.unit)
			tc.expect(t, state, err)
		})
	}
}

func TestManager_ListUnits(t *testing.T) {
	tests := []struct {
		name     string
		slice    func(unit *Unit) string
		pattern  string
		canceled bool
		expect   func(t *testing.T, unit *Unit, units map[string]ActiveState, err error)
	}{
		{
			name:    "list the units of a slice",
			slice:   func(unit *Unit) string { return unit.Slice },
			pattern: "nydus-test-*.service",
			expect: func(t *testing.T, unit *Unit, units map[string]ActiveState, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(map[string]ActiveState{unit.Name: ActiveStateActive}, units)
			},
		},
		{
			name:    "leave units of other slices out",
			slice:   func(unit *Unit) string { return "other-" + unit.Slice },
			pattern: "nydus-test-*.service",
			expect: func(t *testing.T, unit *Unit, units map[string]ActiveState, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(units)
			},
		},
		{
			name:    "leave units the pattern does not match out",
			slice:   func(unit *Unit) string { return unit.Slice },
			pattern: "nydus-other-*.service",
			expect: func(t *testing.T, unit *Unit, units map[string]ActiveState, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(units)
			},
		},
		{
			name:     "units that cannot be listed",
			slice:    func(unit *Unit) string { return unit.Slice },
			pattern:  "nydus-test-*.service",
			canceled: true,
			expect: func(t *testing.T, unit *Unit, units map[string]ActiveState, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "list units nydus-test-*.service")
				assert.Nil(units)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, unit := newTestManager(t), newTestUnit(t)
			assert.NoError(t, m.StartTransientUnit(t.Context(), unit))

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}

			units, err := m.ListUnits(ctx, tc.slice(unit), tc.pattern)
			tc.expect(t, unit, units, err)
		})
	}
}

func TestManager_StartSlice(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m Manager, slice string)
	}{
		{
			name: "start a slice and change its limits",
			expect: func(t *testing.T, m Manager, slice string) {
				assert := assert.New(t)
				assert.NoError(m.StartSlice(t.Context(), slice, "nydus-snapshotter unit test", Resources{MemoryHigh: 1 << 30}))
				_, err := m.MemoryCurrent(t.Context(), slice)
				assert.NoError(err)
				assert.NoError(m.StartSlice(t.Context(), slice, "nydus-snapshotter unit test", Resources{MemoryHigh: 2 << 30, CPUQuotaPerSecUSec: 500_000}))
			},
		},
		{
			name: "invalid slice name",
			expect: func(t *testing.T, m Manager, slice string) {
				assert := assert.New(t)
				assert.ErrorContains(m.StartSlice(t.Context(), "nydus test.slice", "nydus-snapshotter unit test", Resources{}), "start slice nydus test.slice")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t)
			slice := "nydustest" + strconv.Itoa(os.Getpid()) + ".slice"
			t.Cleanup(func() { assert.NoError(t, m.StopUnit(context.Background(), slice)) })
			tc.expect(t, m, slice)
		})
	}
}

func TestManager_SetResources(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m Manager, unit *Unit)
	}{
		{
			name: "limit a running unit",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(m.StartTransientUnit(t.Context(), unit))
				assert.NoError(m.SetResources(t.Context(), unit.Name, Resources{MemoryHigh: 1 << 30}))
			},
		},
		{
			name: "unknown unit",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				assert.ErrorContains(m.SetResources(t.Context(), mockUnknownUnit, Resources{MemoryHigh: 1 << 30}), "set unit "+mockUnknownUnit+" resources")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t)
			tc.expect(t, m, newTestUnit(t))
		})
	}
}

func TestManager_MemoryCurrent(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m Manager, unit *Unit)
	}{
		{
			name: "memory of a slice",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(m.StartTransientUnit(t.Context(), unit))
				_, err := m.MemoryCurrent(t.Context(), unit.Slice)
				assert.NoError(err)
			},
		},
		{
			name: "unit that is no slice",
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(m.StartTransientUnit(t.Context(), unit))
				_, err := m.MemoryCurrent(t.Context(), unit.Name)
				assert.ErrorContains(err, "get slice "+unit.Name+" memory")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t)
			tc.expect(t, m, newTestUnit(t))
		})
	}
}

func TestManager_EnableUnitFiles(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m Manager, units *socketActivated)
	}{
		{
			name: "unit file without install config",
			expect: func(t *testing.T, m Manager, units *socketActivated) {
				assert := assert.New(t)
				assert.NoError(m.EnableUnitFiles(t.Context(), []string{units.socket, units.service}))
			},
		},
		{
			name: "missing unit file",
			expect: func(t *testing.T, m Manager, units *socketActivated) {
				assert := assert.New(t)
				assert.ErrorContains(m.EnableUnitFiles(t.Context(), []string{mockUnknownUnit}), "enable unit files ["+mockUnknownUnit+"]")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t)
			tc.expect(t, m, newSocketActivated(t))
		})
	}
}

func TestManager_Ping(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m *manager)
	}{
		{
			name: "connect once",
			expect: func(t *testing.T, m *manager) {
				assert := assert.New(t)
				assert.NoError(m.Ping(t.Context()))
				conn := m.conn
				assert.NotNil(conn)
				assert.NoError(m.Ping(t.Context()))
				assert.Same(conn, m.conn)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, newTestManager(t).(*manager))
		})
	}
}

func TestManager_runJob(t *testing.T) {
	tests := []struct {
		name       string
		jobTimeout time.Duration
		expect     func(t *testing.T, m Manager, unit *Unit)
	}{
		{
			name:       "job slower than the job timeout",
			jobTimeout: 50 * time.Millisecond,
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				assert.ErrorIs(m.StartTransientUnit(t.Context(), unit), context.DeadlineExceeded)
			},
		},
		{
			name:       "request canceled while the job runs",
			jobTimeout: mockJobTimeout,
			expect: func(t *testing.T, m Manager, unit *Unit) {
				assert := assert.New(t)
				ctx, cancel := context.WithCancel(t.Context())
				defer time.AfterFunc(50*time.Millisecond, cancel).Stop()
				assert.ErrorIs(m.StartTransientUnit(ctx, unit), context.Canceled)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testutil.RequireSystemd(t)
			m := New(tc.jobTimeout)
			t.Cleanup(m.Close)
			unit := newTestUnit(t)
			unit.Notify = true
			unit.TimeoutStart = 5 * time.Second
			tc.expect(t, m, unit)
		})
	}
}

func newTestManager(t *testing.T) Manager {
	t.Helper()
	testutil.RequireSystemd(t)
	m := New(mockJobTimeout)
	t.Cleanup(m.Close)
	return m
}

type socketActivated struct {
	socket, service string
	startsFile      string
}

func (u *socketActivated) starts(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(u.startsFile)
	assert.NoError(t, err)
	return strings.Count(string(data), "\n")
}

func newSocketActivated(t *testing.T) *socketActivated {
	t.Helper()
	name := "nydus-test-activated-" + strconv.Itoa(os.Getpid())
	units := &socketActivated{socket: name + ".socket", service: name + ".service", startsFile: "/run/" + name + ".starts"}
	files := map[string]string{
		units.socket: "[Socket]\nListenStream=/run/" + name + ".sock\nRemoveOnStop=yes\n",
		units.service: "[Unit]\nRequires=" + units.socket + "\nAfter=" + units.socket + "\n\n[Service]\nType=exec\n" +
			"ExecStartPre=/bin/sh -c 'echo >> " + units.startsFile + "; sleep 0.5'\nExecStart=/bin/sleep 300\n",
	}

	reload := func() { assert.NoError(t, exec.Command("systemctl", "daemon-reload").Run()) }
	t.Cleanup(func() {
		m := New(mockJobTimeout)
		defer m.Close()
		assert.NoError(t, m.StopUnit(context.Background(), units.service))
		assert.NoError(t, m.StopUnit(context.Background(), units.socket))
		for file := range files {
			assert.NoError(t, os.Remove(filepath.Join("/run/systemd/system", file)))
		}

		assert.NoError(t, os.RemoveAll(units.startsFile))
		reload()
	})

	for file, data := range files {
		assert.NoError(t, os.WriteFile(filepath.Join("/run/systemd/system", file), []byte(data), 0o644))
	}

	reload()
	return units
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
		m := New(mockJobTimeout)
		defer m.Close()
		assert.NoError(t, m.StopUnit(context.Background(), unit.Name))
		assert.NoError(t, m.StopUnit(context.Background(), unit.Slice))
	})

	return unit
}
