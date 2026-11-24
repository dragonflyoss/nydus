/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package systemd

import (
	"context"
	"fmt"
	"math"
	"math/rand/v2"
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

func TestSystemd_StartTransientUnit(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s Systemd, unit *Unit)
	}{
		{
			name: "start a unit",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.StartTransientUnit(t.Context(), unit))
				state, err := s.ActiveState(t.Context(), unit.Name)
				assert.NoError(err)
				assert.Equal(ActiveStateActive, state)
			},
		},
		{
			name: "refuse a running unit",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.StartTransientUnit(t.Context(), unit))
				assert.ErrorIs(s.StartTransientUnit(t.Context(), unit), errdefs.ErrAlreadyExists)
			},
		},
		{
			name: "start again a failed unit holding the name",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(exec.Command("systemd-run", "--unit", unit.Name, "false").Run())
				assert.Eventually(func() bool {
					state, err := s.ActiveState(t.Context(), unit.Name)
					return err == nil && state == ActiveStateFailed
				}, 10*time.Second, 10*time.Millisecond)

				assert.NoError(s.StartTransientUnit(t.Context(), unit))
				state, err := s.ActiveState(t.Context(), unit.Name)
				assert.NoError(err)
				assert.Equal(ActiveStateActive, state)
			},
		},
		{
			name: "unit without a command",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				unit.ExecStart = nil
				assert.ErrorIs(s.StartTransientUnit(t.Context(), unit), errdefs.ErrInvalidArgument)
			},
		},
		{
			name: "unit whose command is missing",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				unit.ExecStart = []string{"/nonexistent/nydus-test"}
				assert.EqualError(s.StartTransientUnit(t.Context(), unit), fmt.Sprintf("start unit %s: job finished with %q", unit.Name, "failed"))
			},
		},
		{
			name: "notify unit that never reports ready",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				unit.Notify = true
				unit.TimeoutStart = 300 * time.Millisecond
				assert.ErrorContains(s.StartTransientUnit(t.Context(), unit), "finished with")
				state, err := s.ActiveState(t.Context(), unit.Name)
				assert.NoError(err)
				assert.NotEqual(ActiveStateActive, state)
			},
		},
		{
			name: "unit file holding the name",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				unit.Name = newSocketActivated(t).service
				assert.ErrorContains(s.StartTransientUnit(t.Context(), unit), "start unit "+unit.Name)
				state, err := s.ActiveState(t.Context(), unit.Name)
				assert.NoError(err)
				assert.Equal(ActiveStateInactive, state)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSystemd(t)
			tc.expect(t, s, newTestUnit(t))
		})
	}
}

func TestSystemd_StopUnit(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s Systemd, unit *Unit)
	}{
		{
			name: "stop a running unit",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.StartTransientUnit(t.Context(), unit))
				assert.NoError(s.StopUnit(t.Context(), unit.Name))
				state, err := s.ActiveState(t.Context(), unit.Name)
				assert.NoError(err)
				assert.Equal(ActiveStateInactive, state)
			},
		},
		{
			name: "stop an unknown unit",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.StopUnit(t.Context(), unit.Name))
			},
		},
		{
			name: "stop a unit with an invalid name",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				assert.ErrorContains(s.StopUnit(t.Context(), mockInvalidUnit), "stop unit "+mockInvalidUnit)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, newTestSystemd(t), newTestUnit(t))
		})
	}
}

func TestSystemd_confirmStopped(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s *systemd, unit *Unit)
	}{
		{
			name: "unit a failed stop job left running",
			expect: func(t *testing.T, s *systemd, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.StartTransientUnit(t.Context(), unit))
				assert.ErrorContains(s.confirmStopped(t.Context(), unit.Name, &jobError{result: "canceled"}), "left it active")
			},
		},
		{
			name: "unit a failed stop job stopped",
			expect: func(t *testing.T, s *systemd, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.confirmStopped(t.Context(), unit.Name, &jobError{result: "failed"}))
			},
		},
		{
			name: "unit whose state cannot be read",
			expect: func(t *testing.T, s *systemd, unit *Unit) {
				assert := assert.New(t)
				assert.ErrorContains(s.confirmStopped(t.Context(), mockInvalidUnit, &jobError{result: "failed"}), "get unit "+mockInvalidUnit+" state")
			},
		},
		{
			name: "unit that cannot be reset",
			expect: func(t *testing.T, s *systemd, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.Ping(t.Context()))
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				assert.ErrorContains(s.confirmStopped(ctx, unit.Name, &jobError{result: "failed"}), "reset failed unit "+unit.Name)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, newTestSystemd(t).(*systemd), newTestUnit(t))
		})
	}
}

func TestSystemd_StartUnit(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s Systemd, units *socketActivated)
	}{
		{
			name: "start a unit and leave it alone once it runs",
			expect: func(t *testing.T, s Systemd, units *socketActivated) {
				assert := assert.New(t)
				assert.NoError(s.StartUnit(t.Context(), units.socket))
				assert.NoError(s.StartUnit(t.Context(), units.service))
				assert.NoError(s.StartUnit(t.Context(), units.service))
				state, err := s.ActiveState(t.Context(), units.service)
				assert.NoError(err)
				assert.Equal(ActiveStateActive, state)
				assert.Equal(1, units.starts(t))
			},
		},
		{
			name: "wait for the restart a restarted socket gives its running service",
			expect: func(t *testing.T, s Systemd, units *socketActivated) {
				assert := assert.New(t)
				assert.NoError(s.StartUnit(t.Context(), units.socket))
				assert.NoError(s.StartUnit(t.Context(), units.service))
				assert.NoError(s.RestartUnit(t.Context(), units.socket))
				assert.NoError(s.StartUnit(t.Context(), units.service))
				state, err := s.ActiveState(t.Context(), units.service)
				assert.NoError(err)
				assert.Equal(ActiveStateActive, state)
				assert.Equal(2, units.starts(t))
			},
		},
		{
			name: "leave a service alone that its restarted socket is starting again",
			expect: func(t *testing.T, s Systemd, units *socketActivated) {
				assert := assert.New(t)
				assert.NoError(s.StartUnit(t.Context(), units.socket))
				assert.NoError(s.StartUnit(t.Context(), units.service))
				assert.NoError(s.RestartUnit(t.Context(), units.socket))
				assert.Eventually(func() bool { return units.starts(t) == 2 }, 5*time.Second, 10*time.Millisecond)
				assert.NoError(s.StartUnit(t.Context(), units.service))
				state, err := s.ActiveState(t.Context(), units.service)
				assert.NoError(err)
				assert.Equal(ActiveStateActive, state)
				assert.Equal(2, units.starts(t))
			},
		},
		{
			name: "unknown unit",
			expect: func(t *testing.T, s Systemd, units *socketActivated) {
				assert := assert.New(t)
				assert.ErrorContains(s.StartUnit(t.Context(), mockUnknownUnit), "start unit "+mockUnknownUnit)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSystemd(t)
			tc.expect(t, s, newSocketActivated(t))
		})
	}
}

func TestSystemd_RestartUnit(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s Systemd, units *socketActivated)
	}{
		{
			name: "restart a running unit",
			expect: func(t *testing.T, s Systemd, units *socketActivated) {
				assert := assert.New(t)
				assert.NoError(s.StartUnit(t.Context(), units.service))
				assert.NoError(s.RestartUnit(t.Context(), units.service))
				assert.Equal(2, units.starts(t))
			},
		},
		{
			name: "unknown unit",
			expect: func(t *testing.T, s Systemd, units *socketActivated) {
				assert := assert.New(t)
				assert.ErrorContains(s.RestartUnit(t.Context(), mockUnknownUnit), "restart unit "+mockUnknownUnit)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSystemd(t)
			tc.expect(t, s, newSocketActivated(t))
		})
	}
}

func TestSystemd_ActiveState(t *testing.T) {
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
			state, err := newTestSystemd(t).ActiveState(t.Context(), tc.unit)
			tc.expect(t, state, err)
		})
	}
}

func TestSystemd_ListUnits(t *testing.T) {
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
			s, unit := newTestSystemd(t), newTestUnit(t)
			assert.NoError(t, s.StartTransientUnit(t.Context(), unit))

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.canceled {
				cancel()
			}

			units, err := s.ListUnits(ctx, tc.slice(unit), tc.pattern)
			tc.expect(t, unit, units, err)
		})
	}
}

func TestSystemd_StartSlice(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s Systemd, slice string)
	}{
		{
			name: "start a slice and change its limits",
			expect: func(t *testing.T, s Systemd, slice string) {
				assert := assert.New(t)
				assert.NoError(s.StartSlice(t.Context(), slice, "nydus-snapshotter unit test", Resources{MemoryHigh: 1 << 30}))
				_, err := s.MemoryCurrent(t.Context(), slice)
				assert.NoError(err)
				assert.NoError(s.StartSlice(t.Context(), slice, "nydus-snapshotter unit test", Resources{MemoryHigh: 2 << 30, CPUQuotaPerSecUSec: 500_000}))
				var high uint64
				assert.NoError(s.(*systemd).unitProperty(t.Context(), slice, sliceInterface, "MemoryHigh", &high))
				assert.Equal(uint64(2<<30), high)

				assert.NoError(s.StartSlice(t.Context(), slice, "nydus-snapshotter unit test", Resources{}))
				assert.NoError(s.(*systemd).unitProperty(t.Context(), slice, sliceInterface, "MemoryHigh", &high))
				assert.Equal(uint64(math.MaxUint64), high)
			},
		},
		{
			name: "invalid slice name",
			expect: func(t *testing.T, s Systemd, slice string) {
				assert := assert.New(t)
				assert.ErrorContains(s.StartSlice(t.Context(), "nydus test.slice", "nydus-snapshotter unit test", Resources{}), "start slice nydus test.slice")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSystemd(t)
			slice := "nydustest" + strconv.Itoa(os.Getpid()) + ".slice"
			t.Cleanup(func() { assert.NoError(t, s.StopUnit(context.Background(), slice)) })
			tc.expect(t, s, slice)
		})
	}
}

func TestSystemd_SetResources(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s Systemd, unit *Unit)
	}{
		{
			name: "limit a running unit",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.StartTransientUnit(t.Context(), unit))
				assert.NoError(s.SetResources(t.Context(), unit.Name, Resources{MemoryHigh: 1 << 30}))
				var high uint64
				assert.NoError(s.(*systemd).unitProperty(t.Context(), unit.Name, serviceInterface, "MemoryHigh", &high))
				assert.Equal(uint64(1<<30), high)
			},
		},
		{
			name: "unknown unit",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				assert.ErrorContains(s.SetResources(t.Context(), mockUnknownUnit, Resources{MemoryHigh: 1 << 30}), "set unit "+mockUnknownUnit+" resources")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSystemd(t)
			tc.expect(t, s, newTestUnit(t))
		})
	}
}

func TestSystemd_MemoryCurrent(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s Systemd, unit *Unit)
	}{
		{
			name: "memory of a slice",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.StartTransientUnit(t.Context(), unit))
				_, err := s.MemoryCurrent(t.Context(), unit.Slice)
				assert.NoError(err)
			},
		},
		{
			name: "slice that is not loaded",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				current, err := s.MemoryCurrent(t.Context(), "nydustest-unknown.slice")
				assert.NoError(err)
				assert.Equal(uint64(math.MaxUint64), current)
			},
		},
		{
			name: "unit that is no slice",
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				assert.NoError(s.StartTransientUnit(t.Context(), unit))
				_, err := s.MemoryCurrent(t.Context(), unit.Name)
				assert.ErrorContains(err, "get slice "+unit.Name+" memory")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSystemd(t)
			tc.expect(t, s, newTestUnit(t))
		})
	}
}

func TestSystemd_EnableUnitFiles(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s Systemd, units *socketActivated)
	}{
		{
			name: "unit file without install config",
			expect: func(t *testing.T, s Systemd, units *socketActivated) {
				assert := assert.New(t)
				assert.NoError(s.EnableUnitFiles(t.Context(), []string{units.socket, units.service}))
			},
		},
		{
			name: "missing unit file",
			expect: func(t *testing.T, s Systemd, units *socketActivated) {
				assert := assert.New(t)
				assert.ErrorContains(s.EnableUnitFiles(t.Context(), []string{mockUnknownUnit}), "enable unit files ["+mockUnknownUnit+"]")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestSystemd(t)
			tc.expect(t, s, newSocketActivated(t))
		})
	}
}

func TestSystemd_Ping(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s *systemd)
	}{
		{
			name: "connect once",
			expect: func(t *testing.T, s *systemd) {
				assert := assert.New(t)
				assert.NoError(s.Ping(t.Context()))
				conn := s.conn
				assert.NotNil(conn)
				assert.NoError(s.Ping(t.Context()))
				assert.Same(conn, s.conn)
			},
		},
		{
			name: "reconnect once the connection is closed",
			expect: func(t *testing.T, s *systemd) {
				assert := assert.New(t)
				assert.NoError(s.Ping(t.Context()))
				closed := s.conn
				closed.Close()
				assert.Eventually(func() bool { return s.Ping(t.Context()) == nil }, 5*time.Second, 10*time.Millisecond)
				assert.NotSame(closed, s.conn)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, newTestSystemd(t).(*systemd))
		})
	}
}

func TestSystemd_runJob(t *testing.T) {
	tests := []struct {
		name       string
		jobTimeout time.Duration
		expect     func(t *testing.T, s Systemd, unit *Unit)
	}{
		{
			name:       "job slower than the job timeout",
			jobTimeout: 50 * time.Millisecond,
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				assert.ErrorIs(s.StartTransientUnit(t.Context(), unit), context.DeadlineExceeded)
			},
		},
		{
			name:       "request canceled while the job runs",
			jobTimeout: defaultJobTimeout,
			expect: func(t *testing.T, s Systemd, unit *Unit) {
				assert := assert.New(t)
				ctx, cancel := context.WithCancel(t.Context())
				defer time.AfterFunc(50*time.Millisecond, cancel).Stop()
				assert.ErrorIs(s.StartTransientUnit(ctx, unit), context.Canceled)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testutil.RequireSystemd(t)
			s := New().(*systemd)
			s.jobTimeout = tc.jobTimeout
			t.Cleanup(s.Close)
			unit := newTestUnit(t)
			unit.Notify = true
			unit.TimeoutStart = 5 * time.Second
			tc.expect(t, s, unit)
		})
	}
}

func newTestSystemd(t *testing.T) Systemd {
	t.Helper()
	testutil.RequireSystemd(t)
	s := New()
	t.Cleanup(s.Close)
	return s
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
	sleep, err := exec.LookPath("sleep")
	assert.NoError(t, err)
	name := "nydus-test-activated-" + strconv.Itoa(os.Getpid()) + "-" + strconv.Itoa(rand.IntN(1<<30))
	units := &socketActivated{socket: name + ".socket", service: name + ".service", startsFile: "/run/" + name + ".starts"}
	files := map[string]string{
		units.socket: "[Socket]\nListenStream=/run/" + name + ".sock\nRemoveOnStop=yes\n",
		units.service: "[Unit]\nRequires=" + units.socket + "\nAfter=" + units.socket + "\n\n[Service]\nType=exec\n" +
			"ExecStartPre=/bin/sh -c 'echo >> " + units.startsFile + "; sleep 0.5'\nExecStart=" + sleep + " 300\n",
	}

	reload := func() { assert.NoError(t, exec.Command("systemctl", "daemon-reload").Run()) }
	t.Cleanup(func() {
		s := New()
		defer s.Close()
		assert.NoError(t, s.StopUnit(context.Background(), units.service))
		assert.NoError(t, s.StopUnit(context.Background(), units.socket))
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
		Name:        "nydus-test-" + strconv.Itoa(os.Getpid()) + "-" + strconv.Itoa(rand.IntN(1<<30)) + ".service",
		Description: "nydus-snapshotter unit test",
		Slice:       "nydustest" + strconv.Itoa(os.Getpid()) + "units.slice",
		ExecStart:   []string{sleep, "300"},
		TimeoutStop: 10 * time.Second,
	}

	t.Cleanup(func() {
		s := New()
		defer s.Close()
		assert.NoError(t, s.StopUnit(context.Background(), unit.Name))
		assert.NoError(t, s.StopUnit(context.Background(), unit.Slice))
	})

	return unit
}
