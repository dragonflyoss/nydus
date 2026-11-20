/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate mockgen -destination mocks/systemd_mock.go -source systemd.go -package mocks

// Package systemd manages units over systemd's D-Bus API, as runc's systemd
// cgroup driver does, refer to
// https://github.com/opencontainers/cgroups/blob/main/systemd/dbus.go.
package systemd

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	systemddbus "github.com/coreos/go-systemd/v22/dbus"
)

// ActiveState is the ActiveState property of a unit, refer to
// https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html.
type ActiveState string

const (
	// ActiveStateActive is a running unit.
	ActiveStateActive ActiveState = "active"

	// ActiveStateActivating is a starting unit.
	ActiveStateActivating ActiveState = "activating"

	// ActiveStateDeactivating is a stopping unit.
	ActiveStateDeactivating ActiveState = "deactivating"

	// ActiveStateInactive is a stopped or unknown unit.
	ActiveStateInactive ActiveState = "inactive"

	// ActiveStateFailed is a unit whose process failed.
	ActiveStateFailed ActiveState = "failed"
)

// Running reports whether the unit runs or starts.
func (s ActiveState) Running() bool {
	return s == ActiveStateActive || s == ActiveStateActivating
}

// Stopped reports whether the unit is down, cleanly or not.
func (s ActiveState) Stopped() bool {
	return s == ActiveStateInactive || s == ActiveStateFailed
}

const (
	// jobResultDone is the result of a successful job.
	jobResultDone = "done"

	// jobModeReplace replaces conflicting queued jobs, as systemctl does.
	jobModeReplace = "replace"
)

// jobError is a job that finished with a result other than done.
type jobError struct {
	// result is the job result, e.g. failed, timeout or canceled.
	result string
}

// Error returns the job failure.
func (e *jobError) Error() string {
	return fmt.Sprintf("job finished with %q", e.result)
}

// Manager manages units through the Manager object of systemd's D-Bus API.
type Manager interface {
	// StartTransientUnit starts a transient service unit and waits for the
	// job. An existing failed unit is reset and started again; an existing
	// running one returns errdefs.ErrAlreadyExists.
	StartTransientUnit(ctx context.Context, unit *Unit) error

	// StopUnit stops a unit and waits for the job; an unknown unit is not an
	// error.
	StopUnit(ctx context.Context, name string) error

	// StartUnit starts a unit and waits for the job. A running unit is left
	// alone, and one being started or restarted is waited for.
	StartUnit(ctx context.Context, name string) error

	// RestartUnit restarts a unit and waits for the job.
	RestartUnit(ctx context.Context, name string) error

	// ActiveState returns the active state of a unit, "inactive" when unknown.
	ActiveState(ctx context.Context, name string) (ActiveState, error)

	// ListUnits returns the active state of the loaded service units of a
	// slice matching the pattern, keyed by unit name. Units of other slices
	// are left out.
	ListUnits(ctx context.Context, slice, pattern string) (map[string]ActiveState, error)

	// StartSlice starts a slice when not running and applies its resources.
	StartSlice(ctx context.Context, name, description string, resources Resources) error

	// SetResources applies cgroup limits to a loaded unit at runtime.
	SetResources(ctx context.Context, name string, resources Resources) error

	// MemoryCurrent returns the memory.current of a slice.
	MemoryCurrent(ctx context.Context, name string) (uint64, error)

	// EnableUnitFiles enables unit files, then reloads the manager.
	EnableUnitFiles(ctx context.Context, files []string) error

	// Ping connects to systemd when not connected. It fails when systemd
	// cannot be reached or is older than the manager needs.
	Ping(ctx context.Context) error

	// Close closes the D-Bus connection.
	Close()
}

// manager is the D-Bus backed Manager. It reconnects when the bus goes away,
// refer to https://github.com/opencontainers/cgroups/blob/main/systemd/dbus.go.
type manager struct {
	// jobTimeout bounds waiting for a job result.
	jobTimeout time.Duration

	// minVersion is the oldest systemd a connection is kept to.
	minVersion int

	// mu guards conn.
	mu sync.Mutex

	// conn is the current connection, nil until first use.
	conn *systemddbus.Conn
}

// New returns a systemd manager whose jobs wait at most jobTimeout for their
// result.
func New(jobTimeout time.Duration) Manager {
	return &manager{jobTimeout: jobTimeout, minVersion: minVersion}
}

// StartTransientUnit starts a transient service unit and waits for the job.
// An existing failed unit is reset and started again; an existing running one
// returns errdefs.ErrAlreadyExists.
func (m *manager) StartTransientUnit(ctx context.Context, unit *Unit) error {
	// go-systemd panics on an empty command line.
	if len(unit.ExecStart) == 0 {
		return fmt.Errorf("unit %s has no command: %w", unit.Name, errdefs.ErrInvalidArgument)
	}

	properties := unit.properties()

	// Reset a failed unit holding the name and retry once, as runc does,
	// refer to https://github.com/opencontainers/cgroups/blob/main/systemd/common.go.
	err := m.startTransient(ctx, unit.Name, properties)
	if dbusUnitExists.is(err) {
		state, stateErr := m.ActiveState(ctx, unit.Name)
		if stateErr != nil {
			return stateErr
		}

		if !state.Stopped() {
			return fmt.Errorf("unit %s is %s: %w", unit.Name, state, errdefs.ErrAlreadyExists)
		}

		if err := m.resetFailedUnit(ctx, unit.Name); err != nil {
			return err
		}

		err = m.startTransient(ctx, unit.Name, properties)
	}

	if err != nil {
		return fmt.Errorf("start unit %s: %w", unit.Name, err)
	}

	return nil
}

// startTransient starts a transient unit, a service or a slice, and waits for
// the job.
func (m *manager) startTransient(ctx context.Context, name string, properties []systemddbus.Property) error {
	return m.runJob(ctx, func(conn *systemddbus.Conn, ch chan<- string) error {
		_, err := conn.StartTransientUnitContext(ctx, name, jobModeReplace, properties, ch)
		return err
	})
}

// StopUnit stops a unit and waits for the job; an unknown unit is not an
// error.
func (m *manager) StopUnit(ctx context.Context, name string) error {
	err := m.runJob(ctx, func(conn *systemddbus.Conn, ch chan<- string) error {
		_, err := conn.StopUnitContext(ctx, name, jobModeReplace, ch)
		return err
	})

	var jobErr *jobError
	if errors.As(err, &jobErr) {
		return m.confirmStopped(ctx, name, jobErr)
	}

	if err != nil && !dbusNoSuchUnit.is(err) {
		return fmt.Errorf("stop unit %s: %w", name, err)
	}

	return nil
}

// confirmStopped tells whether a unit is down after a stop job that did not
// end in done: a job that was canceled or timed out can leave the unit
// running, which the caller must not take for stopped. The unit is reset
// first so its name is free, as runc resets it, refer to
// https://github.com/opencontainers/cgroups/blob/main/systemd/common.go.
func (m *manager) confirmStopped(ctx context.Context, name string, jobErr *jobError) error {
	log.G(ctx).WithFields(log.Fields{"unit": name, "result": jobErr.result}).Warn("unit stop did not finish cleanly")
	if err := m.resetFailedUnit(ctx, name); err != nil {
		return err
	}

	state, err := m.ActiveState(ctx, name)
	if err != nil {
		return err
	}

	if !state.Stopped() {
		return fmt.Errorf("stop unit %s: job result %s left it %s", name, jobErr.result, state)
	}

	return nil
}

// StartUnit starts a unit and waits for the job. A running unit is left
// alone. A unit already starting or restarting is waited for: systemd merges
// the start into the job in flight, whereas a restart would run a second
// time, refer to job_install in
// https://github.com/systemd/systemd/blob/v255/src/core/job.c.
func (m *manager) StartUnit(ctx context.Context, name string) error {
	if err := m.runJob(ctx, func(conn *systemddbus.Conn, ch chan<- string) error {
		_, err := conn.StartUnitContext(ctx, name, jobModeReplace, ch)
		return err
	}); err != nil {
		return fmt.Errorf("start unit %s: %w", name, err)
	}

	return nil
}

// RestartUnit restarts a unit and waits for the job.
func (m *manager) RestartUnit(ctx context.Context, name string) error {
	if err := m.runJob(ctx, func(conn *systemddbus.Conn, ch chan<- string) error {
		_, err := conn.RestartUnitContext(ctx, name, jobModeReplace, ch)
		return err
	}); err != nil {
		return fmt.Errorf("restart unit %s: %w", name, err)
	}

	return nil
}

// ActiveState returns the active state of a unit, "inactive" when unknown.
func (m *manager) ActiveState(ctx context.Context, name string) (ActiveState, error) {
	var state ActiveState
	if err := m.unitProperty(ctx, name, unitInterface, "ActiveState", &state); err != nil {
		return "", fmt.Errorf("get unit %s state: %w", name, err)
	}

	return state, nil
}

// ListUnits returns the active state of the loaded service units of a slice
// matching the pattern, keyed by unit name. Units of other slices are left
// out.
func (m *manager) ListUnits(ctx context.Context, slice, pattern string) (map[string]ActiveState, error) {
	var statuses []systemddbus.UnitStatus
	if err := m.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) (err error) {
		statuses, err = conn.ListUnitsByPatternsContext(ctx, nil, []string{pattern})
		return err
	}); err != nil {
		return nil, fmt.Errorf("list units %s: %w", pattern, err)
	}

	units := make(map[string]ActiveState, len(statuses))
	for _, status := range statuses {
		var unitSlice string
		if err := m.unitProperty(ctx, status.Name, serviceInterface, "Slice", &unitSlice); err != nil {
			return nil, fmt.Errorf("get unit %s slice: %w", status.Name, err)
		}

		if unitSlice == slice {
			units[status.Name] = ActiveState(status.ActiveState)
		}
	}

	return units, nil
}

// StartSlice starts a slice when not running and applies its resources.
func (m *manager) StartSlice(ctx context.Context, name, description string, resources Resources) error {
	properties := append([]systemddbus.Property{
		systemddbus.PropDescription(description),
	}, resources.properties()...)

	err := m.startTransient(ctx, name, properties)
	if dbusUnitExists.is(err) {
		return m.SetResources(ctx, name, resources)
	}

	if err != nil {
		return fmt.Errorf("start slice %s: %w", name, err)
	}

	return nil
}

// SetResources applies cgroup limits to a loaded unit at runtime.
func (m *manager) SetResources(ctx context.Context, name string, resources Resources) error {
	if err := m.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		return conn.SetUnitPropertiesContext(ctx, name, true, resources.properties()...)
	}); err != nil {
		return fmt.Errorf("set unit %s resources: %w", name, err)
	}

	return nil
}

// MemoryCurrent returns the memory.current of a slice.
func (m *manager) MemoryCurrent(ctx context.Context, name string) (uint64, error) {
	var current uint64
	if err := m.unitProperty(ctx, name, sliceInterface, "MemoryCurrent", &current); err != nil {
		return 0, fmt.Errorf("get slice %s memory: %w", name, err)
	}

	return current, nil
}

// EnableUnitFiles enables unit files, then reloads the manager, as systemctl
// enable does: systemd reads a unit file to enable from disk, so a new one
// needs no reload first, refer to
// https://github.com/systemd/systemd/blob/v255/src/systemctl/systemctl-enable.c.
func (m *manager) EnableUnitFiles(ctx context.Context, files []string) error {
	if err := m.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		if _, _, err := conn.EnableUnitFilesContext(ctx, files, false, true); err != nil {
			return err
		}

		return conn.ReloadContext(ctx)
	}); err != nil {
		return fmt.Errorf("enable unit files %v: %w", files, err)
	}

	return nil
}

// Ping connects to systemd when not connected, as database/sql's DB.Ping
// establishes a connection if necessary, refer to
// https://pkg.go.dev/database/sql#DB.PingContext. It fails when systemd
// cannot be reached or is older than minVersion.
func (m *manager) Ping(ctx context.Context) error {
	_, err := m.connection(ctx)
	return err
}

// Close closes the D-Bus connection.
func (m *manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conn != nil {
		m.conn.Close()
		m.conn = nil
	}
}

// resetFailedUnit resets a failed unit so its name can be reused.
func (m *manager) resetFailedUnit(ctx context.Context, name string) error {
	if err := m.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		return conn.ResetFailedUnitContext(ctx, name)
	}); err != nil && !dbusNoSuchUnit.is(err) {
		return fmt.Errorf("reset failed unit %s: %w", name, err)
	}

	return nil
}

// runJob queues a job and waits for its result. The channel is buffered
// because go-systemd blocks every job while a result is unread, refer to
// https://github.com/coreos/go-systemd/blob/main/dbus/methods.go.
func (m *manager) runJob(ctx context.Context, start func(*systemddbus.Conn, chan<- string) error) error {
	ch := make(chan string, 1)
	if err := m.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		return start(conn, ch)
	}); err != nil {
		return err
	}

	timer := time.NewTimer(m.jobTimeout)
	defer timer.Stop()
	select {
	case result := <-ch:
		if result != jobResultDone {
			return &jobError{result: result}
		}

		return nil
	case <-timer.C:
		return fmt.Errorf("wait for job: %w", context.DeadlineExceeded)
	case <-ctx.Done():
		return ctx.Err()
	}
}
