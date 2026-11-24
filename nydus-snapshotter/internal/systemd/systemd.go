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

// ActiveState is the ActiveState property of a unit, refer to
// https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html.
type ActiveState string

// Running reports whether the unit runs or starts.
func (s ActiveState) Running() bool {
	return s == ActiveStateActive || s == ActiveStateActivating
}

// Stopped reports whether the unit is down, cleanly or not.
func (s ActiveState) Stopped() bool {
	return s == ActiveStateInactive || s == ActiveStateFailed
}

const (
	// defaultJobTimeout bounds a job, from the call that queues it to its
	// result. It is longer than systemd takes over any job here, so the
	// result is systemd's: restarting the snapshotter's socket stops the
	// service, then starts the socket and the service again, 90s each by
	// default, refer to
	// https://www.freedesktop.org/software/systemd/man/latest/systemd-system.conf.html#DefaultTimeoutStartSec=.
	defaultJobTimeout = 5 * time.Minute

	// jobResultDone is the result of a successful job.
	jobResultDone = "done"

	// jobModeReplace is the job mode that replaces conflicting queued jobs,
	// systemctl's default.
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

// Systemd manages units through the Manager object of systemd's D-Bus API.
type Systemd interface {
	// StartTransientUnit starts a transient service unit and waits for the
	// job. An existing failed unit is reset and started again; an existing
	// unit that is not down returns errdefs.ErrAlreadyExists.
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

	// StartSlice starts a transient slice with its resources, or applies
	// them to a slice of that name that already exists.
	StartSlice(ctx context.Context, name, description string, resources Resources) error

	// SetResources applies cgroup limits to a loaded unit at runtime.
	SetResources(ctx context.Context, name string, resources Resources) error

	// MemoryCurrent returns the memory.current of a slice, math.MaxUint64
	// when systemd has none: the slice is not loaded.
	MemoryCurrent(ctx context.Context, name string) (uint64, error)

	// EnableUnitFiles enables unit files, then reloads the manager.
	EnableUnitFiles(ctx context.Context, files []string) error

	// Ping verifies that systemd answers, connecting when not connected.
	Ping(ctx context.Context) error

	// Close closes the D-Bus connection.
	Close()
}

// systemd is the D-Bus backed Systemd. It reconnects when the bus goes away,
// refer to https://github.com/opencontainers/cgroups/blob/main/systemd/dbus.go.
type systemd struct {
	// jobTimeout bounds a job, defaultJobTimeout outside tests.
	jobTimeout time.Duration

	// mu guards conn.
	mu sync.Mutex

	// conn is the current connection, nil until first use.
	conn *systemddbus.Conn
}

// New returns a Systemd whose jobs take at most defaultJobTimeout.
func New() Systemd {
	return &systemd{jobTimeout: defaultJobTimeout}
}

// StartTransientUnit starts a transient service unit and waits for the job.
// An existing failed unit is reset and started again; an existing unit that
// is not down returns errdefs.ErrAlreadyExists.
func (s *systemd) StartTransientUnit(ctx context.Context, unit *Unit) error {
	// go-systemd panics on an empty command line.
	if len(unit.ExecStart) == 0 {
		return fmt.Errorf("unit %s has no command: %w", unit.Name, errdefs.ErrInvalidArgument)
	}

	properties := unit.properties()

	// Reset a failed unit holding the name and retry once, as runc does,
	// refer to https://github.com/opencontainers/cgroups/blob/main/systemd/common.go.
	err := s.startTransient(ctx, unit.Name, properties)
	if dbusUnitExists.is(err) {
		state, stateErr := s.ActiveState(ctx, unit.Name)
		if stateErr != nil {
			return stateErr
		}

		if !state.Stopped() {
			return fmt.Errorf("unit %s is %s: %w", unit.Name, state, errdefs.ErrAlreadyExists)
		}

		if err := s.resetFailedUnit(ctx, unit.Name); err != nil {
			return err
		}

		err = s.startTransient(ctx, unit.Name, properties)
	}

	if err != nil {
		return fmt.Errorf("start unit %s: %w", unit.Name, err)
	}

	return nil
}

// startTransient starts a transient unit, a service or a slice, and waits for
// the job.
func (s *systemd) startTransient(ctx context.Context, name string, properties []systemddbus.Property) error {
	return s.runJob(ctx, func(ctx context.Context, conn *systemddbus.Conn, ch chan<- string) error {
		_, err := conn.StartTransientUnitContext(ctx, name, jobModeReplace, properties, ch)
		return err
	})
}

// StopUnit stops a unit and waits for the job; an unknown unit is not an
// error.
func (s *systemd) StopUnit(ctx context.Context, name string) error {
	err := s.runJob(ctx, func(ctx context.Context, conn *systemddbus.Conn, ch chan<- string) error {
		_, err := conn.StopUnitContext(ctx, name, jobModeReplace, ch)
		return err
	})

	var jobErr *jobError
	if errors.As(err, &jobErr) {
		return s.confirmStopped(ctx, name, jobErr)
	}

	if err != nil && !dbusNoSuchUnit.is(err) {
		return fmt.Errorf("stop unit %s: %w", name, err)
	}

	return nil
}

// confirmStopped returns an error unless a unit is down after a stop job
// that did not end in done: a job that was canceled or timed out can leave
// the unit running, which the caller must not take for stopped. The unit is
// reset first so its name is free, as runc resets it, refer to
// https://github.com/opencontainers/cgroups/blob/main/systemd/common.go.
func (s *systemd) confirmStopped(ctx context.Context, name string, jobErr *jobError) error {
	log.G(ctx).WithFields(log.Fields{"unit": name, "result": jobErr.result}).Warn("unit stop did not finish cleanly")
	if err := s.resetFailedUnit(ctx, name); err != nil {
		return err
	}

	state, err := s.ActiveState(ctx, name)
	if err != nil {
		return err
	}

	if !state.Stopped() {
		return fmt.Errorf("stop unit %s: job result %s left it %s", name, jobErr.result, state)
	}

	return nil
}

// resetFailedUnit resets a failed unit so its name can be reused.
func (s *systemd) resetFailedUnit(ctx context.Context, name string) error {
	if err := s.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		return conn.ResetFailedUnitContext(ctx, name)
	}); err != nil && !dbusNoSuchUnit.is(err) {
		return fmt.Errorf("reset failed unit %s: %w", name, err)
	}

	return nil
}

// StartUnit starts a unit and waits for the job. A running unit is left
// alone. A unit already starting or restarting is waited for: systemd merges
// the start into the job in flight, whereas a restart would run a second
// time, refer to job_install in
// https://github.com/systemd/systemd/blob/v255/src/core/job.c.
func (s *systemd) StartUnit(ctx context.Context, name string) error {
	if err := s.runJob(ctx, func(ctx context.Context, conn *systemddbus.Conn, ch chan<- string) error {
		_, err := conn.StartUnitContext(ctx, name, jobModeReplace, ch)
		return err
	}); err != nil {
		return fmt.Errorf("start unit %s: %w", name, err)
	}

	return nil
}

// RestartUnit restarts a unit and waits for the job.
func (s *systemd) RestartUnit(ctx context.Context, name string) error {
	if err := s.runJob(ctx, func(ctx context.Context, conn *systemddbus.Conn, ch chan<- string) error {
		_, err := conn.RestartUnitContext(ctx, name, jobModeReplace, ch)
		return err
	}); err != nil {
		return fmt.Errorf("restart unit %s: %w", name, err)
	}

	return nil
}

// ActiveState returns the active state of a unit, "inactive" when unknown.
func (s *systemd) ActiveState(ctx context.Context, name string) (ActiveState, error) {
	var state ActiveState
	if err := s.unitProperty(ctx, name, unitInterface, "ActiveState", &state); err != nil {
		return "", fmt.Errorf("get unit %s state: %w", name, err)
	}

	return state, nil
}

// ListUnits returns the active state of the loaded service units of a slice
// matching the pattern, keyed by unit name. Units of other slices are left
// out.
func (s *systemd) ListUnits(ctx context.Context, slice, pattern string) (map[string]ActiveState, error) {
	var statuses []systemddbus.UnitStatus
	if err := s.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) (err error) {
		statuses, err = conn.ListUnitsByPatternsContext(ctx, nil, []string{pattern})
		return err
	}); err != nil {
		return nil, fmt.Errorf("list units %s: %w", pattern, err)
	}

	units := make(map[string]ActiveState, len(statuses))
	for _, status := range statuses {
		var unitSlice string
		if err := s.unitProperty(ctx, status.Name, serviceInterface, "Slice", &unitSlice); err != nil {
			return nil, fmt.Errorf("get unit %s slice: %w", status.Name, err)
		}

		if unitSlice == slice {
			units[status.Name] = ActiveState(status.ActiveState)
		}
	}

	return units, nil
}

// StartSlice starts a transient slice with its resources, or applies them to
// a slice of that name that already exists.
func (s *systemd) StartSlice(ctx context.Context, name, description string, resources Resources) error {
	properties := append([]systemddbus.Property{
		systemddbus.PropDescription(description),
	}, resources.properties()...)

	err := s.startTransient(ctx, name, properties)
	if dbusUnitExists.is(err) {
		return s.SetResources(ctx, name, resources)
	}

	if err != nil {
		return fmt.Errorf("start slice %s: %w", name, err)
	}

	return nil
}

// SetResources applies cgroup limits to a loaded unit at runtime.
func (s *systemd) SetResources(ctx context.Context, name string, resources Resources) error {
	if err := s.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		return conn.SetUnitPropertiesContext(ctx, name, true, resources.properties()...)
	}); err != nil {
		return fmt.Errorf("set unit %s resources: %w", name, err)
	}

	return nil
}

// MemoryCurrent returns the memory.current of a slice, math.MaxUint64 when
// systemd has none: the slice is not loaded.
func (s *systemd) MemoryCurrent(ctx context.Context, name string) (uint64, error) {
	var current uint64
	if err := s.unitProperty(ctx, name, sliceInterface, "MemoryCurrent", &current); err != nil {
		return 0, fmt.Errorf("get slice %s memory: %w", name, err)
	}

	return current, nil
}

// EnableUnitFiles enables unit files, then reloads the manager, as systemctl
// enable does: systemd reads a unit file to enable from disk, so a new one
// needs no reload first, refer to
// https://github.com/systemd/systemd/blob/v255/src/systemctl/systemctl-enable.c.
func (s *systemd) EnableUnitFiles(ctx context.Context, files []string) error {
	if err := s.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		if _, _, err := conn.EnableUnitFilesContext(ctx, files, false, true); err != nil {
			return err
		}

		return conn.ReloadContext(ctx)
	}); err != nil {
		return fmt.Errorf("enable unit files %v: %w", files, err)
	}

	return nil
}

// Ping verifies that systemd answers, connecting when not connected, as
// database/sql's DB.Ping verifies a connection and establishes one if
// necessary, refer to https://pkg.go.dev/database/sql#DB.PingContext. The
// round trip is a read of the manager's SystemState property.
func (s *systemd) Ping(ctx context.Context) error {
	if err := s.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		_, err := conn.SystemStateContext(ctx)
		return err
	}); err != nil {
		return fmt.Errorf("ping systemd: %w", err)
	}

	return nil
}

// Close closes the D-Bus connection.
func (s *systemd) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
}

// runJob queues a job with start and waits for its result, as runc's
// startUnit and cri-o's RunUnderSystemdScope do, refer to
// https://github.com/opencontainers/cgroups/blob/main/systemd/common.go and
// https://github.com/cri-o/cri-o/blob/main/utils/utils_linux.go. Only done is
// a success; any other result, such as failed, timeout, canceled or skipped,
// returns a jobError.
//
//	start ─▶ systemd queues the job ─▶ job removed ─▶ result on ch
//	         jobTimeout or ctx done ──▶ error, the job goes on in systemd
//
// One deadline bounds the call that queues the job and the wait, as gVisor
// bounds its call, refer to
// https://github.com/google/gvisor/blob/master/runsc/cgroup/systemd.go. The
// channel is buffered because go-systemd sends the result under the lock
// every job start takes, refer to
// https://github.com/coreos/go-systemd/blob/main/dbus/methods.go.
func (s *systemd) runJob(ctx context.Context, start func(context.Context, *systemddbus.Conn, chan<- string) error) error {
	ctx, cancel := context.WithTimeout(ctx, s.jobTimeout)
	defer cancel()

	ch := make(chan string, 1)
	if err := s.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		return start(ctx, conn, ch)
	}); err != nil {
		return err
	}

	select {
	case result := <-ch:
		if result != jobResultDone {
			return &jobError{result: result}
		}

		return nil
	case <-ctx.Done():
		return fmt.Errorf("wait for job: %w", ctx.Err())
	}
}
