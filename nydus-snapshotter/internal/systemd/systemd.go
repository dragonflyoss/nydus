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
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	systemddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	// ActiveStateActive is a running unit.
	ActiveStateActive = "active"

	// ActiveStateActivating is a starting unit.
	ActiveStateActivating = "activating"

	// ActiveStateDeactivating is a stopping unit.
	ActiveStateDeactivating = "deactivating"

	// ActiveStateInactive is a stopped or unknown unit.
	ActiveStateInactive = "inactive"

	// ActiveStateFailed is a unit whose process failed.
	ActiveStateFailed = "failed"

	// jobResultDone is the result of a successful job.
	jobResultDone = "done"

	// jobModeReplace replaces conflicting queued jobs, as systemctl does.
	jobModeReplace = "replace"

	// dbusUnitExists is the D-Bus error name of starting a loaded unit.
	dbusUnitExists = "org.freedesktop.systemd1.UnitExists"

	// dbusNoSuchUnit is the D-Bus error name of an unknown unit.
	dbusNoSuchUnit = "org.freedesktop.systemd1.NoSuchUnit"

	// minVersion is the oldest systemd knowing every unit property used,
	// Type=exec being the newest, refer to systemd.service(5).
	minVersion = 240
)

// jobError is a job that finished with a result other than done.
type jobError struct {
	// unit is the unit of the job.
	unit string

	// result is the job result, e.g. failed, timeout or canceled.
	result string
}

// Error returns the job failure.
func (e *jobError) Error() string {
	return fmt.Sprintf("job of unit %s finished with %q", e.unit, e.result)
}

// Resources are cgroup limits of a unit; 0 means no limit.
type Resources struct {
	// MemoryMax is memory.max in bytes.
	MemoryMax uint64

	// MemoryHigh is memory.high in bytes.
	MemoryHigh uint64

	// CPUQuotaPerSecUSec is CPU time in microseconds per second.
	CPUQuotaPerSecUSec uint64
}

// Unit is a transient service unit.
type Unit struct {
	// Name is the unit name.
	Name string

	// Description is the unit description.
	Description string

	// Slice is the slice the unit runs in.
	Slice string

	// ExecStart is the command line.
	ExecStart []string

	// Environment are KEY=VALUE variables of the process; never credentials,
	// which any user can read through systemctl show.
	Environment []string

	// Before orders the unit before these units, so it stops after them.
	Before []string

	// TimeoutStop bounds the stop of the unit, systemd's default when 0.
	TimeoutStop time.Duration

	// OOMScoreAdjust is the OOM score adjustment of the process.
	OOMScoreAdjust int

	// LimitNOFILE is the open file limit, systemd's default when 0.
	LimitNOFILE uint64

	// SyslogIdentifier tags the unit's journal entries, the process name when
	// empty.
	SyslogIdentifier string

	// LogExtraFields are KEY=VALUE fields added to the unit's journal entries.
	LogExtraFields []string

	// Resources are the unit's cgroup limits.
	Resources Resources
}

// Manager manages units through systemd's D-Bus API, its Manager object.
type Manager interface {
	// StartTransientUnit starts a transient service unit and waits for the
	// job. An existing failed unit is reset and started again; an existing
	// running one returns errdefs.ErrAlreadyExists.
	StartTransientUnit(ctx context.Context, unit *Unit) error

	// StopUnit stops a unit and waits for the job; an unknown unit is not an
	// error.
	StopUnit(ctx context.Context, name string) error

	// RestartUnit restarts a unit and waits for the job.
	RestartUnit(ctx context.Context, name string) error

	// ActiveState returns the active state of a unit, "inactive" when unknown.
	ActiveState(ctx context.Context, name string) (string, error)

	// ListUnits returns the active state of the loaded service units of a
	// slice matching the pattern, keyed by unit name. Units of other slices
	// are left out.
	ListUnits(ctx context.Context, slice, pattern string) (map[string]string, error)

	// StartSlice starts a slice when not running and applies its resources.
	StartSlice(ctx context.Context, name string, resources Resources) error

	// SetResources applies cgroup limits to a loaded unit at runtime.
	SetResources(ctx context.Context, name string, resources Resources) error

	// MemoryCurrent returns the memory.current of a slice.
	MemoryCurrent(ctx context.Context, name string) (uint64, error)

	// EnableUnitFiles enables unit files and reloads the manager.
	EnableUnitFiles(ctx context.Context, files []string) error

	// Close closes the D-Bus connection.
	Close()
}

// manager is the D-Bus backed Manager. It reconnects when the bus goes away,
// refer to https://github.com/opencontainers/cgroups/blob/main/systemd/dbus.go.
type manager struct {
	// jobTimeout bounds waiting for a job result.
	jobTimeout time.Duration

	// mu guards conn.
	mu sync.Mutex

	// conn is the current connection, nil until first use.
	conn *systemddbus.Conn
}

// New systemd manager interface whose jobs wait at most jobTimeout for their
// result.
func New(jobTimeout time.Duration) Manager {
	return &manager{jobTimeout: jobTimeout}
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
	err := m.startTransientUnit(ctx, unit.Name, properties)
	if isDBusError(err, dbusUnitExists) {
		state, stateErr := m.ActiveState(ctx, unit.Name)
		if stateErr != nil {
			return stateErr
		}

		if state != ActiveStateFailed && state != ActiveStateInactive {
			return fmt.Errorf("unit %s is %s: %w", unit.Name, state, errdefs.ErrAlreadyExists)
		}

		if err := m.resetFailedUnit(ctx, unit.Name); err != nil {
			return err
		}

		err = m.startTransientUnit(ctx, unit.Name, properties)
	}

	if err != nil {
		return fmt.Errorf("start unit %s: %w", unit.Name, err)
	}

	return nil
}

// startTransientUnit starts a transient unit and waits for the job.
func (m *manager) startTransientUnit(ctx context.Context, name string, properties []systemddbus.Property) error {
	return m.runJob(ctx, name, func(conn *systemddbus.Conn, ch chan<- string) error {
		_, err := conn.StartTransientUnitContext(ctx, name, jobModeReplace, properties, ch)
		return err
	})
}

// StopUnit stops a unit and waits for the job; an unknown unit is not an
// error.
func (m *manager) StopUnit(ctx context.Context, name string) error {
	err := m.runJob(ctx, name, func(conn *systemddbus.Conn, ch chan<- string) error {
		_, err := conn.StopUnitContext(ctx, name, jobModeReplace, ch)
		return err
	})

	// A stop that ends in failure still stops the unit, e.g. one killed after
	// its stop timeout; reset it so its name is free, as runc does, refer to
	// https://github.com/opencontainers/cgroups/blob/main/systemd/common.go.
	var jobErr *jobError
	if errors.As(err, &jobErr) {
		log.G(ctx).WithFields(log.Fields{"unit": name, "result": jobErr.result}).Warn("unit stop did not finish cleanly")
		return m.resetFailedUnit(ctx, name)
	}

	if err != nil && !isDBusError(err, dbusNoSuchUnit) {
		return fmt.Errorf("stop unit %s: %w", name, err)
	}

	return nil
}

// RestartUnit restarts a unit and waits for the job.
func (m *manager) RestartUnit(ctx context.Context, name string) error {
	if err := m.runJob(ctx, name, func(conn *systemddbus.Conn, ch chan<- string) error {
		_, err := conn.RestartUnitContext(ctx, name, jobModeReplace, ch)
		return err
	}); err != nil {
		return fmt.Errorf("restart unit %s: %w", name, err)
	}

	return nil
}

// ActiveState returns the active state of a unit, "inactive" when unknown.
func (m *manager) ActiveState(ctx context.Context, name string) (string, error) {
	var state string
	if err := m.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		p, err := conn.GetUnitPropertyContext(ctx, name, "ActiveState")
		if err != nil {
			return err
		}

		state, err = propertyValue[string](p)
		return err
	}); err != nil {
		return "", fmt.Errorf("get unit %s state: %w", name, err)
	}

	return state, nil
}

// ListUnits returns the active state of the loaded service units of a slice
// matching the pattern, keyed by unit name. Units of other slices are left
// out.
func (m *manager) ListUnits(ctx context.Context, slice, pattern string) (map[string]string, error) {
	var statuses []systemddbus.UnitStatus
	if err := m.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) (err error) {
		statuses, err = conn.ListUnitsByPatternsContext(ctx, nil, []string{pattern})
		return err
	}); err != nil {
		return nil, fmt.Errorf("list units %s: %w", pattern, err)
	}

	units := make(map[string]string, len(statuses))
	for _, status := range statuses {
		var unitSlice string
		if err := m.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
			p, err := conn.GetUnitTypePropertyContext(ctx, status.Name, "Service", "Slice")
			if err != nil {
				return err
			}

			unitSlice, err = propertyValue[string](p)
			return err
		}); err != nil {
			return nil, fmt.Errorf("get unit %s slice: %w", status.Name, err)
		}

		if unitSlice == slice {
			units[status.Name] = status.ActiveState
		}
	}

	return units, nil
}

// StartSlice starts a slice when not running and applies its resources.
func (m *manager) StartSlice(ctx context.Context, name string, resources Resources) error {
	properties := append([]systemddbus.Property{
		systemddbus.PropDescription("nydus daemons"),
	}, resources.properties()...)

	err := m.runJob(ctx, name, func(conn *systemddbus.Conn, ch chan<- string) error {
		_, err := conn.StartTransientUnitContext(ctx, name, jobModeReplace, properties, ch)
		return err
	})
	if isDBusError(err, dbusUnitExists) {
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
	if err := m.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		p, err := conn.GetUnitTypePropertyContext(ctx, name, "Slice", "MemoryCurrent")
		if err != nil {
			return err
		}

		current, err = propertyValue[uint64](p)
		return err
	}); err != nil {
		return 0, fmt.Errorf("get slice %s memory: %w", name, err)
	}

	return current, nil
}

// EnableUnitFiles enables unit files and reloads the manager.
func (m *manager) EnableUnitFiles(ctx context.Context, files []string) error {
	if err := m.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		if err := conn.ReloadContext(ctx); err != nil {
			return err
		}

		if _, _, err := conn.EnableUnitFilesContext(ctx, files, false, true); err != nil {
			return err
		}

		return conn.ReloadContext(ctx)
	}); err != nil {
		return fmt.Errorf("enable unit files %v: %w", files, err)
	}

	return nil
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
	}); err != nil && !isDBusError(err, dbusNoSuchUnit) {
		return fmt.Errorf("reset failed unit %s: %w", name, err)
	}

	return nil
}

// runJob queues a job and waits for its result. The channel is buffered
// because go-systemd blocks every job while a result is unread, refer to
// https://github.com/coreos/go-systemd/blob/main/dbus/methods.go.
func (m *manager) runJob(ctx context.Context, name string, start func(*systemddbus.Conn, chan<- string) error) error {
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
			return &jobError{unit: name, result: result}
		}

		return nil
	case <-timer.C:
		return fmt.Errorf("job of unit %s: %w", name, context.DeadlineExceeded)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// retryOnDisconnect runs op on the connection, reconnecting once the bus has
// closed it, refer to
// https://github.com/opencontainers/cgroups/blob/main/systemd/dbus.go.
func (m *manager) retryOnDisconnect(ctx context.Context, op func(*systemddbus.Conn) error) error {
	for {
		conn, err := m.connection(ctx)
		if err != nil {
			return err
		}

		err = op(conn)
		if !errors.Is(err, dbus.ErrClosed) {
			return err
		}

		log.G(ctx).WithError(err).Warn("systemd connection closed, reconnecting")
		m.resetConnection(conn)
	}
}

// connection returns the current connection, dialing one when needed.
// dbus.NewWithContext falls back to /run/systemd/private as root. godbus
// closes a connection once its dial ctx is done, so the shared connection
// never takes the cancellation of the request that happens to dial it, as
// runc dials with context.TODO, refer to
// https://github.com/opencontainers/cgroups/blob/main/systemd/dbus.go.
func (m *manager) connection(ctx context.Context) (*systemddbus.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conn == nil {
		conn, err := systemddbus.NewWithContext(context.WithoutCancel(ctx))
		if err != nil {
			return nil, fmt.Errorf("connect to systemd: %w", err)
		}

		if err := m.checkVersion(conn); err != nil {
			conn.Close()
			return nil, err
		}

		m.conn = conn
	}

	return m.conn, nil
}

// checkVersion fails on a systemd too old for the unit properties, which
// would otherwise fail every daemon start, as runc gates properties on the
// systemd version, refer to
// https://github.com/opencontainers/cgroups/blob/main/systemd/common.go.
func (m *manager) checkVersion(conn *systemddbus.Conn) error {
	value, err := conn.GetManagerProperty("Version")
	if err != nil {
		return fmt.Errorf("get systemd version: %w", err)
	}

	version, err := parseVersion(value)
	if err != nil {
		return err
	}

	if version < minVersion {
		return fmt.Errorf("systemd %d is older than %d: %w", version, minVersion, errdefs.ErrNotImplemented)
	}

	return nil
}

// resetConnection drops conn if it is still the current connection.
func (m *manager) resetConnection(conn *systemddbus.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conn == conn {
		m.conn.Close()
		m.conn = nil
	}
}

// properties returns the D-Bus properties of the transient unit.
func (u *Unit) properties() []systemddbus.Property {
	extraFields := make([][]byte, 0, len(u.LogExtraFields))
	for _, field := range u.LogExtraFields {
		extraFields = append(extraFields, []byte(field))
	}

	properties := []systemddbus.Property{
		systemddbus.PropDescription(u.Description),
		systemddbus.PropSlice(u.Slice),
		systemddbus.PropType("exec"),
		systemddbus.PropExecStart(u.ExecStart, true),
		newProp("Restart", "no"),
		newProp("CollectMode", "inactive-or-failed"),
		newProp("KillSignal", int32(unix.SIGTERM)),
		newProp("OOMScoreAdjust", int32(u.OOMScoreAdjust)),
		newProp("StandardOutput", "journal"),
		newProp("StandardError", "journal"),
		newProp("LogExtraFields", extraFields),
		// No core dumps: a daemon's memory holds registry credentials.
		newProp("LimitCORE", uint64(0)),
		newProp("LimitCORESoft", uint64(0)),
	}

	// Zero values keep systemd's defaults; a zero limit or timeout would
	// leave the process no file or no time to stop.
	if u.TimeoutStop > 0 {
		properties = append(properties, newProp("TimeoutStopUSec", uint64(u.TimeoutStop.Microseconds())))
	}

	if u.LimitNOFILE > 0 {
		properties = append(properties, newProp("LimitNOFILE", u.LimitNOFILE), newProp("LimitNOFILESoft", u.LimitNOFILE))
	}

	if u.SyslogIdentifier != "" {
		properties = append(properties, newProp("SyslogIdentifier", u.SyslogIdentifier))
	}

	if len(u.Environment) > 0 {
		properties = append(properties, newProp("Environment", u.Environment))
	}

	if len(u.Before) > 0 {
		properties = append(properties, systemddbus.PropBefore(u.Before...))
	}

	return append(properties, u.Resources.properties()...)
}

// properties returns the cgroup properties, systemd's infinity for 0.
func (r *Resources) properties() []systemddbus.Property {
	limit := func(v uint64) uint64 {
		if v == 0 {
			return math.MaxUint64
		}

		return v
	}

	return []systemddbus.Property{
		newProp("MemoryMax", limit(r.MemoryMax)),
		newProp("MemoryHigh", limit(r.MemoryHigh)),
		newProp("CPUQuotaPerSecUSec", limit(r.CPUQuotaPerSecUSec)),
	}
}

// newProp returns a unit property, as runc's systemd driver, refer to
// https://github.com/opencontainers/cgroups/blob/main/systemd/common.go.
func newProp(name string, value any) systemddbus.Property {
	return systemddbus.Property{Name: name, Value: dbus.MakeVariant(value)}
}

// isDBusError reports whether err is the named D-Bus error.
func isDBusError(err error, name string) bool {
	var dbusErr dbus.Error
	return errors.As(err, &dbusErr) && dbusErr.Name == name
}

// parseVersion returns the major version of a systemd version string such as
// "v245.4-1.fc32" or "255", as runc's systemdVersionAtoi does.
func parseVersion(value string) (int, error) {
	value = strings.TrimLeft(value, `"v`)
	if i := strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		value = value[:i]
	}

	version, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse systemd version %q: %w", value, err)
	}

	return version, nil
}

// propertyValue returns the value of a D-Bus property as T.
func propertyValue[T any](p *systemddbus.Property) (T, error) {
	v, ok := p.Value.Value().(T)
	if !ok {
		return v, fmt.Errorf("property %s is %T, want %T", p.Name, p.Value.Value(), v)
	}

	return v, nil
}
