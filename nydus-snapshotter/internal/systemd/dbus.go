/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package systemd

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	systemddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
)

const (
	// dbusUnitExists is the D-Bus error of starting a loaded unit.
	dbusUnitExists dbusError = "org.freedesktop.systemd1.UnitExists"

	// dbusNoSuchUnit is the D-Bus error of an unknown unit.
	dbusNoSuchUnit dbusError = "org.freedesktop.systemd1.NoSuchUnit"

	// unitInterface is the D-Bus interface every unit has, refer to
	// https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html.
	unitInterface = "Unit"

	// serviceInterface is the D-Bus interface of a service unit.
	serviceInterface = "Service"

	// sliceInterface is the D-Bus interface of a slice unit.
	sliceInterface = "Slice"

	// minVersion is the oldest systemd knowing every unit property used,
	// Type=exec being the newest, refer to systemd.service(5).
	minVersion = 240
)

// dbusError is the name of a D-Bus error.
type dbusError string

// is reports whether err is the D-Bus error, as runc's isDbusError does,
// refer to https://github.com/opencontainers/cgroups/blob/main/systemd/common.go.
func (e dbusError) is(err error) bool {
	var dbusErr dbus.Error
	return errors.As(err, &dbusErr) && dbusErr.Name == string(e)
}

// version is the version systemd reports, such as "v245.4-1.fc32" or "255".
type version string

// major returns the major version, as runc's systemdVersionAtoi does, refer
// to https://github.com/opencontainers/cgroups/blob/main/systemd/common.go.
func (v version) major() (int, error) {
	value := strings.TrimLeft(string(v), `"v`)
	if i := strings.IndexFunc(value, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		value = value[:i]
	}

	major, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse systemd version %q: %w", value, err)
	}

	return major, nil
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
// systemddbus.NewWithContext falls back to /run/systemd/private as root. godbus
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

	major, err := version(value).major()
	if err != nil {
		return err
	}

	if major < m.minVersion {
		return fmt.Errorf("systemd %d is older than %d: %w", major, m.minVersion, errdefs.ErrNotImplemented)
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

// unitProperty stores a property of one D-Bus interface of a unit into
// value, a pointer, as godbus's BusObject.StoreProperty does and as runc's
// getUnitTypeProperty reads one, refer to
// https://github.com/opencontainers/cgroups/blob/main/systemd/common.go.
func (m *manager) unitProperty(ctx context.Context, name, iface, property string, value any) error {
	return m.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		p, err := conn.GetUnitTypePropertyContext(ctx, name, iface, property)
		if err != nil {
			return err
		}

		return p.Value.Store(value)
	})
}
