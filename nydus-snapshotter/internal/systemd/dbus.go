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

	"github.com/containerd/log"
	systemddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
)

const (
	// dbusUnitExists is the D-Bus error of a transient unit whose name is
	// taken.
	dbusUnitExists dbusError = "org.freedesktop.systemd1.UnitExists"

	// dbusNoSuchUnit is the D-Bus error of an unknown unit.
	dbusNoSuchUnit dbusError = "org.freedesktop.systemd1.NoSuchUnit"
)

// dbusError is the name of a D-Bus error.
type dbusError string

// is reports whether err is the D-Bus error.
func (e dbusError) is(err error) bool {
	var dbusErr dbus.Error
	return errors.As(err, &dbusErr) && dbusErr.Name == string(e)
}

// retryOnDisconnect runs op on the connection, reconnecting once the bus has
// closed it.
func (s *systemd) retryOnDisconnect(ctx context.Context, op func(*systemddbus.Conn) error) error {
	for {
		conn, err := s.connection(ctx)
		if err != nil {
			return err
		}

		err = op(conn)
		if !errors.Is(err, dbus.ErrClosed) {
			return err
		}

		log.G(ctx).WithError(err).Warn("systemd connection closed, reconnecting")
		s.resetConnection(conn)
	}
}

// connection returns the current connection, dialing one when needed.
// systemddbus.NewWithContext falls back to /run/systemd/private as root.
// godbus closes a connection once its dial ctx is done, so the shared
// connection never takes the cancellation of the request that happens to dial
// it.
func (s *systemd) connection(ctx context.Context) (*systemddbus.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		conn, err := systemddbus.NewWithContext(context.WithoutCancel(ctx))
		if err != nil {
			return nil, fmt.Errorf("connect to systemd: %w", err)
		}

		s.conn = conn
	}

	return s.conn, nil
}

// resetConnection drops conn if it is still the current connection.
func (s *systemd) resetConnection(conn *systemddbus.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == conn {
		s.conn.Close()
		s.conn = nil
	}
}

const (
	// unitInterface is the D-Bus interface every unit has.
	unitInterface = "Unit"

	// serviceInterface is the D-Bus interface of a service unit.
	serviceInterface = "Service"

	// sliceInterface is the D-Bus interface of a slice unit.
	sliceInterface = "Slice"
)

// unitProperty stores a property of one D-Bus interface of a unit into value,
// a pointer.
func (s *systemd) unitProperty(ctx context.Context, name, iface, property string, value any) error {
	return s.retryOnDisconnect(ctx, func(conn *systemddbus.Conn) error {
		p, err := conn.GetUnitTypePropertyContext(ctx, name, iface, property)
		if err != nil {
			return err
		}

		return p.Value.Store(value)
	})
}
