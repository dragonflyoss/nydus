/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package systemd

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	systemddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
)

func TestManager_connection(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m *manager)
	}{
		{
			name: "keep the connection after the dialing request ends",
			expect: func(t *testing.T, m *manager) {
				assert := assert.New(t)
				ctx, cancel := context.WithCancel(t.Context())
				_, err := m.ActiveState(ctx, mockUnknownUnit)
				assert.NoError(err)
				cancel()

				conn := m.conn
				assert.Never(func() bool { return !conn.Connected() }, 200*time.Millisecond, 10*time.Millisecond)
			},
		},
		{
			name: "reconnect once the connection is closed",
			expect: func(t *testing.T, m *manager) {
				assert := assert.New(t)
				assert.NoError(m.Ping(t.Context()))
				closed := m.conn
				closed.Close()
				assert.Eventually(func() bool {
					state, err := m.ActiveState(t.Context(), mockUnknownUnit)
					return err == nil && state == ActiveStateInactive
				}, 5*time.Second, 10*time.Millisecond)
				assert.NotSame(closed, m.conn)
			},
		},
		{
			name: "systemd older than the oldest supported",
			expect: func(t *testing.T, m *manager) {
				assert := assert.New(t)
				m.minVersion = math.MaxInt
				_, err := m.ActiveState(t.Context(), mockUnknownUnit)
				assert.ErrorIs(err, errdefs.ErrNotImplemented)
				assert.Nil(m.conn)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, newTestManager(t).(*manager))
		})
	}
}

func TestManager_checkVersion(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m *manager, conn *systemddbus.Conn)
	}{
		{
			name: "systemd of the host",
			expect: func(t *testing.T, m *manager, conn *systemddbus.Conn) {
				assert := assert.New(t)
				assert.NoError(m.checkVersion(conn))
			},
		},
		{
			name: "connection that is closed",
			expect: func(t *testing.T, m *manager, conn *systemddbus.Conn) {
				assert := assert.New(t)
				conn.Close()
				assert.ErrorContains(m.checkVersion(conn), "get systemd version")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t).(*manager)
			conn, err := m.connection(t.Context())
			assert.NoError(t, err)
			tc.expect(t, m, conn)
		})
	}
}

func TestDBusError_is(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		expect func(t *testing.T, matched bool)
	}{
		{
			name: "named error",
			err:  dbus.Error{Name: string(dbusUnitExists)},
			expect: func(t *testing.T, matched bool) {
				assert := assert.New(t)
				assert.True(matched)
			},
		},
		{
			name: "other error",
			err:  dbus.Error{Name: string(dbusNoSuchUnit)},
			expect: func(t *testing.T, matched bool) {
				assert := assert.New(t)
				assert.False(matched)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, dbusUnitExists.is(tc.err))
		})
	}
}

func TestVersion_major(t *testing.T) {
	tests := []struct {
		name    string
		version version
		expect  func(t *testing.T, major int, err error)
	}{
		{
			name:    "quoted with a v prefix and a distro suffix",
			version: `"v245.4-1.fc32"`,
			expect: func(t *testing.T, major int, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(245, major)
			},
		},
		{
			name:    "debian style",
			version: `"255.4-1ubuntu8.18"`,
			expect: func(t *testing.T, major int, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(255, major)
			},
		},
		{
			name:    "plain number",
			version: "239",
			expect: func(t *testing.T, major int, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(239, major)
			},
		},
		{
			name:    "no number",
			version: `"unknown"`,
			expect: func(t *testing.T, major int, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			major, err := tc.version.major()
			tc.expect(t, major, err)
		})
	}
}

func TestManager_unitProperty(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, m *manager)
	}{
		{
			name: "value of the wanted type",
			expect: func(t *testing.T, m *manager) {
				assert := assert.New(t)
				var state string
				assert.NoError(m.unitProperty(t.Context(), mockUnknownUnit, unitInterface, "ActiveState", &state))
				assert.Equal("inactive", state)
			},
		},
		{
			name: "value of another type",
			expect: func(t *testing.T, m *manager) {
				assert := assert.New(t)
				var state uint64
				assert.Error(m.unitProperty(t.Context(), mockUnknownUnit, unitInterface, "ActiveState", &state))
				assert.Zero(state)
			},
		},
		{
			name: "unknown property",
			expect: func(t *testing.T, m *manager) {
				assert := assert.New(t)
				var state string
				assert.Error(m.unitProperty(t.Context(), mockUnknownUnit, unitInterface, "Unknown", &state))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, newTestManager(t).(*manager))
		})
	}
}
