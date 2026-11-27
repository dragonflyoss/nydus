/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package systemd

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
)

func TestSystemd_connection(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s *systemd)
	}{
		{
			name: "keep the connection after the dialing request ends",
			expect: func(t *testing.T, s *systemd) {
				assert := assert.New(t)
				ctx, cancel := context.WithCancel(t.Context())
				_, err := s.ActiveState(ctx, mockUnknownUnit)
				assert.NoError(err)
				cancel()

				conn := s.conn
				assert.Never(func() bool { return !conn.Connected() }, 200*time.Millisecond, 10*time.Millisecond)
			},
		},
		{
			name: "reconnect once the connection is closed",
			expect: func(t *testing.T, s *systemd) {
				assert := assert.New(t)
				assert.NoError(s.Ping(t.Context()))
				closed := s.conn
				closed.Close()
				assert.Eventually(func() bool {
					state, err := s.ActiveState(t.Context(), mockUnknownUnit)
					return err == nil && state == ActiveStateInactive
				}, 5*time.Second, 10*time.Millisecond)
				assert.NotSame(closed, s.conn)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if os.Geteuid() != 0 {
				t.Skip("talks to systemd as root")
			}

			if _, err := os.Stat("/run/systemd/system"); err != nil {
				t.Skip("needs systemd as init")
			}

			s := New().(*systemd)
			defer s.Close()
			tc.expect(t, s)
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
		{
			name: "error that is no d-bus error",
			err:  errors.New("foo"),
			expect: func(t *testing.T, matched bool) {
				assert := assert.New(t)
				assert.False(matched)
			},
		},
		{
			name: "no error",
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

func TestSystemd_unitProperty(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, s *systemd)
	}{
		{
			name: "value of the wanted type",
			expect: func(t *testing.T, s *systemd) {
				assert := assert.New(t)
				var state string
				assert.NoError(s.unitProperty(t.Context(), mockUnknownUnit, unitInterface, "ActiveState", &state))
				assert.Equal("inactive", state)
			},
		},
		{
			name: "value of another type",
			expect: func(t *testing.T, s *systemd) {
				assert := assert.New(t)
				var state uint64
				assert.Error(s.unitProperty(t.Context(), mockUnknownUnit, unitInterface, "ActiveState", &state))
				assert.Zero(state)
			},
		},
		{
			name: "unknown property",
			expect: func(t *testing.T, s *systemd) {
				assert := assert.New(t)
				var state string
				assert.Error(s.unitProperty(t.Context(), mockUnknownUnit, unitInterface, "Unknown", &state))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if os.Geteuid() != 0 {
				t.Skip("talks to systemd as root")
			}

			if _, err := os.Stat("/run/systemd/system"); err != nil {
				t.Skip("needs systemd as init")
			}

			s := New().(*systemd)
			defer s.Close()
			tc.expect(t, s)
		})
	}
}
