/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package systemd

import (
	"math"
	"time"

	systemddbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	// serviceTypeExec is a service started once its binary runs.
	serviceTypeExec = "exec"

	// serviceTypeNotify is a service started once it sends READY=1.
	serviceTypeNotify = "notify"
)

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

	// Notify makes the unit Type=notify: its start job ends once the process
	// sends READY=1, refer to
	// https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html.
	// Without it the unit is Type=exec, started once its binary runs.
	Notify bool

	// TimeoutStart bounds the start of the unit, which for a Notify unit is
	// the wait for READY=1; 0 keeps systemd's default.
	TimeoutStart time.Duration

	// Watchdog is how long systemd waits for the WATCHDOG=1 keep-alive of a
	// Notify unit before it kills the process, off when 0.
	Watchdog time.Duration

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

// serviceType returns the systemd service type of the unit.
func (u *Unit) serviceType() string {
	if u.Notify {
		return serviceTypeNotify
	}

	return serviceTypeExec
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
		systemddbus.PropType(u.serviceType()),
		// The bool is systemd's ignore-failure flag, the "-" prefix of
		// ExecStart=, whatever go-systemd names it: false makes a missing
		// command fail the start and a failed exit fail the unit, with its
		// status in the journal, refer to bus_set_transient_exec_command in
		// https://github.com/systemd/systemd/blob/v255/src/core/dbus-execute.c.
		systemddbus.PropExecStart(u.ExecStart, false),
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

	// Only the main process may notify, systemd's default for Type=notify.
	if u.Notify {
		properties = append(properties, newProp("NotifyAccess", "main"))
	}

	// Zero values keep systemd's defaults; a zero limit or timeout would
	// leave the process no file or no time to start or stop.
	if u.TimeoutStart > 0 {
		properties = append(properties, newProp("TimeoutStartUSec", uint64(u.TimeoutStart.Microseconds())))
	}

	if u.Watchdog > 0 {
		properties = append(properties, newProp("WatchdogUSec", uint64(u.Watchdog.Microseconds())))
	}

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
