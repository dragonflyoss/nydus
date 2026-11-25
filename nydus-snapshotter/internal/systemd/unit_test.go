/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package systemd

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

var mockUnit = &Unit{
	Name:             "nydusd-ab.service",
	Description:      "nydus daemon",
	Slice:            "system-nydusd.slice",
	ExecStart:        []string{"/opt/nydus-snapshotter/bin/3.0.0/nydus", "fuse"},
	Before:           []string{"containerd.service"},
	TimeoutStop:      10 * time.Second,
	OOMScoreAdjust:   -999,
	LimitNOFILE:      1048576,
	SyslogIdentifier: "nydusd",
	LogExtraFields:   []string{"NYDUS_CHAIN_ID=sha256:ab"},
	Resources:        Resources{MemoryHigh: 1 << 30},
}

func TestUnit_properties(t *testing.T) {
	tests := []struct {
		name   string
		unit   *Unit
		expect func(t *testing.T, properties map[string]any)
	}{
		{
			name: "transient service properties",
			unit: mockUnit,
			expect: func(t *testing.T, properties map[string]any) {
				assert := assert.New(t)
				assert.Equal("exec", properties["Type"])
				assert.Equal("[{/opt/nydus-snapshotter/bin/3.0.0/nydus [/opt/nydus-snapshotter/bin/3.0.0/nydus fuse] false}]", fmt.Sprint(properties["ExecStart"]))
				assert.Equal("no", properties["Restart"])
				assert.Equal("inactive-or-failed", properties["CollectMode"])
				assert.Equal(int32(unix.SIGTERM), properties["KillSignal"])
				assert.Equal(uint64(10_000_000), properties["TimeoutStopUSec"])
				assert.Equal(uint64(1048576), properties["LimitNOFILE"])
				assert.Equal(uint64(1048576), properties["LimitNOFILESoft"])
				assert.Equal(uint64(0), properties["LimitCORE"])
				assert.Equal(uint64(0), properties["LimitCORESoft"])
				assert.Equal("nydusd", properties["SyslogIdentifier"])
				assert.Equal(int32(-999), properties["OOMScoreAdjust"])
				assert.Equal("system-nydusd.slice", properties["Slice"])
				assert.Equal([][]byte{[]byte("NYDUS_CHAIN_ID=sha256:ab")}, properties["LogExtraFields"])
				assert.Equal(true, properties["MemoryAccounting"])
				assert.Equal(uint64(1<<30), properties["MemoryHigh"])
				assert.Equal(uint64(math.MaxUint64), properties["MemoryMax"])
				assert.Equal(uint64(math.MaxUint64), properties["CPUQuotaPerSecUSec"])
			},
		},
		{
			name: "keep systemd defaults for zero values",
			unit: &Unit{Name: "nydusd-ab.service", ExecStart: []string{"/bin/true"}},
			expect: func(t *testing.T, properties map[string]any) {
				assert := assert.New(t)
				assert.NotContains(properties, "Slice")
				assert.NotContains(properties, "Before")
				assert.NotContains(properties, "TimeoutStopUSec")
				assert.NotContains(properties, "LimitNOFILE")
				assert.NotContains(properties, "SyslogIdentifier")
				assert.Equal("exec", properties["Type"])
				assert.NotContains(properties, "NotifyAccess")
				assert.NotContains(properties, "TimeoutStartUSec")
				assert.NotContains(properties, "WatchdogUSec")
			},
		},
		{
			name: "notify unit with a start timeout and a watchdog",
			unit: &Unit{Name: "nydusd-ab.service", ExecStart: []string{"/bin/true"}, Notify: true, TimeoutStart: 10 * time.Second, Watchdog: 3 * time.Minute},
			expect: func(t *testing.T, properties map[string]any) {
				assert := assert.New(t)
				assert.Equal("notify", properties["Type"])
				assert.Equal("main", properties["NotifyAccess"])
				assert.Equal(uint64(10_000_000), properties["TimeoutStartUSec"])
				assert.Equal(uint64(180_000_000), properties["WatchdogUSec"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			properties := make(map[string]any)
			for _, p := range tc.unit.properties() {
				properties[p.Name] = p.Value.Value()
			}

			tc.expect(t, properties)
		})
	}
}

func TestResources_properties(t *testing.T) {
	tests := []struct {
		name      string
		resources *Resources
		expect    func(t *testing.T, properties map[string]any)
	}{
		{
			name:      "zero is no limit",
			resources: &Resources{},
			expect: func(t *testing.T, properties map[string]any) {
				assert := assert.New(t)
				assert.Equal(uint64(math.MaxUint64), properties["MemoryMax"])
				assert.Equal(uint64(math.MaxUint64), properties["MemoryHigh"])
				assert.Equal(uint64(math.MaxUint64), properties["CPUQuotaPerSecUSec"])
			},
		},
		{
			name:      "limits pass through",
			resources: &Resources{MemoryMax: 8 << 30, MemoryHigh: 6 << 30, CPUQuotaPerSecUSec: 4_000_000},
			expect: func(t *testing.T, properties map[string]any) {
				assert := assert.New(t)
				assert.Equal(uint64(8<<30), properties["MemoryMax"])
				assert.Equal(uint64(6<<30), properties["MemoryHigh"])
				assert.Equal(uint64(4_000_000), properties["CPUQuotaPerSecUSec"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			properties := make(map[string]any)
			for _, p := range tc.resources.properties() {
				properties[p.Name] = p.Value.Value()
			}

			tc.expect(t, properties)
		})
	}
}
