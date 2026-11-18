/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDuration_UnmarshalText(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		expect func(t *testing.T, d Duration, err error)
	}{
		{
			name: "seconds",
			text: "10s",
			expect: func(t *testing.T, d Duration, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(Duration(10*time.Second), d)
			},
		},
		{
			name: "several units",
			text: "1h30m",
			expect: func(t *testing.T, d Duration, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(Duration(90*time.Minute), d)
			},
		},
		{
			name: "number without a unit",
			text: "10",
			expect: func(t *testing.T, d Duration, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `parse duration "10"`)
			},
		},
		{
			name: "no duration",
			text: "soon",
			expect: func(t *testing.T, d Duration, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `parse duration "soon"`)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var d Duration
			err := d.UnmarshalText([]byte(tc.text))
			tc.expect(t, d, err)
		})
	}
}

func TestDuration_MarshalText(t *testing.T) {
	tests := []struct {
		name     string
		duration Duration
		expect   func(t *testing.T, text []byte, err error)
	}{
		{
			name:     "duration string",
			duration: Duration(90 * time.Second),
			expect: func(t *testing.T, text []byte, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("1m30s", string(text))
			},
		},
		{
			name:     "zero",
			duration: 0,
			expect: func(t *testing.T, text []byte, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("0s", string(text))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			text, err := tc.duration.MarshalText()
			tc.expect(t, text, err)
		})
	}
}

func TestSize_UnmarshalText(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		expect func(t *testing.T, s Size, err error)
	}{
		{
			name: "binary unit",
			text: "1GiB",
			expect: func(t *testing.T, s Size, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(Size(1<<30), s)
			},
		},
		{
			name: "decimal unit means the binary one",
			text: "512MB",
			expect: func(t *testing.T, s Size, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(Size(512<<20), s)
			},
		},
		{
			name: "bytes",
			text: "4096",
			expect: func(t *testing.T, s Size, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(Size(4096), s)
			},
		},
		{
			name: "zero",
			text: "0",
			expect: func(t *testing.T, s Size, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Zero(s)
			},
		},
		{
			name: "no size",
			text: "lots",
			expect: func(t *testing.T, s Size, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `parse size "lots"`)
			},
		},
		{
			name: "negative size",
			text: "-1GiB",
			expect: func(t *testing.T, s Size, err error) {
				assert := assert.New(t)
				assert.Error(err)
				assert.Zero(s)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var s Size
			err := s.UnmarshalText([]byte(tc.text))
			tc.expect(t, s, err)
		})
	}
}

func TestCPUQuota_UnmarshalText(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		expect func(t *testing.T, q CPUQuota, err error)
	}{
		{
			name: "one and a half CPUs",
			text: "150%",
			expect: func(t *testing.T, q CPUQuota, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(CPUQuota(150), q)
			},
		},
		{
			name: "no quota",
			text: "0%",
			expect: func(t *testing.T, q CPUQuota, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Zero(q)
			},
		},
		{
			name: "number without a percent sign",
			text: "400",
			expect: func(t *testing.T, q CPUQuota, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "missing %")
			},
		},
		{
			name: "no number",
			text: "some%",
			expect: func(t *testing.T, q CPUQuota, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `parse cpu quota "some%"`)
			},
		},
		{
			name: "negative quota",
			text: "-100%",
			expect: func(t *testing.T, q CPUQuota, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse cpu quota")
			},
		},
		{
			name: "quota that overflows microseconds",
			text: "1844674407370956%",
			expect: func(t *testing.T, q CPUQuota, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "out of range")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var q CPUQuota
			err := q.UnmarshalText([]byte(tc.text))
			tc.expect(t, q, err)
		})
	}
}

func TestCPUQuota_PerSecUSec(t *testing.T) {
	tests := []struct {
		name   string
		quota  CPUQuota
		expect func(t *testing.T, usec uint64)
	}{
		{
			name:  "one CPU",
			quota: 100,
			expect: func(t *testing.T, usec uint64) {
				assert := assert.New(t)
				assert.Equal(uint64(time.Second.Microseconds()), usec)
			},
		},
		{
			name:  "one and a half CPUs",
			quota: 150,
			expect: func(t *testing.T, usec uint64) {
				assert := assert.New(t)
				assert.Equal(uint64(1_500_000), usec)
			},
		},
		{
			name:  "no quota",
			quota: 0,
			expect: func(t *testing.T, usec uint64) {
				assert := assert.New(t)
				assert.Zero(usec)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.expect(t, tc.quota.PerSecUSec())
		})
	}
}
