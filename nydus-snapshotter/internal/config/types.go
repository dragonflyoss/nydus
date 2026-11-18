/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/docker/go-units"
)

// Duration is a time.Duration decoded from a Go duration string such as
// "10s".
type Duration time.Duration

// UnmarshalText decodes a duration string.
func (d *Duration) UnmarshalText(text []byte) error {
	v, err := time.ParseDuration(string(text))
	if err != nil {
		return fmt.Errorf("parse duration %q: %w", text, err)
	}

	*d = Duration(v)
	return nil
}

// MarshalText encodes the duration as a string.
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

// Size is a byte count decoded from a size string such as "1GiB" or "512MB".
type Size uint64

// UnmarshalText decodes a size string. MB and MiB both mean 2^20 bytes, as
// in docker run --memory.
func (s *Size) UnmarshalText(text []byte) error {
	v, err := units.RAMInBytes(string(text))
	if err != nil {
		return fmt.Errorf("parse size %q: %w", text, err)
	}

	if v < 0 {
		return fmt.Errorf("negative size %q", text)
	}

	*s = Size(v)
	return nil
}

// usecPerPercent is the CPU time per second of 1%: 10ms.
const usecPerPercent = 10_000

// CPUQuota is a CPU quota decoded from a percentage such as "150%", where
// 100% is one CPU, as systemd's CPUQuota, refer to
// https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#CPUQuota=.
type CPUQuota uint64

// UnmarshalText decodes a percentage string.
func (q *CPUQuota) UnmarshalText(text []byte) error {
	value, ok := strings.CutSuffix(string(text), "%")
	if !ok {
		return fmt.Errorf("parse cpu quota %q: missing %%", text)
	}

	v, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return fmt.Errorf("parse cpu quota %q: %w", text, err)
	}

	if v > math.MaxUint64/usecPerPercent {
		return fmt.Errorf("cpu quota %q is out of range", text)
	}

	*q = CPUQuota(v)
	return nil
}

// PerSecUSec returns the quota as systemd's CPUQuotaPerSecUSec: 1% is 10ms of
// CPU time per second, already on systemd's 10ms granularity.
func (q CPUQuota) PerSecUSec() uint64 {
	return uint64(q) * usecPerPercent
}
