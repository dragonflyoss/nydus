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

// MarshalText encodes the size as a byte count.
func (s Size) MarshalText() ([]byte, error) {
	return []byte(strconv.FormatUint(uint64(s), 10)), nil
}

// usecPerPercent is the CPU time per second of 1%: 10ms.
const usecPerPercent = 10_000

// Percent is a CPU quota decoded from a percentage such as "150%", where
// 100% is one CPU, as systemd's CPUQuota.
type Percent uint64

// UnmarshalText decodes a percentage string.
func (p *Percent) UnmarshalText(text []byte) error {
	value, ok := strings.CutSuffix(string(text), "%")
	if !ok {
		return fmt.Errorf("parse percent %q: missing %%", text)
	}

	v, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return fmt.Errorf("parse percent %q: %w", text, err)
	}

	if v > math.MaxUint64/usecPerPercent {
		return fmt.Errorf("percent %q is out of range", text)
	}

	*p = Percent(v)
	return nil
}

// MarshalText encodes the percentage.
func (p Percent) MarshalText() ([]byte, error) {
	return []byte(strconv.FormatUint(uint64(p), 10) + "%"), nil
}

// CPUQuotaPerSecUSec returns the systemd CPUQuotaPerSecUSec value: 1% is
// 10ms of CPU time per second, already on systemd's 10ms granularity.
func (p Percent) CPUQuotaPerSecUSec() uint64 {
	return uint64(p) * usecPerPercent
}
