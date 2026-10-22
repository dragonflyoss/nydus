// Package soakconfig validates the smoke and scheduled stability workload knobs.
package soakconfig

import (
	"fmt"
	"strconv"
	"time"
)

type Settings struct {
	Duration time.Duration
	Cycles   int
	RSSBytes int64
}

func Parse(get func(string) string) (Settings, error) {
	s := Settings{Duration: 30 * time.Second, Cycles: 20}
	if raw := get("NYDUS_E2E_SOAK_DURATION"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < 10*time.Second || d > 24*time.Hour {
			return s, fmt.Errorf("NYDUS_E2E_SOAK_DURATION must be between 10s and 24h")
		}
		s.Duration = d
	}
	if raw := get("NYDUS_E2E_SOAK_CYCLES"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100000 {
			return s, fmt.Errorf("NYDUS_E2E_SOAK_CYCLES must be between 1 and 100000")
		}
		s.Cycles = n
	}
	if raw := get("NYDUS_E2E_SOAK_RSS_MIB"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1 || n > 1<<20 {
			return s, fmt.Errorf("NYDUS_E2E_SOAK_RSS_MIB must be between 1 and 1048576")
		}
		s.RSSBytes = n << 20
	}
	return s, nil
}
