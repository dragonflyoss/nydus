// Package benchgate compares reports only on a matching stable benchmark host.
package benchgate

import (
	"fmt"
	"math"
	"slices"
)

type Metric struct {
	Value          float64 `json:"value"`
	HigherIsBetter bool    `json:"higher_is_better"`
}

type Report struct {
	Schema   int                          `json:"schema"`
	Host     string                       `json:"host"`
	Arch     string                       `json:"arch"`
	Kernel   string                       `json:"kernel"`
	Settings []string                     `json:"settings"`
	Modes    map[string]map[string]Metric `json:"modes"`
}

func Compare(base, current Report, percent float64) error {
	if percent <= 0 || percent > 100 || math.IsNaN(percent) || math.IsInf(percent, 0) {
		return fmt.Errorf("regression percent must be finite and in (0,100]")
	}
	if base.Schema != 1 || current.Schema != 1 || base.Host == "" || base.Host != current.Host ||
		base.Arch != current.Arch || base.Kernel != current.Kernel || !slices.Equal(base.Settings, current.Settings) {
		return fmt.Errorf("baseline schema, host, architecture, kernel and workload settings must match")
	}
	if len(base.Modes) == 0 || len(base.Modes) != len(current.Modes) {
		return fmt.Errorf("baseline and current mode sets must match and be nonempty")
	}
	for mode, old := range base.Modes {
		now, ok := current.Modes[mode]
		if !ok || len(old) == 0 || len(old) != len(now) {
			return fmt.Errorf("metric sets for %s must match and be nonempty", mode)
		}
		for key, before := range old {
			after, ok := now[key]
			if !ok || before.HigherIsBetter != after.HigherIsBetter ||
				before.Value <= 0 || after.Value <= 0 || math.IsNaN(before.Value) || math.IsNaN(after.Value) ||
				math.IsInf(before.Value, 0) || math.IsInf(after.Value, 0) {
				return fmt.Errorf("invalid or missing %s/%s measurement", mode, key)
			}
			regression := (after.Value/before.Value - 1) * 100
			if before.HigherIsBetter {
				regression = (1 - after.Value/before.Value) * 100
			}
			if regression > percent {
				return fmt.Errorf("%s/%s regressed %.2f%% (budget %.2f%%): %.3f -> %.3f",
					mode, key, regression, percent, before.Value, after.Value)
			}
		}
	}
	return nil
}
