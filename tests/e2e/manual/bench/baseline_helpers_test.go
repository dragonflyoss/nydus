//go:build manual

package bench

import (
	"encoding/json"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/benchgate"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func reportResults(t *testing.T, results map[string]*modeResult) {
	t.Helper()
	var uts unix.Utsname
	require.NoError(t, unix.Uname(&uts))
	r := benchgate.Report{Schema: 1, Host: os.Getenv("NYDUSFS_BENCH_HOST"), Arch: runtime.GOARCH,
		Kernel: strings.TrimRight(string(uts.Release[:]), "\x00"), Modes: map[string]map[string]benchgate.Metric{}}
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "NYDUSFS_PERF_") || strings.HasPrefix(value, "NYDUSFS_BENCH_WARM=") {
			r.Settings = append(r.Settings, value)
		}
	}
	slices.Sort(r.Settings)
	for name, res := range results {
		r.Modes[name] = map[string]benchgate.Metric{
			"mount_seconds":           {Value: res.mountSec},
			"cold_walk_seconds":       {Value: res.coldWalkSec},
			"cold_xattr_walk_seconds": {Value: res.coldXattrWalkSec},
			"first_read_seconds":      {Value: res.firstReadSec},
			"cold_seq_mibps":          {Value: res.coldSeqMiBps, HigherIsBetter: true},
			"cold_rand_iops":          {Value: res.coldRandIOPS, HigherIsBetter: true},
			"negative_lookup_ops":     {Value: res.negativeLookupOps, HigherIsBetter: true},
			"big_dir_lookup_ops":      {Value: res.bigDirLookupOps, HigherIsBetter: true},
		}
	}
	if path := os.Getenv("NYDUSFS_BENCH_OUTPUT"); path != "" {
		data, err := json.MarshalIndent(r, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, append(data, '\n'), 0o644))
	}
	baseline := os.Getenv("NYDUSFS_BENCH_BASELINE")
	budget := os.Getenv("NYDUSFS_BENCH_MAX_REGRESSION_PERCENT")
	if baseline == "" && budget == "" {
		t.Log("performance report only: no stable-host baseline gate configured")
		return
	}
	require.NotEmpty(t, baseline, "a gate requires both a baseline and regression percent")
	require.NotEmpty(t, budget, "choose a regression percent calibrated on this stable host")
	percent, err := strconv.ParseFloat(budget, 64)
	require.NoError(t, err)
	data, err := os.ReadFile(baseline)
	require.NoError(t, err)
	var base benchgate.Report
	require.NoError(t, json.Unmarshal(data, &base))
	require.NoError(t, benchgate.Compare(base, r, percent))
}
