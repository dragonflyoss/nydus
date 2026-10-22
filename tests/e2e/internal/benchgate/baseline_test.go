package benchgate

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBaseline(t *testing.T) {
	t.Parallel()
	makeReport := func(value float64, higher bool) Report {
		return Report{Schema: 1, Host: "dedicated-host", Arch: "amd64", Kernel: "6.15",
			Modes: map[string]map[string]Metric{"fuse": {"lookup": {value, higher}}}}
	}
	require.NoError(t, Compare(makeReport(100, true), makeReport(95, true), 10))
	require.Error(t, Compare(makeReport(100, true), makeReport(80, true), 10))
	require.Error(t, Compare(makeReport(100, false), makeReport(120, false), 10))
	for _, budget := range []float64{0, -1, 101, math.NaN(), math.Inf(1)} {
		require.Error(t, Compare(makeReport(100, true), makeReport(100, true), budget))
	}
	bad := makeReport(100, true)
	bad.Host = "another-host"
	require.Error(t, Compare(makeReport(100, true), bad, 10))
	bad = makeReport(100, true)
	bad.Settings = []string{"different-corpus"}
	require.Error(t, Compare(makeReport(100, true), bad, 10))
	require.Error(t, Compare(makeReport(100, true), makeReport(0, true), 10))
	require.Error(t, Compare(makeReport(100, true), Report{}, 10))
}
