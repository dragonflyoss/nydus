package mount

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseMetrics(t *testing.T) {
	t.Parallel()
	m := ParseMetrics(`
# HELP nydus_backend_read_total Backend reads.
nydus_backend_read_total{source="dragonfly",type="ondemand"} 3
nydus_backend_read_total{type="ondemand",source="fallback"} 5
nydus_backend_read_total{source="origin",type="prefetch"} 7
nydus_backend_read_failure_total{source="dragonfly",type="ondemand"} 1
`)
	require.Equal(t, float64(15), m.Sum("nydus_backend_read_total"))
	require.Equal(t, float64(8), m.Sum("nydus_backend_read_total", `type="ondemand"`))
	require.Equal(t, float64(5), m.Sum("nydus_backend_read_total", `source="fallback"`, `type="ondemand"`))
	require.Zero(t, m.Sum("nydus_backend_read_total", `type="demand"`))
	require.Zero(t, m.Sum("nydus_backend_read_total", `source="fallback"`, `type="prefetch"`))
	require.True(t, m.Has("nydus_backend_read_total"))
	require.False(t, m.Has("backend_origin_read_count"))
}
