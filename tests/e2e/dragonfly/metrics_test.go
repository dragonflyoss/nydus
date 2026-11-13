package dragonfly

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
)

type metric struct {
	name, source string
}

type delta struct {
	before, after mount.Metrics
	fallbacks     int
}

func (d delta) of(m metric) float64 {
	label := `source="` + m.source + `"`
	return d.after.Sum(m.name, label) - d.before.Sum(m.name, label)
}

func (d delta) String() string {
	var parts []string

	for series, v := range d.after {
		if !strings.HasPrefix(series, "nydus_backend_") || strings.Contains(series, "_duration_") {
			continue
		}

		if moved := v - d.before[series]; moved != 0 {
			parts = append(parts, fmt.Sprintf("%s +%g", series, moved))
		}
	}

	if len(parts) == 0 {
		return "no backend metric moved"
	}

	slices.Sort(parts)

	return "metrics moved: " + strings.Join(parts, ", ")
}

func (d delta) expectFallback(t testing.TB) {
	t.Helper()
	if !assert.NotZero(t, d.fallbacks) {
		t.FailNow()
	}

	assert.NotZero(t, d.of(proxyReads))
	assert.Zero(t, d.of(proxyErrors))
}

var (
	proxyReads  = metric{"nydus_backend_read_total", "dragonfly"}
	proxyBytes  = metric{"nydus_backend_read_bytes_total", "dragonfly"}
	proxyErrors = metric{"nydus_backend_read_failure_total", "dragonfly"}
)
