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
}

func (d delta) of(m metric) float64 {
	label := `source="` + m.source + `"`
	return d.after.Sum(m.name, label) - d.before.Sum(m.name, label)
}

func (d delta) backend() bool {
	for _, name := range []metric{proxyReads, originReads, fallbackReads} {
		if d.of(name) != 0 {
			return true
		}
	}

	return false
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
	if !assert.NotZero(t, d.of(fallbackReads)) {
		t.FailNow()
	}

	assert.Zero(t, d.of(proxyErrors))
	assert.Zero(t, d.of(proxyReads))
}

var (
	proxyReads    = metric{"nydus_backend_read_total", "dragonfly"}
	proxyBytes    = metric{"nydus_backend_read_bytes_total", "dragonfly"}
	proxyErrors   = metric{"nydus_backend_read_failure_total", "dragonfly"}
	originReads   = metric{"nydus_backend_read_total", "origin"}
	originErrors  = metric{"nydus_backend_read_failure_total", "origin"}
	fallbackReads = metric{"nydus_backend_read_total", "fallback"}
)
