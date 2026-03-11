package fileexporter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/metrics"
)

func TestNewAndExport(t *testing.T) {
	metrics.Registry = prometheus.NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_counter", Help: "test"})
	metrics.Registry.MustRegister(counter)
	counter.Inc()

	output := filepath.Join(t.TempDir(), "metrics.prom")
	exporter := New(output)
	require.NotNil(t, exporter)

	exporter.Export()

	content, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Contains(t, string(content), "test_counter")
}
