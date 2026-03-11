package metrics

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

type mockExporter struct {
	called int
}

func (m *mockExporter) Export() {
	m.called++
}

func resetMetricsForTest() {
	register = sync.Once{}
	Registry = nil
	exporter = nil
	convertDuration.Reset()
	convertSuccessCount.Reset()
	convertFailureCount.Reset()
	storeCacheDuration.Reset()
}

func TestRegisterAndExport(t *testing.T) {
	resetMetricsForTest()
	mock := &mockExporter{}
	Register(mock)
	Register(&mockExporter{})
	require.NotNil(t, Registry)

	Export()
	require.Equal(t, 1, mock.called)

	exporter = nil
	Export()
}

func TestMetricRecorders(t *testing.T) {
	resetMetricsForTest()
	Register(&mockExporter{})

	start := time.Now().Add(-2 * time.Second)
	ConversionDuration("example.com/repo:tag", 3, start)
	ConversionSuccessCount("example.com/repo:tag")
	ConversionFailureCount("example.com/repo:tag", "mock")
	StoreCacheDuration("example.com/repo:tag", start)

	require.Greater(t, sinceInSeconds(start), 1.0)
	require.Greater(t, testutil.ToFloat64(convertDuration.WithLabelValues("example.com/repo:tag", "3")), 0.0)
	require.Equal(t, float64(1), testutil.ToFloat64(convertSuccessCount.WithLabelValues("example.com/repo:tag")))
	require.Equal(t, float64(1), testutil.ToFloat64(convertFailureCount.WithLabelValues("example.com/repo:tag", "mock")))
	require.Greater(t, testutil.ToFloat64(storeCacheDuration.WithLabelValues("example.com/repo:tag")), 0.0)
}
