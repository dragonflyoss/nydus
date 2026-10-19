package util

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TryFetchMetrics GETs the Prometheus exposition from the apiserver Unix
// socket and parses it into a name to value map, labeled series keeping
// their {...} suffix in the key. Unlike FetchMetrics it returns the error
// instead of failing the test, so a caller can poll for the endpoint or
// treat a daemon without one as having no metrics.
func TryFetchMetrics(socket string) (map[string]float64, error) {
	resp, err := apiserverClient(socket).Get("http://localhost/metrics")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics returned %s", resp.Status)
	}

	// Split every sample on its last space so labels keep their spaces.
	metrics := make(map[string]float64)
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		idx := strings.LastIndexByte(line, ' ')
		if idx < 0 {
			continue
		}

		value, err := strconv.ParseFloat(line[idx+1:], 64)
		if err != nil {
			continue
		}
		metrics[line[:idx]] = value
	}

	return metrics, scanner.Err()
}

// FetchMetrics GETs the Prometheus exposition from the mount's apiserver Unix
// socket and parses it into a name to value map, failing the test when the
// endpoint cannot be read.
func FetchMetrics(t *testing.T, socket string) map[string]float64 {
	t.Helper()
	metrics, err := TryFetchMetrics(socket)
	assert.NoError(t, err, "fetch /metrics from %s", socket)
	return metrics
}

// SumMetric sums the series of every metric whose name matches name, a
// bare name or a `*` glob such as `nydus_read_backend_total`, and whose
// labels carry every given `label="value"` pair, 0 when absent.
func SumMetric(metrics map[string]float64, name string, labels ...string) float64 {
	var total float64
	for key, value := range metrics {
		bare, rest, _ := strings.Cut(key, "{")
		if matched, _ := filepath.Match(name, bare); !matched {
			continue
		}
		matched := true
		for _, label := range labels {
			if !strings.Contains(rest, label) {
				matched = false
				break
			}
		}
		if matched {
			total += value
		}
	}
	return total
}

// WaitAPIServer waits until the apiserver on the Unix socket answers a
// metrics request.
func WaitAPIServer(t *testing.T, socket string) {
	t.Helper()
	assert.Eventually(t, func() bool {
		_, err := TryFetchMetrics(socket)
		return err == nil
	}, 30*time.Second, 100*time.Millisecond, "apiserver %s never came up", socket)
}

// WaitMetricSettled waits until the metric selected like in SumMetric has
// settled on one apiserver and returns the settled value.
func WaitMetricSettled(t *testing.T, socket, name string, labels ...string) float64 {
	t.Helper()
	return WaitSettled(t, name, func() (float64, error) {
		metrics, err := TryFetchMetrics(socket)
		return SumMetric(metrics, name, labels...), err
	})
}

// WaitSettled polls sample until it is non-zero and unchanged across three
// consecutive samples, which is how a test knows background work such as
// prefetch has stopped, and returns the settled value. A sample error is
// treated as not settled yet. name names the value in the failure message.
func WaitSettled(t *testing.T, name string, sample func() (float64, error)) float64 {
	t.Helper()
	var last float64
	stable := 0
	assert.Eventually(t, func() bool {
		current, err := sample()
		if err != nil {
			return false
		}

		if current > 0 && current == last {
			stable++
		} else {
			stable = 0
		}
		last = current

		return stable >= 3
	}, 60*time.Second, 300*time.Millisecond, "%s did not settle within 60s", name)

	return last
}

// SaveTrace GETs the /trace endpoint from the mount's apiserver socket, saves
// the raw JSON access-pattern document to path, and returns the number of
// recorded (blob, chunk) access patterns.
func SaveTrace(t *testing.T, socket, path string) int {
	t.Helper()
	resp, err := apiserverClient(socket).Get("http://localhost/trace")
	if !assert.NoError(t, err, "fetch /trace from %s", socket) {
		return 0
	}
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	raw, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)
	assert.NoError(t, os.WriteFile(path, raw, 0o644))

	var doc struct {
		Version  uint32 `json:"version"`
		Patterns []struct {
			BlobIndex       uint32 `json:"blob_index"`
			ChunkGroupIndex uint32 `json:"chunk_group_index"`
		} `json:"patterns"`
	}
	assert.NoError(t, json.Unmarshal(raw, &doc))
	assert.EqualValues(t, 1, doc.Version, "unexpected trace document version")
	return len(doc.Patterns)
}

// apiserverClient returns an HTTP client that reaches the apiserver listening
// on the Unix socket.
func apiserverClient(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
		Timeout: 5 * time.Second,
	}
}
