package mount

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// API talks to a daemon's --apiserver Unix socket.
type API struct {
	Socket string
	client *http.Client
}

// NewAPI returns a client for the apiserver listening on socket.
func NewAPI(socket string) *API {
	return &API{
		Socket: socket,
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
			Timeout: 5 * time.Second,
		},
	}
}

// Do sends method path to the daemon and returns the response.
func (a *API) Do(method, path string) (*http.Response, error) {
	req, err := http.NewRequest(method, "http://localhost"+path, nil)
	if err != nil {
		return nil, err
	}

	return a.client.Do(req)
}

// Get fetches path and returns the body of a 200 response.
func (a *API) Get(path string) ([]byte, error) {
	resp, err := a.Do(http.MethodGet, path)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s: %s", path, resp.Status, body)
	}

	return body, nil
}

// Trace is the daemon's /trace report: the chunk groups read so far.
type Trace struct {
	Version  int `json:"version"`
	Patterns []struct {
		BlobIndex       int `json:"blob_index"`
		ChunkGroupIndex int `json:"chunk_group_index"`
	} `json:"patterns"`
}

// Trace fetches and parses /trace.
func (a *API) Trace(t testing.TB) Trace {
	t.Helper()
	body, err := a.Get("/trace")
	if err != nil {
		t.Fatalf("trace from %s: %v", a.Socket, err)
	}

	var tr Trace
	if err := json.Unmarshal(body, &tr); err != nil {
		t.Fatalf("parse trace: %v", err)
	}
	if tr.Version != 1 {
		t.Fatalf("trace version %d, want 1", tr.Version)
	}

	return tr
}

// Metrics is a parsed Prometheus exposition: series (name plus labels, as
// printed) to value. Histogram buckets are kept like any other series.
type Metrics map[string]float64

// Metrics fetches and parses /metrics.
func (a *API) Metrics(t testing.TB) Metrics {
	t.Helper()
	body, err := a.Get("/metrics")
	if err != nil {
		t.Fatalf("metrics from %s: %v", a.Socket, err)
	}

	return ParseMetrics(string(body))
}

// ParseMetrics parses Prometheus text exposition.
func ParseMetrics(text string) Metrics {
	m := Metrics{}

	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}

		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			continue
		}

		m[line[:i]] = v
	}

	return m
}

// Sum adds the series of name carrying every requested label.
func (m Metrics) Sum(name string, labels ...string) float64 {
	var total float64

	for series, v := range m {
		bare, rest, _ := strings.Cut(series, "{")
		if bare != name {
			continue
		}

		match := true

		for _, label := range labels {
			if !strings.Contains(","+strings.TrimSuffix(rest, "}")+",", ","+label+",") {
				match = false
				break
			}
		}

		if match {
			total += v
		}
	}

	return total
}

// Has reports whether any series of the metric name is exposed.
func (m Metrics) Has(name string) bool {
	for series := range m {
		if series == name || strings.HasPrefix(series, name+"{") {
			return true
		}
	}

	return false
}
