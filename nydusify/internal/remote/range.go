package remote

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type blobRangeKey struct{}
type blobRange struct{ end, size int64 }

// rangeEnd accepts the single byte ranges used by the registry backend.
// ServeContent resolves the start offset, including suffix ranges.
func rangeEnd(value string, size int64) (int64, error) {
	if size <= 0 {
		return 0, fmt.Errorf("invalid blob size %d", size)
	}
	if value == "" {
		return size - 1, nil
	}
	span, ok := strings.CutPrefix(value, "bytes=")
	first, last, split := strings.Cut(span, "-")
	if !ok || !split || strings.ContainsAny(first+last, "+-, ") {
		return 0, fmt.Errorf("invalid compact range %q", value)
	}
	if first == "" {
		n, err := strconv.ParseInt(last, 10, 64)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid compact suffix range %q", value)
		}
		return size - 1, nil
	}
	start, err := strconv.ParseInt(first, 10, 64)
	if err != nil || start < 0 || start >= size {
		return 0, fmt.Errorf("invalid compact range %q", value)
	}
	end, err := strconv.ParseInt(last, 10, 64)
	if err != nil || end < start || end >= size {
		return 0, fmt.Errorf("invalid compact range %q", value)
	}
	return end, nil
}

// Only the compact fetcher uses this transport. Containerd still owns
// authentication, retry and redirect handling; ordinary pulls are unchanged.
type boundedRangeTransport struct{ http.RoundTripper }

func (t boundedRangeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	span, ok := req.Context().Value(blobRangeKey{}).(blobRange)
	if !ok || req.Method != http.MethodGet {
		return t.RoundTripper.RoundTrip(req)
	}
	start := int64(0)
	if value := req.Header.Get("Range"); value != "" {
		raw := strings.TrimSuffix(strings.TrimPrefix(value, "bytes="), "-")
		var err error
		start, err = strconv.ParseInt(raw, 10, 64)
		if err != nil || start < 0 || start > span.end {
			return nil, fmt.Errorf("invalid compact fetch offset %q", value)
		}
	}
	bounded := req.Clone(req.Context())
	bounded.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, span.end))
	bounded.Header.Set("Accept-Encoding", "identity")
	resp, err := t.RoundTripper.RoundTrip(bounded)
	if err != nil {
		return nil, err
	}
	// Authentication challenges and redirects must reach containerd/http.Client.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		expected := fmt.Sprintf("bytes %d-%d/%d", start, span.end, span.size)
		if resp.StatusCode != http.StatusPartialContent || resp.Header.Get("Content-Range") != expected ||
			(resp.ContentLength >= 0 && resp.ContentLength != span.end-start+1) {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("registry did not honor compact range: %s, %q", resp.Status, resp.Header.Get("Content-Range"))
		}
	}
	return resp, nil
}
