package registry

import (
	"net/http"
	"strings"
	"syscall"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

func TestMetadataResponse(t *testing.T) {
	t.Parallel()
	footer := func(r *http.Request) bool {
		return registry.IsBlobGet(r) && strings.HasPrefix(r.Header.Get("Range"), "bytes=-")
	}
	meta := func(r *http.Request) bool {
		return registry.IsBlobGet(r) && strings.HasPrefix(r.Header.Get("Range"), "bytes=") && !footer(r)
	}
	for _, tc := range []struct {
		name  string
		fault registry.Fault
	}{
		{"missing_content_range", registry.Fault{Match: footer, Headers: map[string]string{"Content-Range": ""}}},
		{"invalid_content_range", registry.Fault{Match: footer, Headers: map[string]string{"Content-Range": "bytes 0-1/not-a-length"}}},
		{"unknown_content_length", registry.Fault{Match: footer, Headers: map[string]string{"Content-Range": "bytes 0-1/*"}}},
		{"short_footer", registry.Fault{Match: footer, ShortBody: 1}},
		{"short_metadata", registry.Fault{Match: meta, ShortBody: 1}},
	} {
		for _, scope := range []string{"none", "all"} {
			t.Run(tc.name+"/"+scope, func(t *testing.T) {
				image, proxy, addr := newRegistrySuite(t)
				proxy.faults.Set(tc.fault)
				config := image.config("http://" + addr)
				config.HTTP.MaxRetries = mount.Ptr(0)
				config.Prefetch.Scope = scope
				m := image.mount(t, config)
				if scope == "all" {
					m.waitLogs(t, "failed to prefetch priority blob")
					require.Zero(t, m.backendReads(t, "ondemand", "origin"), "only prefetch should have run")
				} else {
					_, err := readWindow(m.Path("data/size/08392705"), 0)
					require.ErrorIs(t, err, syscall.EIO)
					m.waitLogs(t, "read failed:")
				}
				// Metadata discovery is not a data-read metric. No data may be
				// fetched until the footer and metadata are both validated.
				require.Zero(t, m.API.Metrics(t).Sum("nydus_backend_read_total"))
				if tc.fault.ShortBody > 0 {
					m.waitLogs(t, "early eof")
				} else {
					m.waitLogs(t, "missing a valid content-range")
				}
				require.Positive(t, proxy.faults.Hits())
				require.LessOrEqual(t, proxy.faults.Hits(), 4, "invalid metadata must fail without unbounded retries")
				require.True(t, m.Daemon.Alive())
				for _, request := range proxy.faults.Requests() {
					if request.Faulted {
						require.Equal(t, http.StatusPartialContent, request.Status, "exercise response validation, not HTTP error handling")
					}
				}
				proxy.faults.Clear()
				readWindows(t, m, image, 1<<20)
			})
		}
	}
}
