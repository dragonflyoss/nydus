package registry

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
)

func TestReadThroughOrigin(t *testing.T) {
	t.Parallel()
	image, proxy, addr := newRegistrySuite(t)
	m := image.mount(t, image.config(addr))
	if !assert.NoError(t, m.read(t, image, "data/content/text")) {
		t.FailNow()
	}
	if !assert.NoError(t, m.read(t, image, "data/size/08392705")) {
		t.FailNow()
	}
	if !assert.Positive(t, m.backendReads(t, "ondemand", "origin")) {
		t.FailNow()
	}

	assert.Zero(t, m.backendFailures(t, "ondemand", "origin"))
	assert.Positive(t, proxy.blobGetCount())
}

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
		log   string
	}{
		{"MissingContentRange", registry.Fault{Match: footer, Headers: map[string]string{"Content-Range": ""}}, "missing Content-Range"},
		{"InvalidContentRange", registry.Fault{Match: footer, Headers: map[string]string{"Content-Range": "bytes 0-1/not-a-length"}}, "invalid Content-Range bytes 0-1/not-a-length"},
		{"UnknownContentLength", registry.Fault{Match: footer, Headers: map[string]string{"Content-Range": "bytes 0-1/*"}}, "invalid Content-Range bytes 0-1/*"},
		{"ShortFooter", registry.Fault{Match: footer, ShortBody: 1}, "early eof"},
		{"ShortMetadata", registry.Fault{Match: meta, ShortBody: 1}, "early eof"},
	} {
		for _, scope := range []string{"none", "all"} {
			t.Run(tc.name+"/"+scope, func(t *testing.T) {
				t.Parallel()
				image, proxy, addr := newRegistrySuite(t)
				proxy.faults.Set(tc.fault)
				config := image.config(addr)
				config.HTTP.MaxRetries = mount.Ptr(0)
				config.prefetch.Scope = scope
				m := image.mount(t, config)

				m.expectFailure(t, scope)

				m.Daemon.WaitForLog(t, 10*time.Second, tc.log)

				if !assert.Zero(t, m.API.Metrics(t).Sum("nydus_backend_read_total")) {
					t.FailNow()
				}
				if !assert.Positive(t, proxy.faults.Hits()) {
					t.FailNow()
				}
				if !assert.LessOrEqual(t, proxy.faults.Hits(), 4) {
					t.FailNow()
				}
				if !assert.True(t, m.Daemon.Alive()) {
					t.FailNow()
				}

				for _, request := range proxy.faults.Requests() {
					if request.Faulted {
						assert.Equal(t, http.StatusPartialContent, request.Status)
					}
				}

				proxy.faults.Clear()
				m.readWindows(t, image, 1<<20)
			})
		}
	}
}
