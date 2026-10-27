package dragonfly

//e2e:serial the D tests share one Dragonfly cluster and stop and restart its components.

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
)

// policyOptions give dfdaemon time to
// report the origin's status before the SDK request times out.
var policyOptions = options{Timeout: "10s", FallbackRateLimit: 1000}

// policyBound bounds one faulted read: up to two Dragonfly attempts and two
// origin attempts per backend read.
const policyBound = 60 * time.Second

// TestD6ErrorCodePolicy checks what an on-demand read does with each status
// the origin returns to dfdaemon's back-to-source request, which dfdaemon
// reports to nydus as a backend error. The origin answers nydus's own
// fallback requests with the same status, so a read that falls back still
// fails. Terminal 403/404 responses never fall back; 408/429/5xx fall back
// after the SDK's retry budget. A 401 triggers auth through Dragonfly.
func TestD6ErrorCodePolicy(t *testing.T) {
	c := newCluster(t)

	for _, status := range []int{403, 404, 408, 429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			m := mountFaulted(t, c, status)
			d, err := readMeasured(t, m, status)
			expectEIO(t, err, d, http.StatusText(status))
			if d.of(proxyErrors) == 0 {
				t.Fatalf("failed read was not counted; %v", d)
			}
			m.Daemon.WaitFor(t, 5*time.Second, "failed read log", func() bool {
				return strings.Contains(m.Daemon.FileLog(), "read failed:")
			})
			wantFallback := status == 408 || status == 429 || status >= 500
			if got := strings.Contains(m.Daemon.FileLog(), "falling back to the origin"); got != wantFallback {
				t.Errorf("fallback=%v, want %v for status %d", got, wantFallback, status)
			}
		})
	}

	t.Run("401_fetches_token_and_retries_via_dragonfly", func(t *testing.T) {
		img := uniqueImage(t)
		auth := startAuthOrigin(t, startOrigin(t, img))
		m := mountDragonfly(t, c, img, auth.URL, policyOptions)
		var err error
		d := measure(t, m, func() {
			within(t, m, policyBound, "a read from an origin requiring a token", func() { err = readData(t, m) })
		})
		if err != nil {
			t.Fatalf("read: %v; %v", err, d)
		}
		if n := auth.Tokens.Load(); n != 1 {
			t.Errorf("fetched %d tokens, want 1", n)
		}
		if d.of(fallbackReads) != 0 || d.of(proxyReads) == 0 {
			t.Errorf("want the retry with the token served by Dragonfly, without a fallback; %v", d)
		}
	})
}

// mountFaulted mounts a fresh image whose origin answers every blob GET
// with status.
func mountFaulted(t env.TB, c *cluster, status int) *mount.Mounted {
	t.Helper()
	img := uniqueImage(t)
	origin := startOrigin(t, img)
	origin.Faults.Set(registry.Fault{Status: status})
	return mountDragonfly(t, c, img, origin.URL, policyOptions)
}

// readMeasured reads the image's data, returning the read error and how the
// metrics moved.
func readMeasured(t env.TB, m *mount.Mounted, status int) (delta, error) {
	t.Helper()
	var err error
	d := measure(t, m, func() {
		within(t, m, policyBound, "a read with the origin answering "+http.StatusText(status), func() { err = readData(t, m) })
	})
	return d, err
}
