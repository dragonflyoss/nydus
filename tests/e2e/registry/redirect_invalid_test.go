package registry

import (
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestRedirectInvalid(t *testing.T) {
	t.Parallel()
	for _, fault := range []string{"missing_location", "loop"} {
		for _, scope := range []string{"none", "all"} {
			t.Run(fault+"/"+scope, func(t *testing.T) {
				image, proxy, addr := newRegistrySuite(t)
				proxy.RedirectBlobs(true)
				proxy.setRedirectFault(fault)
				config := image.config("http://" + addr)
				config.HTTP.MaxRetries = mount.Ptr(0)
				config.Prefetch.Scope = scope
				m := image.mount(t, config)
				start := time.Now()
				if scope == "all" {
					m.waitLogs(t, "failed to prefetch priority blob")
					require.Zero(t, m.backendReads(t, "ondemand", "origin"))
				} else {
					_, err := readWindow(m.Path("data/size/08392705"), 0)
					require.ErrorIs(t, err, syscall.EIO)
				}
				require.Less(t, time.Since(start), 10*time.Second)
				require.Positive(t, proxy.Redirects())
				require.LessOrEqual(t, proxy.Redirects(), 8, "a redirect loop must terminate without a request storm")
				require.Zero(t, proxy.BlobGets())
				require.True(t, m.Daemon.Alive())
				proxy.setRedirectFault("")
				readWindows(t, m, image, 2<<20)
			})
		}
	}
}
