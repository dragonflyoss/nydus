package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

type registryProxy struct {
	next                            http.Handler
	faults                          registry.Faults
	injectedBase                    int
	basic, bearer                   string
	redirect                        bool
	challenges, redirects, blobGets atomic.Int32
	mu                              sync.Mutex
	tokenExpires                    int
	tokenStatus                     int
	tokenBody                       *string
	tokenDelay                      time.Duration
	tokens                          atomic.Int32
	redirectFault                   string
	redirectStatus                  int
	redirectGeneration              int
	expireCachedRedirect            bool
	staleRedirects                  atomic.Int32
}

func newRegistryProxy(t *testing.T, origin string) (*registryProxy, string) {
	t.Helper()
	target, err := url.Parse(origin)
	require.NoError(t, err)
	p := &registryProxy{tokenExpires: 300}
	p.next = p.faults.Wrap(httputil.NewSingleHostReverseProxy(target))
	server := httptest.NewServer(p)
	t.Cleanup(server.Close)
	return p, strings.TrimPrefix(server.URL, "http://")
}

func (p *registryProxy) Inject(status, count int) {
	p.injectedBase = p.faults.Hits()
	if status == 0 {
		p.faults.Clear()
		return
	}
	p.faults.Set(registry.Fault{Status: status, Times: max(0, count)})
}

func (p *registryProxy) RequireBasic(credential string) { p.basic = credential }
func (p *registryProxy) RequireBearer(token string)     { p.bearer = token }
func (p *registryProxy) RedirectBlobs(on bool)          { p.redirect = on }
func (p *registryProxy) Injected() int                  { return p.faults.Hits() - p.injectedBase }
func (p *registryProxy) Challenges() int                { return int(p.challenges.Load()) }
func (p *registryProxy) Redirects() int                 { return int(p.redirects.Load()) }
func (p *registryProxy) BlobGets() int                  { return int(p.blobGets.Load()) }

func (p *registryProxy) tokenResponse(expires, status int, body *string, delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenExpires, p.tokenStatus, p.tokenBody, p.tokenDelay = expires, status, body, delay
}

func (p *registryProxy) expireRedirect(status int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.redirectGeneration++
	p.redirectStatus = status
}

func (p *registryProxy) setRedirectFault(fault string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.redirectFault = fault
}

func (p *registryProxy) expireFirstCachedRedirect(status int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireCachedRedirect = true
	p.redirectStatus = status
}

func (p *registryProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	// A suffix GET learns the signed URL; the following metadata GET is
	// the first cache hit, so this transition deterministically expires it.
	if p.expireCachedRedirect && strings.HasPrefix(r.URL.Path, "/redirected/") &&
		!strings.HasPrefix(r.Header.Get("Range"), "bytes=-") {
		p.redirectGeneration++
		p.expireCachedRedirect = false
	}
	expires, status, body, delay := p.tokenExpires, p.tokenStatus, p.tokenBody, p.tokenDelay
	redirectFault, redirectStatus, generation := p.redirectFault, p.redirectStatus, p.redirectGeneration
	p.mu.Unlock()
	if r.URL.Path == "/token" {
		p.tokens.Add(1)
		if delay > 0 {
			select {
			case <-time.After(delay):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if status != 0 {
			w.WriteHeader(status)
		}
		if body != nil {
			_, _ = w.Write([]byte(*body))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token": p.bearer, "expires_in": expires})
		return
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	challenge := ""
	if p.basic != "" && r.Header.Get("Authorization") != "Basic "+p.basic {
		challenge = `Basic realm="e2e"`
	} else if p.bearer != "" && r.Header.Get("Authorization") != "Bearer "+p.bearer {
		challenge = fmt.Sprintf(`Bearer realm="%s://%s/token",service="e2e",scope="repository:e2e:pull"`, scheme, r.Host)
	}
	if challenge != "" {
		p.challenges.Add(1)
		w.Header().Set("WWW-Authenticate", challenge)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	redirected := strings.HasPrefix(r.URL.Path, "/redirected/")
	if redirected {
		if r.URL.Query().Get("generation") != fmt.Sprint(generation) && redirectStatus != 0 {
			p.staleRedirects.Add(1)
			w.WriteHeader(redirectStatus)
			return
		}
		r = r.Clone(r.Context())
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/redirected")
	}
	if registry.IsBlobGet(r) {
		if p.redirect && (!redirected || redirectFault == "loop") {
			p.redirects.Add(1)
			if redirectFault != "missing_location" {
				w.Header().Set("Location", fmt.Sprintf("%s://%s/redirected%s?generation=%d", scheme, r.Host, r.URL.Path, generation))
			}
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		p.blobGets.Add(1)
	}
	p.next.ServeHTTP(w, r)
}
