package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Auth puts a registry behind the distribution bearer-token flow: GET
// /token issues a fresh token, and any other request without a valid one is
// answered 401 with a Bearer challenge whose realm is that endpoint and
// whose scope is a pull of repo. Valid requests are proxied to the registry.
type Auth struct {
	repo  string
	proxy *httputil.ReverseProxy

	// mu guards valid, issued and denied.
	mu     sync.Mutex
	valid  map[string]bool
	issued int
	denied int
}

// NewAuth returns the token gate for repo in front of the registry at
// upstream, a base URL.
func NewAuth(t testing.TB, upstream, repo string) *Auth {
	t.Helper()
	target, err := url.Parse(upstream)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorLog = log.New(io.Discard, "", 0)

	return &Auth{repo: repo, proxy: proxy, valid: map[string]bool{}}
}

// ServeHTTP issues tokens, challenges requests without a valid one and
// proxies the rest.
func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"token": a.issue(), "expires_in": 3600})
		return
	}

	if !a.allow(r) {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer realm="http://%s/token",service="e2e",scope="repository:%s:pull"`, r.Host, a.repo))

		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	a.proxy.ServeHTTP(w, r)
}

// issue returns a fresh valid token.
func (a *Auth) issue() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.issued++
	token := fmt.Sprintf("token-%d", a.issued)
	a.valid[token] = true

	return token
}

// allow reports whether r carries a valid token, counting a denial when
// it does not.
func (a *Auth) allow(r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	a.mu.Lock()
	defer a.mu.Unlock()

	if ok && a.valid[token] {
		return true
	}

	a.denied++

	return false
}

// Revoke invalidates every token issued so far.
func (a *Auth) Revoke() {
	a.mu.Lock()
	defer a.mu.Unlock()
	clear(a.valid)
}

// Counts returns how many tokens were issued and requests denied.
func (a *Auth) Counts() (issued, denied int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.issued, a.denied
}
