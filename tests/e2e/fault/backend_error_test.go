package fault

import (
	"net/http"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
)

// TestBackendError makes the registry fail blob reads the ways registries
// do. The registry backend retries 5xx, 408, 429 and timeouts with jittered
// exponential backoff from 1s, up to http.max_retries (default 3) times; any
// other status fails at once. A 401 drops the cached token, fetches a new
// one from the challenge's realm and retries once. After every fault is
// lifted the same file reads back right: a failed fetch poisons nothing.
func TestBackendError(t *testing.T) {
	t.Parallel()
	img := fixture.Get(t, "zstd-4k")
	cases := []struct {
		name string
		run  func(t *testing.T, a mount.Adapter, img fixture.Image)
	}{
		{"transient-5xx", backendTransient},
		{"persistent-5xx", backendPersistent},
		{"404", backendNotFound},
		{"timeout", backendTimeout},
		{"cut", backendCut},
		{"401", backendTokenRefresh},
	}
	for _, a := range adapters {
		t.Run(a.Name(), func(t *testing.T) {
			t.Parallel()
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					t.Parallel()
					c.run(t, a, img)
				})
			}
		})
	}
}

// backendTransient: two 503s are absorbed by the retries.
func backendTransient(t *testing.T, a mount.Adapter, img fixture.Image) {
	reg := pushImage(t, img)
	m := registryMount(t, a, img, reg.URL, nil, false)
	prime(t, m)

	reg.Faults.Set(registry.Fault{Status: http.StatusServiceUnavailable, Times: 2})
	expectCorrect(t, readOnce(t, m.Root, lookup(t, img, bigFile)))
	if hits := reg.Faults.Hits(); hits != 2 {
		t.Errorf("want both 503s consumed by retries, got %d faulted requests", hits)
	}
}

// backendPersistent: a registry that keeps answering 503 fails the read
// once the retries are spent, rather than retrying forever.
func backendPersistent(t *testing.T, a mount.Adapter, img fixture.Image) {
	reg := pushImage(t, img)
	m := registryMount(t, a, img, reg.URL, &mount.HTTP{MaxRetries: mount.Ptr(1)}, false)
	prime(t, m)
	big := lookup(t, img, bigFile)

	reg.Faults.Set(registry.Fault{Status: http.StatusServiceUnavailable})
	r := readOnce(t, m.Root, big)
	expectFailed(t, r)
	expectNotWrong(t, r)
	if r.Elapsed > 20*time.Second {
		t.Errorf("one retry should fail the read well within 20s: %s", r)
	}
	if hits := reg.Faults.Hits(); hits < 2 {
		t.Errorf("max_retries 1 should try each request twice, saw %d faulted requests", hits)
	}

	reg.Faults.Clear()
	expectCorrect(t, readOnce(t, m.Root, big))
}

// backendNotFound: a 404 is final, so the read fails at once without a
// backoff and without a retry per request.
func backendNotFound(t *testing.T, a mount.Adapter, img fixture.Image) {
	reg := pushImage(t, img)
	m := registryMount(t, a, img, reg.URL, nil, false)
	prime(t, m)
	big := lookup(t, img, bigFile)
	failedReads := func() float64 { return m.API.Metrics(t).Sum("nydus_backend_read_failure_total", `source="origin"`) }
	before := failedReads()

	reg.Faults.Set(registry.Fault{Status: http.StatusNotFound})
	r := readOnce(t, m.Root, big)
	expectFailed(t, r)
	expectNotWrong(t, r)
	if r.Elapsed > 5*time.Second {
		t.Errorf("a 404 should fail without backing off: %s", r)
	}
	// Readahead and the kernel's retry of a failed page turn one read(2)
	// into several backend reads, more so through fileio's two page caches,
	// so the registry requests are judged against the backend reads that
	// failed: a retried 404 would show as more requests than reads. A
	// request still in flight counts as a hit before its read fails.
	var hits int
	var failed float64
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		hits, failed = reg.Faults.Hits(), failedReads()-before
		if (failed > 0 && float64(hits) <= failed) || time.Now().After(deadline) {
			break
		}
	}
	if failed == 0 || float64(hits) > failed {
		t.Errorf("a 404 must not be retried: %d registry requests for %v failed backend reads", hits, failed)
	}

	reg.Faults.Clear()
	expectCorrect(t, readOnce(t, m.Root, big))
}

// backendTimeout: a registry that accepts the request and never answers is
// cut off by http.request_timeout, retried, then failed.
func backendTimeout(t *testing.T, a mount.Adapter, img fixture.Image) {
	reg := pushImage(t, img)
	m := registryMount(t, a, img, reg.URL, &mount.HTTP{RequestTimeout: "1s", MaxRetries: mount.Ptr(1)}, false)
	prime(t, m)
	big := lookup(t, img, bigFile)

	reg.Faults.Set(registry.Fault{Delay: time.Minute})
	check := func(t env.TB) {
		// Two 1s timeouts and a backoff fail one backend read in about
		// 3s; the read(2) has to fail well before the hang detector.
		r := readWithin(t, m.Root, big, 20*time.Second)
		expectFailed(t, r)
		expectNotWrong(t, r)
		if hits := reg.Faults.Hits(); hits < 2 {
			t.Errorf("a timeout should be retried, saw %d faulted requests", hits)
		}
	}
	if _, ok := a.(mount.Fileio); ok {
		env.KnownIssue(t, "KI-12", check)
	} else {
		check(t)
	}

	reg.Faults.Clear()
	expectCorrect(t, readOnce(t, m.Root, big))
}

// backendCut: a connection dropped mid-body is a short read, which must
// not be taken for data.
func backendCut(t *testing.T, a mount.Adapter, img fixture.Image) {
	reg := pushImage(t, img)
	m := registryMount(t, a, img, reg.URL, nil, false)
	prime(t, m)
	big := lookup(t, img, bigFile)

	reg.Faults.Set(registry.Fault{CutAfter: 4096, Times: 1})
	r := readOnce(t, m.Root, big)
	expectNotWrong(t, r)
	t.Logf("read across a cut connection: %s", r)

	reg.Faults.Clear()
	expectCorrect(t, readOnce(t, m.Root, big))
}

// backendTokenRefresh: once the registry stops honoring the cached token,
// the backend fetches a new one and the read goes through. Each request
// that met the 401 fetches at most one token, so the number fetched is
// bounded by the requests in flight, not unbounded.
func backendTokenRefresh(t *testing.T, a mount.Adapter, img fixture.Image) {
	reg := pushImage(t, img)
	auth := startAuthProxy(t, reg.URL)
	m := registryMount(t, a, img, auth.URL, nil, false)
	prime(t, m)
	issued, _ := auth.counts()
	if issued == 0 {
		t.Fatalf("the registry demanded a token but none was fetched")
	}

	auth.revoke()
	expectCorrect(t, readOnce(t, m.Root, lookup(t, img, bigFile)))
	after, denied := auth.counts()
	t.Logf("tokens: %d before revocation, %d after; %d requests denied", issued, after-issued, denied)
	if n := after - issued; n < 1 || n > 16 {
		t.Errorf("want one token refresh per request that met the 401, got %d tokens", n)
	}
}
