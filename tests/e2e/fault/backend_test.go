package fault

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestBackendError(t *testing.T) {
	t.Parallel()
	img := image{fixture.Get(t, "zstd-4k")}

	cases := []struct {
		name string
		run  func(t *testing.T, a mount.Adapter, img image)
	}{
		{"Transient5xx", backendTransient},
		{"Persistent5xx", backendPersistent},
		{"NotFound", backendNotFound},
		{"Timeout", backendTimeout},
		{"Cut", backendCut},
		{"TokenRefresh", backendTokenRefresh},
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

func backendTransient(t *testing.T, a mount.Adapter, img image) {
	reg := img.serve(t)
	m := img.mountRegistry(t, a, reg.Registry.URL, nil, false)
	m.prime(t)

	reg.Registry.Faults.Set(registry.Fault{Status: http.StatusServiceUnavailable, Times: 2})
	m.read(t, bigFile).expectCorrect(t)
	hits := reg.Registry.Faults.Hits()
	assert.Equal(t, 2, hits)
}

func backendPersistent(t *testing.T, a mount.Adapter, img image) {
	reg := img.serve(t)
	m := img.mountRegistry(t, a, reg.Registry.URL, &mount.HTTPConfig{MaxRetries: mount.Ptr(1)}, false)
	m.prime(t)
	big := img.lookup(t, bigFile)

	reg.Registry.Faults.Set(registry.Fault{Status: http.StatusServiceUnavailable})
	r := big.readOnce(t, m.Root)
	r.expectFailed(t)
	r.expectNotWrong(t)
	assert.LessOrEqual(t, r.elapsed, 20*time.Second)
	assert.GreaterOrEqual(t, reg.Registry.Faults.Hits(), 2)

	reg.Registry.Faults.Clear()
	big.readOnce(t, m.Root).expectCorrect(t)
}

func backendNotFound(t *testing.T, a mount.Adapter, img image) {
	reg := img.serve(t)
	m := img.mountRegistry(t, a, reg.Registry.URL, nil, false)
	m.prime(t)
	big := img.lookup(t, bigFile)
	before := m.API.Metrics(t).Sum("nydus_backend_read_failure_total", `source="origin"`)

	reg.Registry.Faults.Set(registry.Fault{Status: http.StatusNotFound})
	r := big.readOnce(t, m.Root)
	r.expectFailed(t)
	r.expectNotWrong(t)
	assert.LessOrEqual(t, r.elapsed, 5*time.Second)

	if !assert.Eventually(t, func() bool {
		body, err := m.API.Get("/metrics")
		if err != nil {
			return false
		}

		failed := mount.ParseMetrics(string(body)).Sum("nydus_backend_read_failure_total", `source="origin"`) - before

		return failed > 0 && float64(reg.Registry.Faults.Hits()) <= failed
	}, 5*time.Second, 100*time.Millisecond) {
		t.FailNow()
	}

	reg.Registry.Faults.Clear()
	big.readOnce(t, m.Root).expectCorrect(t)
}

func backendTimeout(t *testing.T, a mount.Adapter, img image) {
	reg := img.serve(t)
	m := img.mountRegistry(t, a, reg.Registry.URL, &mount.HTTPConfig{RequestTimeout: "1s", MaxRetries: mount.Ptr(1)}, false)
	m.prime(t)
	big := img.lookup(t, bigFile)

	reg.Registry.Faults.Set(registry.Fault{Delay: time.Minute})

	r := big.judge(t, 20*time.Second, func() (string, error) {
		f, err := os.Open(m.Path(big.rel))
		if err != nil {
			return "", err
		}

		defer func() { _ = f.Close() }()

		if err := unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_RANDOM); err != nil {
			return "", err
		}
		if err := unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED); err != nil {
			return "", err
		}

		h := sha256.New()
		_, err = io.CopyBuffer(h, io.NewSectionReader(f, 0, big.size), make([]byte, os.Getpagesize()))

		return hex.EncodeToString(h.Sum(nil)), err
	})

	r.expectFailed(t)
	r.expectNotWrong(t)
	assert.GreaterOrEqual(t, reg.Registry.Faults.Hits(), 2)

	reg.Registry.Faults.Clear()
	big.readOnce(t, m.Root).expectCorrect(t)
}

func backendCut(t *testing.T, a mount.Adapter, img image) {
	reg := img.serve(t)
	m := img.mountRegistry(t, a, reg.Registry.URL, nil, false)
	m.prime(t)
	big := img.lookup(t, bigFile)

	reg.Registry.Faults.Set(registry.Fault{CutAfter: 4096, Times: 1})
	r := big.readOnce(t, m.Root)
	r.expectNotWrong(t)
	t.Logf("read across a cut connection: %s", r)

	reg.Registry.Faults.Clear()
	big.readOnce(t, m.Root).expectCorrect(t)
}

func backendTokenRefresh(t *testing.T, a mount.Adapter, img image) {
	reg := img.serve(t)
	auth := registry.NewAuth(t, reg.Registry.URL, repo)
	srv := httptest.NewServer(auth)
	t.Cleanup(srv.Close)

	m := img.mountRegistry(t, a, srv.URL, nil, false)
	m.prime(t)
	issued, _ := auth.Counts()
	if !assert.NotZero(t, issued) {
		t.FailNow()
	}

	auth.Revoke()
	m.read(t, bigFile).expectCorrect(t)
	after, denied := auth.Counts()
	t.Logf("tokens: %d before revocation, %d after; %d requests denied", issued, after-issued, denied)
	assert.Positive(t, after-issued)
	assert.LessOrEqual(t, after-issued, 16)
}

var rangeIgnoredFiles = []string{"data/content/text", "data/dedup/orig", "data/size/00065537", bigFile}

func TestRangeIgnored(t *testing.T) {
	t.Parallel()
	for _, layout := range []string{"zstd-4k", "none-4k"} {
		img := image{fixture.Get(t, layout)}

		for _, a := range adapters {
			t.Run(layout+"/"+a.Name(), func(t *testing.T) {
				t.Parallel()
				rangeIgnored(t, a, img)
			})
		}
	}
}

func rangeIgnored(t *testing.T, a mount.Adapter, img image) {
	reg := img.serve(t)
	m := img.mountRegistry(t, a, reg.Registry.URL, nil, false)
	m.prime(t)
	before := m.API.Metrics(t)

	reg.Registry.Faults.Set(registry.Fault{IgnoreRange: true})
	var results []result
	failed := 0

	for _, rel := range rangeIgnoredFiles {
		r := m.read(t, rel)
		t.Logf("%s", r)
		results = append(results, r)

		if r.err != nil {
			failed++
		}
	}

	after := m.API.Metrics(t)

	if !assert.NotZero(t, reg.Registry.Faults.Hits()) {
		t.FailNow()
	}
	if !assert.True(t, after.Has("nydus_backend_read_total")) {
		t.FailNow()
	}

	crc := after.Sum("nydus_cache_write_failure_total", `reason="checksum"`) - before.Sum("nydus_cache_write_failure_total", `reason="checksum"`)
	backendErrs := after.Sum("nydus_backend_read_failure_total") - before.Sum("nydus_backend_read_failure_total")
	t.Logf("%d of %d reads failed; %v CRC errors, %v backend errors", failed, len(results), crc, backendErrs)

	if !assert.True(t, m.Daemon.Alive()) {
		t.FailNow()
	}

	reg.Registry.Faults.Clear()

	for _, rel := range rangeIgnoredFiles {
		m.read(t, rel).expectCorrect(t)
	}

	for _, r := range results {
		r.expectNotWrong(t)
	}

	assert.Zero(t, crc)
	assert.NotZero(t, failed)
	assert.NotZero(t, backendErrs)
}
