package nydusify

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/corpus"
	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/util/registry"
	"github.com/stretchr/testify/assert"
)

func TestOptimize(t *testing.T) {
	t.Parallel()
	env.RequireRoot(t)

	srcDir := filepath.Join(env.WorkDir(t), "src")
	if !assert.NoError(t, os.MkdirAll(filepath.Join(srcDir, "data"), 0o755)) {
		t.FailNow()
	}

	for i, name := range []string{"partial", "unread", "first", "last"} {
		data := corpus.Bytes(uint64(20261019+i), 2<<20+(i+1)*64<<10)
		if !assert.NoError(t, os.WriteFile(filepath.Join(srcDir, "data", name), data, 0o644)) {
			t.FailNow()
		}
	}

	src := newSource(t, "optimize", srcDir)

	reg := registry.Start(t)
	srcRef := reg.Ref("optimize", "oci")
	nydusRef := reg.Ref("optimize", "nydus")
	optRef := reg.Ref("optimize", "optimized")
	reg.PushDirs(t, srcRef, src.dirs...)
	nydusify(t, "convert", "--source", srcRef, "--target", nydusRef)
	nydusify(t, "check", "--source", srcRef, "--target", nydusRef)

	workload := func(mnt string) {
		for _, name := range []string{"first", "partial", "last"} {
			f, err := os.Open(filepath.Join(mnt, "data", name))
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			var r io.Reader = f
			if name == "partial" {
				r = io.LimitReader(f, 100<<10)
			}

			_, err = io.Copy(io.Discard, r)

			if !assert.NoError(t, f.Close()) {
				t.FailNow()
			}

			assert.NoError(t, err)
		}
	}

	baseline, mnt, api := ref(nydusRef).mount(t, false)
	workload(mnt)
	metrics := api.Metrics(t)
	if !assert.Positive(t, metrics.Sum("nydus_backend_read_total", `type="ondemand"`)) {
		t.FailNow()
	}
	if !assert.Zero(t, metrics.Sum("nydus_backend_read_total", `type="prefetch"`)) {
		t.FailNow()
	}
	if !assert.Zero(t, metrics.Sum("nydus_cache_write_total", `type="prefetch"`)) {
		t.FailNow()
	}

	raw, err := api.Get("/trace")
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	traced := traceLen(t, raw)
	if !assert.Greater(t, traced, 1) {
		t.FailNow()
	}

	baseline.Stop()

	record := filepath.Join(env.WorkDir(t), "trace.json")
	if !assert.NoError(t, os.WriteFile(record, raw, 0o644)) {
		t.FailNow()
	}

	nydusify(t, "optimize", "--type", "ondemand", "--trace-file", record, "--source", nydusRef, "--target", optRef)

	opt := ref(optRef).pull(t, src.want)
	assert.Len(t, opt.Blobs, 2)
	manifest, err := ref(optRef).image(t).Manifest()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Contains(t, manifest.Layers[1].Annotations, nydusOptimizedAnnotation) {
		t.FailNow()
	}

	_, mnt, api = ref(optRef).mount(t, true)
	waitRedirectFill(t, api, traced)
	metrics = api.Metrics(t)
	if !assert.Positive(t, metrics.Sum("nydus_backend_read_total", `type="prefetch"`)) {
		t.FailNow()
	}
	if !assert.EqualValues(t, traced, metrics.Sum("nydus_cache_write_total", `type="redirect"`)) {
		t.FailNow()
	}
	if !assert.Zero(t, metrics.Sum("nydus_cache_write_failure_total")) {
		t.FailNow()
	}
	if !assert.Zero(t, metrics.Sum("nydus_cache_write_total", `type="prefetch"`)) {
		t.FailNow()
	}
	if !assert.Zero(t, metrics.Sum("nydus_backend_read_total", `type="ondemand"`)) {
		t.FailNow()
	}

	workload(mnt)
	metrics = api.Metrics(t)
	if !assert.Zero(t, metrics.Sum("nydus_backend_read_total", `type="ondemand"`)) {
		t.FailNow()
	}

	assert.Positive(t, metrics.Sum("nydus_cache_read_total"))
	fstest.VerifyMount(t, mnt, src.want, src.compare())

	backRef := reg.Ref("optimize", "oci-back")
	nydusify(t, "convert", "--compressor", "oci-gzip", "--source", optRef, "--target", backRef)
	nydusify(t, "check", "--source", optRef, "--target", backRef)
	manifest, err = ref(backRef).image(t).Manifest()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Len(t, manifest.Layers, 1)
	fstest.VerifyMount(t, ref(backRef).extract(t), src.want, src.compare())
}

func traceLen(t testing.TB, raw []byte) int {
	t.Helper()
	var doc struct {
		Version  int               `json:"version"`
		Patterns []json.RawMessage `json:"patterns"`
	}

	if !assert.NoError(t, json.Unmarshal(raw, &doc)) {
		t.FailNow()
	}
	if !assert.Equal(t, 1, doc.Version) {
		t.FailNow()
	}

	return len(doc.Patterns)
}

func waitRedirectFill(t testing.TB, api *mount.API, want int) {
	t.Helper()
	if !assert.Eventually(t, func() bool {
		body, err := api.Get("/metrics")
		return err == nil && mount.ParseMetrics(string(body)).Sum("nydus_cache_write_total", `type="redirect"`) >= float64(want)
	}, time.Minute, 100*time.Millisecond) {
		t.FailNow()
	}
}
