package nydusify

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/registry"
	"github.com/stretchr/testify/require"
)

// TestOptimize runs the image-level optimize pipeline: record a workload on
// a mount of the converted image, `nydusify optimize --trace-file` it into an
// ondemand blob, and mount the optimized image with prefetch on a cold
// cache. Prefetch must land every traced chunk group in its source blob's
// cache through the ondemand blob alone, so replaying the workload reads
// nothing on demand. The optimized image still converts back to OCI.
func TestOptimize(t *testing.T) {
	t.Parallel()
	env.RequireRoot(t)

	// Four incompressible files, each spanning more than one 2MiB chunk.
	srcDir := filepath.Join(env.WorkDir(t), "src")
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "data"), 0o755))
	rng := rand.New(rand.NewSource(20261019))
	for i := 1; i <= 4; i++ {
		data := make([]byte, 2<<20+i*64<<10)
		_, _ = rng.Read(data)
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "data", fmt.Sprintf("file%d", i)), data, 0o644))
	}
	src := newSource(t, "optimize", srcDir)

	reg := registry.Start(t)
	srcRef := reg.Ref("optimize", "oci")
	nydusRef := reg.Ref("optimize", "nydus")
	optRef := reg.Ref("optimize", "optimized")
	reg.PushDirs(t, srcRef, src.dirs...)
	nydusify(t, "convert", "--source", srcRef, "--target", nydusRef)
	nydusify(t, "check", "--source", srcRef, "--target", nydusRef)

	// Two whole files and the head of a third, out of order.
	workload := func(mnt string) {
		for _, name := range []string{"file3", "file1", "file4"} {
			f, err := os.Open(filepath.Join(mnt, "data", name))
			require.NoError(t, err)
			var r io.Reader = f
			if name == "file1" {
				r = io.LimitReader(f, 100<<10)
			}
			_, err = io.Copy(io.Discard, r)
			require.NoError(t, f.Close())
			require.NoError(t, err, "read %s", name)
		}
	}

	baseline, mnt, api := startMount(t, nydusRef, false)
	workload(mnt)
	metrics := api.Metrics(t)
	require.Positive(t, metrics.Sum("nydus_backend_read_total", `type="ondemand"`), "the workload must read on demand")
	require.Zero(t, metrics.Sum("nydus_backend_read_total", `type="prefetch"`), "prefetch is off")
	require.Zero(t, metrics.Sum("nydus_cache_write_total", `type="prefetch"`), "prefetch is off")
	raw, err := api.Get("/trace")
	require.NoError(t, err)
	traced := traceLen(t, raw)
	require.Greater(t, traced, 1, "the trace must cover several chunk groups")
	baseline.Stop()

	record := filepath.Join(env.WorkDir(t), "trace.json")
	require.NoError(t, os.WriteFile(record, raw, 0o644))
	nydusify(t, "optimize", "--type", "ondemand", "--trace-file", record, "--source", nydusRef, "--target", optRef)

	opt := pullNydus(t, optRef, src.want)
	require.Len(t, opt.Blobs, 2, "the source blob and the ondemand blob")
	manifest, err := remoteImage(t, optRef).Manifest()
	require.NoError(t, err)
	require.Contains(t, manifest.Layers[1].Annotations, nydusOptimizedAnnotation, "the ondemand blob is marked")

	_, mnt, api = startMount(t, optRef, true)
	waitRedirectFill(t, api, traced)
	metrics = api.Metrics(t)
	require.Positive(t, metrics.Sum("nydus_backend_read_total", `type="prefetch"`), "prefetch must fetch the ondemand blob")
	require.EqualValues(t, traced, metrics.Sum("nydus_cache_write_total", `type="redirect"`),
		"prefetch must fill every traced chunk group into its source blob's cache")
	require.Zero(t, metrics.Sum("nydus_cache_write_failure_total"), "all redirected fills must succeed")
	require.Zero(t, metrics.Sum("nydus_cache_write_total", `type="prefetch"`), "the ondemand blob fills the source caches, never its own")
	require.Zero(t, metrics.Sum("nydus_backend_read_total", `type="ondemand"`), "prefetch must not read on demand")
	workload(mnt)
	metrics = api.Metrics(t)
	require.Zero(t, metrics.Sum("nydus_backend_read_total", `type="ondemand"`), "the traced workload must be served from the prefetched cache")
	require.Positive(t, metrics.Sum("nydus_cache_read_total"))
	oracle.VerifyMount(t, mnt, src.want, src.compare())

	// The ondemand blob only holds copies, so the reverse conversion skips it.
	backRef := reg.Ref("optimize", "oci-back")
	nydusify(t, "convert", "--compressor", "oci-gzip", "--source", optRef, "--target", backRef)
	nydusify(t, "check", "--source", optRef, "--target", backRef)
	manifest, err = remoteImage(t, backRef).Manifest()
	require.NoError(t, err)
	require.Len(t, manifest.Layers, 1, "one OCI layer per source layer")
	oracle.VerifyMount(t, extractOCI(t, backRef), src.want, src.compare())
}
