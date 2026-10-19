package e2e

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// TestNydusifyOptimize exercises the full image-level optimize pipeline
// against a local registry:
//
//  1. docker build/push a source OCI image, convert it with `nydusify
//     convert`, and validate it with `nydusify check`.
//  2. Mount the nydus image WITHOUT prefetch, replay a read workload, and
//     verify the baseline metrics show on-demand backend reads. Save the
//     recorded /trace pattern to a file and run `nydusify optimize
//     --pattern` to repack the traced chunks into the ondemand blob and push
//     the optimized image.
//  3. Mount the optimized image WITH prefetch on a cold cache, wait for
//     prefetch to quiesce, replay the same workload, and verify:
//     - the ondemand blob was fetched (nydus_prefetch_redirect_blob_total > 0),
//     - every traced chunk group was filled into its source blob's cache through
//     the redirect path (nydus_fill_chunk_group_from_redirect_blob_total == trace
//     size, no skips),
//     - the workload triggered zero on-demand backend reads
//     (nydus_read_backend_total{type="ondemand"} == 0), proving the
//     optimization works,
//     - file contents are byte-identical to the corpus.
func TestNydusifyOptimize(t *testing.T) {
	util.SkipUnlessRoot(t, "mounting FUSE")
	util.SkipUnlessDocker(t)
	registry := util.SkipUnlessRegistry(t)

	assert := assert.New(t)

	// Corpus: four ~2.06-2.25 MiB pseudo-random files so each spans more than
	// one 2 MiB chunk and the trace covers multiple chunks.
	workDir := t.TempDir()
	corpusDir := filepath.Join(workDir, "corpus")
	assert.NoError(os.MkdirAll(corpusDir, 0o755))
	corpusFiles := []string{"file1", "file2", "file3", "file4"}
	for i, name := range corpusFiles {
		size := 2<<20 + (i+1)*64*1024
		assert.NoError(os.WriteFile(filepath.Join(corpusDir, name), util.RandomBytes(size, int64(i+1)), 0o644))
	}

	sourceRef := fmt.Sprintf("%s/nydus-e2e/optimize-src:%d", registry, time.Now().UnixNano())
	nydusRef := sourceRef + "-nydus"
	optimizedRef := nydusRef + "-optimized"

	t.Log("Building and pushing source OCI image...")
	util.DockerBuildAndPush(t, corpusDir, sourceRef, "FROM scratch\nCOPY . /data\n")

	t.Log("Converting to nydus format...")
	util.RunNydusify(t, nydusifyBin, nydusBin, "convert", "--source", sourceRef, "--target", nydusRef,
		"--work-dir", filepath.Join(workDir, "convert"))

	t.Log("Checking converted image...")
	util.RunNydusify(t, nydusifyBin, nydusBin, "check", "--source", sourceRef, "--target", nydusRef,
		"--work-dir", filepath.Join(workDir, "check"))

	// The read workload replayed on both mounts: two full files plus a
	// partial head read, in a deliberate non-sequential order.
	workload := func(mountpoint string) {
		_, err := os.ReadFile(filepath.Join(mountpoint, "data", "file3"))
		assert.NoError(err)

		head := make([]byte, 100*1024)
		f, err := os.Open(filepath.Join(mountpoint, "data", "file1"))
		if !assert.NoError(err) {
			return
		}
		_, err = io.ReadFull(f, head)
		assert.NoError(f.Close())
		assert.NoError(err)

		_, err = os.ReadFile(filepath.Join(mountpoint, "data", "file4"))
		assert.NoError(err)
	}

	t.Log("Mounting baseline (no prefetch) and tracing the workload...")
	baselineWorkDir := filepath.Join(workDir, "mount-baseline")
	baselineMountpoint := filepath.Join(workDir, "mnt-baseline")
	var traceCount int
	func() {
		unmount := util.MountNydusify(t, nydusifyBin, nydusBin, nydusRef, baselineMountpoint, baselineWorkDir, false)
		defer unmount()
		workload(baselineMountpoint)

		// The baseline must read on demand and never prefetch.
		socket := filepath.Join(baselineWorkDir, "apiserver.sock")
		metrics := util.FetchMetrics(t, socket)
		assert.Greater(util.SumMetric(metrics, "nydus_read_backend_total", `type="ondemand"`), 0.0,
			"baseline workload must trigger on-demand backend reads")
		assert.Zero(util.SumMetric(metrics, "nydus_prefetch_redirect_blob_total"))
		assert.Zero(util.SumMetric(metrics, "nydus_fill_chunk_group_from_redirect_blob_total"))
		assert.Zero(util.SumMetric(metrics, "nydus_read_chunk_group_total", `type="prefetch"`, `storage="backend"`),
			"baseline mount must not prefetch")

		traceCount = util.SaveTrace(t, socket, filepath.Join(workDir, "pattern.json"))
		assert.Greater(traceCount, 1, "trace must cover multiple groups")
		t.Logf("baseline: ondemand_reads=%v trace_chunk_groups=%d",
			util.SumMetric(metrics, "nydus_read_backend_total", `type="ondemand"`), traceCount)

		t.Log("Optimizing with the saved trace pattern...")
		util.RunNydusify(t, nydusifyBin, nydusBin, "optimize",
			"--pattern", filepath.Join(workDir, "pattern.json"),
			"--source", nydusRef,
			"--target", optimizedRef,
			"--work-dir", filepath.Join(workDir, "optimize"))
	}()

	t.Log("Mounting optimized image (prefetch, cold cache) and replaying the workload...")
	optimizedWorkDir := filepath.Join(workDir, "mount-optimized")
	optimizedMountpoint := filepath.Join(workDir, "mnt-optimized")
	func() {
		unmount := util.MountNydusify(t, nydusifyBin, nydusBin, optimizedRef, optimizedMountpoint, optimizedWorkDir, true)
		defer unmount()

		// Prefetch must pull the ondemand blob and fill every traced group
		// through the redirect path without an on-demand read.
		socket := filepath.Join(optimizedWorkDir, "apiserver.sock")
		util.WaitMetricSettled(t, socket, "nydus_read_backend_total", `type="prefetch"`)
		metrics := util.FetchMetrics(t, socket)
		assert.Greater(util.SumMetric(metrics, "nydus_prefetch_redirect_blob_total"), 0.0,
			"prefetch must fetch the ondemand (redirect) blob from the backend")
		assert.Equal(float64(traceCount), util.SumMetric(metrics, "nydus_fill_chunk_group_from_redirect_blob_total"),
			"every traced group must be filled into its source cache via redirect")
		assert.Zero(util.SumMetric(metrics, "nydus_fill_chunk_group_from_redirect_blob_failure_total"),
			"no redirect chunk group may be skipped on a cold cache")
		assert.Zero(util.SumMetric(metrics, "nydus_read_backend_total", `type="ondemand"`),
			"prefetch warmup must not issue on-demand reads")
		t.Logf("optimized after prefetch: redirect_reads=%v redirect_fills=%v regular_fills=%v",
			util.SumMetric(metrics, "nydus_prefetch_redirect_blob_total"),
			util.SumMetric(metrics, "nydus_fill_chunk_group_from_redirect_blob_total"),
			util.SumMetric(metrics, "nydus_read_chunk_group_total", `type="prefetch"`, `storage="backend"`))

		// The traced workload is then served entirely from the warmed cache.
		workload(optimizedMountpoint)
		metrics = util.FetchMetrics(t, socket)
		assert.Zero(util.SumMetric(metrics, "nydus_read_backend_total", `type="ondemand"`),
			"the traced workload must be served entirely from the warmed cache")
		assert.Greater(util.SumMetric(metrics, "nydus_read_chunk_group_total", `storage="local"`), 0.0)

		// Full content verification against the corpus.
		for _, name := range corpusFiles {
			want, err := os.ReadFile(filepath.Join(corpusDir, name))
			assert.NoError(err)
			got, err := os.ReadFile(filepath.Join(optimizedMountpoint, "data", name))
			assert.NoError(err)
			assert.True(bytes.Equal(want, got), "content mismatch for %s", name)
		}
	}()

	// The ondemand blob holds copies of the other blobs' chunk groups and no
	// filesystem tree, so the reverse conversion must skip it and still
	// reproduce the original layers.
	t.Log("Converting the optimized image back to OCI...")
	ociRef := optimizedRef + "-oci"
	util.RunNydusify(t, nydusifyBin, nydusBin, "convert",
		"--compressor", "oci-gzip",
		"--source", optimizedRef, "--target", ociRef,
		"--work-dir", filepath.Join(workDir, "tooci"))
	util.RunNydusify(t, nydusifyBin, nydusBin, "check",
		"--source", optimizedRef, "--target", ociRef,
		"--work-dir", filepath.Join(workDir, "check-tooci"))
}
