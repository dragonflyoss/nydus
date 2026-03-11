package converter

import (
	"os"
	"path/filepath"
	"testing"

	accelconverter "github.com/goharbor/acceleration-service/pkg/converter"
	"github.com/stretchr/testify/require"
)

func TestGetConfig(t *testing.T) {
	opt := Opt{
		WorkDir:          "/work",
		NydusImagePath:   "/usr/bin/nydus-image",
		BackendType:      "registry",
		BackendConfig:    "{\"host\":\"registry\"}",
		BackendForcePush: true,
		ChunkDictRef:     "bootstrap:registry:example.com/repo:tag",
		Docker2OCI:       true,
		MergePlatform:    true,
		OCIRef:           true,
		WithReferrer:     true,
		PrefetchPatterns: "/etc\n/bin",
		Compressor:       "zstd",
		FsVersion:        "6",
		FsAlignChunk:     true,
		ChunkSize:        "0x100000",
		BatchSize:        "32",
		CacheRef:         "example.com/cache:latest",
		CacheVersion:     "v2",
		CacheMaxRecords:  42,
	}

	cfg := getConfig(opt)
	require.Equal(t, "/work", cfg["work_dir"])
	require.Equal(t, "/usr/bin/nydus-image", cfg["builder"])
	require.Equal(t, "registry", cfg["backend_type"])
	require.Equal(t, "{\"host\":\"registry\"}", cfg["backend_config"])
	require.Equal(t, "true", cfg["backend_force_push"])
	require.Equal(t, "bootstrap:registry:example.com/repo:tag", cfg["chunk_dict_ref"])
	require.Equal(t, "true", cfg["docker2oci"])
	require.Equal(t, "true", cfg["merge_manifest"])
	require.Equal(t, "true", cfg["oci_ref"])
	require.Equal(t, "true", cfg["with_referrer"])
	require.Equal(t, "/etc\n/bin", cfg["prefetch_patterns"])
	require.Equal(t, "zstd", cfg["compressor"])
	require.Equal(t, "6", cfg["fs_version"])
	require.Equal(t, "true", cfg["fs_align_chunk"])
	require.Equal(t, "0x100000", cfg["fs_chunk_size"])
	require.Equal(t, "32", cfg["batch_size"])
	require.Equal(t, "example.com/cache:latest", cfg["cache_ref"])
	require.Equal(t, "v2", cfg["cache_version"])
	require.Equal(t, "42", cfg["cache_max_records"])
}

func TestDumpMetric(t *testing.T) {
	metric := &accelconverter.Metric{}
	metricPath := filepath.Join(t.TempDir(), "metric.json")

	require.NoError(t, dumpMetric(metric, metricPath))

	content, err := os.ReadFile(metricPath)
	require.NoError(t, err)
	require.Contains(t, string(content), "\"SourceImageSize\":0")
	require.Contains(t, string(content), "\"TargetPushElapsed\":0")

	err = dumpMetric(metric, filepath.Join(metricPath, "missing", "metric.json"))
	require.ErrorContains(t, err, "Create file for metric")
}
