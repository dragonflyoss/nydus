package build

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/stretchr/testify/require"
)

func TestOptimizeReject(t *testing.T) {
	t.Parallel()
	base := fixture.Get(t, "zstd-4k")
	for _, tc := range []struct{ name, trace string }{
		{"Malformed", `{"version":`},
		{"Version", `{"version":999,"patterns":[]}`},
		{"Empty", `{"version":1,"patterns":[]}`},
		{"UnknownBlob", `{"version":1,"patterns":[{"blob_index":65535,"chunk_group_index":0}]}`},
		{"UnknownGroup", `{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":4294967295}]}`},
		{"IndexOverflow", `{"version":1,"patterns":[{"blob_index":65536,"chunk_group_index":0}]}`},
		{"OutputFailure", `{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":0}]}`},
		{"MixedCompressors", `{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":0},{"blob_index":2,"chunk_group_index":0}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			img := base
			if tc.name == "MixedCompressors" {
				img.Bootstrap, img.BlobDir = filepath.Join(dir, "parent.boot"), filepath.Join(dir, "sources")
				require.NoError(t, os.Mkdir(img.BlobDir, 0o755))
				var blobs []string
				for _, layout := range []string{"lz4-64k", "zstd-4k"} {
					blob := fixture.Get(t, layout).Blob()
					require.NoError(t, os.Symlink(blob, filepath.Join(img.BlobDir, filepath.Base(blob))))
					blobs = append(blobs, blob)
				}
				fixture.Run(t, env.Nydus(t), append([]string{"merge", "--bootstrap", img.Bootstrap}, blobs...)...)
			}
			parent := fileSHA256(t, img.Bootstrap)
			trace := filepath.Join(dir, "trace.json")
			require.NoError(t, os.WriteFile(trace, []byte(tc.trace), 0o600))
			output := filepath.Join(dir, "optimized.boot")
			if tc.name == "OutputFailure" {
				require.NoError(t, os.Mkdir(output, 0o755))
			}
			config := mount.LocalConfig(img.BlobDir, filepath.Join(dir, "cache")).Write(t, dir, "config.json")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, env.Nydus(t), "optimize",
				"--parent-bootstrap", img.Bootstrap, "--bootstrap", output, "--blob-dir", filepath.Join(dir, "blobs"),
				"--config", config, "--trace-file", trace).CombinedOutput()
			require.NoError(t, ctx.Err(), "optimize hung: %s", out)
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit, "%s", out)
			require.Positive(t, exit.ExitCode())
			require.NotEqual(t, 101, exit.ExitCode(), "Rust panic: %s", out)
			require.Contains(t, string(out), "error")
			if tc.name == "MixedCompressors" {
				require.Contains(t, string(out), "the other source blobs")
			}
			require.Equal(t, parent, fileSHA256(t, img.Bootstrap), "failed optimize changed parent")
			if tc.name != "OutputFailure" {
				require.NoFileExists(t, output)
			}
		})
	}
}
