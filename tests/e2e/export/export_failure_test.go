package export

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/stretchr/testify/require"
)

func TestExportFailure(t *testing.T) {
	t.Parallel()
	img := fixture.Get(t, "zstd-4k")
	digest := fileSHA256(t, img.Blob())
	for _, scenario := range []string{"BrokenPipe", "NoSpace", "CorruptSource", "Cancellation"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			source := img.Blob()
			if scenario == "CorruptSource" {
				source = filepath.Join(t.TempDir(), "bad.blob")
				require.NoError(t, os.WriteFile(source, []byte("truncated"), 0o600))
			}
			args := []string{"export", source}
			if scenario == "NoSpace" {
				args = append(args, "--output", "/dev/full")
			}
			cmd := exec.CommandContext(ctx, env.Nydus(t), args...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if scenario == "BrokenPipe" || scenario == "Cancellation" {
				r, w, err := os.Pipe()
				require.NoError(t, err)
				defer func() { _ = r.Close() }()
				defer func() { _ = w.Close() }()
				cmd.Stdout = w
				require.NoError(t, cmd.Start())
				require.NoError(t, w.Close())
				head := make([]byte, 512)
				_, err = io.ReadFull(r, head)
				require.NoError(t, err, "export must start before interruption")
				if scenario == "Cancellation" {
					cancel()
				} else {
					require.NoError(t, r.Close())
				}
			} else {
				cmd.Stdout = io.Discard
				require.NoError(t, cmd.Start())
			}
			err := cmd.Wait()
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit, "%s", stderr.String())
			require.NotEqual(t, 101, exit.ExitCode(), "Rust panic: %s", stderr.String())
			if scenario != "Cancellation" {
				require.NoError(t, ctx.Err(), "export hung: %s", stderr.String())
				require.NotEmpty(t, stderr.String(), "failure must be diagnosed")
			}
			require.Equal(t, digest, fileSHA256(t, img.Blob()))
		})
	}
}
