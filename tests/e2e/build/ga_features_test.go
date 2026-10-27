package build

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
)

// TestGAFeatures guards the supported product binary, not arbitrary Cargo
// feature subsets. Registry and Dragonfly support are exercised by their E2E.
func TestGAFeatures(t *testing.T) {
	t.Parallel()
	bin := env.Nydus(t)
	for _, command := range []string{"build", "check", "export", "merge", "optimize", "fuse", "fileio"} {
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, bin, command, "--help").CombinedOutput()
			require.NoError(t, ctx.Err(), "%s", out)
			require.NoError(t, err, "%s", out)
			require.Contains(t, string(out), "Usage:")
		})
	}
}
