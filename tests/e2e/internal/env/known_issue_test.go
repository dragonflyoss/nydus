package env

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestKnownIssue(t *testing.T) {
	t.Parallel()
	if scenario := os.Getenv("NYDUS_TEST_KNOWN_ISSUE_SCENARIO"); scenario != "" {
		KnownIssue(t, "KI-TEST", func(t TB) {
			if scenario == "bug" {
				t.Errorf("incorrect product behavior")
			}
		})
		return
	}
	bin, err := os.Executable()
	require.NoError(t, err)
	for _, tc := range []struct {
		name, strict, scenario string
		fails, skips           bool
	}{
		{"LocalBug", "0", "bug", false, true},
		{"LocalFixed", "0", "fixed", true, false},
		{"CIBug", "1", "bug", true, false},
		{"CIFixed", "1", "fixed", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "-test.run=^TestKnownIssue$", "-test.v")
			cmd.Env = append(os.Environ(), "NYDUS_TEST_FAIL_KNOWN_ISSUES="+tc.strict,
				"NYDUS_TEST_KNOWN_ISSUE_SCENARIO="+tc.scenario)
			out, err := cmd.CombinedOutput()
			require.NoError(t, ctx.Err(), "%s", out)
			if tc.fails {
				var exit *exec.ExitError
				require.ErrorAs(t, err, &exit, "%s", out)
				require.Equal(t, 1, exit.ExitCode(), "%s", out)
			} else {
				require.NoError(t, err, "%s", out)
			}
			if tc.skips {
				require.Contains(t, string(out), "--- SKIP:")
			} else {
				require.NotContains(t, string(out), "--- SKIP:")
			}
		})
	}
}
