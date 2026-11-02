package conventions

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
)

func TestCoverageExport(t *testing.T) {
	t.Parallel()
	root, err := env.RepoRoot()
	require.NoError(t, err)
	for _, outcome := range []string{"success", "failure", "skipped", "cancelled"} {
		t.Run(outcome, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command("bash", filepath.Join(root, "tests/scripts/e2e_coverage.sh"), "export")
			cmd.Env = append(os.Environ(), "COVERAGE_DIR="+dir, "COVERAGE_TEST_OUTCOME="+outcome)
			out, err := cmd.CombinedOutput()
			if outcome == "skipped" || outcome == "cancelled" {
				require.NoError(t, err, "%s", out)
			} else {
				require.Error(t, err, "executed tests without profiles must not pass")
				require.Contains(t, string(out), "no Rust profiles")
			}
			status, err := os.ReadFile(filepath.Join(dir, "status.txt"))
			require.NoError(t, err)
			require.Contains(t, string(status), "test_outcome="+outcome)
			require.Contains(t, string(status), "rust_raw_files=0")
			require.Contains(t, string(status), "missing_profile_is_not_zero_coverage=true")
			require.NoFileExists(t, filepath.Join(dir, "rust-e2e.lcov"))
			require.NoFileExists(t, filepath.Join(dir, "go-e2e.out"))
		})
	}
}
