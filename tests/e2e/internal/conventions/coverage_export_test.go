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
	t.Run("CommentReports", func(t *testing.T) {
		cmd := exec.Command("python3", filepath.Join(root, "tests/scripts/coverage_comment_test.py"))
		cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", out)
	})
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
	t.Run("MergeGo", func(t *testing.T) {
		dir := t.TempDir()
		unit, product := filepath.Join(dir, "unit.out"), filepath.Join(dir, "product.out")
		require.NoError(t, os.WriteFile(unit, []byte("mode: atomic\npkg/main.go:1.1,2.2 3 0\npkg/main.go:3.1,4.2 2 4\n"), 0o600))
		require.NoError(t, os.WriteFile(product, []byte("mode: set\npkg/main.go:1.1,2.2 3 1\npkg/main.go:3.1,4.2 2 0\n"), 0o600))
		run := func() ([]byte, error) {
			cmd := exec.Command("bash", filepath.Join(root, "tests/scripts/e2e_coverage.sh"), "merge-go", unit, product)
			cmd.Env = append(os.Environ(), "COVERAGE_DIR="+dir)
			return cmd.CombinedOutput()
		}
		out, err := run()
		require.NoError(t, err, "%s", out)
		require.Contains(t, string(out), "5/5 statements (100.00%)")
		merged, err := os.ReadFile(filepath.Join(dir, "go-combined.out"))
		require.NoError(t, err)
		require.Equal(t, "mode: set\npkg/main.go:1.1,2.2 3 1\npkg/main.go:3.1,4.2 2 1\n", string(merged))

		require.NoError(t, os.WriteFile(product, []byte("mode: set\npkg/main.go:1.1,2.2 4 1\n"), 0o600))
		out, err = run()
		require.Error(t, err)
		require.Contains(t, string(out), "incompatible statement counts")

		require.NoError(t, os.WriteFile(product, []byte("mode: set\npkg/main.go:1.1,3.2 3 1\n"), 0o600))
		out, err = run()
		require.Error(t, err)
		require.Contains(t, string(out), "incompatible source blocks")
	})
}
