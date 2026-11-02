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
	dir := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(root, "tests/scripts/e2e_coverage.sh"), "export")
	cmd.Env = append(os.Environ(), "COVERAGE_DIR="+dir)
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "executed tests without profiles must not pass")
	require.Contains(t, string(out), "no Rust profiles")
	require.NoFileExists(t, filepath.Join(dir, "rust-e2e.lcov"))
	require.NoFileExists(t, filepath.Join(dir, "go-e2e.out"))
}
