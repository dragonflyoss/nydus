package env

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// RepoRoot returns the nydus repository root: the closest ancestor of the
// working directory holding both Cargo.toml and tests/e2e/go.mod. Test
// binaries run in their package directory, which sits at varying depths.
func RepoRoot() (string, error) {
	return repoRoot()
}

var repoRoot = sync.OnceValues(func() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		_, cargo := os.Stat(filepath.Join(dir, "Cargo.toml"))
		_, module := os.Stat(filepath.Join(dir, "tests", "e2e", "go.mod"))
		if cargo == nil && module == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no nydus repository root above the working directory")
		}

		dir = parent
	}
})

// WorkDir returns a fresh per-test directory that, unlike t.TempDir, is
// traversable by other users: the permission cases drop to an unprivileged
// uid, and the daemons may run under a different one.
func WorkDir(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{dir, filepath.Dir(dir)} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatalf("chmod %s: %v", d, err)
		}
	}

	return dir
}
