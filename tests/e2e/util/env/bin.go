package env

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Nydus returns the nydus binary under test.
func Nydus(t testing.TB) string {
	t.Helper()
	return bin(t, "nydus", "NYDUS_BIN")
}

// Nydusify returns the nydusify binary under test.
func Nydusify(t testing.TB) string {
	t.Helper()
	return bin(t, "nydusify", "NYDUSIFY_BIN")
}

// Snapshotter returns the nydus-snapshotter binary under test.
func Snapshotter(t testing.TB) string {
	t.Helper()
	return bin(t, "nydus-snapshotter", "NYDUS_SNAPSHOTTER_BIN")
}

// Writer returns the nydus-core writer-fixture example.
func Writer(t testing.TB) string {
	t.Helper()
	return bin(t, "examples/writer-fixture", "NYDUS_WRITER_BIN")
}

// bin resolves a binary under test and fails the test when it is missing: the
// binary under test is never an optional precondition. An explicit key wins;
// otherwise the newest in-tree build among target/ci, target/release and
// target/debug (or nydusify/, nydus-snapshotter/bin/) is used, so a stale
// profile never shadows a fresh one; PATH is the last resort.
func bin(t testing.TB, name, key string) string {
	t.Helper()
	if p := os.Getenv(key); p != "" {
		if st, err := os.Stat(p); !isExecutable(st, err) {
			t.Fatalf("%s=%s is not an executable file", key, p)
		}

		return p
	}

	if root, err := RepoRoot(); err == nil {
		var newest string
		var newestMtime time.Time

		for _, dir := range []string{"target/ci", "target/release", "target/debug", "nydusify", "nydus-snapshotter/bin"} {
			p := filepath.Join(root, dir, name)
			st, err := os.Stat(p)
			if !isExecutable(st, err) {
				continue
			}

			if newest == "" || st.ModTime().After(newestMtime) {
				newest, newestMtime = p, st.ModTime()
			}
		}

		if newest != "" {
			return newest
		}
	}

	p, err := exec.LookPath(name)
	if err != nil {
		t.Fatalf("%s not found in target/{ci,release,debug}, nydusify/, nydus-snapshotter/bin/ or on PATH", name)
	}

	return p
}

// isExecutable reports whether the stat of a path found an executable
// file.
func isExecutable(st os.FileInfo, err error) bool {
	return err == nil && !st.IsDir() && st.Mode()&0o111 != 0
}

var subcommands sync.Map

// HasSubcommand reports whether the nydus binary was built with the feature
// that provides the subcommand. The probe is cached per process.
func HasSubcommand(t testing.TB, name string) bool {
	t.Helper()
	ok, cached := subcommands.Load(name)
	if !cached {
		ok = exec.Command(Nydus(t), name, "--help").Run() == nil
		subcommands.Store(name, ok)
	}

	return ok.(bool)
}

// MustHaveSubcommand skips t unless the nydus binary was built with the
// feature that provides the subcommand.
func MustHaveSubcommand(t testing.TB, name string) {
	t.Helper()
	if !HasSubcommand(t, name) {
		Skipf(t, "%s lacks the %s subcommand (build with FEATURES=...,%s)", Nydus(t), name, name)
	}
}
