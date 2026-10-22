// Package env locates the binaries under test and decides how a missing
// precondition is reported.
//
// Every e2e package resolves binaries, root, kernel features and external
// tools through this package, so CI can turn each missing precondition into a
// failure with a single switch (NYDUS_E2E_REQUIRE=1) instead of letting a test
// skip silently.
package env

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// TB is the subset of testing.TB the harness needs. *testing.T satisfies it,
// and so does the recorder KnownIssue hands its body, which lets every helper
// run inside a known-issue case as well as a normal one.
type TB interface {
	Helper()
	Name() string
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	FailNow()
	Failed() bool
	TempDir() string
	Cleanup(func())
}

// Strict reports whether a missing precondition fails the test rather than
// skipping it. CI sets NYDUS_E2E_REQUIRE=1.
func Strict() bool {
	return os.Getenv("NYDUS_E2E_REQUIRE") == "1"
}

// Require reports an unmet precondition: a failure in strict mode, a skip
// otherwise. It is the only sanctioned way for an e2e test to skip.
func Require(t TB, ok bool, format string, args ...any) {
	t.Helper()
	if ok {
		return
	}
	msg := "precondition: " + fmt.Sprintf(format, args...)
	// Only a real test can skip. Inside a known-issue body the miss is handed
	// back to KnownIssue, which reports it against the real test, so it is
	// never mistaken for the bug reproducing.
	if r, ok := t.(*recorder); ok {
		r.preconditionMiss(msg)
	}
	if tt, ok := t.(*testing.T); ok && !Strict() {
		tt.Skipf("%s", msg)
		return
	}
	t.Fatalf("%s (NYDUS_E2E_REQUIRE=1 turns missing preconditions into failures)", msg)
}

// RequireRoot requires the test binary to run as root, which every mount,
// device node and chown in the corpora needs.
func RequireRoot(t TB) {
	t.Helper()
	Require(t, os.Geteuid() == 0, "must run as root (make e2e runs the test binary through sudo)")
}

// RequireTool returns the absolute path of an external tool from PATH.
func RequireTool(t TB, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	Require(t, err == nil, "%s not found on PATH", name)
	return p
}

// KernelVersion returns the running kernel's major and minor version.
func KernelVersion() (major, minor int) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return 0, 0
	}
	release := string(bytes.TrimRight(uts.Release[:], "\x00"))
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ = strconv.Atoi(parts[0])
	minor, _ = strconv.Atoi(strings.TrimRightFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' }))
	return major, minor
}

// KernelAtLeast reports whether the running kernel is at least major.minor.
func KernelAtLeast(major, minor int) bool {
	gotMajor, gotMinor := KernelVersion()
	return gotMajor > major || (gotMajor == major && gotMinor >= minor)
}

// RequireKernel requires at least major.minor; why names the feature.
func RequireKernel(t TB, major, minor int, why string) {
	t.Helper()
	gotMajor, gotMinor := KernelVersion()
	Require(t, KernelAtLeast(major, minor), "kernel %d.%d < %d.%d: %s", gotMajor, gotMinor, major, minor, why)
}

// HasFilesystem reports whether the kernel lists fsType in /proc/filesystems,
// loading its module first when it is not built in.
func HasFilesystem(fsType string) bool {
	if listsFilesystem(fsType) {
		return true
	}
	_ = exec.Command("modprobe", fsType).Run()
	return listsFilesystem(fsType)
}

func listsFilesystem(fsType string) bool {
	data, err := os.ReadFile("/proc/filesystems")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[len(fields)-1] == fsType {
			return true
		}
	}
	return false
}

// RequireFilesystem requires kernel support for fsType.
func RequireFilesystem(t TB, fsType string) {
	t.Helper()
	Require(t, HasFilesystem(fsType), "kernel lacks %s support", fsType)
}

var (
	repoRootOnce sync.Once
	repoRoot     string
	repoRootErr  error
)

// RepoRoot returns the nydus repository root: the closest ancestor of the
// working directory holding both Cargo.toml and tests/e2e/go.mod. Test
// binaries run in their package directory, which sits at varying depths.
func RepoRoot() (string, error) {
	repoRootOnce.Do(func() {
		dir, err := os.Getwd()
		if err != nil {
			repoRootErr = err
			return
		}
		for {
			if fileExists(filepath.Join(dir, "Cargo.toml")) && fileExists(filepath.Join(dir, "tests", "e2e", "go.mod")) {
				repoRoot = dir
				return
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				repoRootErr = fmt.Errorf("no nydus repository root above the working directory")
				return
			}
			dir = parent
		}
	})
	return repoRoot, repoRootErr
}

// binEnv maps a binary name to the variable that overrides its location.
var binEnv = map[string]string{
	"nydus":    "NYDUS_BIN",
	"nydusify": "NYDUSIFY_BIN",
}

// LookupBin resolves a binary under test. An explicit NYDUS_BIN or
// NYDUSIFY_BIN wins; otherwise the newest in-tree build among target/ci,
// target/release and target/debug (or nydusify/nydusify) is used, so a stale
// profile never shadows a fresh one; PATH is the last resort.
func LookupBin(name string) (string, error) {
	if key, ok := binEnv[name]; ok {
		if p := os.Getenv(key); p != "" {
			if err := checkExecutable(p); err != nil {
				return "", fmt.Errorf("%s: %w", key, err)
			}
			return p, nil
		}
	}

	if root, err := RepoRoot(); err == nil {
		candidates := []string{
			filepath.Join(root, "target", "ci", name),
			filepath.Join(root, "target", "release", name),
			filepath.Join(root, "target", "debug", name),
			filepath.Join(root, "nydusify", name),
		}
		var newest string
		var newestMtime int64
		for _, p := range candidates {
			st, err := os.Stat(p)
			if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
				continue
			}
			if m := st.ModTime().UnixNano(); newest == "" || m > newestMtime {
				newest, newestMtime = p, m
			}
		}
		if newest != "" {
			return newest, nil
		}
	}

	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("%s not found in target/{ci,release,debug}, nydusify/ or on PATH", name)
}

// Bin resolves a binary under test and fails the test when it is missing:
// the binary under test is never an optional precondition.
func Bin(t TB, name string) string {
	t.Helper()
	p, err := LookupBin(name)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return p
}

// Nydus is Bin(t, "nydus").
func Nydus(t TB) string {
	t.Helper()
	return Bin(t, "nydus")
}

// Nydusify is Bin(t, "nydusify").
func Nydusify(t TB) string {
	t.Helper()
	return Bin(t, "nydusify")
}

// WorkDir returns a fresh per-test directory that, unlike t.TempDir, is
// traversable by other users: the permission cases drop to an unprivileged
// uid, and the daemons may run under a different one.
func WorkDir(t TB) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{dir, filepath.Dir(dir)} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatalf("chmod %s: %v", d, err)
		}
	}
	return dir
}

// CacheRoot is the directory shared fixtures (corpora, built images) are
// cached under across test binaries: NYDUS_E2E_CACHE, or .test-tmp/e2e-cache
// in the repository.
func CacheRoot() (string, error) {
	if dir := os.Getenv("NYDUS_E2E_CACHE"); dir != "" {
		return dir, os.MkdirAll(dir, 0o755)
	}
	root, err := RepoRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, ".test-tmp", "e2e-cache")
	return dir, os.MkdirAll(dir, 0o755)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func checkExecutable(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("%s is a directory", path)
	}
	if st.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", path)
	}
	return nil
}
