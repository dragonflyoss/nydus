package util

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// erofsFuseEnv names the environment variable that points at the C erofsfuse
// binary used as the reference reader.
const erofsFuseEnv = "EROFS_C_FUSE"

// LookupExecutable returns the path of the executable name, preferring the
// in-tree build under target/{release,debug}/ (and nydusify/ for the Go
// binary) over PATH so the tests always exercise the freshly built binaries.
func LookupExecutable(name string) (string, error) {
	// Locate the repository root from this source file rather than the
	// working directory, which differs between the e2e package and its
	// subpackages.
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("cannot locate the repository root")
	}

	root := filepath.Join(filepath.Dir(file), "..", "..", "..")
	for _, dir := range []string{
		filepath.Join(root, "target", "release"),
		filepath.Join(root, "target", "debug"),
		filepath.Join(root, "nydusify"),
	} {
		if p := filepath.Join(dir, name); isExecutable(p) {
			return p, nil
		}
	}

	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not found in target/{release,debug}/ or on PATH", name)
	}

	return p, nil
}

// LookupExecutableFromEnv returns the executable named by the environment
// variable env when it is set, and LookupExecutable of name otherwise.
func LookupExecutableFromEnv(env, name string) (string, error) {
	p := os.Getenv(env)
	if p == "" {
		return LookupExecutable(name)
	}

	if !isExecutable(p) {
		return "", fmt.Errorf("%s=%s is not an executable file", env, p)
	}

	return p, nil
}

// LookupErofsFuse returns the path of the C erofsfuse binary from
// EROFS_C_FUSE, the common install locations or PATH.
func LookupErofsFuse() (string, error) {
	if p := os.Getenv(erofsFuseEnv); p != "" {
		if !isExecutable(p) {
			return "", fmt.Errorf("%s=%s is not an executable file", erofsFuseEnv, p)
		}

		return p, nil
	}

	for _, p := range []string{"/usr/bin/erofsfuse", "/usr/local/bin/erofsfuse"} {
		if isExecutable(p) {
			return p, nil
		}
	}

	if p, err := exec.LookPath("erofsfuse"); err == nil {
		return p, nil
	}

	return "", fmt.Errorf("erofsfuse not found, set %s=path to enable comparison", erofsFuseEnv)
}

// isExecutable reports whether path is a regular file with an execute bit.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Mode()&0o111 != 0
}

// SkipUnlessRoot skips the test when it is not running as root, naming what
// needs root in the skip message.
func SkipUnlessRoot(t *testing.T, reason string) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skipf("requires root: %s", reason)
	}
}

// SkipUnlessSubcommand skips the test when the nydus binary was built
// without subcommand, naming the cargo features that add it.
func SkipUnlessSubcommand(t *testing.T, nydusBin, subcommand, features string) {
	t.Helper()
	if out, err := exec.Command(nydusBin, subcommand, "--help").CombinedOutput(); err != nil {
		t.Skipf("nydus binary lacks the %s subcommand; build with --features %s: %s", subcommand, features, out)
	}
}
