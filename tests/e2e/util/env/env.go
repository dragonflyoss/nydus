// Package env describes the environment the e2e tests run in, as the Go
// tree's internal/testenv does: the binaries under test, root, kernel
// features, external tools, working directories and NYDUS_E2E_* knobs, and
// how a missing precondition is reported.
//
// Every e2e package resolves binaries, root, kernel features and external
// tools through this package, so CI (the CI environment variable every CI
// system sets) turns each missing precondition into a failure instead of
// letting a test skip silently.
package env

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// Strict reports whether a missing precondition fails the test rather than
// skipping it: under CI it does.
func Strict() bool {
	return os.Getenv("CI") != ""
}

// Require reports an unmet precondition: a failure in strict mode, a skip
// otherwise. It is the only sanctioned way for an e2e test to skip.
func Require(t testing.TB, ok bool, format string, args ...any) {
	t.Helper()
	if ok {
		return
	}

	msg := "precondition: " + fmt.Sprintf(format, args...)

	if !Strict() {
		t.Skip(msg)
	}

	t.Fatalf("%s (CI turns missing preconditions into failures)", msg)
}

// RequireRoot requires the test binary to run as root, which every mount,
// device node and chown in the corpora needs.
func RequireRoot(t testing.TB) {
	t.Helper()
	Require(t, os.Geteuid() == 0, "must run as root (make e2e runs the test binary through sudo)")
}

// RequireTool returns the absolute path of an external tool from PATH.
func RequireTool(t testing.TB, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	Require(t, err == nil, "%s not found on PATH", name)

	return p
}
