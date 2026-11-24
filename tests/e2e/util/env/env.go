// Package env reports the environment the e2e tests run in, in the manner of
// golang/go's internal/testenv.
package env

import (
	"os"
	"testing"
)

// CI reports whether the tests run under CI, where a missing precondition
// fails the test instead of skipping it.
func CI() bool {
	return os.Getenv("CI") != ""
}

// Skipf skips t with the formatted reason, or fails it under CI.
func Skipf(t testing.TB, format string, args ...any) {
	t.Helper()
	if CI() {
		t.Fatalf(format, args...)
	}

	t.Skipf(format, args...)
}

// MustHaveRoot skips t unless it runs as root.
func MustHaveRoot(t testing.TB) {
	t.Helper()
	if os.Geteuid() != 0 {
		Skipf(t, "must run as root")
	}
}
