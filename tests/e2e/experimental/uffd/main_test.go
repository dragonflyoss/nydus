package uffd

import (
	"os"
	"testing"
)

// TestMain intercepts the re-exec of this binary as the outstanding-fault
// child of TestLifecycle before any test runs.
func TestMain(m *testing.M) {
	if os.Getenv(childModeEnv) == childModeOutstandingFault {
		os.Exit(runOutstandingFaultChild())
	}
	os.Exit(m.Run())
}
