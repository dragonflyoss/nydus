package env

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Command is exec.Command bounded by the test's deadline, as golang/go's
// internal/testenv.Command is: under a deadline bin is killed two grace
// periods before it, which reserves one for Wait to give up on bin's output
// (WaitDelay) and one for the test to report the failure, instead of the
// test binary timing out.
func Command(t testing.TB, bin string, args ...string) *exec.Cmd {
	t.Helper()
	ctx := context.Background()

	gracePeriod := 100 * time.Millisecond
	if td, ok := t.(interface{ Deadline() (time.Time, bool) }); ok {
		if deadline, ok := td.Deadline(); ok {
			gracePeriod = max(gracePeriod, time.Until(deadline)/20)

			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, deadline.Add(-2*gracePeriod))
			t.Cleanup(cancel)
		}
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.WaitDelay = gracePeriod

	return cmd
}

// Run runs bin with Command and returns its combined output, failing the
// test with that output on a non-zero exit.
func Run(t testing.TB, bin string, args ...string) string {
	t.Helper()
	out, err := Command(t, bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", filepath.Base(bin), strings.Join(args, " "), err, out)
	}

	return string(out)
}
