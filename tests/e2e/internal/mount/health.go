package mount

import (
	"regexp"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
)

// Normal NBD disconnect warnings are deliberately excluded.
var transportFailure = regexp.MustCompile(`nbd: (invalid request magic|read .* failed:|read length .* exceeds cap|unsupported request type)|fanotify: (immediate deny|fstat event fd failed|ready-range lookup failed|denying and skipping unusable event)|unknown event fd|InvalidRange|fanotify fetch (backend failure|worker panicked)`)

// RequireHealthy rejects protocol errors, failed reads and denied fanotify events.
func RequireHealthy(t env.TB, d *Daemon) {
	t.Helper()
	require.Empty(t, transportFailure.FindAllString(d.Log(), -1), "daemon transport errors")
}
