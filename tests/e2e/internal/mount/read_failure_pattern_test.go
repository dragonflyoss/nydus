package mount

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestReadFailurePattern pins the shared transport health oracle.
func TestReadFailurePattern(t *testing.T) {
	t.Parallel()
	log := strings.Join([]string{
		"INFO nbd service attached to /dev/nbd0",
		"WARN nbd: failed to read request header: unexpected EOF",
		"WARN nbd: failed to handle request: broken pipe",
		"WARN nbd: read length 33554432 exceeds cap 16777216, rejecting",
		"WARN nbd: read [0x0, +4096) failed: input/output error",
	}, "\n")
	require.Len(t, transportFailure.FindAllString(log, -1), 2)
	require.False(t, transportFailure.MatchString("nbd: failed to read request header: unexpected EOF"))
	require.False(t, transportFailure.MatchString("nbd: failed to handle request: broken pipe"))
	for _, line := range []string{
		"nbd: invalid request magic",
		"nbd: unsupported request type",
		"fanotify: immediate deny",
		"unknown event fd",
		"InvalidRange",
		"fanotify: fstat event fd failed",
		"fanotify: ready-range lookup failed",
		"fanotify: denying and skipping unusable event",
		"fanotify fetch backend failure",
		"fanotify fetch worker panicked",
	} {
		require.True(t, transportFailure.MatchString(line), "%s", line)
	}
}
