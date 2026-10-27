package uffd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPrefaultAndBatching covers the HANDSHAKE prefault and multi-frame
// RANGE_RESPONSEs: on a warm 20-blob image the prefault answer spans more
// ranges than one frame carries, and mapping it yields the whole device
// with no further fault.
func TestPrefaultAndBatching(t *testing.T) {
	t.Parallel()
	requireUserfaultfd(t)
	s := startService(t, layeredImage(t, 20))

	// Warm the cache, so the prefault probe resolves every blob range, and
	// keep the bytes as the reference.
	want := deviceBytes(t, s.socket, 0, s.deviceSize(t))

	c := newFaultClient(t, s, handshakePrefault, 2<<20, 0)
	ranges, fds, frames := c.readRanges(t, caseDeadline)
	defer closeFds(fds)
	require.Greater(t, len(ranges), maxRangesPerMsg, "the image yields no more ranges than one frame carries")
	require.GreaterOrEqual(t, frames, 2, "prefault answer not split over frames")
	c.mapRanges(t, ranges, fds, false)
	c.ack(t)

	// Every page is mapped, so the snapshot deadline catches any page the
	// prefault missed.
	requireSameBytes(t, want, c.snapshot(t, "read of the prefault-mapped device"), "prefault-mapped memory")
}
