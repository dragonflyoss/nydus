package uffd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRealFaultZerocopy resolves faults the zerocopy way: the service
// answers each with RANGE_RESPONSE fds, the client maps them over the VMA
// and wakes the fault, and the resumed read sees the device bytes.
func TestRealFaultZerocopy(t *testing.T) {
	t.Parallel()
	requireUserfaultfd(t)
	s := startService(t, standardImage(t))
	const faultSize = 64 << 10
	c := newFaultClient(t, s, 0, faultSize, 0)
	c.ack(t)
	want := deviceBytes(t, s.socket, 0, c.deviceSize)

	// Data: the EROFS metadata at the device head.
	ch := c.touchAsync(t, 0)
	require.NotEmpty(t, c.serveZerocopyFault(t))
	require.Equal(t, want[0], waitTouch(t, ch, faultDeadline, "zerocopy fault at device offset 0"))
	requireSameBytes(t, want[:faultSize], c.mem[:faultSize], "zerocopy-mapped head window")

	// Hole: the device tail maps as zero pages.
	tail := c.deviceSize - faultSize
	ch = c.touchAsync(t, tail)
	c.serveZerocopyFault(t)
	require.Zero(t, waitTouch(t, ch, faultDeadline, "zerocopy fault at the device tail"))
	requireSameBytes(t, want[tail:], c.mem[tail:], "zerocopy-mapped tail window")

	// The fixed mappings stay installed: re-reads need no round trip.
	requireSameBytes(t, want[:faultSize], c.mem[:faultSize], "warm re-read of the head window")
}
