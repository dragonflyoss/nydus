package uffd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRealFaultZeropage faults in the /dev/zero hole at the device tail:
// the service completes it as a zero page.
func TestRealFaultZeropage(t *testing.T) {
	t.Parallel()
	requireUserfaultfd(t)
	s := startService(t, standardImage(t))
	c := newFaultClient(t, s, handshakeCopy, blockSize, 0)
	c.ack(t)

	// The flattened data is aligned up to the device size, so the last
	// range must be a /dev/zero hole reaching the device end.
	ranges, fds := fetch(t, s.socket, 0, c.deviceSize)
	defer closeFds(fds)
	require.NotEmpty(t, ranges)
	last := ranges[len(ranges)-1]
	require.True(t, isZeroDevice(t, fds[len(fds)-1]), "the image has no /dev/zero tail hole")
	require.Equal(t, c.deviceSize, last.deviceOffset+last.length, "tail hole does not reach the device end")
	target := c.deviceSize - uint64(c.blockSize)
	require.GreaterOrEqual(t, target, last.deviceOffset, "tail block outside the zero hole")

	b := waitTouch(t, c.touchAsync(t, target), faultDeadline, "zero-page fault at the device tail")
	require.Zero(t, b, "zero hole faulted in non-zero")
	require.Equal(t, make([]byte, c.blockSize), c.mem[target:target+uint64(c.blockSize)], "tail block not zero after the fault")
}
