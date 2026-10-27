package uffd

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// TestServiceSmoke drives the stateless requests on one session, without a
// userfaultfd: STAT reports the geometry, FETCH of the first block returns
// an fd exposing the EROFS superblock, and PROBE returns one fd per range.
func TestServiceSmoke(t *testing.T) {
	t.Parallel()
	s := startService(t, standardImage(t))
	conn := dial(t, s.socket)
	defer func() { require.NoError(t, conn.Close()) }()

	deviceSize, block := stat(t, conn)
	require.Positive(t, deviceSize)
	require.Equal(t, uint32(blockSize), block)

	send(t, conn, msgFetch, encodeRange(0, uint64(block)))
	ranges, fds, _ := readRangeResponse(t, conn)
	defer closeFds(fds)
	require.NotEmpty(t, ranges)
	require.Equal(t, deviceRange{deviceOffset: 0, fileOffset: 0, length: uint64(block)}, ranges[0])
	// The device head is the bootstrap.
	head := make([]byte, 4)
	_, err := unix.Pread(fds[0], head, int64(ranges[0].fileOffset)+erofsSuperOffset)
	require.NoError(t, err)
	require.Equal(t, uint32(erofsSuperMagic), binary.LittleEndian.Uint32(head), "FETCH fd lacks the EROFS superblock")

	send(t, conn, msgProbe, nil)
	probed, probeFds, _ := readRangeResponse(t, conn)
	defer closeFds(probeFds)
	require.NotEmpty(t, probed)
}
