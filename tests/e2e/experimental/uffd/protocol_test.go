package uffd

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/erofs"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestProtocol(t *testing.T) {
	t.Parallel()
	s := startService(t, standardImage(t))
	conn := dial(t, s.socket)
	defer func() { _ = conn.Close() }()
	deviceSize, block := conn.stat(t)
	if !assert.Positive(t, deviceSize) {
		t.FailNow()
	}
	if !assert.Equal(t, uint32(blockSize), block) {
		t.FailNow()
	}

	conn.send(t, msgFetch, encodeRange(0, uint64(block)))
	var ranges []deviceRange
	var fds []int
	conn.withReadDeadline(t, faultTimeout, func() { ranges, fds, _ = conn.readRangeResponse(t) })
	defer closeFDs(fds)

	if !assert.NotEmpty(t, ranges) {
		t.FailNow()
	}
	if !assert.Equal(t, deviceRange{deviceOffset: 0, fileOffset: 0, length: uint64(block)}, ranges[0]) {
		t.FailNow()
	}

	head := make([]byte, 4)
	_, err := unix.Pread(fds[0], head, int64(ranges[0].fileOffset)+erofs.SuperOffset)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, uint32(erofs.SuperMagic), binary.LittleEndian.Uint32(head))

	conn.send(t, msgProbe, nil)
	var probed []deviceRange
	var probeFds []int
	conn.withReadDeadline(t, faultTimeout, func() { probed, probeFds, _ = conn.readRangeResponse(t) })
	defer closeFDs(probeFds)
	assert.NotEmpty(t, probed)
}

func TestMalformedRequests(t *testing.T) {
	t.Parallel()
	s := startService(t, standardImage(t))
	deviceSize := s.deviceSize(t)

	devNull, err := os.Open("/dev/null")
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = devNull.Close() }()
	dummy := int(devNull.Fd())

	sendHandshake := func(t *testing.T, conn client, payload []byte, fds []int) {
		conn.writeRawFrame(t, protocolMagic, 0, msgHandshake, uint32(len(payload)), payload, fds)
	}

	for _, tc := range []struct {
		name string
		send func(t *testing.T, conn client)
	}{
		{"BadMagic", func(t *testing.T, conn client) {
			conn.writeRawFrame(t, 0xdeadbeef, 0, msgStat, 0, nil, nil)
		}},
		{"OversizedPayloadLength", func(t *testing.T, conn client) {
			conn.writeRawFrame(t, protocolMagic, 0, msgFetch, 1<<20, nil, nil)
		}},
		{"TruncatedPayload", func(t *testing.T, conn client) {
			conn.writeRawFrame(t, protocolMagic, 0, msgFetch, fetchRequestSize, make([]byte, 8), nil)
			assert.NoError(t, conn.CloseWrite())
		}},
		{"HandshakeUnsupportedVersion", func(t *testing.T, conn client) {
			sendHandshake(t, conn, encodeHandshakePayload(protocolVersion+1, 0, 0, nil), []int{dummy})
		}},
		{"HandshakeMissingFd", func(t *testing.T, conn client) {
			sendHandshake(t, conn, encodeHandshakePayload(protocolVersion, 0, 0, nil), nil)
		}},
		{"HandshakeExtraFds", func(t *testing.T, conn client) {
			sendHandshake(t, conn, encodeHandshakePayload(protocolVersion, 0, 0, nil), []int{dummy, dummy})
		}},
		{"HandshakeMalformedRegions", func(t *testing.T, conn client) {
			sendHandshake(t, conn, encodeHandshakePayload(protocolVersion, 0, 1, nil), []int{dummy})
		}},
		{"StatWithPayload", func(t *testing.T, conn client) {
			conn.writeRawFrame(t, protocolMagic, 0, msgStat, 4, make([]byte, 4), nil)
		}},
		{"StatWithUnexpectedFd", func(t *testing.T, conn client) {
			conn.writeRawFrame(t, protocolMagic, 0, msgStat, 0, nil, []int{dummy})
		}},
		{"FetchWithUnexpectedFd", func(t *testing.T, conn client) {
			payload := encodeRange(0, blockSize)
			conn.writeRawFrame(t, protocolMagic, 0, msgFetch, uint32(len(payload)), payload, []int{dummy})
		}},
		{"FetchZeroLength", func(t *testing.T, conn client) {
			conn.send(t, msgFetch, encodeRange(0, 0))
		}},
		{"FetchUnaligned", func(t *testing.T, conn client) {
			conn.send(t, msgFetch, encodeRange(123, blockSize))
		}},
		{"FetchOutOfBounds", func(t *testing.T, conn client) {
			conn.send(t, msgFetch, encodeRange(deviceSize, blockSize))
		}},
		{"FetchOffsetOverflow", func(t *testing.T, conn client) {
			conn.send(t, msgFetch, encodeRange(^uint64(0)-blockSize+1, 2*blockSize))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := dial(t, s.socket)
			defer func() { _ = conn.Close() }()
			tc.send(t, conn)
			conn.expectClosed(t)
			s.expectAlive(t, deviceSize)
		})
	}

	t.Run("UnknownMessageTypeIgnored", func(t *testing.T) {
		conn := dial(t, s.socket)
		defer func() { _ = conn.Close() }()
		conn.writeRawFrame(t, protocolMagic, 0, 0x55, 0, nil, nil)
		size, _ := conn.stat(t)
		assert.Equal(t, deviceSize, size)
	})

	t.Run("UnknownHeaderFlagsIgnored", func(t *testing.T) {
		conn := dial(t, s.socket)
		defer func() { _ = conn.Close() }()
		conn.writeRawFrame(t, protocolMagic, 0x8000, msgStat, 0, nil, nil)

		conn.withReadDeadline(t, faultTimeout, func() {
			h, payload, fds := conn.readFrame(t)
			if !assert.Equal(t, uint16(msgStatResponse), h.msgType) {
				t.FailNow()
			}

			assert.Empty(t, fds)
			assert.Len(t, payload, statResponseSize)
		})
	})
}
