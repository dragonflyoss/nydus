package uffd

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNegativeProtocol sends malformed and unsupported frames: each ends
// its session without a success-shaped answer and without hanging, and the
// service keeps serving new sessions. Unknown message types and header flag
// bits are tolerated, as protocol v1 requires.
func TestNegativeProtocol(t *testing.T) {
	t.Parallel()
	s := startService(t, standardImage(t))
	deviceSize := s.deviceSize(t)

	devNull, err := os.Open("/dev/null")
	require.NoError(t, err)
	defer func() { _ = devNull.Close() }()
	dummy := int(devNull.Fd())

	handshake := func(version uint16, regionCount byte, regions int) []byte {
		payload := make([]byte, 4+regions*regionSize)
		binary.LittleEndian.PutUint16(payload[0:2], version)
		payload[3] = regionCount
		return payload
	}
	sendHandshake := func(t *testing.T, conn *net.UnixConn, payload []byte, fds []int) {
		writeRawFrame(t, conn, magic, 0, msgHandshake, uint32(len(payload)), payload, fds)
	}

	for _, tc := range []struct {
		name string
		send func(t *testing.T, conn *net.UnixConn)
	}{
		{"BadMagic", func(t *testing.T, conn *net.UnixConn) {
			writeRawFrame(t, conn, 0xdeadbeef, 0, msgStat, 0, nil, nil)
		}},
		{"OversizedPayloadLength", func(t *testing.T, conn *net.UnixConn) {
			writeRawFrame(t, conn, magic, 0, msgFetch, 1<<20, nil, nil)
		}},
		{"TruncatedPayload", func(t *testing.T, conn *net.UnixConn) {
			writeRawFrame(t, conn, magic, 0, msgFetch, fetchRequestSize, make([]byte, 8), nil)
			require.NoError(t, conn.CloseWrite())
		}},
		{"HandshakeUnsupportedVersion", func(t *testing.T, conn *net.UnixConn) {
			sendHandshake(t, conn, handshake(protocolVersion+1, 0, 0), []int{dummy})
		}},
		{"HandshakeMissingFd", func(t *testing.T, conn *net.UnixConn) {
			sendHandshake(t, conn, handshake(protocolVersion, 0, 0), nil)
		}},
		{"HandshakeExtraFds", func(t *testing.T, conn *net.UnixConn) {
			sendHandshake(t, conn, handshake(protocolVersion, 0, 0), []int{dummy, dummy})
		}},
		{"HandshakeMalformedRegions", func(t *testing.T, conn *net.UnixConn) {
			// One region declared, none sent.
			sendHandshake(t, conn, handshake(protocolVersion, 1, 0), []int{dummy})
		}},
		{"StatWithPayload", func(t *testing.T, conn *net.UnixConn) {
			writeRawFrame(t, conn, magic, 0, msgStat, 4, make([]byte, 4), nil)
		}},
		{"StatWithUnexpectedFd", func(t *testing.T, conn *net.UnixConn) {
			writeRawFrame(t, conn, magic, 0, msgStat, 0, nil, []int{dummy})
		}},
		{"FetchWithUnexpectedFd", func(t *testing.T, conn *net.UnixConn) {
			payload := encodeRange(0, blockSize)
			writeRawFrame(t, conn, magic, 0, msgFetch, uint32(len(payload)), payload, []int{dummy})
		}},
		{"FetchZeroLength", func(t *testing.T, conn *net.UnixConn) {
			send(t, conn, msgFetch, encodeRange(0, 0))
		}},
		{"FetchUnaligned", func(t *testing.T, conn *net.UnixConn) {
			send(t, conn, msgFetch, encodeRange(123, blockSize))
		}},
		{"FetchOutOfBounds", func(t *testing.T, conn *net.UnixConn) {
			send(t, conn, msgFetch, encodeRange(deviceSize, blockSize))
		}},
		{"FetchOffsetOverflow", func(t *testing.T, conn *net.UnixConn) {
			send(t, conn, msgFetch, encodeRange(^uint64(0)-blockSize+1, 2*blockSize))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := dial(t, s.socket)
			defer func() { _ = conn.Close() }()
			tc.send(t, conn)
			requireFailsClosed(t, conn)
			requireAlive(t, s, deviceSize)
		})
	}

	t.Run("UnknownMessageTypeIgnored", func(t *testing.T) {
		conn := dial(t, s.socket)
		defer func() { _ = conn.Close() }()
		writeRawFrame(t, conn, magic, 0, 0x55, 0, nil, nil)
		size, _ := stat(t, conn)
		require.Equal(t, deviceSize, size)
	})

	t.Run("UnknownHeaderFlagsIgnored", func(t *testing.T) {
		conn := dial(t, s.socket)
		defer func() { _ = conn.Close() }()
		writeRawFrame(t, conn, magic, 0x8000, msgStat, 0, nil, nil)
		withReadDeadline(t, conn, faultDeadline, func() {
			h, payload, fds := readFrame(t, conn)
			require.Equal(t, uint16(msgStatResponse), h.msgType)
			require.Empty(t, fds)
			require.Len(t, payload, statResponseSize)
		})
	})
}
