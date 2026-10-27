package continuity

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestFDTransfer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		tag      byte
		sent     int
		expected int
	}{
		{name: "connection", tag: 'F', sent: 1, expected: 1},
		{name: "wrong tag", tag: 'X', sent: 1, expected: 1},
		{name: "wrong count", tag: 'F', sent: 2, expected: 1},
		{name: "truncated rights", tag: 'F', sent: 64, expected: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			receiver, senderFile := newControlChannel(t)
			sender, err := net.FileConn(senderFile)
			require.NoError(t, senderFile.Close())
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, sender.Close())
				require.NoError(t, receiver.Close())
			})
			peer, sentinel := newControlChannel(t)
			t.Cleanup(func() { require.NoError(t, peer.Close()) })
			rights := make([]int, tc.sent)
			for i := range rights {
				rights[i] = int(sentinel.Fd())
			}
			conn, ok := sender.(*net.UnixConn)
			require.True(t, ok)
			_, _, err = conn.WriteMsgUnix([]byte{tc.tag}, unix.UnixRights(rights...), nil)
			require.NoError(t, err)
			require.NoError(t, sentinel.Close())

			fds, err := recvFDsExact(receiver, tc.expected)
			if tc.tag == 'F' && tc.sent == tc.expected {
				require.NoError(t, err)
				require.Len(t, fds, tc.expected)
				for _, fd := range fds {
					require.NoError(t, unix.Close(fd))
				}
			} else {
				require.Error(t, err)
				require.Nil(t, fds)
			}
			setControlDeadline(t, peer)
			_, err = peer.Read(make([]byte, 1))
			require.ErrorIs(t, err, io.EOF, "received descriptors leaked")
		})
	}
}
