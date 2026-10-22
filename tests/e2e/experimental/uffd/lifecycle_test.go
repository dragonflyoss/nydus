package uffd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestLifecycle walks one service through client disconnects, with and
// without an outstanding fault, a graceful stop under an active session,
// and a restart over a stale socket. The steps share the service and run
// in order.
func TestLifecycle(t *testing.T) {
	t.Parallel()
	requireUserfaultfd(t)
	s := startService(t, standardImage(t))
	deviceSize := s.deviceSize(t)

	t.Run("ClientDisconnect", func(t *testing.T) {
		c := newFaultClient(t, s, handshakeCopy, blockSize, 0)
		c.ack(t)
		c.close(t)
		requireAlive(t, s, deviceSize)
	})

	t.Run("DisconnectWithOutstandingFault", func(t *testing.T) {
		// The child declares only the first half of the device and reads a
		// page of the second, so that fault stays outstanding. It is a
		// separate process because an unresolved fault starves the Go
		// runtime timers of the faulting process.
		half := alignDown(deviceSize/2, blockSize)
		require.Positive(t, half, "device too small to split")
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(),
			childModeEnv+"="+childModeOutstandingFault,
			childSocketEnv+"="+s.socket,
			fmt.Sprintf("%s=%d", childDeviceSizeEnv, deviceSize),
			fmt.Sprintf("%s=%d", childRegionSizeEnv, half),
		)
		stdin, err := cmd.StdinPipe()
		require.NoError(t, err)
		stdout, err := cmd.StdoutPipe()
		require.NoError(t, err)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		require.NoError(t, cmd.Start())
		exited := make(chan error, 1)
		defer func() {
			_ = stdin.Close()
			_ = cmd.Process.Kill()
			<-exited
		}()

		lines := make(chan string, 16)
		go func() {
			sc := bufio.NewScanner(stdout)
			for sc.Scan() {
				lines <- sc.Text()
			}
			close(lines)
			exited <- cmd.Wait()
		}()
		next := func(what string) string {
			select {
			case line, ok := <-lines:
				require.True(t, ok, "child exited before %s:\n%s", what, stderr.String())
				return line
			case <-time.After(caseDeadline):
				t.Fatalf("timed out waiting for child %s:\n%s", what, stderr.String())
				return ""
			}
		}

		require.Equal(t, "READY", next("READY"))
		require.Equal(t, "TOUCHING", next("TOUCHING"))
		select {
		case line := <-lines:
			t.Fatalf("a fault outside the declared region was resolved: child printed %q", line)
		case <-time.After(time.Second):
		}

		// With both userfaultfd copies gone, the blocked read resolves as an
		// anonymous zero page, never as wrong data.
		_, err = io.WriteString(stdin, "close\n")
		require.NoError(t, err)
		require.Equal(t, "RESOLVED 0", next("RESOLVED"))
		require.Equal(t, "DONE", next("DONE"))
		select {
		case err := <-exited:
			exited <- err
			require.NoError(t, err, "child exit:\n%s", stderr.String())
		case <-time.After(caseDeadline):
			t.Fatalf("child still running %v after teardown:\n%s", caseDeadline, stderr.String())
		}
		requireAlive(t, s, deviceSize)
	})

	t.Run("ServiceStopWithActiveSession", func(t *testing.T) {
		c := newFaultClient(t, s, handshakeCopy, blockSize, 0)
		c.ack(t)
		require.True(t, s.daemon.Stop(), "service did not stop on SIGTERM")
		require.Zero(t, s.daemon.ExitCode(), "service exit code")
		_, err := os.Stat(s.socket)
		require.True(t, os.IsNotExist(err), "service left its socket behind")
		requireFailsClosed(t, c.conn)
		c.close(t)
	})

	t.Run("RestartWithStaleSocket", func(t *testing.T) {
		// A leftover file at the socket path does not block a restart, and
		// new sessions work against the restarted service (v1 promises new
		// sessions, not resumption).
		require.NoError(t, os.WriteFile(s.socket, nil, 0o644))
		s.start(t)
		c := newFaultClient(t, s, handshakeCopy, blockSize, 0)
		c.ack(t)
		b := waitTouch(t, c.touchAsync(t, 0), faultDeadline, "cold fault after restart")
		require.Equal(t, deviceBytes(t, s.socket, 0, blockSize)[0], b, "restarted service resolved a wrong byte")
	})
}
