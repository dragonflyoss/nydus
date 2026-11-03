package continuity

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const soAcceptCon = "00010000"

func TestLiveOwnerWithoutControl(t *testing.T) {
	t.Parallel()
	t.Run("Missing", func(t *testing.T) { liveOwnerWithoutControl(t, false) })

	t.Run("Unresponsive", func(t *testing.T) { liveOwnerWithoutControl(t, true) })
}

func liveOwnerWithoutControl(t *testing.T, unresponsive bool) {
	h, source := setup(t)
	old := h.spawn(t, "live-owner")
	h.waitMounted(t)
	h.waitServing(t, old, 10*time.Second)
	dev := mountDev(t, h.mountpoint)
	hiddenSocket := h.controlSocket + ".hidden"
	if !assert.NoError(t, os.Rename(h.controlSocket, hiddenSocket)) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = os.Rename(hiddenSocket, h.controlSocket) })
	var listener *net.UnixListener

	var accepted chan *net.UnixConn
	if unresponsive {
		var err error
		listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: h.controlSocket, Net: "unix"})
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		t.Cleanup(func() { _ = listener.Close() })
		accepted = make(chan *net.UnixConn, 1)

		go func() {
			conn, _ := listener.AcceptUnix()
			accepted <- conn
		}()
	}

	attempt := h.spawn(t, "blocked-by-live-owner")

	if unresponsive {
		select {
		case conn := <-accepted:
			if !assert.NotNil(t, conn) {
				t.FailNow()
			}

			defer func() { _ = conn.Close() }()

		case <-time.After(10 * time.Second):
			t.Fatal("successor never probed the unresponsive control endpoint")
		}
	}

	if !assert.True(t, attempt.WaitExit(45*time.Second)) {
		t.FailNow()
	}
	if !assert.Positive(t, attempt.ExitCode()) {
		t.FailNow()
	}
	if !assert.True(t, old.Alive()) {
		t.FailNow()
	}

	info, err := requestControlInfo(hiddenSocket)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, uint32(old.Pid()), info.Info.PID) {
		t.FailNow()
	}

	h.requireFilesystem(t, source, dev)

	if listener != nil {
		assert.NoError(t, listener.Close())
	}
	if !assert.NoError(t, os.Rename(hiddenSocket, h.controlSocket)) {
		t.FailNow()
	}

	h.waitServing(t, old, 10*time.Second)
	old.Signal(unix.SIGTERM)
	assert.True(t, old.WaitExit(30*time.Second))
	h.waitUnmounted(t)
}

func TestWithoutAPIServer(t *testing.T) {
	t.Parallel()
	h, source := setup(t)
	h.controlSocket = ""
	initial := h.spawn(t, "api-off-initial")
	h.waitMounted(t)

	if !assert.FileExists(t, h.stateBase()+".owner") {
		t.FailNow()
	}
	if !assert.FileExists(t, h.stateBase()+".lock") {
		t.FailNow()
	}

	dev := mountDev(t, h.mountpoint)
	h.requireFilesystem(t, source, dev)
	assert.Empty(t, listeningSockets(t, initial.Pid()))

	if !assert.True(t, initial.Alive()) {
		t.FailNow()
	}

	initial.Signal(unix.SIGTERM)

	if !assert.True(t, initial.WaitExit(30*time.Second)) {
		t.FailNow()
	}

	assert.Zero(t, initial.ExitCode())
	h.waitUnmounted(t)
}

func listeningSockets(t *testing.T, pid int) []string {
	t.Helper()
	fds, err := filepath.Glob(fmt.Sprintf("/proc/%d/fd/*", pid))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	held := map[string]bool{}

	for _, fd := range fds {
		target, _ := os.Readlink(fd)
		if inode, ok := strings.CutPrefix(target, "socket:["); ok {
			held[strings.TrimSuffix(inode, "]")] = true
		}
	}

	table, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/unix", pid))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	var listening []string

	for _, line := range strings.Split(string(table), "\n") {
		if fields := strings.Fields(line); len(fields) >= 7 && fields[3] == soAcceptCon && held[fields[6]] {
			listening = append(listening, line)
		}
	}

	return listening
}
