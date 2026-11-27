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

// liveOwnerWithoutControl starts a second daemon beside a live protected
// owner whose control endpoint is missing or unresponsive. The start must
// fail without touching the Holder's retained copy of the live session.
func liveOwnerWithoutControl(t *testing.T, unresponsive bool) {
	h, source := setup(t, true)
	old := h.spawn(t, "live-owner")
	h.waitMounted(t)
	sessionID := h.holder.requireStoredBundle().SessionID
	h.waitServing(t, old, sessionID, 10*time.Second)
	dev := mountDev(t, h.mountpoint)
	commands := h.holder.receivedCommands()
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

	assert.Equal(t, commands, h.holder.receivedCommands(),
		"control failure must not fetch a retained copy while the original reader lives")

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

	h.waitServing(t, old, sessionID, 10*time.Second)
	old.Signal(unix.SIGTERM)
	assert.True(t, old.WaitExit(30*time.Second))
	h.waitUnmounted(t)
}

func TestWithoutAPIServer(t *testing.T) {
	t.Parallel()
	if os.Getenv(handleHelperEnv) == "1" {
		runHandleHelper(t)
		return
	}

	runProtectionMatrix(t, withoutAPIServer)
}

// withoutAPIServer serves without a control endpoint. A protected session
// must still survive a crash: the Holder alone carries it to the next daemon.
func withoutAPIServer(t *testing.T, protected bool) {
	h, source := setup(t, protected)
	h.controlSocket = ""
	initial := h.spawn(t, "api-off-initial")
	h.waitMounted(t)
	handles := startHandleKeeper(t, h)

	var sessionID *string
	if protected {
		sessionID = h.holder.requireStoredBundle().SessionID
		if !assert.NotNil(t, sessionID) {
			t.FailNow()
		}

		assert.Regexp(t, `^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`, *sessionID)

		if !assert.FileExists(t, h.stateBase()+".owner") {
			t.FailNow()
		}
		if !assert.FileExists(t, h.stateBase()+".lock") {
			t.FailNow()
		}
	}

	dev := mountDev(t, h.mountpoint)
	h.requireFilesystem(t, source, dev)
	assert.Empty(t, listeningSockets(t, initial.Pid()))

	serving := initial
	if protected {
		initial.Kill()
		serving = h.spawn(t, "api-off-recovered")
	}

	handles.verify(t, source)
	h.requireFilesystem(t, source, dev)

	if !assert.True(t, serving.Alive()) {
		t.FailNow()
	}

	if protected {
		assert.Empty(t, listeningSockets(t, serving.Pid()))
		assert.Equal(t, []string{"fetch", "retain", "fetch"}, h.holder.receivedCommands())
		assert.Equal(t, sessionID, h.holder.requireStoredBundle().SessionID)
	}

	serving.Signal(unix.SIGTERM)

	if !assert.True(t, serving.WaitExit(30*time.Second)) {
		t.FailNow()
	}

	assert.Zero(t, serving.ExitCode())
	h.waitUnmounted(t)

	if protected {
		h.holder.requireReleased()
		assert.Equal(t, []string{"fetch", "retain", "fetch", "release"}, h.holder.receivedCommands())
	}
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
