package continuity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// TestFailoverMatrix crashes Failover-Protected Sessions and recovers them
// through a Recovery Holder.
func TestFailoverMatrix(t *testing.T) {
	t.Parallel()
	t.Run("Matrix", failoverMatrix)

	t.Run("LiveOwnerMissingControl", func(t *testing.T) { liveOwnerWithoutControl(t, false) })

	t.Run("LiveOwnerUnresponsiveControl", func(t *testing.T) { liveOwnerWithoutControl(t, true) })

	t.Run("DiscoveryInterruptedByCrash", discoveryInterruptedByCrash)

	t.Run("RecoveryRetryAndConcurrentStarts", recoveryRetryAndConcurrentStarts)
}

// killWithJournaledStressRequest SIGKILLs daemon while the journal holds at
// least one published request, so recovery has an inflight request to
// resend, and returns how many the journal retained. Without a journal it
// just kills the daemon. beforeKill runs right before the SIGKILL.
func killWithJournaledStressRequest(
	t *testing.T,
	daemon *mount.Daemon,
	journalFD int,
	beforeKill func(),
) int {
	t.Helper()
	if journalFD < 0 {
		beforeKill()
		daemon.Kill()

		return 0
	}

	mapping := mapInflightJournal(t, journalFD, unix.PROT_READ)
	defer func() { assert.NoError(t, unix.Munmap(mapping)) }()

	deadline := time.Now().Add(200 * time.Second)
	for time.Now().Before(deadline) {
		if countInflightSlots(mapping) == 0 {
			runtime.Gosched()
			continue
		}

		// Freeze the daemon and look again: the request may have completed
		// between the first look and the stop.
		daemon.Signal(unix.SIGSTOP)
		time.Sleep(2 * time.Millisecond)

		if countInflightSlots(mapping) == 0 {
			daemon.Signal(unix.SIGCONT)
			continue
		}

		beforeKill()
		daemon.Kill()
		assert.NotZero(t, daemon.ExitCode(), "the daemon unexpectedly exited cleanly after SIGKILL")
		published := countInflightSlots(mapping)
		if !assert.Positive(t, published,
			"the trapped stress request disappeared from the journal after the crash") {
			t.FailNow()
		}

		return published
	}

	t.Fatal("continuous stress did not publish a FUSE request before the deadline")

	return 0
}

func failoverMatrix(t *testing.T) {
	h, stressSource := setup(t, true)
	holder := h.holder
	initial := h.spawn(t, "matrix-initial")
	h.waitMounted(t)
	h.waitControlOwner(t, initial, 10*time.Second)

	heldHandles := startHandleKeeper(t, h)
	stored := holder.requireStoredBundle()
	held := holder.requireStoredBundleCopy()
	sessionID := stored.SessionID

	var heldState controlTransferState
	if !assert.NoError(t, json.Unmarshal(held.Metadata, &heldState)) {
		t.FailNow()
	}
	if !assert.Equal(t, sessionID, heldState.SessionID) {
		t.FailNow()
	}

	dev := mountDev(t, h.mountpoint)
	stress := h.startStress(t, stressSource)

	upgraded := h.spawn(t, "matrix-upgraded")
	h.waitServing(t, upgraded, sessionID, 30*time.Second)

	if !assert.True(t, initial.WaitExit(30*time.Second), "the initial daemon did not exit after hot upgrade") {
		t.FailNow()
	}

	assert.Zero(t, initial.ExitCode())
	assert.Equal(t, sessionID, holder.requireStoredBundle().SessionID,
		"hot upgrade replaced the stored Session Transfer")
	assert.Equal(t, []string{"fetch", "retain"}, holder.receivedCommands(),
		"protected hot upgrade contacted the Holder")
	h.requireFilesystem(t, stressSource, dev)

	crashGenerations := make([]int64, 0, 2)
	recovered := upgraded

	for attempt := 1; attempt <= 2; attempt++ {
		journaled := killWithJournaledStressRequest(t, recovered, held.journalFD(t), func() {
			crashGenerations = append(crashGenerations, stress.markCrash())
		})

		h.waitControlUnavailable(t)
		t.Logf("crash %d retained %d published journal entries", attempt, journaled)
		recovered = h.spawn(t, fmt.Sprintf("matrix-recovery-%d", attempt))
		h.waitServing(t, recovered, sessionID, 30*time.Second)

		if !assert.True(t, recovered.Alive()) {
			t.FailNow()
		}

		h.requireFilesystem(t, stressSource, dev)
	}

	heldHandles.verify(t, stressSource)
	fstest.VerifyMount(t, h.mountpoint, fstest.ScanSource(t, h.sourceDir), fstest.CompareOptions{Nlink: true})

	ops, errs, maxStall := stress.stop(t)
	eioByCrash := stress.failoverEIOs()
	t.Logf("failover matrix stress: %d iterations, EIOs by crash %v, max stall %v", ops, eioByCrash, maxStall)
	assert.Positive(t, ops)
	assert.Empty(t, errs)
	assert.Less(t, maxStall, maxUpgradeStall)
	assert.Len(t, crashGenerations, 2)

	for _, crash := range crashGenerations {
		assert.LessOrEqual(t, eioByCrash[crash], int64(1),
			"at most one stress operation may observe an error spanning crash %d", crash)
	}

	held.close()
	assert.True(t, recovered.Alive(), "dropping holder descriptor copies tore down the recovered daemon")
	assert.True(t, mount.IsMountpoint(h.mountpoint), "dropping holder descriptor copies unmounted the FUSE session")

	shutdownBundle := holder.requireStoredBundleCopy()
	recovered.Signal(unix.SIGTERM)

	if !assert.True(t, recovered.WaitExit(30*time.Second), "the second recovery ignored explicit shutdown") {
		t.FailNow()
	}

	assert.Zero(t, recovered.ExitCode())
	h.waitUnmounted(t)
	holder.requireReleased()

	// A Holder that missed the release still retains the session. That is
	// not permission to recover it or to mount afresh over it.
	holder.restoreRetainedTransfer(shutdownBundle)
	stale := h.spawn(t, "matrix-stale-retention")

	if !assert.True(t, stale.WaitExit(45*time.Second), "stale retention was not rejected") {
		t.FailNow()
	}

	assert.NotZero(t, stale.ExitCode(), "clean shutdown incorrectly authorized recovery")
	h.waitUnmounted(t)
	assert.Equal(t, sessionID, holder.requireStoredBundle().SessionID,
		"startup silently replaced a stale retained Session Transfer")

	holder.closeRetainedTransfer()
	fresh := h.spawn(t, "matrix-fresh-after-cleanup")
	h.waitMounted(t)
	newSessionID := holder.requireStoredBundle().SessionID
	assert.NotEqual(t, sessionID, newSessionID)
	h.waitServing(t, fresh, newSessionID, 30*time.Second)
	fresh.Signal(unix.SIGTERM)
	assert.True(t, fresh.WaitExit(30*time.Second))
	h.waitUnmounted(t)
	holder.requireReleased()
}

// discoveryInterruptedByCrash kills the predecessor after a successor has
// selected hot upgrade. The same launch must fall back to recovery through
// the Holder.
func discoveryInterruptedByCrash(t *testing.T) {
	h, source := setup(t, true)
	old := h.spawn(t, "discovered-owner")
	h.waitMounted(t)
	sessionID := h.holder.requireStoredBundle().SessionID
	h.waitServing(t, old, sessionID, 10*time.Second)
	dev := mountDev(t, h.mountpoint)
	info, err := requestControlInfo(h.controlSocket)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	commands := h.holder.receivedCommands()

	if !assert.NoError(t, os.Rename(h.controlSocket, h.controlSocket+".hidden")) {
		t.FailNow()
	}

	proxy := startInterruptedUpgradeControl(t, h.controlSocket, info)
	attempt := h.spawn(t, "interrupted-upgrade")
	handoffConn := proxy.takeConnection(t)

	if !assert.True(t, old.Alive(), "predecessor died before the selected upgrade began") {
		t.FailNow()
	}

	assert.Equal(t, commands, h.holder.receivedCommands(), "selected hot upgrade contacted the Holder")
	old.Kill()

	// Both the authenticated control peer and the owner are now dead. Expose
	// EOF only after pidfd exit and lifetime-lock release are observable.
	assert.NoError(t, handoffConn.Close())
	h.waitServing(t, attempt, sessionID, 30*time.Second)

	if !assert.True(t, attempt.Alive(), "the same-launch recovery exited after publishing control") {
		t.FailNow()
	}

	assert.Equal(t, append(commands, "fetch"), h.holder.receivedCommands())
	h.requireFilesystem(t, source, dev)
	attempt.Signal(unix.SIGTERM)

	if !assert.True(t, attempt.WaitExit(30*time.Second)) {
		t.FailNow()
	}

	assert.Zero(t, attempt.ExitCode())
	h.waitUnmounted(t)
}

// recoveryRetryAndConcurrentStarts recovers after the Holder rejected a
// fetch, then races two starts for the same retained session: exactly one
// may serve it.
func recoveryRetryAndConcurrentStarts(t *testing.T) {
	h, source := setup(t, true)
	old := h.spawn(t, "retry-original")
	h.waitMounted(t)
	holder := h.holder
	sessionID := holder.requireStoredBundle().SessionID
	h.waitServing(t, old, sessionID, 10*time.Second)
	dev := mountDev(t, h.mountpoint)
	commands := holder.receivedCommands()
	old.Kill()

	holder.setFetchHook(func() error { return errors.New("injected fetch rejection") })
	rejected := h.spawn(t, "rejected-recovery")

	if !assert.True(t, rejected.WaitExit(45*time.Second)) {
		t.FailNow()
	}

	assert.NotZero(t, rejected.ExitCode(), "Holder rejection was interpreted as Empty")
	assert.Equal(t, append(commands, "fetch"), holder.receivedCommands())
	assert.Equal(t, sessionID, holder.requireStoredBundle().SessionID)
	h.waitControlUnavailable(t)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseFetch := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseFetch)

	holder.setFetchHook(func() error {
		select {
		case entered <- struct{}{}:

		default:
		}

		select {
		case <-release:
			return nil

		case <-time.After(controlProtocolTimeout):
			return errors.New("test did not release blocked fetch")
		}
	})

	first := h.spawn(t, "concurrent-recovery-1")

	select {
	case <-entered:

	case <-time.After(15 * time.Second):
		t.Fatal("retry did not fetch the retained session")
	}

	second := h.spawn(t, "concurrent-recovery-2")
	releaseFetch()

	var serving *mount.Daemon
	if !assert.Eventually(t, func() bool {
		pid, err := controlOwnerPID(h.controlSocket)
		if err != nil {
			return false
		}

		if pid == uint32(first.Pid()) && first.Alive() && !second.Alive() {
			serving = first
		} else if pid == uint32(second.Pid()) && second.Alive() && !first.Alive() {
			serving = second
		}

		return serving != nil
	}, 45*time.Second, 100*time.Millisecond,
		"concurrent starts did not converge to exactly one serving incarnation") {
		t.FailNow()
	}

	assert.Equal(t, append(commands, "fetch", "fetch"), holder.receivedCommands(),
		"the second concurrent start fetched a second reader instead of serializing with recovery")
	h.waitServing(t, serving, sessionID, 10*time.Second)
	h.requireFilesystem(t, source, dev)
	serving.Signal(unix.SIGTERM)
	assert.True(t, serving.WaitExit(30*time.Second))
	h.waitUnmounted(t)
}

const interruptedUpgradeHelperEnv = "NYDUS_E2E_FUSE_INTERRUPTED_UPGRADE_HELPER"

// acceptInterruptedUpgrade answers a starting daemon's info request as the
// predecessor described by info, then stops after its handoff_begin so the
// selected upgrade never completes.
func acceptInterruptedUpgrade(listener *net.UnixListener, info controlResponse) (conn control, err error) {
	raw, err := listener.AcceptUnix()
	if err != nil {
		return control{}, err
	}

	conn = control{raw}

	defer func() {
		if err != nil {
			_ = conn.Close()
		}
	}()

	if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return conn, err
	}
	if err = conn.acceptHTTP(); err != nil {
		return conn, err
	}

	for _, expected := range []string{"info", "handoff_begin"} {
		request, readErr := conn.read()
		if readErr != nil {
			return conn, readErr
		}
		if request.Type != expected {
			return conn, fmt.Errorf("expected startup control command %q, got %q", expected, request.Type)
		}

		if expected == "info" {
			instance := *info.Info
			instance.PID = uint32(os.Getpid())
			info.Info = &instance

			if err = conn.write(info); err != nil {
				return conn, err
			}
		} else if err = conn.SetDeadline(time.Now().Add(controlProtocolTimeout)); err != nil {
			return conn, err
		}
	}

	return conn, nil
}

// interruptedUpgradeControl is a helper process that impersonates a
// predecessor's control endpoint and hands the accepted connection back to
// the test before exiting.
type interruptedUpgradeControl struct {
	*mount.Daemon
	protocol control
}

func startInterruptedUpgradeControl(t *testing.T, path string, info controlResponse) *interruptedUpgradeControl {
	t.Helper()
	protocol, childFile := newControlChannel(t)
	t.Cleanup(func() { _ = protocol.Close() })
	cmd := exec.Command(os.Args[0],
		"-test.run=^TestInterruptedUpgradeControlSameConnection$", "-test.timeout=30s")

	cmd.Env = append(os.Environ(),
		interruptedUpgradeHelperEnv+"=1",
		"NYDUS_E2E_FUSE_APISERVER=unix://"+path,
	)

	cmd.ExtraFiles = []*os.File{childFile}
	helper := &interruptedUpgradeControl{
		Daemon:   mount.StartCmd(t, t.TempDir(), "interrupted-upgrade-control", cmd),
		protocol: protocol,
	}

	if !assert.NoError(t, childFile.Close()) {
		t.FailNow()
	}

	protocol.setDeadline(t)
	protocol.mustWrite(t, info)

	if !assert.Equal(t, "listening", protocol.mustRead(t).Type, helper.Log()) {
		t.FailNow()
	}

	return helper
}

// takeConnection receives the control connection the helper accepted and
// waits for the helper to exit.
func (c *interruptedUpgradeControl) takeConnection(t *testing.T) control {
	t.Helper()
	c.protocol.setDeadline(t)
	fds, err := c.protocol.recvFDsExact(1)
	if !assert.NoError(t, err, c.Log()) {
		t.FailNow()
	}

	file := os.NewFile(uintptr(fds[0]), "interrupted-upgrade-control")
	conn, err := net.FileConn(file)

	if !assert.NoError(t, file.Close()) {
		t.FailNow()
	}
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = conn.Close() })

	// Keep a duplicate of the stream alive until the real reader also exits.
	// EOF must not race with exit of the authenticated control peer.
	if !assert.True(t, c.WaitExit(controlProtocolTimeout), c.Log()) {
		t.FailNow()
	}

	assert.Zero(t, c.ExitCode(), c.Log())

	return control{conn.(*net.UnixConn)}
}

func runInterruptedUpgradeHelper(t *testing.T) {
	file := os.NewFile(uintptr(helperInheritedFD), "interrupted-upgrade-protocol")
	raw, err := net.FileConn(file)

	if !assert.NoError(t, file.Close()) {
		t.FailNow()
	}
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	protocol := control{raw.(*net.UnixConn)}
	defer func() { _ = protocol.Close() }()
	protocol.setDeadline(t)
	info := protocol.mustRead(t)

	listener, err := net.ListenUnix("unix", &net.UnixAddr{
		Name: strings.TrimPrefix(os.Getenv("NYDUS_E2E_FUSE_APISERVER"), "unix://"), Net: "unix",
	})
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = listener.Close() }()
	protocol.mustWrite(t, map[string]string{"type": "listening"})

	conn, err := acceptInterruptedUpgrade(listener, info)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = conn.Close() }()
	accepted, err := conn.File()
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = accepted.Close() }()
	assert.NoError(t, protocol.sendFDs([]int{int(accepted.Fd())}))
}

// TestInterruptedUpgradeControlSameConnection is the harness self-test for
// interruptedUpgradeControl: the handed-back connection is the very stream
// the client authenticated, and it outlives the helper that accepted it.
func TestInterruptedUpgradeControlSameConnection(t *testing.T) {
	t.Parallel()
	if os.Getenv(interruptedUpgradeHelperEnv) == "1" {
		runInterruptedUpgradeHelper(t)
		return
	}

	path := mount.SocketPath(t)
	sessionID := "retained-session"
	info := controlResponse{
		Type:      "info",
		Info:      &controlInstanceInfo{PID: 1, Mountpoint: "/mnt/image", ImageDigest: "digest"},
		SessionID: &sessionID,
	}

	helper := startInterruptedUpgradeControl(t, path, info)
	client, err := dialControl(path, 5*time.Second)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = client.Close() })
	client.mustWrite(t, map[string]string{"type": "info"})
	response := client.mustRead(t)
	if !assert.Equal(t, "info", response.Type) {
		t.FailNow()
	}
	if !assert.NotNil(t, response.SessionID) {
		t.FailNow()
	}

	assert.Equal(t, sessionID, *response.SessionID)
	peerPID, peerUID, err := peerCredentials(client.UnixConn)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, uint32(peerPID), response.Info.PID)
	assert.Equal(t, uint32(os.Geteuid()), peerUID)
	assert.Equal(t, helper.Pid(), peerPID)
	assert.NotEqual(t, os.Getpid(), peerPID)
	pidfd, err := unix.PidfdOpen(peerPID, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = unix.Close(pidfd) })

	client.setDeadline(t)
	client.mustWrite(t, map[string]any{"type": "handoff_begin", "peer": info.Info})
	conn := helper.takeConnection(t)
	poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	assert.Equal(t, 1, n, "the authenticated control peer must have exited before EOF")
	assert.NotZero(t, poll[0].Revents&unix.POLLIN)
	conn.mustWrite(t, map[string]string{"type": "error", "message": "test interruption"})
	assert.Equal(t, "test interruption", client.mustRead(t).Message)
	assert.NoError(t, conn.Close())
	_, err = client.read()
	assert.ErrorIs(t, err, io.EOF)
}
