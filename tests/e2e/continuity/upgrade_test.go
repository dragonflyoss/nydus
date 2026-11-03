package continuity

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestHotUpgrade(t *testing.T) {
	t.Parallel()
	h, _ := setup(t)
	heldSource, err := os.ReadFile(filepath.Join(h.sourceDir, heldFileRel))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	stressSource, err := os.ReadFile(filepath.Join(h.sourceDir, stressFileRel))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	predecessor := *h

	if os.Getenv("NYDUS_E2E_FUSE_PREDECESSOR") != "" {
		bin, err := exec.LookPath(os.Getenv("NYDUS_E2E_FUSE_PREDECESSOR"))
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		bin, err = filepath.Abs(bin)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		predecessor.nydus = bin
	}

	old := predecessor.spawn(t, "old")
	h.waitMounted(t)
	h.waitServing(t, old, 10*time.Second)

	if !assert.FileExists(t, h.stateBase()+".owner") {
		t.FailNow()
	}
	if !assert.FileExists(t, h.stateBase()+".lock") {
		t.FailNow()
	}

	devOld := mountDev(t, h.mountpoint)
	fstest.VerifyMount(t, h.mountpoint, fstest.ScanSource(t, h.sourceDir), fstest.CompareOptions{Nlink: true})

	held, err := os.Open(filepath.Join(h.mountpoint, heldFileRel))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = held.Close() }()
	firstHalf := make([]byte, heldFileSize/2)
	_, err = io.ReadFull(held, firstHalf)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.True(t, bytes.Equal(heldSource[:heldFileSize/2], firstHalf)) {
		t.FailNow()
	}

	heldDir := h.openPartialDir(t, heldDirRel)
	if !assert.False(t, heldDir.readBatch(t)) {
		t.FailNow()
	}

	preNames := len(heldDir.names)
	if !assert.Positive(t, preNames) {
		t.FailNow()
	}
	if !assert.Less(t, preNames, heldDirEntries) {
		t.FailNow()
	}

	stress := h.startStress(t, stressSource)

	successor := h.spawn(t, "new")
	h.waitServing(t, successor, 30*time.Second)
	h.assertMountIdentity(t, devOld)

	if !assert.True(t, successor.Alive()) {
		t.FailNow()
	}

	old.WaitForLog(t, 10*time.Second, "handoff complete; control socket removed")

	if !assert.True(t, old.WaitExit(30*time.Second)) {
		t.FailNow()
	}
	if !assert.Zero(t, old.ExitCode()) {
		t.FailNow()
	}

	secondHalf, err := io.ReadAll(held)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Len(t, secondHalf, heldFileSize/2) {
		t.FailNow()
	}
	if !assert.True(t, bytes.Equal(heldSource[heldFileSize/2:], secondHalf)) {
		t.FailNow()
	}
	if !assert.NoError(t, held.Close()) {
		t.FailNow()
	}

	heldDir.readRest(t)
	heldDir.close()

	if !assert.Len(t, heldDir.names, heldDirEntries) {
		t.FailNow()
	}

	slices.Sort(heldDir.names)

	for i, name := range heldDir.names {
		assert.Equal(t, fmt.Sprintf("entry_%04d", i), name)
	}

	fstest.VerifyMount(t, h.mountpoint, fstest.ScanSource(t, h.sourceDir), fstest.CompareOptions{Nlink: true})
	_, err = os.Stat(h.controlSocket)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	ops, errs, maxStall := stress.stop(t)
	t.Logf("stress: %d iterations across hot upgrade, max stall %v", ops, maxStall)
	assert.Positive(t, ops)
	assert.Empty(t, errs)
	assert.Less(t, maxStall, maxUpgradeStall)

	shutdownHeld, err := os.Open(filepath.Join(h.mountpoint, heldFileRel))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	t.Cleanup(func() { _ = shutdownHeld.Close() })
	successor.Signal(unix.SIGTERM)

	if !assert.True(t, successor.WaitExit(30*time.Second)) {
		t.FailNow()
	}

	assert.Zero(t, successor.ExitCode())
	h.waitUnmounted(t)
}

func TestPreReadyRollback(t *testing.T) {
	t.Parallel()
	if os.Getenv(preReadyHelperEnv) == "1" {
		runPreReadyHelper(t)
		return
	}

	h, stressSource := setup(t)

	old := h.spawn(t, "old")
	h.waitMounted(t)
	h.waitServing(t, old, 10*time.Second)
	devOld := mountDev(t, h.mountpoint)
	stress := h.startStress(t, stressSource)

	fakeSuccessor := h.startFakeHotUpgradeSuccessor(t)

	time.Sleep(2 * time.Second)
	fakeSuccessor.Kill()
	old.WaitForLog(t, 15*time.Second, "resuming service")

	if !assert.True(t, old.Alive()) {
		t.FailNow()
	}

	h.waitServing(t, old, 10*time.Second)
	h.assertMountIdentity(t, devOld)

	resumed := stress.count()
	if !assert.Eventually(t, func() bool { return stress.count() > resumed }, maxUpgradeStall, 100*time.Millisecond) {
		t.FailNow()
	}

	ops, errs, maxStall := stress.stop(t)
	t.Logf("stress: %d iterations across the aborted handoff, max stall %v", ops, maxStall)
	assert.Positive(t, ops)
	assert.Empty(t, errs)
	assert.Less(t, maxStall, maxUpgradeStall)
	fstest.VerifyMount(t, h.mountpoint, fstest.ScanSource(t, h.sourceDir), fstest.CompareOptions{Nlink: true})

	successor := h.spawn(t, "new")
	h.waitServing(t, successor, 30*time.Second)

	if !assert.True(t, old.WaitExit(30*time.Second)) {
		t.FailNow()
	}
	if !assert.Zero(t, old.ExitCode()) {
		t.FailNow()
	}

	fstest.VerifyMount(t, h.mountpoint, fstest.ScanSource(t, h.sourceDir), fstest.CompareOptions{Nlink: true})
	successor.Signal(unix.SIGTERM)
	assert.True(t, successor.WaitExit(30*time.Second))
	h.waitUnmounted(t)
}

func TestFDTransfer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		tag      byte
		sent     int
		expected int
	}{
		{name: "Connection", tag: 'F', sent: 1, expected: 1},
		{name: "WrongTag", tag: 'X', sent: 1, expected: 1},
		{name: "WrongCount", tag: 'F', sent: 2, expected: 1},
		{name: "TruncatedRights", tag: 'F', sent: 64, expected: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			receiver, senderFile := newControlChannel(t)
			sender, err := net.FileConn(senderFile)

			if !assert.NoError(t, senderFile.Close()) {
				t.FailNow()
			}
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			t.Cleanup(func() {
				assert.NoError(t, sender.Close())
				assert.NoError(t, receiver.Close())
			})

			peer, sentinel := newControlChannel(t)
			t.Cleanup(func() { assert.NoError(t, peer.Close()) })

			rights := make([]int, tc.sent)
			for i := range rights {
				rights[i] = int(sentinel.Fd())
			}

			conn, ok := sender.(*net.UnixConn)
			if !assert.True(t, ok) {
				t.FailNow()
			}

			_, _, err = conn.WriteMsgUnix([]byte{tc.tag}, unix.UnixRights(rights...), nil)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			if !assert.NoError(t, sentinel.Close()) {
				t.FailNow()
			}

			fds, err := receiver.recvFDs(tc.expected)

			if tc.tag == 'F' && tc.sent == tc.expected {
				assert.NoError(t, err)

				if !assert.Len(t, fds, tc.expected) {
					t.FailNow()
				}

				for _, fd := range fds {
					assert.NoError(t, unix.Close(fd))
				}
			} else {
				assert.Error(t, err)
				assert.Nil(t, fds)
			}

			peer.setDeadline(t)
			_, err = peer.Read(make([]byte, 1))
			assert.ErrorIs(t, err, io.EOF)
		})
	}
}

func newControlChannel(t *testing.T) (control, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	parentFile := os.NewFile(uintptr(fds[0]), "control-parent")
	childFile := os.NewFile(uintptr(fds[1]), "control-child")
	conn, err := net.FileConn(parentFile)

	if !assert.NoError(t, parentFile.Close()) {
		t.FailNow()
	}

	assert.NoError(t, err)
	unixConn, ok := conn.(*net.UnixConn)
	if !assert.True(t, ok) {
		t.FailNow()
	}

	return control{unixConn}, childFile
}

const preReadyHelperEnv = "NYDUS_E2E_FUSE_PRE_READY_HELPER"

func runPreReadyHelper(t *testing.T) {
	mountpoint, err := filepath.EvalSymlinks(os.Getenv("NYDUS_E2E_FUSE_MOUNTPOINT"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	imageBytes, err := os.ReadFile(os.Getenv("NYDUS_E2E_FUSE_BOOTSTRAP"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	imageDigest := sha256.Sum256(imageBytes)
	conn, err := dialControl(strings.TrimPrefix(os.Getenv("NYDUS_E2E_FUSE_APISERVER"), "unix://"), 5*time.Second)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = conn.Close() }()
	conn.mustWrite(t, map[string]string{"type": "info"})
	info := conn.mustRead(t)
	if !assert.Equal(t, "info", info.Type) {
		t.FailNow()
	}
	if !assert.NotNil(t, info.Info) {
		t.FailNow()
	}
	if !assert.Equal(t, mountpoint, info.Info.Mountpoint) {
		t.FailNow()
	}
	if !assert.Equal(t, fmt.Sprintf("%x", imageDigest), info.Info.ImageDigest) {
		t.FailNow()
	}

	assert.Nil(t, info.SessionID)
	conn.setDeadline(t)

	conn.mustWrite(t, map[string]any{
		"type": "handoff_begin",
		"peer": controlInstanceInfo{
			PID:         uint32(os.Getpid()),
			Version:     "e2e-pre-ready-successor",
			Mountpoint:  mountpoint,
			ImageDigest: fmt.Sprintf("%x", imageDigest),
		},
	})

	response := conn.mustRead(t)
	assert.Equal(t, "handoff_transfer", response.Type)
	metadata, err := conn.readRaw()
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.NotEmpty(t, metadata) {
		t.FailNow()
	}

	var state controlTransferState
	if !assert.NoError(t, json.Unmarshal(metadata, &state)) {
		t.FailNow()
	}
	if !assert.Equal(t, uint32(1), state.Version) {
		t.FailNow()
	}
	if !assert.Equal(t, mountpoint, state.Mountpoint) {
		t.FailNow()
	}
	if !assert.Equal(t, fmt.Sprintf("%x", imageDigest), state.ImageDigest) {
		t.FailNow()
	}
	if !assert.Equal(t, uint32(7), state.FuseSessionState.ProtoMajor) {
		t.FailNow()
	}

	assert.NotZero(t, state.FuseSessionState.ProtoMinor)
	fds, err := conn.recvFDs(1)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer closeFDs(fds)
	var receivedFuse, fuseDevice unix.Stat_t
	if !assert.NoError(t, unix.Fstat(fds[0], &receivedFuse)) {
		t.FailNow()
	}
	if !assert.NoError(t, unix.Stat("/dev/fuse", &fuseDevice)) {
		t.FailNow()
	}
	if !assert.Equal(t, uint32(unix.S_IFCHR), receivedFuse.Mode&unix.S_IFMT) {
		t.FailNow()
	}

	assert.Equal(t, fuseDevice.Rdev, receivedFuse.Rdev)

	_, err = fmt.Fprintln(os.Stdout, "TRANSFERRED")
	assert.NoError(t, err)

	select {}
}

func closeFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}
}
