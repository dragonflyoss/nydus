package continuity

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// The inflight journal layout follows fuser: a header of magic, version and
// slot capacity, then one tagged 16-byte slot per request.
const (
	inflightJournalMagic                 = "FUSRIFL\x00"
	inflightJournalVersionOffset         = 8
	inflightJournalVersion        uint32 = 1
	inflightJournalCapacityOffset        = 12
	inflightJournalHeaderSize            = 16
	inflightJournalSlotSize              = 16
	inflightSlotTagMask           uint64 = 3
	inflightSlotTagInflight       uint64 = 2
)

// recoveryBundle is one retained Session Transfer: its opaque metadata and
// every FUSE device, followed by the inflight journal when the metadata
// reports one.
type recoveryBundle struct {
	SessionID string
	Metadata  []byte
	FDs       []int
}

// journalFD returns the bundle's inflight journal, or -1 when the session
// keeps none.
func (b *recoveryBundle) journalFD(t *testing.T) int {
	t.Helper()
	var state controlTransferState
	if !assert.NoError(t, json.Unmarshal(b.Metadata, &state)) {
		t.FailNow()
	}
	if !assert.NotNil(t, state.SessionID, "only a protected session keeps a journal") {
		t.FailNow()
	}
	if !state.InflightJournal {
		return -1
	}
	if !assert.GreaterOrEqual(t, len(b.FDs), 2, "a journal follows at least one device") {
		t.FailNow()
	}

	return b.FDs[len(b.FDs)-1]
}

func (b *recoveryBundle) close() {
	for i, fd := range b.FDs {
		if fd >= 0 {
			_ = unix.Close(fd)
			b.FDs[i] = -1
		}
	}
}

func (b *recoveryBundle) duplicate() (*recoveryBundle, error) {
	bundleCopy := &recoveryBundle{
		SessionID: b.SessionID,
		Metadata:  slices.Clone(b.Metadata),
	}

	for _, fd := range b.FDs {
		duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			bundleCopy.close()
			return nil, err
		}

		bundleCopy.FDs = append(bundleCopy.FDs, duplicate)
	}

	return bundleCopy, nil
}

// fakeRecoveryHolder speaks the Holder protocol on a Unix socket. It retains
// one session's bundle, hands out copies on fetch, and releases it by
// session ID.
type fakeRecoveryHolder struct {
	t        *testing.T
	listener *net.UnixListener
	workers  sync.WaitGroup

	mu        sync.Mutex
	bundle    *recoveryBundle
	commands  []string
	fetchHook func() error
}

func newFakeRecoveryHolder(t *testing.T, h *harness) *fakeRecoveryHolder {
	t.Helper()
	holder := &fakeRecoveryHolder{t: t}
	h.holder = holder
	t.Cleanup(holder.cleanup)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: h.supervisorSocket, Net: "unix"})
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.NoError(t, os.Chmod(h.supervisorSocket, 0o600)) {
		t.FailNow()
	}

	holder.listener = listener
	holder.workers.Add(1)

	go func() {
		defer holder.workers.Done()
		holder.serve()
	}()

	return holder
}

func peerCredentials(conn *net.UnixConn) (int, uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}

	var credentials *unix.Ucred

	var credentialErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}

	if credentialErr != nil {
		return 0, 0, credentialErr
	}
	if credentials == nil || credentials.Pid <= 0 {
		return 0, 0, errors.New("peer has invalid credentials")
	}

	return int(credentials.Pid), credentials.Uid, nil
}

func (h *fakeRecoveryHolder) serve() {
	for {
		conn, err := h.listener.AcceptUnix()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				h.t.Errorf("supervisor accept failed: %v", err)
			}

			return
		}

		h.workers.Add(1)

		go func() {
			defer h.workers.Done()
			defer func() { _ = conn.Close() }()

			if err := h.handle(control{conn}); err != nil {
				h.t.Errorf("holder transaction failed: %v", err)
			}
		}()
	}
}

func (h *fakeRecoveryHolder) handle(conn control) error {
	if err := conn.SetDeadline(time.Now().Add(controlProtocolTimeout)); err != nil {
		return err
	}

	_, peerUID, err := peerCredentials(conn.UnixConn)
	if err != nil {
		return err
	}
	if peerUID != uint32(os.Geteuid()) {
		return fmt.Errorf("supervisor peer uid %d differs from holder uid %d", peerUID, os.Geteuid())
	}

	payload, err := conn.readRaw()
	if err != nil {
		return err
	}

	reject := func(message string) error {
		return conn.write(map[string]any{"type": "error", "message": message})
	}

	var command struct {
		Type      string `json:"type"`
		SessionID string `json:"session_id,omitempty"`
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&command); err != nil {
		return reject(err.Error())
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return reject("trailing command data")
	}

	h.mu.Lock()
	h.commands = append(h.commands, command.Type)
	h.mu.Unlock()

	switch command.Type {
	case "fetch":
		h.mu.Lock()
		hook := h.fetchHook
		h.mu.Unlock()

		if hook != nil {
			if err := hook(); err != nil {
				return reject(err.Error())
			}
		}

		h.mu.Lock()
		if h.bundle == nil {
			h.mu.Unlock()
			return conn.write(map[string]any{"type": "empty"})
		}

		bundle, err := h.bundle.duplicate()
		h.mu.Unlock()

		if err != nil {
			return reject(err.Error())
		}

		defer bundle.close()

		if err := conn.write(map[string]any{"type": "transfer"}); err != nil {
			return err
		}
		if err := conn.writeRaw(bundle.Metadata); err != nil {
			return err
		}

		return conn.sendFDs(bundle.FDs)

	case "retain":
		metadata, err := conn.readRaw()
		if err != nil {
			return err
		}

		fds, err := conn.recvFDs(maxTransferFDs)
		if err != nil {
			return err
		}

		stored := &recoveryBundle{SessionID: command.SessionID, Metadata: metadata, FDs: fds}
		if command.SessionID == "" {
			stored.close()
			return reject("retain requires a session ID")
		}

		h.mu.Lock()
		if h.bundle != nil {
			h.mu.Unlock()
			stored.close()

			return reject("a Session Transfer is already retained")
		}

		h.bundle = stored
		h.mu.Unlock()

		return conn.write(map[string]any{"type": "retained"})

	case "release":
		h.mu.Lock()
		defer h.mu.Unlock()

		if h.bundle != nil && h.bundle.SessionID != command.SessionID {
			return reject("another session is retained")
		}
		if h.bundle != nil {
			h.bundle.close()
			h.bundle = nil
		}

		return conn.write(map[string]any{"type": "released"})

	default:
		return reject("unknown Holder command")
	}
}

func (h *fakeRecoveryHolder) receivedCommands() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	return slices.Clone(h.commands)
}

func (h *fakeRecoveryHolder) setFetchHook(hook func() error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fetchHook = hook
}

func (h *fakeRecoveryHolder) retains() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.bundle != nil
}

// requireStoredBundle waits for a Failover-Protected Session to store its
// Session Transfer and returns the stored metadata.
func (h *fakeRecoveryHolder) requireStoredBundle() controlTransferState {
	h.t.Helper()
	var metadata []byte
	if !assert.Eventually(h.t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()

		if h.bundle == nil {
			return false
		}

		metadata = slices.Clone(h.bundle.Metadata)

		return true
	}, 10*time.Second, 100*time.Millisecond,
		"the Failover-Protected Session never stored its Session Transfer in the Holder") {
		h.t.FailNow()
	}

	var state controlTransferState
	if !assert.NoError(h.t, json.Unmarshal(metadata, &state)) {
		h.t.FailNow()
	}

	assert.Equal(h.t, uint32(1), state.Version)
	assert.NotEmpty(h.t, state.Mountpoint)
	assert.NotEmpty(h.t, state.ImageDigest)

	if !assert.NotNil(h.t, state.SessionID) {
		h.t.FailNow()
	}
	if !assert.NotEmpty(h.t, *state.SessionID) {
		h.t.FailNow()
	}

	return state
}

// requireStoredBundleCopy returns a copy of the retained bundle whose
// descriptors stay open until the test ends or the copy is closed.
func (h *fakeRecoveryHolder) requireStoredBundleCopy() *recoveryBundle {
	h.t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()

	if !assert.NotNil(h.t, h.bundle) {
		h.t.FailNow()
	}

	bundleCopy, err := h.bundle.duplicate()
	if !assert.NoError(h.t, err) {
		h.t.FailNow()
	}

	h.t.Cleanup(bundleCopy.close)

	return bundleCopy
}

func (h *fakeRecoveryHolder) requireReleased() {
	h.t.Helper()
	if !assert.Eventually(h.t, func() bool {
		h.mu.Lock()
		defer h.mu.Unlock()

		return h.bundle == nil && slices.Contains(h.commands, "release")
	}, 10*time.Second, 100*time.Millisecond, "shutdown did not release the Holder's retention") {
		h.t.FailNow()
	}
}

// restoreRetainedTransfer puts back a bundle the Holder already released, as
// a Holder that missed the release would still keep it.
func (h *fakeRecoveryHolder) restoreRetainedTransfer(bundle *recoveryBundle) {
	h.t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()

	if !assert.Nil(h.t, h.bundle) {
		h.t.FailNow()
	}

	h.bundle = bundle
}

func (h *fakeRecoveryHolder) closeRetainedTransfer() {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.bundle != nil {
		h.bundle.close()
		h.bundle = nil
	}
}

func (h *fakeRecoveryHolder) cleanup() {
	if h.listener != nil {
		_ = h.listener.Close()
	}

	h.workers.Wait()
	h.closeRetainedTransfer()
}

func (c control) sendFDs(fds []int) error {
	oob := unix.UnixRights(fds...)
	n, oobn, err := c.WriteMsgUnix([]byte{'F'}, oob, nil)
	if err != nil {
		return err
	}
	if n != 1 || oobn != len(oob) {
		return fmt.Errorf("short descriptor write: payload=%d oob=%d want=1/%d", n, oobn, len(oob))
	}

	return nil
}

func mapInflightJournal(t *testing.T, fd int, protection int) []byte {
	t.Helper()
	var stat unix.Stat_t
	if !assert.NoError(t, unix.Fstat(fd, &stat)) {
		t.FailNow()
	}
	if !assert.GreaterOrEqual(t, stat.Size, int64(inflightJournalHeaderSize+inflightJournalSlotSize)) {
		t.FailNow()
	}

	mapping, err := unix.Mmap(fd, 0, int(stat.Size), protection, unix.MAP_SHARED)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	if !assert.Equal(t, inflightJournalMagic, string(mapping[:inflightJournalVersionOffset])) {
		t.FailNow()
	}
	if !assert.Equal(t, inflightJournalVersion, binary.NativeEndian.Uint32(
		mapping[inflightJournalVersionOffset:inflightJournalCapacityOffset],
	)) {
		t.FailNow()
	}

	capacity := int(binary.NativeEndian.Uint32(
		mapping[inflightJournalCapacityOffset:inflightJournalHeaderSize],
	))
	if !assert.LessOrEqual(t, inflightJournalHeaderSize+capacity*inflightJournalSlotSize, len(mapping)) {
		t.FailNow()
	}

	return mapping
}

func countInflightSlots(mapping []byte) int {
	capacity := int(binary.NativeEndian.Uint32(
		mapping[inflightJournalCapacityOffset:inflightJournalHeaderSize],
	))
	count := 0

	for index := range capacity {
		offset := inflightJournalHeaderSize + index*inflightJournalSlotSize
		if binary.NativeEndian.Uint64(mapping[offset:offset+8])&inflightSlotTagMask == inflightSlotTagInflight {
			count++
		}
	}

	return count
}

const handleHelperEnv = "NYDUS_E2E_FUSE_HANDLE_HELPER"

type handleReport struct {
	Ready      bool     `json:"ready,omitempty"`
	PreNames   int      `json:"pre_names,omitempty"`
	FileSize   int      `json:"file_size,omitempty"`
	FileDigest string   `json:"file_digest,omitempty"`
	DirNames   []string `json:"dir_names,omitempty"`
}

// handleKeeper is a separate process that holds an open file and a partly
// read directory across the daemon's crashes, then reads both to the end.
type handleKeeper struct {
	*mount.Daemon
	conn control
}

func startHandleKeeper(t *testing.T, h *harness) *handleKeeper {
	t.Helper()
	conn, childFile := newControlChannel(t)
	t.Cleanup(func() { _ = conn.Close() })
	cmd := exec.Command(os.Args[0], "-test.run=^TestWithoutAPIServer$")

	cmd.Env = append(os.Environ(),
		handleHelperEnv+"=1",
		"NYDUS_E2E_FUSE_HANDLE_FILE="+filepath.Join(h.mountpoint, recoveryHeldFileRel),
		"NYDUS_E2E_FUSE_HANDLE_DIR="+filepath.Join(h.mountpoint, heldDirRel),
	)

	cmd.ExtraFiles = []*os.File{childFile}
	keeper := &handleKeeper{
		Daemon: mount.StartCmd(t, t.TempDir(), "handle-keeper", cmd),
		conn:   conn,
	}

	if !assert.NoError(t, childFile.Close()) {
		t.FailNow()
	}

	conn.setDeadline(t)
	var ready handleReport
	if !assert.NoError(t, json.NewDecoder(conn).Decode(&ready), keeper.Log()) {
		t.FailNow()
	}
	if !assert.True(t, ready.Ready, keeper.Log()) {
		t.FailNow()
	}

	assert.Positive(t, ready.PreNames)
	assert.Less(t, ready.PreNames, heldDirEntries)

	if !assert.NoError(t, conn.SetDeadline(time.Time{})) {
		t.FailNow()
	}

	return keeper
}

// verify has the keeper finish reading through the handles it opened before
// the crashes and checks what it read.
func (k *handleKeeper) verify(t *testing.T, expectedFile []byte) {
	t.Helper()
	k.conn.setDeadline(t)
	if !assert.NoError(t, json.NewEncoder(k.conn).Encode(map[string]string{"type": "verify"})) {
		t.FailNow()
	}

	var report handleReport
	if !assert.NoError(t, json.NewDecoder(k.conn).Decode(&report), k.Log()) {
		t.FailNow()
	}

	assert.Equal(t, len(expectedFile), report.FileSize)
	expectedDigest := sha256.Sum256(expectedFile)
	assert.Equal(t, fmt.Sprintf("%x", expectedDigest), report.FileDigest)

	if !assert.Len(t, report.DirNames, heldDirEntries) {
		t.FailNow()
	}

	slices.Sort(report.DirNames)

	for i, name := range report.DirNames {
		assert.Equal(t, fmt.Sprintf("entry_%04d", i), name)
	}

	assert.NoError(t, k.conn.Close())

	if !assert.True(t, k.WaitExit(controlProtocolTimeout), k.Log()) {
		t.FailNow()
	}

	assert.Zero(t, k.ExitCode(), k.Log())
}

func runHandleHelper(t *testing.T) {
	protocol := os.NewFile(uintptr(helperInheritedFD), "held-handle-protocol")
	if !assert.NotNil(t, protocol) {
		t.FailNow()
	}

	defer func() { _ = protocol.Close() }()

	heldFile, err := os.Open(os.Getenv("NYDUS_E2E_FUSE_HANDLE_FILE"))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	defer func() { _ = heldFile.Close() }()
	heldDir := openPartialDirAt(t, os.Getenv("NYDUS_E2E_FUSE_HANDLE_DIR"))
	if !assert.False(t, heldDir.readBatch(t), "the held directory was exhausted before recovery") {
		t.FailNow()
	}
	if !assert.NoError(t, json.NewEncoder(protocol).Encode(handleReport{
		Ready:    true,
		PreNames: len(heldDir.names),
	})) {
		t.FailNow()
	}

	var command map[string]string
	if !assert.NoError(t, json.NewDecoder(protocol).Decode(&command)) {
		t.FailNow()
	}
	if !assert.Equal(t, "verify", command["type"]) {
		t.FailNow()
	}

	fileBytes, err := io.ReadAll(io.NewSectionReader(heldFile, 0, stressFileSize))
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	heldDir.readRest(t)
	heldDir.close()
	fileDigest := sha256.Sum256(fileBytes)
	assert.NoError(t, json.NewEncoder(protocol).Encode(handleReport{
		FileSize:   len(fileBytes),
		FileDigest: fmt.Sprintf("%x", fileDigest),
		DirNames:   heldDir.names,
	}))
}

func TestFakeRecoveryHolderProtocol(t *testing.T) {
	t.Parallel()
	h := &harness{supervisorSocket: mount.SocketPath(t)}
	holder := newFakeRecoveryHolder(t, h)

	connect := func(command string, sessionID ...string) control {
		raw, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: h.supervisorSocket, Net: "unix"})
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		conn := control{raw}
		t.Cleanup(func() { _ = conn.Close() })
		conn.setDeadline(t)

		request := map[string]string{"type": command}
		if len(sessionID) > 0 {
			request["session_id"] = sessionID[0]
		}

		conn.mustWrite(t, request)

		return conn
	}

	expectEOF := func(peer control, message string) {
		peer.setDeadline(t)
		_, err := peer.Read(make([]byte, 1))
		assert.ErrorIs(t, err, io.EOF, message)
	}

	assert.Equal(t, "empty", connect("fetch").mustRead(t).Type)
	assert.Equal(t, "error", connect("unknown").mustRead(t).Type)

	firstPeer, firstFD := newControlChannel(t)
	secondPeer, secondFD := newControlChannel(t)

	t.Cleanup(func() {
		_ = firstPeer.Close()
		_ = secondPeer.Close()
		_ = firstFD.Close()
		_ = secondFD.Close()
	})

	metadata := []byte(`{"opaque":"unchanged"}`)
	assert.Equal(t, "released", connect("release", "first").mustRead(t).Type,
		"releasing an empty Holder must succeed so a retry is safe")

	retain := connect("retain", "first")
	if !assert.NoError(t, retain.writeRaw(metadata)) {
		t.FailNow()
	}
	if !assert.NoError(t, retain.sendFDs([]int{int(firstFD.Fd()), int(secondFD.Fd())})) {
		t.FailNow()
	}
	if !assert.Equal(t, "retained", retain.mustRead(t).Type) {
		t.FailNow()
	}

	assert.NoError(t, firstFD.Close())
	assert.NoError(t, secondFD.Close())

	rejectedPeer, rejectedFD := newControlChannel(t)

	t.Cleanup(func() {
		_ = rejectedPeer.Close()
		_ = rejectedFD.Close()
	})

	replacement := connect("retain", "second")
	if !assert.NoError(t, replacement.writeRaw([]byte(`{"opaque":"replacement"}`))) {
		t.FailNow()
	}
	if !assert.NoError(t, replacement.sendFDs([]int{int(rejectedFD.Fd()), int(rejectedFD.Fd())})) {
		t.FailNow()
	}

	assert.Equal(t, "error", replacement.mustRead(t).Type)
	assert.NoError(t, rejectedFD.Close())
	expectEOF(rejectedPeer, "rejected replacement leaked received descriptors")

	for range 2 {
		fetch := connect("fetch")
		if !assert.Equal(t, "transfer", fetch.mustRead(t).Type) {
			t.FailNow()
		}

		got, err := fetch.readRaw()
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		assert.Equal(t, metadata, got)
		fds, err := fetch.recvFDsExact(2)
		if !assert.NoError(t, err) {
			t.FailNow()
		}

		closeFDs(fds)
	}

	assert.Equal(t, "error", connect("release", "second").mustRead(t).Type,
		"another session must not release the retained one")
	assert.True(t, holder.retains(), "a rejected release dropped the retained bundle")
	assert.Equal(t, "released", connect("release", "first").mustRead(t).Type)

	for _, peer := range []control{firstPeer, secondPeer} {
		expectEOF(peer, "release or fetch leaked descriptor copies")
	}

	assert.Equal(t, "empty", connect("fetch").mustRead(t).Type,
		"only a release or explicit cleanup should make a populated Holder empty")
	assert.False(t, holder.retains())
}
