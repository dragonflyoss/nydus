package continuity

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if os.Getenv("NYDUS_E2E_FUSE_PRE_READY_HELPER") == "1" {
		runPreReadyHelper(childAssertions{})
	}
	os.Exit(m.Run())
}

type assertionTB interface {
	require.TestingT
	Helper()
}

// The protocol child runs before the test suite: keep its assertions, but do not
// register an always-skipped fake test in the parent suite.
type childAssertions struct{}

func (childAssertions) Helper() {}
func (childAssertions) Errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
func (childAssertions) FailNow() { os.Exit(1) }

func runPreReadyHelper(t assertionTB) {
	mountpoint, err := filepath.EvalSymlinks(os.Getenv("NYDUS_E2E_FUSE_MOUNTPOINT"))
	require.NoError(t, err)
	imageBytes, err := os.ReadFile(os.Getenv("NYDUS_E2E_FUSE_BOOTSTRAP"))
	require.NoError(t, err)
	imageDigest := sha256.Sum256(imageBytes)
	conn, err := dialControl(strings.TrimPrefix(os.Getenv("NYDUS_E2E_FUSE_APISERVER"), "unix://"), 5*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	writeCtlFrame(t, conn, map[string]string{"type": "info"})
	info := readCtlFrame(t, conn)
	require.Equal(t, "info", info.Type)
	require.NotNil(t, info.Info)
	require.Equal(t, mountpoint, info.Info.Mountpoint)
	require.Equal(t, fmt.Sprintf("%x", imageDigest), info.Info.ImageDigest)
	require.Nil(t, info.SessionID)
	setControlDeadline(t, conn)
	writeCtlFrame(t, conn, map[string]any{
		"type": "handoff_begin",
		"peer": ctlInstanceInfo{
			PID:         uint32(os.Getpid()),
			Version:     "e2e-pre-ready-successor",
			Mountpoint:  mountpoint,
			ImageDigest: fmt.Sprintf("%x", imageDigest),
		},
	})
	response := readCtlFrame(t, conn)
	require.Equal(t, "handoff_transfer", response.Type,
		"pre-READY successor expected a Session Transfer, got %q: %s",
		response.Type, response.Message)
	metadata, err := readRawFrame(conn)
	require.NoError(t, err)
	require.NotEmpty(t, metadata)
	var state ctlTransferState
	require.NoError(t, json.Unmarshal(metadata, &state))
	require.Equal(t, uint32(1), state.Version)
	require.Equal(t, mountpoint, state.Mountpoint)
	require.Equal(t, fmt.Sprintf("%x", imageDigest), state.ImageDigest)
	require.Equal(t, uint32(7), state.FuseSessionState.ProtoMajor)
	require.NotZero(t, state.FuseSessionState.ProtoMinor)
	fds, err := recvFDsExact(conn, 1)
	require.NoError(t, err)
	defer closeFDs(fds)
	var receivedFuse, fuseDevice unix.Stat_t
	require.NoError(t, unix.Fstat(fds[0], &receivedFuse))
	require.NoError(t, unix.Stat("/dev/fuse", &fuseDevice))
	require.Equal(t, uint32(unix.S_IFCHR), receivedFuse.Mode&unix.S_IFMT)
	require.Equal(t, fuseDevice.Rdev, receivedFuse.Rdev)

	_, err = fmt.Fprintln(os.Stdout, "TRANSFERRED")
	require.NoError(t, err)
	for {
		time.Sleep(time.Hour)
	}
}
