package continuity

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestWithoutAPIServer(t *testing.T) {
	t.Parallel()
	env, source := setupContinuityHarness(t)
	apiPath := env.ctlSock
	env.ctlSock = ""
	initial := env.spawnDaemonIncarnation(t, "api-off-initial")
	env.requireMounted(t, "API-off daemon failed to mount")
	require.FileExists(t, env.stateBase()+".owner")
	require.FileExists(t, env.stateBase()+".lock")
	dev := env.mountIdentity(t)
	env.requireFilesystem(t, source, dev)
	require.NoFileExists(t, apiPath, "API-off startup created an HTTP socket")
	require.True(t, initial.alive(), initial.logCorpus())
	require.NoError(t, initial.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, initial.waitExit(30*time.Second), "API-off daemon ignored SIGTERM")
	require.True(t, initial.cmd.ProcessState.Success(), initial.logCorpus())
	env.requireUnmounted(t, "API-off shutdown left the mount attached")
}
