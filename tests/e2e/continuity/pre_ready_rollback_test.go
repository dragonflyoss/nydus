package continuity

import (
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPreReadyRollback(t *testing.T) {
	t.Parallel()
	env, stressSource := setupContinuityHarness(t)

	old := env.spawnDaemonIncarnation(t, "old")
	env.requireMounted(t, "the daemon failed to mount")
	env.requireServingSession(t, old, 10*time.Second, 100*time.Millisecond,
		"the daemon did not publish its control endpoint")
	devOld := env.mountIdentity(t)
	stress := startIOStress(t, env.mntDir, stressSource)

	fakeSuccessor := env.startFakeHotUpgradeSuccessor(t)

	// The old daemon is paused now; the kernel queues requests. Give the
	// stress loop time to pile a few up, then "crash" before reporting ready:
	// close our fd copy and the control connection (EOF).
	time.Sleep(2 * time.Second)
	require.NoError(t, fakeSuccessor.cmd.Process.Kill())
	require.True(t, fakeSuccessor.waitExit(controlProtocolTimeout))
	require.Error(t, fakeSuccessor.waitErr)

	require.Eventually(t, func() bool {
		return strings.Contains(old.logCorpus(), "resuming service")
	}, 15*time.Second, 200*time.Millisecond,
		"the old daemon did not resume after the successor died")
	require.True(t, old.alive(), "the old daemon must survive an aborted handoff")
	env.requireServingSession(t, old, 10*time.Second, 100*time.Millisecond,
		"rollback did not restore the predecessor's control endpoint")
	env.requireMountIdentity(t, devOld, "the mount must be untouched")

	// The queued requests must have been served: keep stressing a little,
	// then assert zero errors across the pause + resume.
	time.Sleep(2 * time.Second)
	ops, errs, maxStall := stress.stop(t)
	t.Logf("stress: %d iterations across the aborted handoff, max stall %v", ops, maxStall)
	require.Greater(t, ops, int64(0), "the stress loop never completed an iteration")
	require.Empty(t, errs, "IO errors during the aborted handoff: %v", errs)
	require.Less(t, maxStall, maxUpgradeStall,
		"a stress iteration stalled for %v — the fallback did not resume promptly", maxStall)
	oracle.VerifyMount(t, env.mntDir, oracle.ScanSource(t, env.sourceDir), oracle.CompareOptions{Nlink: true})

	successor := env.spawnDaemonIncarnation(t, "new")
	env.requireServingSession(t, successor, 30*time.Second, 200*time.Millisecond,
		"upgrade after rollback did not publish the successor's control endpoint")
	require.True(t, old.waitExit(30*time.Second), "the old daemon did not exit")
	require.True(t, old.cmd.ProcessState.Success(),
		"the old daemon exited non-zero: %v", old.cmd.ProcessState)
	oracle.VerifyMount(t, env.mntDir, oracle.ScanSource(t, env.sourceDir), oracle.CompareOptions{Nlink: true})

	require.NoError(t, successor.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, successor.waitExit(30*time.Second), "the successor ignored SIGTERM")
	env.requireUnmounted(t, "the mountpoint is still mounted after shutdown")
}
