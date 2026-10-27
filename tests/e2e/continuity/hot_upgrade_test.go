package continuity

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestHotUpgrade(t *testing.T) {
	t.Parallel()
	env, _ := setupContinuityHarness(t)
	heldSource, err := os.ReadFile(filepath.Join(env.sourceDir, heldFileRel))
	require.NoError(t, err)
	stressSource, err := os.ReadFile(filepath.Join(env.sourceDir, stressFileRel))
	require.NoError(t, err)

	predecessor := *env
	if os.Getenv("NYDUS_E2E_FUSE_PREDECESSOR") != "" {
		bin, err := exec.LookPath(os.Getenv("NYDUS_E2E_FUSE_PREDECESSOR"))
		require.NoError(t, err)
		bin, err = filepath.Abs(bin)
		require.NoError(t, err)
		predecessor.nydusBin = bin
	}
	old := predecessor.spawnDaemonIncarnation(t, "old")
	env.requireMounted(t, "the first daemon failed to mount")
	env.requireServingSession(t, old, 10*time.Second, 100*time.Millisecond,
		"the first daemon did not publish its control endpoint")
	require.FileExists(t, env.stateBase()+".owner",
		"startup did not create its mountpoint-keyed lifetime ownership lock")
	require.FileExists(t, env.stateBase()+".lock",
		"startup did not create its mountpoint-keyed startup lock")
	devOld := env.mountIdentity(t)
	oracle.VerifyMount(t, env.mntDir, oracle.ScanSource(t, env.sourceDir), oracle.CompareOptions{Nlink: true})

	held, err := os.Open(filepath.Join(env.mntDir, heldFileRel))
	require.NoError(t, err)
	defer func() { _ = held.Close() }()
	firstHalf := make([]byte, heldFileSize/2)
	_, err = io.ReadFull(held, firstHalf)
	require.NoError(t, err)
	require.True(t, bytes.Equal(heldSource[:heldFileSize/2], firstHalf),
		"pre-upgrade read through the held fd differs from the source")

	heldDir := openPartialDirReader(t, filepath.Join(env.mntDir, heldDirRel))
	require.False(t, heldDir.readBatch(t), "the held directory was exhausted in one small batch")
	preNames := len(heldDir.names)
	require.Greater(t, preNames, 0, "the first getdents batch returned no entries")
	require.Less(t, preNames, heldDirEntries, "the held directory must be only partially read")

	stress := startIOStress(t, env.mntDir, stressSource)

	successor := env.spawnDaemonIncarnation(t, "new")
	env.requireServingSession(t, successor, 30*time.Second, 200*time.Millisecond,
		"the successor did not publish its control endpoint")
	env.requireMountIdentity(t, devOld,
		"the mount must not move across an fd handoff (same st_dev)")
	require.True(t, successor.alive(), "the successor exited right after the handoff")
	require.Eventually(t, func() bool {
		return strings.Contains(old.logCorpus(), "handoff complete; control socket removed")
	}, 10*time.Second, 200*time.Millisecond, "the old daemon did not log handoff completion")
	require.True(t, old.waitExit(30*time.Second),
		"the old daemon did not exit after the handoff despite having nothing left to serve")
	require.True(t, old.cmd.ProcessState.Success(),
		"the old daemon exited non-zero after the handoff: %v", old.cmd.ProcessState)

	secondHalf, err := io.ReadAll(held)
	require.NoError(t, err)
	require.Len(t, secondHalf, heldFileSize/2)
	require.True(t, bytes.Equal(heldSource[heldFileSize/2:], secondHalf),
		"post-upgrade read through the held fd differs from the source")
	require.NoError(t, held.Close())

	heldDir.readRest(t)
	heldDir.close()
	require.Len(t, heldDir.names, heldDirEntries,
		"the directory handle did not list every entry after handoff")
	slices.Sort(heldDir.names)
	for i, name := range heldDir.names {
		require.Equal(t, fmt.Sprintf("entry_%04d", i), name, "unexpected directory entry")
	}

	oracle.VerifyMount(t, env.mntDir, oracle.ScanSource(t, env.sourceDir), oracle.CompareOptions{Nlink: true})
	_, err = os.Stat(env.ctlSock)
	require.NoError(t, err, "the successor did not re-publish the control socket")

	ops, errs, maxStall := stress.stop(t)
	t.Logf("stress: %d iterations across hot upgrade, max stall %v", ops, maxStall)
	require.Greater(t, ops, int64(0), "the stress loop never completed an iteration")
	require.Empty(t, errs, "IO errors during hot upgrade: %v", errs)
	require.Less(t, maxStall, maxUpgradeStall,
		"a stress iteration stalled for %v — the handoff pause is not bounded", maxStall)

	shutdownHeld, err := os.Open(filepath.Join(env.mntDir, heldFileRel))
	require.NoError(t, err)
	require.NoError(t, successor.cmd.Process.Signal(unix.SIGTERM))
	require.True(t, successor.waitExit(30*time.Second), "the final daemon ignored SIGTERM")
	require.True(t, successor.cmd.ProcessState.Success(),
		"the final daemon exited non-zero on SIGTERM: %v", successor.cmd.ProcessState)
	env.requireUnmounted(t, "the mountpoint is still mounted after shutdown")
	_ = shutdownHeld.Close()
}
