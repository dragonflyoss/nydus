package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFuseIdmap(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("FUSE idmapped mounts require Linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("FUSE idmapped mount test requires root")
	}
	if !kernelAtLeast(t, 6, 12) {
		t.Skip("FUSE_ALLOW_IDMAP requires Linux 6.12 or newer")
	}
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("/dev/fuse is unavailable: %v", err)
	}

	root := t.TempDir()
	corpus := filepath.Join(root, "corpus")
	bootstrap := filepath.Join(root, "bootstrap")
	blobDir := filepath.Join(root, "blobs")
	require.NoError(t, os.MkdirAll(corpus, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(corpus, "owned-by-root"), []byte("idmap\n"), 0644))

	nydusBin := mustLookupExecutable(t, "nydus")
	blob := buildNydusFSImageToDir(t, nydusBin, bootstrap, blobDir, corpus, 4096)
	stagingBefore := idmapStagingInstances(t)

	t.Run("PlainControl", func(t *testing.T) {
		mountpoint := filepath.Join(root, "plain")
		stop := mountNydus(t, nydusBin, "", blob, mountpoint)
		defer stop()
		require.Equal(t, uint32(0), statOwner(t, filepath.Join(mountpoint, "owned-by-root")).Uid)
	})

	configPath := filepath.Join(root, "config.yaml")
	cacheDir := filepath.Join(root, "cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0755))
	require.NoError(t, os.WriteFile(configPath, []byte(fmt.Sprintf(`backend:
  type: local
  config:
    dir: %s
cache:
  type: local
  config:
    dir: %s
id_mapping:
  mapping:
    - internal: 0
      external: 300000
      range: 65536
`, blobDir, cacheDir)), 0644))

	mountA := filepath.Join(root, "mapped-a")
	mountB := filepath.Join(root, "mapped-b")
	sessionA := startIdmappedNydus(t, nydusBin, blob, mountA, "0:100000:65536")
	defer sessionA.stop(t)
	sessionB := startIdmappedNydus(
		t,
		nydusBin,
		"",
		mountB,
		"0:200000:65536",
		"--bootstrap",
		bootstrap,
		"--config",
		configPath,
	)
	defer sessionB.stop(t)

	ownerA := statOwner(t, filepath.Join(mountA, "owned-by-root"))
	ownerB := statOwner(t, filepath.Join(mountB, "owned-by-root"))
	require.Equal(t, uint32(100000), ownerA.Uid)
	require.Equal(t, uint32(100000), ownerA.Gid)
	require.Equal(t, uint32(200000), ownerB.Uid, "CLI mapping must replace config mapping")
	require.Equal(t, uint32(200000), ownerB.Gid, "CLI mapping must replace config mapping")

	sessionA.stop(t)
	sessionB.stop(t)

	mountC := filepath.Join(root, "mapped-config")
	sessionC := startIdmappedNydus(
		t,
		nydusBin,
		"",
		mountC,
		"",
		"--bootstrap",
		bootstrap,
		"--config",
		configPath,
	)
	defer sessionC.stop(t)
	ownerC := statOwner(t, filepath.Join(mountC, "owned-by-root"))
	require.Equal(t, uint32(300000), ownerC.Uid, "config mapping must apply without CLI extents")
	require.Equal(t, uint32(300000), ownerC.Gid, "config mapping must apply without CLI extents")
	sessionC.stop(t)

	t.Run("MissingMappingCapabilitiesFailsClosed", func(t *testing.T) {
		setpriv, err := exec.LookPath("setpriv")
		if err != nil {
			t.Skip("setpriv is unavailable")
		}
		target := filepath.Join(root, "missing-capabilities")
		require.NoError(t, os.MkdirAll(target, 0755))
		before := idmapStagingInstances(t)
		output, err := exec.Command(
			setpriv,
			"--bounding-set=-setuid,-setgid",
			nydusBin,
			"fuse",
			"--blob",
			blob,
			"--mountpoint",
			target,
			"--id-map",
			"0:100000:65536",
		).CombinedOutput()
		require.Error(t, err, "idmap startup without mapping capabilities must fail")
		require.Contains(t, string(output), "uid_map")
		require.False(t, isMountpoint(target), "failed idmap startup must not expose a mount")
		require.Eventually(t, func() bool {
			return stagingSetsEqual(before, idmapStagingInstances(t))
		}, 5*time.Second, 100*time.Millisecond, "failed idmap startup leaked a staging instance")
	})

	t.Run("OccupiedTargetFailsClosed", func(t *testing.T) {
		target := filepath.Join(root, "occupied")
		require.NoError(t, os.MkdirAll(target, 0755))
		output, err := exec.Command("mount", "-t", "tmpfs", "-o", "size=4096", "tmpfs", target).CombinedOutput()
		require.NoError(t, err, "mounting occupied target: %s", output)
		defer func() { _ = exec.Command("umount", target).Run() }()

		output, err = exec.Command(
			nydusBin,
			"fuse",
			"--blob",
			blob,
			"--mountpoint",
			target,
			"--id-map",
			"0:100000:65536",
		).CombinedOutput()
		require.Error(t, err, "an occupied target must not be stacked")
		require.Contains(t, string(output), "already a mountpoint")
		require.True(t, isMountpoint(target), "the pre-existing target mount must remain")
	})

	require.Eventually(t, func() bool {
		return stagingSetsEqual(stagingBefore, idmapStagingInstances(t))
	}, 5*time.Second, 100*time.Millisecond, "idmap staging instances leaked after shutdown")
}

type idmappedNydus struct {
	cmd     *exec.Cmd
	done    chan error
	logPath string
	mount   string
	stopped bool
}

func startIdmappedNydus(
	t *testing.T,
	nydusBin,
	blob,
	mountpoint,
	mapping string,
	extraArgs ...string,
) *idmappedNydus {
	t.Helper()
	require.NoError(t, os.MkdirAll(mountpoint, 0755))
	logPath := filepath.Join(t.TempDir(), "nydus-idmap.log")
	logFile, err := os.Create(logPath)
	require.NoError(t, err)

	args := []string{"fuse", "--mountpoint", mountpoint}
	if mapping != "" {
		args = append(args, "--id-map", mapping)
	}
	if blob != "" {
		args = append(args, "--blob", blob)
	}
	args = append(args, extraArgs...)
	cmd := exec.Command(nydusBin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
		_ = logFile.Close()
	}()

	session := &idmappedNydus{
		cmd:     cmd,
		done:    done,
		logPath: logPath,
		mount:   mountpoint,
	}
	deadline := time.After(15 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-done:
			session.stopped = true
			output, _ := os.ReadFile(logPath)
			if idmapUnsupported(string(output)) {
				t.Skipf("running kernel/FUSE stack does not support idmapped FUSE: %s", output)
			}
			require.NoError(t, err, "nydus idmap mount failed:\n%s", output)
			require.FailNow(t, "nydus exited before mounting", string(output))
		case <-ticker.C:
			if isMountpoint(mountpoint) {
				return session
			}
		case <-deadline:
			_ = cmd.Process.Kill()
			<-done
			session.stopped = true
			output, _ := os.ReadFile(logPath)
			require.FailNow(t, "nydus idmap mount timed out", string(output))
		}
	}
}

func (session *idmappedNydus) stop(t *testing.T) {
	t.Helper()
	if session.stopped {
		return
	}
	session.stopped = true
	require.NoError(t, session.cmd.Process.Signal(syscall.SIGTERM))
	select {
	case err := <-session.done:
		output, _ := os.ReadFile(session.logPath)
		require.NoError(t, err, "nydus idmap shutdown failed:\n%s", output)
	case <-time.After(10 * time.Second):
		_ = session.cmd.Process.Kill()
		<-session.done
		output, _ := os.ReadFile(session.logPath)
		require.FailNow(t, "nydus idmap shutdown timed out", string(output))
	}
	require.Eventually(t, func() bool {
		return !isMountpoint(session.mount)
	}, 5*time.Second, 100*time.Millisecond, "visible idmapped mount leaked")
}

func statOwner(t *testing.T, path string) *syscall.Stat_t {
	t.Helper()
	var stat syscall.Stat_t
	require.NoError(t, syscall.Lstat(path, &stat))
	return &stat
}

func idmapUnsupported(output string) bool {
	return strings.Contains(output, "kernel did not accept FUSE_ALLOW_IDMAP") ||
		strings.Contains(output, "mount_setattr(MOUNT_ATTR_IDMAP)") &&
			strings.Contains(output, "Operation not supported")
}

func kernelAtLeast(t *testing.T, wantMajor, wantMinor int) bool {
	t.Helper()
	output, err := exec.Command("uname", "-r").Output()
	require.NoError(t, err)
	fields := strings.SplitN(strings.TrimSpace(string(output)), ".", 3)
	require.GreaterOrEqual(t, len(fields), 2)
	major, err := strconv.Atoi(fields[0])
	require.NoError(t, err)
	minor, err := strconv.Atoi(fields[1])
	require.NoError(t, err)
	return major > wantMajor || major == wantMajor && minor >= wantMinor
}

func idmapStagingInstances(t *testing.T) map[string]struct{} {
	t.Helper()
	entries, err := os.ReadDir("/run/nydus/idmap")
	if os.IsNotExist(err) {
		return map[string]struct{}{}
	}
	require.NoError(t, err)
	instances := make(map[string]struct{})
	for _, entry := range entries {
		if entry.IsDir() && entry.Name() != "locks" {
			instances[entry.Name()] = struct{}{}
		}
	}
	return instances
}

func stagingSetsEqual(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if _, ok := right[key]; !ok {
			return false
		}
	}
	return true
}
