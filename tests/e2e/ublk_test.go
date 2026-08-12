package e2e

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/stretchr/testify/require"
)

const ublkChunkSize = 4096

// TestUblkService serves an image as a ublk block device, mounts it with the
// kernel EROFS driver and checks the result matches the same image mounted
// through FUSE.
func TestUblkService(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("ublk target requires Linux")
	}
	if os.Geteuid() != 0 {
		t.Skip("ublk target requires root to create block devices")
	}

	nydusBin := mustLookupExecutable(t, "nydus")
	if out, err := exec.Command(nydusBin, "ublk", "--help").CombinedOutput(); err != nil {
		t.Skipf("nydus binary does not include the ublk subcommand; build with FEATURES=cli,ublk: %s", out)
	}
	if out, err := exec.Command("modprobe", "ublk_drv").CombinedOutput(); err != nil {
		t.Skipf("ublk_drv is unavailable (needs Linux 6.0+): %s", out)
	}
	if _, err := os.Stat("/dev/ublk-control"); err != nil {
		t.Skipf("/dev/ublk-control is missing: %v", err)
	}

	tmpDir := t.TempDir()
	corpusDir := filepath.Join(tmpDir, "corpus")
	bootstrapPath := filepath.Join(tmpDir, "image.boot")
	blobDir := filepath.Join(tmpDir, "blobs")
	cacheDir := filepath.Join(tmpDir, "cache")
	logDir := filepath.Join(tmpDir, "logs")
	configPath := filepath.Join(tmpDir, "config.yaml")
	blockMnt := filepath.Join(tmpDir, "mnt-ublk")
	fuseMnt := filepath.Join(tmpDir, "mnt-fuse")

	corpus.MakeStandardCorpus(t, corpusDir)
	buildNydusFSImageToDir(t, nydusBin, bootstrapPath, blobDir, corpusDir, ublkChunkSize)
	writeLocalStorageConfig(t, configPath, blobDir, cacheDir)

	devPath, stopDaemon := startUblkService(t, nydusBin, bootstrapPath, configPath, logDir)
	defer stopDaemon()

	require.NoError(t, os.MkdirAll(blockMnt, 0755))
	out, err := exec.Command("mount", "-t", "erofs", "-o", "ro", devPath, blockMnt).CombinedOutput()
	require.NoError(t, err, "failed to mount %s as erofs: %s", devPath, out)
	// Unmount before the daemon is stopped: the daemon serves I/O for its own
	// device, so an unmount that flushes I/O while it is exiting would hang.
	defer func() {
		if out, err := exec.Command("umount", blockMnt).CombinedOutput(); err != nil {
			t.Logf("failed to umount %s: %s", blockMnt, out)
		}
	}()

	umountFuse := mountNydusBootstrapWithCache(t, nydusBin, bootstrapPath, blobDir, "", fuseMnt)
	defer umountFuse()

	// The FUSE mount is the reference implementation of the same image, so any
	// mismatch points at the flattened block address space.
	compareTrees(t, fuseMnt, blockMnt)

	entries, err := os.ReadDir(blockMnt)
	require.NoError(t, err)
	require.NotEmpty(t, entries, "ublk/erofs mount is empty")
}

// compareTrees checks that `got` exposes exactly the same tree as `want`:
// same entries, types, modes, sizes, symlink targets and file contents.
func compareTrees(t *testing.T, want, got string) {
	t.Helper()

	wantEntries := describeTree(t, want)
	gotEntries := describeTree(t, got)
	require.Equal(t, wantEntries, gotEntries, "ublk/erofs mount differs from the FUSE mount")

	for rel, info := range wantEntries {
		if !info.mode.IsRegular() {
			continue
		}
		require.Equal(t, sha256File(t, filepath.Join(want, rel)), sha256File(t, filepath.Join(got, rel)),
			"content mismatch for %s", rel)
	}
}

type entryInfo struct {
	mode    os.FileMode
	size    int64
	symlink string
}

func describeTree(t *testing.T, root string) map[string]entryInfo {
	t.Helper()

	entries := make(map[string]entryInfo)
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}

		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		entry := entryInfo{mode: info.Mode()}
		switch {
		case info.Mode().IsRegular():
			entry.size = info.Size()
		case info.Mode()&os.ModeSymlink != 0:
			entry.symlink, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		entries[rel] = entry
		return nil
	}))

	return entries
}

// startUblkService runs `nydus ublk` and returns the device path it prints on
// stdout together with a shutdown function.
func startUblkService(t *testing.T, nydusBin, bootstrapPath, configPath, logDir string) (string, func()) {
	t.Helper()
	require.NoError(t, os.MkdirAll(logDir, 0755))

	cmd := exec.Command(nydusBin, "ublk",
		"--bootstrap", bootstrapPath,
		"--config", configPath,
		"--log-dir", logDir,
	)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	stop := func() {
		if cmd.Process == nil {
			return
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _, _ = cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
		}
	}

	type result struct {
		path string
		err  error
	}
	results := make(chan result, 1)
	go func() {
		// The daemon also logs to stdout, so scan for the device path line
		// rather than assuming it comes first.
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "/dev/ublkb") {
				results <- result{path: line}
				return
			}
		}
		results <- result{err: fmt.Errorf("no device path on stdout: %v", scanner.Err())}
	}()

	select {
	case res := <-results:
		if res.err != nil || res.path == "" {
			stop()
			t.Fatalf("nydus ublk did not report a device path: %v", res.err)
		}
		require.Eventually(t, func() bool {
			_, err := os.Stat(res.path)
			return err == nil
		}, 10*time.Second, 200*time.Millisecond, "%s did not appear within 10s", res.path)
		return res.path, stop
	case <-time.After(30 * time.Second):
		stop()
		t.Fatal("timed out waiting for nydus ublk to start")
		return "", stop
	}
}
