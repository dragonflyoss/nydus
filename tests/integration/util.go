package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// lookupExecutable tries to find the given executable name on PATH or unorderedly under ../../target/{release,debug}/.
// This allows the tests to run without requiring the user to have installed the binary or to have built it in
// a specific way.
func lookupExecutable(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}

	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		return "", err
	}

	for _, profile := range []string{"release", "debug"} {
		p := filepath.Join(root, "target", profile, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	return "", fmt.Errorf("%s not found on PATH or in target/{release,debug}/", name)
}

// mustLookupExecutable is a test helper that wraps lookupExecutable and fails the test if the executable is not found.
func mustLookupExecutable(t *testing.T, name string) string {
	p, err := lookupExecutable(name)
	if err != nil {
		require.NoError(t, err)
	}

	return p
}

// isMountpoint reports whether path is currently a mountpoint.
func isMountpoint(path string) bool {
	return exec.Command("mountpoint", "-q", path).Run() == nil
}

// mountLepton runs `lepton mount` in the background and returns a cleanup
// function that unmounts the filesystem and reaps the child process.
func mountLepton(t *testing.T, leptonBin, imagePath, blobdev, mnt string) (cleanup func()) {
	require.NoError(t, os.MkdirAll(mnt, 0755))
	args := []string{"mount", imagePath, mnt}
	if blobdev != "" {
		args = append(args, "--blobdev", blobdev)
	}

	cmd := exec.Command(leptonBin, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	// Wait for the mountpoint to become ready.
	require.Eventually(t, func() bool {
		return isMountpoint(mnt)
	}, 10*time.Second, 200*time.Millisecond, "lepton mount failed to mount within 10s")

	return func() {
		_ = exec.Command("fusermount", "-u", mnt).Run()

		// Send SIGTERM and don't block indefinitely while waiting.
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan struct{})
			go func() { _ = cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
			}
		}
	}
}

// buildLeptonFSImage invokes `lepton build` to create an LeptonFS image and its
// associated blob device file.
func buildLeptonFSImage(t *testing.T, leptonBin, imagePath, blobdev, srcDir string) {
	args := []string{"build", imagePath, srcDir, "--chunksize", "4096"}
	if blobdev != "" {
		args = append(args, "--blobdev", blobdev)
	}

	out, err := exec.Command(leptonBin, args...).CombinedOutput()
	require.NoError(t, err, "lepton build failed: %s", string(out))
}
