package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var sha256FilenamePattern = regexp.MustCompile("^[0-9a-f]{64}$")
var blobMetaFilenamePattern = regexp.MustCompile(`^[0-9a-f]{64}\.blob\.meta$`)

const (
	erofsCFuseEnv = "EROFS_C_FUSE"
	erofsMkfsEnv  = "EROFS_MKFS"
)

// setupXfstests checks if the xfstests "check" script is present in the given directory, and if not, runs the setup_xfstests.sh script to
// set up the xfstests environment.
func setupXfstests(t *testing.T, dir string) {
	if _, err := os.Stat(filepath.Join(dir, "check")); os.IsNotExist(err) {
		script, err := filepath.Abs(filepath.Join("..", "scripts", "setup_xfstests.sh"))
		require.NoError(t, err)
		require.FileExists(t, script)

		out, err := exec.Command("bash", script).CombinedOutput()
		require.NoError(t, err, "setup_xfstests.sh failed:\n%s", out)
	}
}

// setupCErofsfuse checks if erofsfuse is available. An explicit EROFS_C_FUSE
// path wins and skips the setup script.
func setupCErofsfuse(t *testing.T) {
	if _, err := lookupCErofsFuseExecutable(); err == nil {
		if os.Getenv(erofsMkfsEnv) != "" {
			_, err := lookupCErofsMkfsExecutable()
			require.NoError(t, err)
		}
		return
	} else if os.Getenv(erofsCFuseEnv) != "" {
		require.NoError(t, err)
	}

	script, err := filepath.Abs(filepath.Join("..", "scripts", "setup_erofsfuse.sh"))
	require.NoError(t, err)

	out, err := exec.Command("bash", script).CombinedOutput()
	require.NoError(t, err, "setup_erofsfuse.sh failed:\n%s", out)
}

// mustLookupExecutable is a test helper that wraps lookupExecutable and fails the test if the executable is not found.
func mustLookupExecutable(t *testing.T, name string) string {
	p, err := lookupExecutable(name)
	require.NoError(t, err)
	return p
}

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

// mustLookupCErofsFuse is a test helper that wraps lookupCErofsFuseExecutable and fails the test if the erofsfuse executable is not found.
func mustLookupCErofsFuse(t *testing.T) string {
	p, err := lookupCErofsFuseExecutable()
	require.NoError(t, err)
	return p
}

// lookupCErofsFuseExecutable tries to find the erofsfuse executable, which is required for comparison testing.
// It first checks the EROFS_C_FUSE environment variable, then looks in common locations, and
// finally checks the PATH.
func lookupCErofsFuseExecutable() (string, error) {
	if p := os.Getenv(erofsCFuseEnv); p != "" {
		if err := validateExecutablePath(p, erofsCFuseEnv); err != nil {
			return "", err
		}
		return p, nil
	}

	for _, p := range []string{
		"/usr/bin/erofsfuse",
		"/usr/local/bin/erofsfuse",
	} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	if p, err := exec.LookPath("erofsfuse"); err == nil {
		return p, nil
	}

	return "", fmt.Errorf("erofsfuse not found, set %s=path to enable comparison", erofsCFuseEnv)
}

func lookupCErofsMkfsExecutable() (string, error) {
	if p := os.Getenv(erofsMkfsEnv); p != "" {
		if err := validateExecutablePath(p, erofsMkfsEnv); err != nil {
			return "", err
		}
		return p, nil
	}

	if p, err := exec.LookPath("mkfs.erofs"); err == nil {
		return p, nil
	}

	return "", fmt.Errorf("mkfs.erofs not found, set %s=path if a test requires it", erofsMkfsEnv)
}

func validateExecutablePath(path, envName string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s=%s is not accessible: %w", envName, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s=%s points to a directory", envName, path)
	}
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("%s=%s is not executable", envName, path)
	}
	return nil
}

// mustLookupFio is a test helper that wraps lookupExecutable for "fio" and fails the test if fio is not found.
func mustLookupFio(t *testing.T) string {
	p, err := exec.LookPath("fio")
	require.NoError(t, err, "fio not found; install with: apt-get install fio")
	return p
}

// dropCaches drops the Linux page cache, dentries, and inodes by writing to /proc/sys/vm/drop_caches.
func dropCaches(t *testing.T) {
	// Sync the filesystem to ensure all dirty data is flushed to disk before dropping caches.
	syscall.Sync()

	// Write "3" to /proc/sys/vm/drop_caches to drop page cache, dentries, and inodes.
	err := os.WriteFile("/proc/sys/vm/drop_caches", []byte("3"), 0644)
	require.NoError(t, err)

	// Wait a moment to allow the system to drop caches before proceeding with the test.
	time.Sleep(500 * time.Millisecond)
}

// isMountpoint reports whether path is currently a mountpoint.
func isMountpoint(path string) bool {
	return exec.Command("mountpoint", "-q", path).Run() == nil
}

// mountCErofsFuse mounts the EROFS image at imagePath using the C erofsfuse implementation and
// returns a cleanup function to unmount it.
func mountCErofsFuse(t *testing.T, cErofsFuseBin, imagePath, mnt string, blobdevs ...string) (cleanup func()) {
	_ = exec.Command("fusermount", "-u", mnt).Run()
	require.NoError(t, os.MkdirAll(mnt, 0755))

	// Invocation: erofsfuse [--device=BLOB]... IMAGE MOUNTPOINT -f
	args := []string{}
	for _, blobdev := range blobdevs {
		if blobdev == "" {
			continue
		}
		args = append(args, "--device="+blobdev)
	}
	args = append(args, imagePath, mnt, "-f")

	cmd := exec.Command(cErofsFuseBin, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	// Wait for the mountpoint to become ready.
	require.Eventually(t, func() bool {
		return isMountpoint(mnt)
	}, 10*time.Second, 200*time.Millisecond, "erofsfuse failed to mount within 10s")

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

// mountLepton runs `lepton fuse` in the background and returns a cleanup
// function that unmounts the filesystem and reaps the child process.
func mountLepton(t *testing.T, leptonBin, imagePath, blobdev, mnt string) (cleanup func()) {
	_ = exec.Command("fusermount", "-u", mnt).Run()
	require.NoError(t, os.MkdirAll(mnt, 0755))

	args := []string{"fuse", "--mountpoint", mnt}
	if imagePath != "" && blobdev != "" {
		args = append(args, "--bootstrap", imagePath, "--blob-dir", filepath.Dir(blobdev))
	} else if blobdev != "" {
		args = append(args, "--blob", blobdev)
	} else {
		require.FailNow(t, "mountLepton requires either blobdev or imagePath+blobdev")
	}

	cmd := exec.Command(leptonBin, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	// Wait for the mountpoint to become ready.
	require.Eventually(t, func() bool {
		return isMountpoint(mnt)
	}, 10*time.Second, 200*time.Millisecond, "lepton fuse failed to mount within 10s")

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

// mountLeptonBootstrap runs `lepton fuse` using a bootstrap plus a blob directory.
func mountLeptonBootstrap(t *testing.T, leptonBin, bootstrapPath, blobDir, mnt string) (cleanup func()) {
	return mountLeptonBootstrapWithCache(t, leptonBin, bootstrapPath, blobDir, "", mnt)
}

// mountLeptonBootstrapWithCache runs `lepton fuse` using a bootstrap plus a blob directory,
// optionally enabling the persistent chunk cache.
func mountLeptonBootstrapWithCache(
	t *testing.T,
	leptonBin,
	bootstrapPath,
	blobDir,
	cacheDir,
	mnt string,
) (cleanup func()) {
	_ = exec.Command("fusermount", "-u", mnt).Run()
	require.NoError(t, os.MkdirAll(mnt, 0755))

	args := []string{"fuse", "--bootstrap", bootstrapPath, "--blob-dir", blobDir, "--mountpoint", mnt}
	if cacheDir != "" {
		require.NoError(t, os.MkdirAll(cacheDir, 0755))
		args = append(args, "--cache-dir", cacheDir)
	}
	cmd := exec.Command(leptonBin, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	require.Eventually(t, func() bool {
		return isMountpoint(mnt)
	}, 10*time.Second, 200*time.Millisecond, "lepton bootstrap fuse failed to mount within 10s")

	return func() {
		_ = exec.Command("fusermount", "-u", mnt).Run()

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
func buildLeptonFSImage(t *testing.T, leptonBin, imagePath, blobdev, srcDir string, chunkSize int) string {
	args := []string{"build", "--blob", blobdev, "--chunk-size", fmt.Sprint(chunkSize), "--compressor", "zstd"}
	if imagePath != "" {
		args = append(args, "--bootstrap", imagePath)
	}
	args = append(args, srcDir)

	out, err := exec.Command(leptonBin, args...).CombinedOutput()
	require.NoError(t, err, "lepton build failed: %s", string(out))
	return blobdev
}

func buildLeptonFSImageToDir(t *testing.T, leptonBin, imagePath, blobDir, srcDir string, chunkSize int) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(blobDir, 0755))
	before := listFilesInDir(t, blobDir)

	args := []string{"build", "--blob-dir", blobDir, "--chunk-size", fmt.Sprint(chunkSize), "--compressor", "zstd"}
	if imagePath != "" {
		args = append(args, "--bootstrap", imagePath)
	}
	args = append(args, srcDir)

	out, err := exec.Command(leptonBin, args...).CombinedOutput()
	require.NoError(t, err, "lepton build --blob-dir failed: %s", string(out))

	after := listFilesInDir(t, blobDir)
	var blobs []string
	var blobMetas []string
	var unexpected []string
	for path := range after {
		if _, existed := before[path]; existed {
			continue
		}

		base := filepath.Base(path)
		switch {
		case sha256FilenamePattern.MatchString(base):
			blobs = append(blobs, path)
		case blobMetaFilenamePattern.MatchString(base):
			blobMetas = append(blobMetas, path)
		default:
			unexpected = append(unexpected, path)
		}
	}
	require.Empty(t, unexpected, "unexpected files created in blob-dir: %v", unexpected)
	require.Len(t, blobs, 1, "expected exactly one new blob in blob-dir")
	require.Len(t, blobMetas, 1, "expected exactly one new blob_meta in blob-dir")
	require.True(t, sha256FilenamePattern.MatchString(filepath.Base(blobs[0])), "blob file name must be sha256: %s", blobs[0])
	return blobs[0]
}

// mergeLeptonBootstrap invokes `lepton merge` and writes an overlaid bootstrap.
func mergeLeptonBootstrap(t *testing.T, leptonBin, bootstrapPath string, sources ...string) {
	args := []string{"merge", "--bootstrap", bootstrapPath}
	args = append(args, sources...)

	out, err := exec.Command(leptonBin, args...).CombinedOutput()
	require.NoError(t, err, "lepton merge failed: %s", string(out))
}

func listFilesInDir(t *testing.T, dir string) map[string]struct{} {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	files := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			files[filepath.Join(dir, entry.Name())] = struct{}{}
		}
	}
	return files
}
