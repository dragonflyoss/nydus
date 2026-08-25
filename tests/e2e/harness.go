package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
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

// setupCErofsFuse checks if erofsfuse is available. An explicit EROFS_C_FUSE
// path wins and skips the setup script.
func setupCErofsFuse(t *testing.T) {
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

// lookupExecutable tries to find the given executable name unorderedly under
// ../../target/{release,debug}/ (and ../../nydusify/ for the Go binary), then
// falls back to PATH. In-tree builds win so the tests always exercise the
// freshly built binaries even when a stale copy is installed system-wide.
func lookupExecutable(name string) (string, error) {
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

	// The nydusify Go binary is built in-tree at nydusify/nydusify.
	if p := filepath.Join(root, "nydusify", name); name == "nydusify" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}

	return "", fmt.Errorf("%s not found in target/{release,debug}/ or on PATH", name)
}

// envOr returns the value of the named environment variable, or def when it
// is unset or empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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

// fsckErofsImage validates a freshly built bootstrap with erofs-utils. A nydus
// image is plain EROFS, so fsck.erofs is an oracle that is completely
// independent of the nydus reader: it catches encoding bugs that the reader
// happens to tolerate. Skipped when erofs-utils is not installed so the check
// can be added everywhere without making it a hard dependency.
func fsckErofsImage(t *testing.T, bootstrap, blobDir string) {
	t.Helper()

	fsck, err := exec.LookPath("fsck.erofs")
	if err != nil {
		t.Logf("fsck.erofs not found, skipping structural validation of %s", bootstrap)
		return
	}

	devices, err := erofsDeviceArgs(bootstrap, blobDir)
	require.NoError(t, err, "reading the device table of %s", bootstrap)

	args := append([]string{"--extract"}, devices...)
	args = append(args, bootstrap)

	out, err := exec.Command(fsck, args...).CombinedOutput()
	require.NoError(t, err, "fsck.erofs rejected %s: %s", bootstrap, out)
	// fsck.erofs still exits 0 after reporting structural problems such as
	// "wrong dirent name order", so the output has to be scanned as well.
	require.NotContains(t, string(out), "filesystem corruption",
		"fsck.erofs found corruption in %s", bootstrap)
}

// EROFS on-disk offsets needed to locate the device table.
const (
	erofsSuperOffset   = 1024
	erofsSuperMagic    = 0xE0F5E1E2
	erofsDevSlotSize   = 128
	erofsDevTagLen     = 64
	erofsExtraDevicesO = 86 // u16, relative to the superblock
	erofsDevtSlotOffO  = 88 // u16, relative to the superblock
)

// erofsDeviceArgs builds the fsck.erofs --device flags from the image's own
// device table. Listing the blob directory instead would be wrong for merged
// images: the directory accumulates the blobs of every layer, while a given
// bootstrap references only its own, and fsck rejects a count mismatch.
func erofsDeviceArgs(bootstrap, blobDir string) ([]string, error) {
	f, err := os.Open(bootstrap)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	header := make([]byte, erofsSuperOffset+128)
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, fmt.Errorf("reading superblock: %w", err)
	}
	sb := header[erofsSuperOffset:]
	if magic := binary.LittleEndian.Uint32(sb); magic != erofsSuperMagic {
		return nil, fmt.Errorf("bad EROFS magic 0x%08x in %s", magic, bootstrap)
	}

	count := int(binary.LittleEndian.Uint16(sb[erofsExtraDevicesO:]))
	if count == 0 {
		return nil, nil
	}
	slotOff := int(binary.LittleEndian.Uint16(sb[erofsDevtSlotOffO:])) * erofsDevSlotSize

	table := make([]byte, count*erofsDevSlotSize)
	if _, err := f.ReadAt(table, int64(slotOff)); err != nil {
		return nil, fmt.Errorf("reading device table at %d: %w", slotOff, err)
	}

	args := make([]string, 0, count)
	for i := 0; i < count; i++ {
		tag := table[i*erofsDevSlotSize : i*erofsDevSlotSize+erofsDevTagLen]
		name := string(bytes.TrimRight(tag, "\x00"))
		if name == "" {
			return nil, fmt.Errorf("device slot %d of %s has an empty tag", i, bootstrap)
		}
		args = append(args, "--device="+filepath.Join(blobDir, name))
	}
	return args, nil
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

// startFuseMount starts a prepared FUSE daemon command, waits for mnt to
// become a mountpoint, and returns a cleanup that unmounts (with EBUSY
// retries) and reaps the child.
func startFuseMount(t *testing.T, cmd *exec.Cmd, mnt, label string) (cleanup func()) {
	t.Helper()
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	require.NoError(t, cmd.Start())

	require.Eventually(t, func() bool {
		return isMountpoint(mnt)
	}, 10*time.Second, 200*time.Millisecond, label+" failed to mount within 10s")

	return func() {
		unmountFuse(mnt)

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

	return startFuseMount(t, exec.Command(cErofsFuseBin, args...), mnt, "erofsfuse")
}

// mountNydus runs `nydus fuse` in the background and returns a cleanup
// function that unmounts the filesystem and reaps the child process.
func mountNydus(t *testing.T, nydusBin, imagePath, blobdev, mnt string) (cleanup func()) {
	_ = exec.Command("fusermount", "-u", mnt).Run()
	require.NoError(t, os.MkdirAll(mnt, 0755))

	args := []string{"fuse", "--mountpoint", mnt}
	if imagePath != "" && blobdev != "" {
		args = append(args, "--bootstrap", imagePath, "--blob-dir", filepath.Dir(blobdev))
	} else if blobdev != "" {
		args = append(args, "--blob", blobdev)
	} else {
		require.FailNow(t, "mountNydus requires either blobdev or imagePath+blobdev")
	}

	return startFuseMount(t, exec.Command(nydusBin, args...), mnt, "nydus fuse")
}

// mountNydusBootstrap runs `nydus fuse` using a bootstrap plus a blob directory.
func mountNydusBootstrap(t *testing.T, nydusBin, bootstrapPath, blobDir, mnt string) (cleanup func()) {
	return mountNydusBootstrapWithCache(t, nydusBin, bootstrapPath, blobDir, "", mnt)
}

// mountNydusBootstrapWithCache runs `nydus fuse` using a bootstrap plus a blob directory,
// optionally enabling the persistent chunk cache.
func mountNydusBootstrapWithCache(
	t *testing.T,
	nydusBin,
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
	return startFuseMount(t, exec.Command(nydusBin, args...), mnt, "nydus bootstrap fuse")
}

// unmountFuse detaches mnt, retrying while the kernel still holds references.
// A umount straight after heavy I/O routinely returns EBUSY for a moment, and
// giving up there leaves a dead mountpoint that later trips up directory
// removal.
func unmountFuse(mnt string) {
	for i := 0; i < 50; i++ {
		if !isMountpoint(mnt) {
			return
		}
		for _, argv := range [][]string{
			{"fusermount3", "-u", mnt},
			{"fusermount", "-u", mnt},
		} {
			_ = exec.Command(argv[0], argv[1:]...).Run()
			if !isMountpoint(mnt) {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = exec.Command("umount", "-l", mnt).Run()
}

func buildNydusFSImageToDir(t *testing.T, nydusBin, imagePath, blobDir, srcDir string, chunkSize int) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(blobDir, 0755))
	before := listFilesInDir(t, blobDir)

	args := []string{"build", "--blob-dir", blobDir, "--chunk-size", fmt.Sprint(chunkSize), "--compressor", "zstd"}
	if imagePath != "" {
		args = append(args, "--bootstrap", imagePath)
	}
	args = append(args, srcDir)

	out, err := exec.Command(nydusBin, args...).CombinedOutput()
	require.NoError(t, err, "nydus build --blob-dir failed: %s", string(out))

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
	if imagePath != "" {
		fsckErofsImage(t, imagePath, blobDir)
	}
	return blobs[0]
}

// mergeNydusBootstrap invokes `nydus merge` and writes an overlaid bootstrap.
func mergeNydusBootstrap(t *testing.T, nydusBin, bootstrapPath string, sources ...string) {
	args := []string{"merge", "--bootstrap", bootstrapPath}
	args = append(args, sources...)

	out, err := exec.Command(nydusBin, args...).CombinedOutput()
	require.NoError(t, err, "nydus merge failed: %s", string(out))
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

// sha256File returns the hex SHA-256 of a file, streaming to support large
// files. Shared by every transport suite.
func sha256File(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	h := sha256.New()
	_, err = io.Copy(h, f)
	require.NoError(t, err)
	return hex.EncodeToString(h.Sum(nil))
}

// wipeCacheDir removes every per-blob artifact so the next daemon starts
// COLD. Leaving a stale .group.map behind makes the daemon believe groups
// are ready while the re-created .blob.data is all zeros — reads would
// return zeros without fetching. Wipe data+meta+map+lock.
func wipeCacheDir(cacheDir string) {
	for _, pattern := range []string{"*.blob.data", "*.blob.meta", "*.group.map", "*.prefetch.lock"} {
		matches, _ := filepath.Glob(filepath.Join(cacheDir, pattern))
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
}

// countMatchingLines counts the lines of corpus matching re.
func countMatchingLines(corpus string, re *regexp.Regexp) int {
	count := 0
	for _, line := range strings.Split(corpus, "\n") {
		if re.MatchString(line) {
			count++
		}
	}
	return count
}

// lookupBinFromEnv resolves a test binary: an explicit env override wins,
// otherwise the name is resolved from PATH.
func lookupBinFromEnv(t *testing.T, envName, name string) string {
	t.Helper()
	if p := os.Getenv(envName); p != "" {
		require.NoError(t, validateExecutablePath(p, envName))
		return p
	}
	return mustLookupExecutable(t, name)
}

// writeLocalStorageConfig writes the standard local-backend storage config
// (prefetch disabled) used by the transport test suites.
func writeLocalStorageConfig(t *testing.T, path, blobDir, cacheDir string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(cacheDir, 0755))
	config := fmt.Sprintf(
		"backend:\n  type: local\n  config:\n    dir: %s\nstorage:\n  dir: %s\nprefetch:\n  scope: none\n",
		blobDir,
		cacheDir,
	)
	require.NoError(t, os.WriteFile(path, []byte(config), 0644))
}

// readFileOrEmpty reads path for log dumps, treating missing or unreadable
// files as empty.
func readFileOrEmpty(path string) []byte {
	data, _ := os.ReadFile(path)
	return data
}

// daemonProc tracks a spawned transport daemon (nydus nbd/fanotify): the
// command, its exit channel, and its log locations. Embedded by the
// per-transport test envs so spawn/stop/liveness/log logic is shared.
type daemonProc struct {
	daemonCmd    *exec.Cmd
	daemonExited chan struct{} // closed when cmd.Wait() returns
	daemonLog    string
	logDir       string
}

// spawnDaemonCmd starts cmd with its output tee'd to the daemon log and
// tracks its exit; readiness polling stays with the caller (per-transport).
func (d *daemonProc) spawnDaemonCmd(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	logFile, err := os.Create(d.daemonLog)
	require.NoError(t, err)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	require.NoError(t, cmd.Start())
	d.daemonCmd = cmd
	d.daemonExited = make(chan struct{})
	go func() { _ = cmd.Wait(); close(d.daemonExited) }()
	_ = logFile.Close()
}

// stopDaemon SIGTERMs the daemon and reaps it, escalating to SIGKILL after
// 20s. Safe to call when the daemon already exited or was never started.
func (d *daemonProc) stopDaemon(t *testing.T) {
	t.Helper()
	if d.daemonCmd == nil || d.daemonCmd.Process == nil {
		return
	}
	// If already exited (e.g. crash detected elsewhere), just reap.
	if d.daemonExited != nil {
		select {
		case <-d.daemonExited:
			d.daemonCmd = nil
			return
		default:
		}
	}
	_ = d.daemonCmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-d.daemonExited:
	case <-time.After(20 * time.Second):
		_ = d.daemonCmd.Process.Kill()
		<-d.daemonExited
	}
	d.daemonCmd = nil
}

func (d *daemonProc) daemonAlive() bool {
	return d.daemonCmd != nil && d.daemonCmd.ProcessState == nil
}

// logCorpus concatenates the console log and every file-log sink.
func (d *daemonProc) logCorpus() string {
	var b strings.Builder
	b.Write(readFileOrEmpty(d.daemonLog))
	entries, _ := os.ReadDir(d.logDir)
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			b.Write(readFileOrEmpty(filepath.Join(d.logDir, entry.Name())))
		}
	}
	return b.String()
}

// countLogs counts lines across every log sink matching the ERE-style pattern.
func (d *daemonProc) countLogs(pattern string) int {
	return countMatchingLines(d.logCorpus(), regexp.MustCompile(pattern))
}
