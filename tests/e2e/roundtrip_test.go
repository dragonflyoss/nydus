package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/corpus"
	"github.com/pkg/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func erofsKernelCompatibilitySkipReason(release, filesystems string) (string, error) {
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		return "", fmt.Errorf("parse kernel release %q: %w", release, err)
	}
	if major < 5 || (major == 5 && minor < 16) {
		return fmt.Sprintf("native EROFS compatibility requires Linux 5.16 or newer; running %s", release), nil
	}
	for _, filesystem := range strings.Fields(filesystems) {
		if filesystem == "erofs" {
			return "", nil
		}
	}
	return "EROFS is unavailable in /proc/filesystems (not built in or module not loaded)", nil
}

func TestErofsKernelCompatibilityPrerequisites(t *testing.T) {
	for _, test := range []struct {
		name        string
		release     string
		filesystems string
		skipReason  string
	}{
		{"old major", "4.19.320", "\terofs\n", "requires Linux 5.16"},
		{"old vendor kernel", "5.10.112-005.ali5000", "\terofs\n", "requires Linux 5.16"},
		{"before minimum", "5.15.0-1092-azure", "\terofs\n", "requires Linux 5.16"},
		{"minimum", "5.16.0", "nodev\tsysfs\n\terofs\n", ""},
		{"new major", "6.0-rc1", "\terofs\n", ""},
		{"new vendor kernel", "6.8.0-1021-azure", "\terofs\n", ""},
		{"missing erofs", "6.8.0", "nodev\tsysfs\n\text4\n", "EROFS is unavailable"},
		{"different filesystem", "6.8.0", "\terofs_test\n", "EROFS is unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reason, err := erofsKernelCompatibilitySkipReason(test.release, test.filesystems)
			require.NoError(t, err)
			if test.skipReason == "" {
				require.Empty(t, reason)
			} else {
				require.Contains(t, reason, test.skipReason)
			}
		})
	}
	_, err := erofsKernelCompatibilitySkipReason("invalid", "\terofs\n")
	require.Error(t, err)
}

func TestErofsKernelCompatibility(t *testing.T) {
	kernel, err := exec.Command("uname", "-r").Output()
	require.NoError(t, err)
	release := strings.TrimSpace(string(kernel))
	filesystems, err := os.ReadFile("/proc/filesystems")
	require.NoError(t, err)
	reason, err := erofsKernelCompatibilitySkipReason(release, string(filesystems))
	require.NoError(t, err)
	if reason != "" {
		t.Skip(reason)
	}
	t.Logf("native EROFS kernel: %s", release)

	require.Equal(t, 0, os.Geteuid(), "native EROFS validation requires root")
	require.Equal(t, 4096, os.Getpagesize(), "native baseline requires 4 KiB pages")
	for _, tool := range []string{"losetup", "mount", "fsck.erofs"} {
		_, err := exec.LookPath(tool)
		require.NoError(t, err, "required native validation tool: %s", tool)
	}
	root := t.TempDir()
	blobDir := filepath.Join(root, "blobs")
	decodedDir := filepath.Join(root, "decoded")
	expected := filepath.Join(root, "expected")
	for _, dir := range []string{blobDir, decodedDir, expected} {
		require.NoError(t, os.MkdirAll(dir, 0755))
	}
	nydusBin := mustLookupExecutable(t, "nydus")
	var sources []string
	var firstDecoded []byte
	for layerIndex := 0; layerIndex < 2; layerIndex++ {
		source := filepath.Join(root, fmt.Sprintf("layer%d", layerIndex))
		require.NoError(t, os.MkdirAll(source, 0755))
		for index := 0; index < 3; index++ {
			name := fmt.Sprintf("layer%d-file%d", layerIndex, index)
			data := bytes.Repeat([]byte{byte(index + 1)}, 100+index*4096)
			timestamp := time.Unix(1_700_000_000+int64(index), int64(index)*123_456_789)
			for _, dir := range []string{source, expected} {
				path := filepath.Join(dir, name)
				require.NoError(t, os.WriteFile(path, data, 0644))
				require.NoError(t, os.Chtimes(path, timestamp, timestamp))
			}
		}
		bootstrap := filepath.Join(root, fmt.Sprintf("layer%d.bootstrap", layerIndex))
		before := listFilesInDir(t, blobDir)
		out, err := exec.Command(nydusBin, "build", "--blob-dir", blobDir,
			"--bootstrap", bootstrap, "--chunk-size", "4096", "--block-group-size", "1048576",
			"--compressor", "none", source).CombinedOutput()
		require.NoError(t, err, "build: %s", out)
		var blob string
		for path := range listFilesInDir(t, blobDir) {
			if _, existed := before[path]; !existed && sha256FilenamePattern.MatchString(filepath.Base(path)) {
				require.Empty(t, blob)
				blob = path
			}
		}
		require.NotEmpty(t, blob)
		sources = append(sources, blob)
		header, err := os.ReadFile(bootstrap)
		require.NoError(t, err)
		slot := int(binary.LittleEndian.Uint16(header[erofsSuperOffset+erofsDevtSlotOffO:])) * erofsDevSlotSize
		blocks := binary.LittleEndian.Uint32(header[slot+64:])
		fullBlob, err := os.ReadFile(blob)
		require.NoError(t, err)
		decodedSize := int(blocks) * 4096
		require.Less(t, decodedSize, 1048576)
		require.GreaterOrEqual(t, len(fullBlob), decodedSize)
		decoded := fullBlob[:decodedSize]
		require.NoError(t, os.WriteFile(filepath.Join(decodedDir, filepath.Base(blob)), decoded, 0644))
		if layerIndex == 0 {
			firstDecoded = append([]byte(nil), decoded...)
		}
		t.Run(fmt.Sprintf("Build%d", layerIndex), func(t *testing.T) {
			verifyNativeErofsTree(t, bootstrap, decodedDir, source)
		})
	}
	merged := filepath.Join(root, "merged.bootstrap")
	mergeNydusBootstrap(t, nydusBin, merged, sources...)
	t.Run("Merge", func(t *testing.T) { verifyNativeErofsTree(t, merged, decodedDir, expected) })
	config := filepath.Join(root, "config.yaml")
	writeLocalStorageConfig(t, config, blobDir, filepath.Join(root, "cache"))
	trace := filepath.Join(root, "trace.json")
	require.NoError(t, os.WriteFile(trace, []byte(`{"version":1,"patterns":[{"blob_index":1,"block_group_index":0}]}`), 0644))
	optimized := filepath.Join(root, "optimized.bootstrap")
	out, err := exec.Command(nydusBin, "optimize", "--parent-bootstrap", merged,
		"--bootstrap", optimized, "--blob-dir", blobDir, "--config", config, "--trace-file", trace).CombinedOutput()
	require.NoError(t, err, "optimize: %s", out)
	devices, err := erofsDeviceArgs(optimized, decodedDir)
	require.NoError(t, err)
	require.Len(t, devices, 3)
	require.NoError(t, os.WriteFile(strings.TrimPrefix(devices[2], "--device="), firstDecoded, 0644))
	t.Run("Optimize", func(t *testing.T) { verifyNativeErofsTree(t, optimized, decodedDir, expected) })
}

func verifyNativeErofsTree(t *testing.T, bootstrap, decodedDir, expected string) {
	t.Helper()
	fsckErofsImage(t, bootstrap, decodedDir)
	deviceArgs, err := erofsDeviceArgs(bootstrap, decodedDir)
	require.NoError(t, err)
	devicePaths := make([]string, 0, len(deviceArgs))
	for _, arg := range deviceArgs {
		devicePaths = append(devicePaths, strings.TrimPrefix(arg, "--device="))
	}
	mountpoint := mountNativeErofs(t, bootstrap, devicePaths...)
	roDiffTree(t, expected, mountpoint, true)
}

func mountNativeErofs(t *testing.T, bootstrap string, devicePaths ...string) string {
	t.Helper()
	mountpoint := filepath.Join(t.TempDir(), "mnt")
	require.NoError(t, os.Mkdir(mountpoint, 0755))
	mounted := false
	attach := func(path string) string {
		out, err := exec.Command("losetup", "--find", "--show", "--read-only", path).CombinedOutput()
		require.NoError(t, err, "attach %s: %s", path, out)
		device := strings.TrimSpace(string(out))
		t.Cleanup(func() {
			if mounted {
				t.Errorf("retaining %s because native mount cleanup failed", device)
				return
			}
			out, err := exec.Command("losetup", "--detach", device).CombinedOutput()
			assert.NoError(t, err, "detach %s: %s", device, out)
		})
		return device
	}
	primary := attach(bootstrap)
	options := []string{"ro"}
	for _, path := range devicePaths {
		options = append(options, "device="+attach(path))
	}
	out, err := exec.Command("mount", "-t", "erofs", "-o", strings.Join(options, ","), primary, mountpoint).CombinedOutput()
	require.NoError(t, err, "native EROFS mount: %s", out)
	mounted = true
	t.Cleanup(func() {
		if err := unix.Unmount(mountpoint, 0); err != nil {
			t.Errorf("unmount native EROFS %s: %v", mountpoint, err)
			return
		}
		mounted = false
	})
	return mountpoint
}

func TestBlobMount(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	for _, chunkSize := range []int{4096, 16384} {
		chunkSize := chunkSize
		t.Run(fmt.Sprintf("ChunkSize%d", chunkSize), func(t *testing.T) {
			tmpDir := t.TempDir()
			corpusDir := filepath.Join(tmpDir, "corpus")
			bootstrapPath := filepath.Join(tmpDir, "test.bootstrap")
			blobDir := filepath.Join(tmpDir, "blobs")
			cacheDir := filepath.Join(tmpDir, "cache")
			mntDir := filepath.Join(tmpDir, "mnt")

			t.Log("Generating corpus...")
			corpus := corpus.MakeStandardCorpus(t, corpusDir)
			corpus.CreateUnixSocket(t, "special/socket")

			t.Log("Building blob and mounting it directly...")
			nydusBin := mustLookupExecutable(t, "nydus")
			blobPath := buildNydusFSImageToDir(t, nydusBin, bootstrapPath, blobDir, corpusDir, chunkSize)
			logNydusCheckOutput(t, nydusBin, "--blob", blobPath)
			logNydusCheckOutput(t, nydusBin, "--bootstrap", bootstrapPath, "--blob-dir", blobDir)
			func() {
				unmount := mountNydus(t, nydusBin, "", blobPath, mntDir)
				defer unmount()
				roDiffTree(t, corpusDir, mntDir, true)
			}()

			func() {
				unmount := mountNydusBootstrap(t, nydusBin, bootstrapPath, blobDir, mntDir)
				defer unmount()
				roDiffTree(t, corpusDir, mntDir, true)
			}()

			func() {
				unmount := mountNydusBootstrapWithCache(t, nydusBin, bootstrapPath, blobDir, cacheDir, mntDir)
				defer unmount()
				roDiffTree(t, corpusDir, mntDir, true)
				verifyBlobCacheArtifacts(t, cacheDir, blobPath)
			}()
		})
	}
}

func TestMergedMount(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}

	tmpDir := t.TempDir()
	layer1Dir := filepath.Join(tmpDir, "layer1")
	layer2Dir := filepath.Join(tmpDir, "layer2")
	layer3Dir := filepath.Join(tmpDir, "layer3")
	expectedDir := filepath.Join(tmpDir, "expected")
	mountpoint := filepath.Join(tmpDir, "mnt")
	prepareMergedE2ECorpora(t, layer1Dir, layer2Dir, layer3Dir, expectedDir)

	nydusBin := mustLookupExecutable(t, "nydus")
	blobDir := filepath.Join(tmpDir, "blobs")
	layer1Bootstrap := filepath.Join(tmpDir, "layer1.bootstrap")
	layer2Bootstrap := filepath.Join(tmpDir, "layer2.bootstrap")
	layer3Bootstrap := filepath.Join(tmpDir, "layer3.bootstrap")
	mergedBootstrap := filepath.Join(tmpDir, "merged.bootstrap")
	cacheDir := filepath.Join(tmpDir, "cache")

	layer1Blob := buildNydusFSImageToDir(t, nydusBin, layer1Bootstrap, blobDir, layer1Dir, 4096)
	layer2Blob := buildNydusFSImageToDir(t, nydusBin, layer2Bootstrap, blobDir, layer2Dir, 4096)
	layer3Blob := buildNydusFSImageToDir(t, nydusBin, layer3Bootstrap, blobDir, layer3Dir, 4096)
	logNydusCheckOutput(t, nydusBin, "--bootstrap", layer1Bootstrap, "--blob-dir", blobDir)

	mergeNydusBootstrap(
		t,
		nydusBin,
		mergedBootstrap,
		layer1Blob,
		layer2Blob,
		layer3Blob,
	)
	logNydusCheckOutput(t, nydusBin, "--bootstrap", mergedBootstrap, "--blob-dir", blobDir)

	func() {
		unmount := mountNydusBootstrap(t, nydusBin, mergedBootstrap, blobDir, mountpoint)
		defer unmount()
		printMergeDebugPaths(t, layer1Dir, layer2Dir, layer3Dir, mountpoint)

		roDiffTree(t, expectedDir, mountpoint, true)
		verifyWhiteoutResults(t, mountpoint)
	}()

	func() {
		unmount := mountNydusBootstrapWithCache(t, nydusBin, mergedBootstrap, blobDir, cacheDir, mountpoint)
		defer unmount()

		roDiffTree(t, expectedDir, mountpoint, true)
		verifyWhiteoutResults(t, mountpoint)
		verifyBlobCacheArtifacts(t, cacheDir, layer1Blob, layer2Blob, layer3Blob)
		pauseMergeDebugIfRequested(t, mountpoint)
	}()
}

func TestMergedMountKernelErofsMatchesNydusFuse(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	kernel, err := exec.Command("uname", "-r").Output()
	require.NoError(t, err)
	release := strings.TrimSpace(string(kernel))
	filesystems, err := os.ReadFile("/proc/filesystems")
	require.NoError(t, err)
	reason, err := erofsKernelCompatibilitySkipReason(release, string(filesystems))
	require.NoError(t, err)
	if reason != "" {
		t.Skip(reason)
	}
	for _, tool := range []string{"losetup", "mount"} {
		_, err := exec.LookPath(tool)
		require.NoError(t, err, "required native validation tool: %s", tool)
	}

	tmpDir := t.TempDir()
	layer1Dir := filepath.Join(tmpDir, "layer1")
	layer2Dir := filepath.Join(tmpDir, "layer2")
	layer3Dir := filepath.Join(tmpDir, "layer3")
	expectedDir := filepath.Join(tmpDir, "expected")
	nydusMountpoint := filepath.Join(tmpDir, "nydus-mnt")
	prepareMergedE2ECorpora(t, layer1Dir, layer2Dir, layer3Dir, expectedDir)

	nydusBin := mustLookupExecutable(t, "nydus")
	blobDir := filepath.Join(tmpDir, "blobs")
	layer1Bootstrap := filepath.Join(tmpDir, "layer1.bootstrap")
	layer2Bootstrap := filepath.Join(tmpDir, "layer2.bootstrap")
	layer3Bootstrap := filepath.Join(tmpDir, "layer3.bootstrap")
	mergedBootstrap := filepath.Join(tmpDir, "merged.bootstrap")
	cacheDir := filepath.Join(tmpDir, "cache")

	layer1Blob := buildNydusFSImageToDir(t, nydusBin, layer1Bootstrap, blobDir, layer1Dir, 4096)
	layer2Blob := buildNydusFSImageToDir(t, nydusBin, layer2Bootstrap, blobDir, layer2Dir, 4096)
	layer3Blob := buildNydusFSImageToDir(t, nydusBin, layer3Bootstrap, blobDir, layer3Dir, 4096)
	mergeNydusBootstrap(
		t,
		nydusBin,
		mergedBootstrap,
		layer1Blob,
		layer2Blob,
		layer3Blob,
	)

	unmountNydus := mountNydusBootstrapWithCache(t, nydusBin, mergedBootstrap, blobDir, cacheDir, nydusMountpoint)
	defer unmountNydus()

	// Full-tree walk against the expected merge prewarms cache data so the
	// cached .blob.data devices can back a native kernel mount.
	roDiffTree(t, expectedDir, nydusMountpoint, true)
	verifyBlobCacheArtifacts(t, cacheDir, layer1Blob, layer2Blob, layer3Blob)

	nativeMountpoint := mountNativeErofs(
		t,
		mergedBootstrap,
		cachedBlobDataDevicesForBlobs(t, cacheDir, layer1Blob, layer2Blob, layer3Blob)...,
	)
	roDiffTree(t, nativeMountpoint, nydusMountpoint, true)
}

func cachedBlobDataDevicesForBlobs(t *testing.T, cacheDir string, blobs ...string) []string {
	t.Helper()

	// The kernel EROFS mount consumes plain external devices. Nydus builds
	// zstd-compressed full blobs, so this path uses cache files populated by
	// nydus fuse as decoded .blob.data devices.
	devices := make([]string, 0, len(blobs))
	for _, blob := range blobs {
		blobID := fullBlobDigest(t, blob)
		cachedBlob := filepath.Join(cacheDir, blobID+".blob.data")
		require.FileExists(t, cachedBlob, "cached uncompressed blob data should exist after nydus cached mount")
		devices = append(devices, cachedBlob)
	}
	return devices
}

func fullBlobDigest(t *testing.T, blob string) string {
	t.Helper()

	data, err := os.ReadFile(blob)
	require.NoError(t, err)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func prepareMergedE2ECorpora(t *testing.T, layer1Dir, layer2Dir, layer3Dir, expectedDir string) {
	t.Helper()

	base := corpus.MakeStandardCorpus(t, layer1Dir)
	addMergeBaseEntries(t, base)

	layer2 := corpus.NewCorpus(t, layer2Dir)
	layer2.CreateFile(t, "merge/.wh.remove.txt", nil)
	layer2.CreateFile(t, "merge/middle.txt", []byte("middle-from-layer2"))
	layer2.CreateFile(t, "merge/dir/mid.txt", []byte("mid-from-layer2"))
	layer2.CreateFile(t, "xattrs/merged_upper", []byte("merged upper xattr\n"))
	layer2.SetXattr(t, "xattrs/merged_upper", "user.merged", []byte("layer2"))
	layer2.CreateFile(t, "xattrs/merged_override", []byte("merged override from layer2\n"))
	layer2.SetXattr(t, "xattrs/merged_override", "user.layer", []byte("layer2"))
	layer2.SetXattr(t, "xattrs/merged_override", "user.extra", []byte("layer2-extra"))
	layer2.CreateDir(t, "xattrs/merged_dir")
	layer2.SetXattr(t, "xattrs/merged_dir", "user.dir.merged", []byte("layer2-dir"))
	layer2.CreateSymlink(t, "symlinks/merged_link", "../files/tiny_2b")
	layer2.CreateFIFO(t, "special/upper_fifo")
	layer2.CreateFile(t, "upperhard/original", []byte("upper shared"))
	layer2.CreateHardlink(t, "upperhard/link1", "upperhard/original")
	layer2.CreateSymlink(t, "merge/type_file_to_link", "../files/tiny_2b")

	layer3 := corpus.NewCorpus(t, layer3Dir)
	layer3.CreateFile(t, "files/tiny_2b", []byte("ok"))
	layer3.CreateFile(t, "merge/lower.txt", []byte("lower-v3"))
	layer3.CreateFile(t, "merge/type_link_to_file", []byte("layer3-file-wins"))
	layer3.CreateFile(t, "merge/dir/.wh.base.txt", nil)
	layer3.CreateFile(t, "merge/dir/top.txt", []byte("top-from-layer3"))
	layer3.CreateFile(t, "merge/opq/.wh..wh..opq", nil)
	layer3.CreateFile(t, "merge/opq/new.txt", []byte("new-from-layer3"))

	cloneTreePreservingLinks(t, layer1Dir, expectedDir)
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "xattrs/merged_upper")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "xattrs/merged_override")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "xattrs/merged_dir")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "symlinks/merged_link")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "special/upper_fifo")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "upperhard")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "merge/type_file_to_link")
	copyPathPreservingMetadata(t, layer3Dir, expectedDir, "merge/type_link_to_file")
	copyPathPreservingMetadata(t, layer3Dir, expectedDir, "files/tiny_2b")
	copyPathPreservingMetadata(t, layer3Dir, expectedDir, "merge/lower.txt")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "merge/middle.txt")
	copyPathPreservingMetadata(t, layer2Dir, expectedDir, "merge/dir/mid.txt")
	copyPathPreservingMetadata(t, layer3Dir, expectedDir, "merge/dir/top.txt")

	removeExpectedPath(t, expectedDir, "merge/remove.txt")
	removeExpectedPath(t, expectedDir, "merge/dir/base.txt")
	removeExpectedPath(t, expectedDir, "merge/opq")
	copyPathPreservingMetadata(t, layer3Dir, expectedDir, "merge/opq/new.txt")
	overlayExpectedDirectoryMetadata(t, layer2Dir, expectedDir)
	overlayExpectedDirectoryMetadata(t, layer3Dir, expectedDir)
}

func cloneTreePreservingLinks(t *testing.T, srcDir, dstDir string) {
	t.Helper()
	require.NoError(t, os.RemoveAll(dstDir))
	require.NoError(t, os.MkdirAll(dstDir, 0755))
	copySource := srcDir + string(os.PathSeparator) + "."
	out, err := exec.Command("cp", "-a", copySource, dstDir).CombinedOutput()
	require.NoError(t, err, "cp -a failed: %s", string(out))
}

func copyPathPreservingMetadata(t *testing.T, srcRoot, dstRoot, rel string) {
	t.Helper()

	srcPath := filepath.Join(srcRoot, rel)
	dstPath := filepath.Join(dstRoot, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(dstPath), 0755))
	require.NoError(t, os.RemoveAll(dstPath))
	out, err := exec.Command("cp", "-a", srcPath, dstPath).CombinedOutput()
	require.NoError(t, err, "cp -a failed: %s", string(out))
}

func overlayExpectedDirectoryMetadata(t *testing.T, srcRoot, dstRoot string) {
	t.Helper()

	err := filepath.WalkDir(srcRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}

		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		return copyDirectoryMetadata(path, filepath.Join(dstRoot, rel))
	})
	require.NoError(t, err)
}

func copyDirectoryMetadata(srcPath, dstPath string) error {
	srcInfo, err := os.Lstat(srcPath)
	if err != nil {
		return err
	}

	dstInfo, err := os.Lstat(dstPath)
	if err != nil {
		return err
	}
	if !srcInfo.IsDir() || !dstInfo.IsDir() {
		return nil
	}

	srcStat := srcInfo.Sys().(*syscall.Stat_t)
	if err := os.Chmod(dstPath, srcInfo.Mode().Perm()); err != nil {
		return err
	}
	if err := os.Chown(dstPath, int(srcStat.Uid), int(srcStat.Gid)); err != nil {
		return err
	}
	if err := os.Chtimes(
		dstPath,
		time.Unix(srcStat.Atim.Sec, srcStat.Atim.Nsec),
		time.Unix(srcStat.Mtim.Sec, srcStat.Mtim.Nsec),
	); err != nil {
		return err
	}

	return syncXattrs(srcPath, dstPath)
}

func syncXattrs(srcPath, dstPath string) error {
	srcNames, err := xattr.List(srcPath)
	if err != nil {
		return err
	}
	dstNames, err := xattr.List(dstPath)
	if err != nil {
		return err
	}

	srcSet := make(map[string]struct{}, len(srcNames))
	for _, name := range srcNames {
		srcSet[name] = struct{}{}
		value, err := xattr.Get(srcPath, name)
		if err != nil {
			return err
		}
		if err := xattr.Set(dstPath, name, value); err != nil {
			return err
		}
	}

	for _, name := range dstNames {
		if _, ok := srcSet[name]; ok {
			continue
		}
		if err := xattr.Remove(dstPath, name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	return nil
}

func addMergeBaseEntries(t *testing.T, corpus *corpus.Corpus) {
	t.Helper()

	corpus.CreateFile(t, "merge/lower.txt", []byte("lower-v1"))
	corpus.CreateFile(t, "merge/remove.txt", []byte("remove-me"))
	corpus.CreateFile(t, "merge/shared/keep.txt", []byte("shared-from-layer1"))
	corpus.CreateFile(t, "merge/dir/base.txt", []byte("base-from-layer1"))
	corpus.CreateFile(t, "merge/opq/old.txt", []byte("old-from-layer1"))
	corpus.CreateFile(t, "merge/opq/subdir/old_nested.txt", []byte("nested-old-from-layer1"))
	corpus.CreateFile(t, "merge/type_file_to_link", []byte("layer1-regular"))
	corpus.CreateSymlink(t, "merge/type_link_to_file", "../files/tiny_2b")
	corpus.CreateFile(t, "xattrs/merged_override", []byte("merged override from layer1\n"))
	corpus.SetXattr(t, "xattrs/merged_override", "user.layer", []byte("layer1"))
}

func removeExpectedPath(t *testing.T, root, rel string) {
	t.Helper()
	require.NoError(t, os.RemoveAll(filepath.Join(root, rel)))
}

func verifyWhiteoutResults(t *testing.T, mountpoint string) {
	t.Helper()
	requireNotExist(t, filepath.Join(mountpoint, "merge", "remove.txt"))
	requireNotExist(t, filepath.Join(mountpoint, "merge", "dir", "base.txt"))
	requireNotExist(t, filepath.Join(mountpoint, "merge", "opq", "old.txt"))
	requireNotExist(t, filepath.Join(mountpoint, "merge", "opq", "subdir"))
	requireNotExist(t, filepath.Join(mountpoint, "merge", ".wh.remove.txt"))
	requireNotExist(t, filepath.Join(mountpoint, "merge", "dir", ".wh.base.txt"))
	requireNotExist(t, filepath.Join(mountpoint, "merge", "opq", ".wh..wh..opq"))
}

func printMergeDebugPaths(t *testing.T, layer1Dir, layer2Dir, layer3Dir, mountpoint string) {
	t.Helper()
	message := fmt.Sprintf(
		"merge test paths:\n  layer1=%s\n  layer2=%s\n  layer3=%s\n  mountpoint=%s\n",
		layer1Dir,
		layer2Dir,
		layer3Dir,
		mountpoint,
	)
	t.Logf("%s", message)
	_, _ = fmt.Fprint(os.Stderr, message)
}

func logNydusCheckOutput(t *testing.T, nydusBin string, args ...string) {
	t.Helper()

	cmdArgs := append([]string{"check"}, args...)
	out, err := exec.Command(nydusBin, cmdArgs...).CombinedOutput()
	require.NoError(t, err, "nydus check failed: %s", string(out))
	t.Logf("nydus %s output:\n%s", strings.Join(cmdArgs, " "), string(out))
}

func pauseMergeDebugIfRequested(t *testing.T, mountpoint string) {
	t.Helper()
	pauseSecs := corpus.EnvInt("NYDUSFS_MERGE_PAUSE_SECS", 0)
	if pauseSecs <= 0 {
		return
	}

	message := fmt.Sprintf(
		"pausing merge test for %d seconds before cleanup; inspect mountpoint: %s\n",
		pauseSecs,
		mountpoint,
	)
	t.Logf("%s", message)
	_, _ = fmt.Fprint(os.Stderr, message)
	time.Sleep(time.Duration(pauseSecs) * time.Second)
}

func requireNotExist(t *testing.T, path string) {
	t.Helper()
	_, err := os.Lstat(path)
	require.True(t, errors.Is(err, os.ErrNotExist), "expected path to be absent: %s", path)
}

func verifyBlobCacheArtifacts(t *testing.T, cacheDir string, blobs ...string) {
	t.Helper()

	entries, err := os.ReadDir(cacheDir)
	require.NoError(t, err)

	var dataCount int
	var blockGroupMapCount int
	var blobMetaCount int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		switch {
		case strings.HasSuffix(name, ".blob.data"):
			dataCount++
		case strings.HasSuffix(name, ".group.map"):
			blockGroupMapCount++
		case strings.HasSuffix(name, ".blob.meta"):
			blobMetaCount++
		}
	}

	blobCount := len(blobs)
	assert.Equal(t, blobCount, dataCount, "unexpected cached blob.data count")
	assert.Equal(t, blobCount, blockGroupMapCount, "unexpected cached block group map count")
	assert.Equal(t, blobCount, blobMetaCount, "unexpected cached blob_meta count")

	for _, blob := range blobs {
		prefix := fullBlobDigest(t, blob)
		require.FileExists(t, filepath.Join(cacheDir, prefix+".blob.data"))
		require.FileExists(t, filepath.Join(cacheDir, prefix+".blob.meta"))
		require.FileExists(t, filepath.Join(cacheDir, prefix+".group.map"))
	}
}

// TestNydusifyOptimizeE2E exercises the full image-level optimize pipeline
// against a local registry:
//
//  1. docker build/push a source OCI image, convert it with `nydusify
//     convert`, and validate it with `nydusify check`.
//  2. Mount the nydus image WITHOUT prefetch, replay a read workload, and
//     verify the baseline metrics show on-demand backend reads. Save the
//     recorded /trace pattern to a file and run `nydusify optimize
//     --pattern` to build the ondemand (redirect) blob from it and push the
//     optimized image.
//  3. Mount the optimized image WITH prefetch on a cold cache, wait for
//     prefetch to quiesce, replay the same workload, and verify:
//     - the ondemand blob was fetched (backend_redirect_read_count > 0),
//     - every traced block group was filled into its source blob's cache through
//     the redirect path (cache_redirect_fill_block_group == trace size, no skips),
//     - the workload triggered zero on-demand backend reads
//     (backend_ondemand_read_count == 0), proving the optimization works,
//     - file contents are byte-identical to the corpus.
func TestNydusifyOptimize(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	skipUnlessDocker(t)
	registry := skipUnlessTestRegistry(t)

	nydusBin := mustLookupExecutable(t, "nydus")
	nydusifyBin := mustLookupExecutable(t, "nydusify")

	// Corpus: four ~1.2-1.5 MiB pseudo-random files so each spans more than
	// one 1 MiB blob meta group and the trace covers multiple groups.
	tmpDir := t.TempDir()
	corpusDir := filepath.Join(tmpDir, "corpus")
	require.NoError(t, os.MkdirAll(corpusDir, 0755))
	corpusFiles := []string{"file1", "file2", "file3", "file4"}
	for i, name := range corpusFiles {
		size := 1<<20 + (i+1)*64*1024
		require.NoError(t, os.WriteFile(filepath.Join(corpusDir, name), pseudoRandomTestBytes(size, uint64(i+1)), 0644))
	}

	srcRef := uniqueImageRef(registry, "nydus-e2e/optimize-src")
	nydusRef := srcRef + "-nydus"
	optRef := optimizedRef(nydusRef)

	t.Log("Building and pushing source OCI image...")
	dockerBuildAndPush(t, corpusDir, srcRef)

	t.Log("Converting to nydus format...")
	runNydusifyCommand(t, nydusifyBin, nydusBin, "convert", "--source", srcRef, "--target", nydusRef,
		"--work-dir", filepath.Join(tmpDir, "convert"))

	t.Log("Checking converted image...")
	runNydusifyCommand(t, nydusifyBin, nydusBin, "check", "--source", srcRef, "--target", nydusRef,
		"--work-dir", filepath.Join(tmpDir, "check"))

	// The read workload replayed on both mounts: two full files plus a
	// partial head read, in a deliberate non-sequential order.
	workload := func(mnt string) {
		readFilesInOrder(t, filepath.Join(mnt, "data"), "file3")
		head := make([]byte, 100*1024)
		f, err := os.Open(filepath.Join(mnt, "data", "file1"))
		require.NoError(t, err)
		_, err = io.ReadFull(f, head)
		require.NoError(t, f.Close())
		require.NoError(t, err)
		readFilesInOrder(t, filepath.Join(mnt, "data"), "file4")
	}

	t.Log("Mounting baseline (no prefetch) and tracing the workload...")
	baselineWork := filepath.Join(tmpDir, "mount-baseline")
	baselineMnt := filepath.Join(tmpDir, "mnt-baseline")
	var traceCount int
	func() {
		unmount := startNydusifyMount(t, nydusifyBin, nydusBin, nydusRef, baselineMnt, baselineWork, false)
		defer unmount()
		workload(baselineMnt)

		socket := filepath.Join(baselineWork, "apiserver.sock")
		metrics := fetchMetrics(t, socket)
		require.Greater(t, metricValue(metrics, "backend_ondemand_read_count"), 0.0,
			"baseline workload must trigger on-demand backend reads")
		require.Zero(t, metricValue(metrics, "backend_redirect_read_count"))
		require.Zero(t, metricValue(metrics, "cache_redirect_fill_block_group"))
		require.Zero(t, metricValue(metrics, "cache_fill_block_group"),
			"baseline mount must not prefetch")
		traceCount = saveTrace(t, socket, filepath.Join(tmpDir, "pattern.json"))
		require.Greater(t, traceCount, 1, "trace must cover multiple groups")
		t.Logf("baseline: ondemand_reads=%v trace_block_groups=%d",
			metricValue(metrics, "backend_ondemand_read_count"), traceCount)

		t.Log("Optimizing with the saved trace pattern...")
		runNydusifyCommand(t, nydusifyBin, nydusBin, "optimize",
			"--pattern", filepath.Join(tmpDir, "pattern.json"),
			"--source", nydusRef,
			"--target", optRef,
			"--work-dir", filepath.Join(tmpDir, "optimize"))
	}()

	t.Log("Mounting optimized image (prefetch, cold cache) and replaying the workload...")
	optWork := filepath.Join(tmpDir, "mount-optimized")
	optMnt := filepath.Join(tmpDir, "mnt-optimized")
	func() {
		unmount := startNydusifyMount(t, nydusifyBin, nydusBin, optRef, optMnt, optWork, true)
		defer unmount()

		socket := filepath.Join(optWork, "apiserver.sock")
		waitPrefetchQuiesce(t, socket)

		metrics := fetchMetrics(t, socket)
		require.Greater(t, metricValue(metrics, "backend_redirect_read_count"), 0.0,
			"prefetch must fetch the ondemand (redirect) blob from the backend")
		require.Equal(t, float64(traceCount), metricValue(metrics, "cache_redirect_fill_block_group"),
			"every traced group must be filled into its source cache via redirect")
		require.Zero(t, metricValue(metrics, "cache_redirect_skip_block_group"),
			"no redirect group may be skipped")
		require.Zero(t, metricValue(metrics, "backend_ondemand_read_count"),
			"prefetch warmup must not issue on-demand reads")
		t.Logf("optimized after prefetch: redirect_reads=%v redirect_fills=%v regular_fills=%v",
			metricValue(metrics, "backend_redirect_read_count"),
			metricValue(metrics, "cache_redirect_fill_block_group"),
			metricValue(metrics, "cache_fill_block_group"))

		workload(optMnt)

		metrics = fetchMetrics(t, socket)
		require.Zero(t, metricValue(metrics, "backend_ondemand_read_count"),
			"the traced workload must be served entirely from the warmed cache")
		require.Greater(t, metricValue(metrics, "cache_hit_block_group"), 0.0)

		// Full content verification against the corpus.
		for _, name := range corpusFiles {
			want, err := os.ReadFile(filepath.Join(corpusDir, name))
			require.NoError(t, err)
			got, err := os.ReadFile(filepath.Join(optMnt, "data", name))
			require.NoError(t, err)
			require.True(t, bytes.Equal(want, got), "content mismatch for %s", name)
		}
	}()

	// The ondemand blob holds a rearranged copy of the other blobs and no
	// filesystem tree, so the reverse conversion must skip it and still
	// reproduce the original layers.
	t.Log("Converting the optimized image back to OCI...")
	backRef := optRef + "-oci"
	runNydusifyCommand(t, nydusifyBin, nydusBin, "convert",
		"--compressor", "oci-gzip",
		"--source", optRef, "--target", backRef,
		"--work-dir", filepath.Join(tmpDir, "tooci"))
	runNydusifyCommand(t, nydusifyBin, nydusBin, "check",
		"--source", optRef, "--target", backRef,
		"--work-dir", filepath.Join(tmpDir, "check-tooci"))
}

// pseudoRandomTestBytes generates deterministic pseudo-random bytes (xorshift)
// so corpus files are incompressible and reproducible across runs.
func pseudoRandomTestBytes(n int, seed uint64) []byte {
	buf := make([]byte, n)
	state := seed*0x9e3779b97f4a7c15 + 0x2545f4914f6cdd1d
	for i := range buf {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		buf[i] = byte(state)
	}
	return buf
}

// TestReproducibleBuildE2E pins the build against the inputs that historically
// leak into an image: the wall clock, the order the source filesystem happens
// to report things in, and the paths the build ran under. Two builds that agree
// here produce the same layer digest, so a rebuild costs no registry storage.
func TestReproducibleBuild(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to build the corpus")
	}

	nydusBin := mustLookupExecutable(t, "nydus")
	root := t.TempDir()

	build := func(t *testing.T, src string) (bootstrap string, blob string) {
		t.Helper()
		out, err := os.MkdirTemp(root, "out-")
		require.NoError(t, err)
		bootstrap = filepath.Join(out, "boot")
		blob = buildNydusFSImageToDir(t, nydusBin, bootstrap, filepath.Join(out, "blobs"), src, 4096)
		return bootstrap, blob
	}

	sameImage := func(t *testing.T, aSrc, bSrc string) {
		t.Helper()
		aBoot, aBlob := build(t, aSrc)
		bBoot, bBlob := build(t, bSrc)
		require.Equal(t, sha256OfFile(t, aBoot), sha256OfFile(t, bBoot), "bootstrap differs")
		require.Equal(t, filepath.Base(aBlob), filepath.Base(bBlob), "blob digest differs")
	}

	// A tree with one of everything the builder has to encode.
	stage := func(t *testing.T, dir string, reverse bool) {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "d"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "d", "base"), []byte("payload"), 0o644))
		require.NoError(t, os.Symlink("base", filepath.Join(dir, "d", "link")))

		names := make([]int, 0, 24)
		for i := 0; i < 24; i++ {
			names = append(names, i)
		}
		if reverse {
			for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 {
				names[i], names[j] = names[j], names[i]
			}
		}
		for _, i := range names {
			p := filepath.Join(dir, "d", fmt.Sprintf("f%02d", i))
			require.NoError(t, os.WriteFile(p, []byte(strings.Repeat("x", i*97)), 0o644))
			require.NoError(t, os.Link(filepath.Join(dir, "d", "base"),
				filepath.Join(dir, "d", fmt.Sprintf("h%02d", i))))
			require.NoError(t, unix.Setxattr(filepath.Join(dir, "d", "base"),
				fmt.Sprintf("user.a%02d", i), []byte("v"), 0))
		}

		// A fixed timestamp everywhere, so only the ordering varies.
		require.NoError(t, filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			ts := unix.NsecToTimespec(time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
			return unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{ts, ts}, unix.AT_SYMLINK_NOFOLLOW)
		}))
	}

	t.Run("SameSourceTwice", func(t *testing.T) {
		src := filepath.Join(root, "same")
		stage(t, src, false)
		sameImage(t, src, src)
	})

	t.Run("CreationOrderDoesNotMatter", func(t *testing.T) {
		a := filepath.Join(root, "fwd")
		b := filepath.Join(root, "rev")
		stage(t, a, false)
		stage(t, b, true)
		sameImage(t, a, b)
	})

	t.Run("SourcePathDoesNotMatter", func(t *testing.T) {
		a := filepath.Join(root, "p")
		b := filepath.Join(root, "a", "much", "longer", "path", "to", "the", "same", "tree")
		stage(t, a, false)
		stage(t, b, false)
		sameImage(t, a, b)
	})

	t.Run("EmptyTreeHasNoClock", func(t *testing.T) {
		// Nothing but a root means no mtime to anchor the epoch to; reading the
		// clock there would change the image on every build.
		a := filepath.Join(root, "empty-a")
		b := filepath.Join(root, "empty-b")
		require.NoError(t, os.MkdirAll(a, 0o755))
		require.NoError(t, os.MkdirAll(b, 0o755))
		sameImage(t, a, b)
	})

	t.Run("RootMtimeDoesNotMatter", func(t *testing.T) {
		a := filepath.Join(root, "rm-a")
		b := filepath.Join(root, "rm-b")
		stage(t, a, false)
		stage(t, b, false)
		for dir, when := range map[string]time.Time{
			a: time.Date(2021, 6, 1, 0, 0, 0, 0, time.UTC),
			b: time.Date(2024, 11, 30, 0, 0, 0, 0, time.UTC),
		} {
			ts := unix.NsecToTimespec(when.UnixNano())
			require.NoError(t, unix.UtimesNanoAt(unix.AT_FDCWD, dir, []unix.Timespec{ts, ts}, 0))
		}
		sameImage(t, a, b)
	})

	t.Run("MergeIsStable", func(t *testing.T) {
		l1 := filepath.Join(root, "l1")
		l2 := filepath.Join(root, "l2")
		stage(t, l1, false)
		stage(t, l2, true)
		_, blob1 := build(t, l1)
		_, blob2 := build(t, l2)

		first := filepath.Join(root, "merged-a")
		second := filepath.Join(root, "merged-b")
		mergeNydusBootstrap(t, nydusBin, first, blob1, blob2)
		mergeNydusBootstrap(t, nydusBin, second, blob1, blob2)
		require.Equal(t, sha256OfFile(t, first), sha256OfFile(t, second), "merged bootstrap differs")
	})
}

func sha256OfFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
