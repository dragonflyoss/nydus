package e2e

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dragonflyoss/nydus/tests/e2e/util"
	"github.com/stretchr/testify/assert"
)

// skipUnlessKernelErofs skips the test unless root can mount EROFS through
// the kernel driver, Linux 5.16 or newer with EROFS and the given tools.
func skipUnlessKernelErofs(t *testing.T, tools ...string) {
	t.Helper()
	util.SkipUnlessRoot(t, "mounting EROFS through the kernel")
	if major, minor := util.KernelVersion(t); major < 5 || (major == 5 && minor < 16) {
		t.Skipf("kernel %d.%d < 5.16: native EROFS compatibility unavailable", major, minor)
	}
	if !util.ErofsSupported() {
		t.Skip("erofs not in /proc/filesystems — kernel lacks EROFS support")
	}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("required native validation tool: %v", err)
		}
	}
}

// TestErofsKernelCompatibility builds two uncompressed layers, decodes their
// blob meta independently of the nydus reader into flat devices and mounts
// every bootstrap, the merge and the optimized merge included, through the
// kernel EROFS driver, so a reader bug cannot mask an encoding bug. The
// native erofs-* layers need no decoding and are mounted as they are.
func TestErofsKernelCompatibility(t *testing.T) {
	skipUnlessKernelErofs(t, "losetup", "mount", "fsck.erofs")
	assert.Equal(t, 4096, os.Getpagesize(), "native baseline requires 4 KiB pages")

	// Lay out the blobs, the decoded flat devices the kernel mounts and the
	// expected merged tree.
	workDir := t.TempDir()
	blobDir := filepath.Join(workDir, "blobs")
	decodedDir := filepath.Join(workDir, "decoded")
	expectedDir := filepath.Join(workDir, "expected")
	for _, dir := range []string{blobDir, decodedDir, expectedDir} {
		assert.NoError(t, os.MkdirAll(dir, 0o755))
	}

	var blobs []string
	var firstDecoded []byte
	for layerIndex := range 2 {
		// Write three files of distinct content and timestamps into the
		// layer and the expected merged tree alike.
		source := filepath.Join(workDir, fmt.Sprintf("layer%d", layerIndex))
		assert.NoError(t, os.MkdirAll(source, 0o755))
		for index := range 3 {
			name := fmt.Sprintf("layer%d-file%d", layerIndex, index)
			data := bytes.Repeat([]byte{byte(index + 1)}, 100+index*4096)
			timestamp := time.Unix(1_700_000_000+int64(index), int64(index)*123_456_789)
			for _, dir := range []string{source, expectedDir} {
				path := filepath.Join(dir, name)
				assert.NoError(t, os.WriteFile(path, data, 0o644))
				assert.NoError(t, os.Chtimes(path, timestamp, timestamp))
			}
		}

		// Build the layer uncompressed.
		bootstrap := filepath.Join(workDir, fmt.Sprintf("layer%d.bootstrap", layerIndex))
		blob := util.BuildImage(t, nydusBin, bootstrap, blobDir, source, 4096, "--compressor", "none")
		blobs = append(blobs, blob)

		// The block count of the device slot sizes the decoded device.
		header, err := os.ReadFile(bootstrap)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		slot := int(binary.LittleEndian.Uint16(header[util.ErofsSuperOffset+util.ErofsDevtSlotOff:])) * util.ErofsDevSlotSize
		blocks := binary.LittleEndian.Uint32(header[slot+util.ErofsDevBlocksOff:])
		decodedSize := int(blocks) * 4096
		assert.Less(t, decodedSize, 1048576)

		fullBlob, err := os.ReadFile(blob)
		assert.NoError(t, err)
		blobMeta, err := os.ReadFile(blob + ".blob.meta")
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		decoded := decodeBlobMeta(t, blobMeta, fullBlob, decodedSize)
		assert.NoError(t, os.WriteFile(filepath.Join(decodedDir, filepath.Base(blob)), decoded, 0o644))
		if layerIndex == 0 {
			firstDecoded = decoded
		}

		t.Run(fmt.Sprintf("build layer %d", layerIndex), func(t *testing.T) {
			verifyNativeErofsTree(t, bootstrap, decodedDir, source)
		})
	}

	mergedBootstrap := filepath.Join(workDir, "merged.bootstrap")
	util.MergeBootstrap(t, nydusBin, mergedBootstrap, blobs...)
	t.Run("merge", func(t *testing.T) { verifyNativeErofsTree(t, mergedBootstrap, decodedDir, expectedDir) })

	// Optimize the merge with a one-group trace and back the ondemand blob it
	// adds as the third device with the first layer's decoded data.
	configPath := filepath.Join(workDir, "config.yaml")
	util.WriteLocalBackendConfig(t, configPath, blobDir, filepath.Join(workDir, "cache"), "none")
	traceFile := filepath.Join(workDir, "trace.json")
	assert.NoError(t, os.WriteFile(traceFile, []byte(`{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":0}]}`), 0o644))
	optimizedBootstrap := filepath.Join(workDir, "optimized.bootstrap")
	out, err := exec.Command(nydusBin, "optimize", "--parent-bootstrap", mergedBootstrap,
		"--bootstrap", optimizedBootstrap, "--blob-dir", blobDir, "--config", configPath, "--trace-file", traceFile).CombinedOutput()
	assert.NoError(t, err, "optimize: %s", out)

	devices, err := util.ErofsDeviceArgs(optimizedBootstrap, decodedDir)
	assert.NoError(t, err)
	if !assert.Len(t, devices, 3) {
		t.FailNow()
	}
	assert.NoError(t, os.WriteFile(strings.TrimPrefix(devices[2], "--device="), firstDecoded, 0o644))
	t.Run("optimize", func(t *testing.T) { verifyNativeErofsTree(t, optimizedBootstrap, decodedDir, expectedDir) })

	// Native layers need no decoding: the full blob in the store is the device
	// itself (data at offset 0), carries no blob meta and gets no sidecar.
	for _, compressor := range []string{"erofs-none", "erofs-lz4", "erofs-zstd"} {
		t.Run("native "+compressor, func(t *testing.T) {
			if compressor == "erofs-zstd" {
				if major, minor := util.KernelVersion(t); major < 6 || (major == 6 && minor < 10) {
					t.Skip("erofs-zstd needs Linux 6.10+")
				}
			}

			// fsck.erofs cannot decode the compressed native layers, so the
			// kernel alone is their oracle.
			assert := assert.New(t)
			verify := verifyNativeErofsTree
			if compressor != "erofs-none" {
				verify = verifyKernelMountTree
			}

			nativeBlobDir := filepath.Join(workDir, compressor, "blobs")
			assert.NoError(os.MkdirAll(nativeBlobDir, 0o755))

			var nativeBlobs []string
			for layerIndex := range 2 {
				// Build the layer natively and check the one blob it wrote is
				// a raw device without a blob meta.
				source := filepath.Join(workDir, fmt.Sprintf("layer%d", layerIndex))
				bootstrap := filepath.Join(workDir, compressor, fmt.Sprintf("layer%d.bootstrap", layerIndex))
				before := util.ListFiles(t, nativeBlobDir)
				out, err := exec.Command(nydusBin, "build", "--blob-dir", nativeBlobDir,
					"--bootstrap", bootstrap, "--chunk-size", "4096", "--compressor", compressor,
					"--erofs-data-alignment", "16384", source).CombinedOutput()
				assert.NoError(err, "build: %s", out)

				blobs, blobMetas := util.NewBlobFiles(t, nativeBlobDir, before)
				assert.Empty(blobMetas, "native layers carry no blob meta")
				if !assert.Len(blobs, 1) {
					t.FailNow()
				}
				blob := blobs[0]

				fullBlob, err := os.ReadFile(blob)
				if !assert.NoError(err) || !assert.GreaterOrEqual(len(fullBlob), 4096, "footer block") {
					t.FailNow()
				}
				footer := fullBlob[len(fullBlob)-4096:]
				assert.Equal("NDFOOTER", string(footer[:8]))
				assert.NotZero(binary.LittleEndian.Uint32(footer[12:])&(1<<1), "RAW_DEVICE feature")
				assert.Zero(binary.LittleEndian.Uint64(footer[72:]), "no blob meta region")

				nativeBlobs = append(nativeBlobs, blob)
				verify(t, bootstrap, nativeBlobDir, source)
			}

			mergedBootstrap := filepath.Join(workDir, compressor, "merged.bootstrap")
			util.MergeBootstrap(t, nydusBin, mergedBootstrap, nativeBlobs...)
			verify(t, mergedBootstrap, nativeBlobDir, expectedDir)
		})
	}
}

// decodeBlobMeta decodes the blob meta of an uncompressed layer independently
// of the nydus reader into the flat device of decodedSize bytes the kernel
// mounts, copying every group's chunks out of fullBlob. The tables follow the
// header back to back at 8-byte boundaries, each starting with a 16-byte
// common header; all chunks, including lone ones, have a four-byte length and
// the GroupTable terminator carries the totals. The test cannot go on with a
// device it could not decode, so a bound that fails ends it.
func decodeBlobMeta(t *testing.T, blobMeta, fullBlob []byte, decodedSize int) []byte {
	t.Helper()
	if !assert.GreaterOrEqual(t, len(blobMeta), 24) {
		t.FailNow()
	}
	assert.Equal(t, "NDBLMETA", string(blobMeta[:8]))
	assert.Zero(t, binary.LittleEndian.Uint32(blobMeta[12:]), "no incompat features")

	tableCount := int(binary.LittleEndian.Uint16(blobMeta[20:]))
	tables := map[uint16][]byte{}
	offset := 24
	for range tableCount {
		offset = (offset + 7) / 8 * 8
		if !assert.LessOrEqual(t, offset+16, len(blobMeta), "table header") {
			t.FailNow()
		}
		tableHeader := blobMeta[offset:]
		headerSize := int(binary.LittleEndian.Uint16(tableHeader[2:]))
		size := headerSize + int(binary.LittleEndian.Uint32(tableHeader[8:]))*int(binary.LittleEndian.Uint32(tableHeader[12:]))
		if !assert.GreaterOrEqual(t, headerSize, 16) || !assert.LessOrEqual(t, offset+size, len(blobMeta)) {
			t.FailNow()
		}
		tables[binary.LittleEndian.Uint16(tableHeader)] = blobMeta[offset : offset+size]
		offset += size
	}

	tableEntries := func(kind uint16, entrySize int) ([]byte, []byte, int) {
		table, ok := tables[kind]
		if !assert.True(t, ok, "table %d", kind) {
			t.FailNow()
		}

		headerSize := int(binary.LittleEndian.Uint16(table[2:]))
		if !assert.Equal(t, entrySize, int(binary.LittleEndian.Uint32(table[8:])), "table %d entry size", kind) {
			t.FailNow()
		}
		count := int(binary.LittleEndian.Uint32(table[12:]))

		return table[:headerSize], table[headerSize:], count
	}
	groupHeader, groupTable, groupEntries := tableEntries(1, 24)
	assert.Zero(t, groupHeader[17], "compressor none")
	_, chunkTable, chunkCount := tableEntries(2, 4)
	granuleHeader, indexTable, indexCount := tableEntries(3, 4)

	if !assert.Positive(t, groupEntries, "GroupTable terminator") {
		t.FailNow()
	}
	groupCount := groupEntries - 1
	terminator := groupTable[groupCount*24:]
	assert.Equal(t, chunkCount, int(binary.LittleEndian.Uint32(terminator[12:])))
	totalBlocks := int(binary.LittleEndian.Uint32(terminator[8:]))
	assert.Equal(t, decodedSize, totalBlocks*4096, "device blocks cover the groups")

	group := func(i int) (compressedOffset int, startBlock int, firstMember int, uncompressedSize int) {
		if !assert.Less(t, i, groupEntries, "group index") {
			t.FailNow()
		}
		entry := groupTable[i*24:]
		return int(binary.LittleEndian.Uint64(entry)), int(binary.LittleEndian.Uint32(entry[8:])),
			int(binary.LittleEndian.Uint32(entry[12:])), int(binary.LittleEndian.Uint32(entry[16:]))
	}
	chunkLen := func(index int) int {
		if !assert.Less(t, index, chunkCount, "chunk index") {
			t.FailNow()
		}
		return int(binary.LittleEndian.Uint32(chunkTable[index*4:]))
	}
	assert.LessOrEqual(t, granuleHeader[16], groupHeader[16], "granule within the group span")
	granuleBytes := uint64(4096) << granuleHeader[16]
	if !assert.Equal(t, (uint64(decodedSize)+granuleBytes-1)/granuleBytes, uint64(indexCount)) {
		t.FailNow()
	}

	// Copy every group's chunks into the decoded device, checking on the
	// way that the granule index points at the group of every block.
	decoded := make([]byte, decodedSize)
	for g := range groupCount {
		sourceOffset, startBlock, firstMember, uncompressedSize := group(g)
		sourceEnd, nextBlock, nextMember, _ := group(g + 1)
		assert.Equal(t, sourceEnd-sourceOffset, uncompressedSize, "group %d is plain (uncompressed size == compressed size)", g)
		assert.Greater(t, nextMember, firstMember)

		for block := startBlock; block < nextBlock; block++ {
			index := uint64(block*4096) / granuleBytes
			if !assert.Less(t, int(index), indexCount, "granule index of block %d", block) {
				t.FailNow()
			}
			candidate := int(binary.LittleEndian.Uint32(indexTable[int(index)*4:]))
			if !assert.Less(t, candidate, groupCount) {
				t.FailNow()
			}
			_, followingBlock, _, _ := group(candidate + 1)
			if block >= followingBlock {
				candidate++
			}
			assert.Equal(t, g, candidate, "GranuleIndexTable lookup")
		}

		targetOffset := startBlock * 4096
		for chunk := firstMember; chunk < nextMember; chunk++ {
			length := chunkLen(chunk)
			assert.Positive(t, length)
			assert.LessOrEqual(t, length, 4096)
			assert.LessOrEqual(t, sourceOffset+length, sourceEnd, "group %d payload", g)
			assert.LessOrEqual(t, targetOffset+length, nextBlock*4096, "group %d span", g)
			if !assert.LessOrEqual(t, sourceOffset+length, len(fullBlob)) || !assert.LessOrEqual(t, targetOffset+length, decodedSize) {
				t.FailNow()
			}
			copy(decoded[targetOffset:targetOffset+length], fullBlob[sourceOffset:sourceOffset+length])
			sourceOffset += length
			targetOffset += (length + 4095) / 4096 * 4096
		}
		assert.Equal(t, sourceEnd, sourceOffset, "group %d payload is its chunks", g)
		assert.Equal(t, nextBlock*4096, targetOffset, "group %d spans its chunks' blocks", g)
	}

	compressedEnd, terminatorBlock, terminatorMember, _ := group(groupCount)
	assert.Equal(t, chunkCount, terminatorMember)
	assert.Equal(t, totalBlocks, terminatorBlock)
	assert.LessOrEqual(t, compressedEnd, len(fullBlob))

	return decoded
}

// verifyNativeErofsTree checks the bootstrap with fsck.erofs over the decoded
// devices and then diffs its kernel mount against expected.
func verifyNativeErofsTree(t *testing.T, bootstrap, decodedDir, expected string) {
	t.Helper()
	util.FsckImage(t, bootstrap, decodedDir)
	verifyKernelMountTree(t, bootstrap, decodedDir, expected)
}

// verifyKernelMountTree mounts the image through the kernel EROFS driver and
// diffs it against expected, without the fsck.erofs data extraction. The
// compressed native layers need it: erofs-utils 1.7.1 (the host package) has
// no zstd support and cannot decode the LZ4 packed inode the kernel reads
// fine, so the kernel is the oracle for their data.
func verifyKernelMountTree(t *testing.T, bootstrap, decodedDir, expected string) {
	t.Helper()
	deviceArgs, err := util.ErofsDeviceArgs(bootstrap, decodedDir)
	assert.NoError(t, err)
	devices := make([]string, 0, len(deviceArgs))
	for _, arg := range deviceArgs {
		devices = append(devices, strings.TrimPrefix(arg, "--device="))
	}

	mountpoint := util.MountErofsLoop(t, bootstrap, devices...)
	util.CheckDirectoryEqual(t, expected, mountpoint, true)
}

// TestMergedMountKernelErofsMatchesNydusFuse mounts the merged image through
// nydus fuse with a chunk cache, warms the whole cache, then mounts the same
// bootstrap through the kernel EROFS driver over the cached .blob.data files
// and diffs the two mounts.
func TestMergedMountKernelErofsMatchesNydusFuse(t *testing.T) {
	skipUnlessKernelErofs(t, "losetup", "mount")

	assert := assert.New(t)
	workDir := t.TempDir()
	layer1Dir := filepath.Join(workDir, "layer1")
	layer2Dir := filepath.Join(workDir, "layer2")
	layer3Dir := filepath.Join(workDir, "layer3")
	expectedDir := filepath.Join(workDir, "expected")
	nydusMountpoint := filepath.Join(workDir, "nydus-mnt")
	prepareMergeLayers(t, layer1Dir, layer2Dir, layer3Dir, expectedDir)

	// Build one image per layer and merge them.
	blobDir := filepath.Join(workDir, "blobs")
	mergedBootstrap := filepath.Join(workDir, "merged.bootstrap")
	cacheDir := filepath.Join(workDir, "cache")
	layer1Blob := util.BuildImage(t, nydusBin, filepath.Join(workDir, "layer1.bootstrap"), blobDir, layer1Dir, 4096)
	layer2Blob := util.BuildImage(t, nydusBin, filepath.Join(workDir, "layer2.bootstrap"), blobDir, layer2Dir, 4096)
	layer3Blob := util.BuildImage(t, nydusBin, filepath.Join(workDir, "layer3.bootstrap"), blobDir, layer3Dir, 4096)
	util.MergeBootstrap(t, nydusBin, mergedBootstrap, layer1Blob, layer2Blob, layer3Blob)

	// Walk the whole tree against the expected merge so the cache holds every
	// chunk decoded: the kernel mount consumes plain devices while the store
	// holds zstd-compressed blobs, so the cached .blob.data files back it.
	unmountNydus := util.MountNydusBootstrap(t, nydusBin, mergedBootstrap, blobDir, cacheDir, nydusMountpoint)
	defer unmountNydus()
	util.CheckDirectoryEqual(t, expectedDir, nydusMountpoint, true)
	verifyChunkCacheFiles(t, cacheDir, layer1Blob, layer2Blob, layer3Blob)

	// Mount the same bootstrap through the kernel over the cached blob data
	// and diff the two mounts.
	devices := make([]string, 0, 3)
	for _, blob := range []string{layer1Blob, layer2Blob, layer3Blob} {
		blobData := filepath.Join(cacheDir, util.Sha256File(t, blob)+".blob.data")
		assert.FileExists(blobData, "cached uncompressed blob data should exist after nydus cached mount")
		devices = append(devices, blobData)
	}
	nativeMountpoint := util.MountErofsLoop(t, mergedBootstrap, devices...)
	util.CheckDirectoryEqual(t, nativeMountpoint, nydusMountpoint, true)
}
