// Package kernel tests that the Linux EROFS driver reads nydus images: native
// layers straight from their blobs, chunk-based layers from a decoded
// device, and that it reads them exactly as the FUSE reader does.
package kernel

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/mount"
	"github.com/dragonflyoss/nydus/tests/e2e/internal/oracle"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const blockSize = 4096

// requireKernelFor requires a kernel whose EROFS driver reads layout's
// encoding: chunk-based files on extra devices, LZ4 with fragments, zstd.
func requireKernelFor(t env.TB, layout fixture.Layout) {
	t.Helper()
	env.RequireKernel(t, 5, 16, "EROFS chunk-based files on extra devices")
	for i, arg := range layout.Args {
		if arg != "--compressor" || i+1 == len(layout.Args) {
			continue
		}
		switch layout.Args[i+1] {
		case "erofs-lz4":
			env.RequireKernel(t, 6, 1, "EROFS LZ4 fragments")
		case "erofs-zstd":
			env.RequireKernel(t, 6, 10, "EROFS zstd")
		}
	}
}

// mountErofs mounts bootstrap with the kernel EROFS driver, each file in
// devices backing the extra device of the same index, all read-only through
// loop devices. Everything is torn down when the test ends.
func mountErofs(t *testing.T, bootstrap string, devices []string) string {
	t.Helper()
	env.RequireRoot(t)
	env.RequireFilesystem(t, "erofs")
	losetup := env.RequireTool(t, "losetup")
	env.Require(t, os.Getpagesize() == blockSize, "EROFS images use 4KiB blocks, the page size is %d", os.Getpagesize())

	mnt := filepath.Join(env.WorkDir(t), "mnt")
	require.NoError(t, os.Mkdir(mnt, 0o755))
	attach := func(path string) string {
		out, err := exec.Command(losetup, "--find", "--show", "--read-only", path).CombinedOutput()
		require.NoError(t, err, "losetup %s: %s", path, out)
		dev := strings.TrimSpace(string(out))
		// Registered before the unmount below, so it runs after it.
		t.Cleanup(func() {
			if out, err := exec.Command(losetup, "--detach", dev).CombinedOutput(); err != nil {
				t.Errorf("losetup --detach %s: %v: %s", dev, err, out)
			}
		})
		return dev
	}
	primary := attach(bootstrap)
	var opts []string
	for _, path := range devices {
		opts = append(opts, "device="+attach(path))
	}
	err := unix.Mount(primary, mnt, "erofs", unix.MS_RDONLY, strings.Join(opts, ","))
	require.NoError(t, err, "mount -t erofs %s (%s)", bootstrap, strings.Join(opts, ","))
	t.Cleanup(func() { mount.Unmount(mnt) })
	return mnt
}

// deviceFiles returns the files backing the extra devices of bootstrap: the
// device table's tag plus suffix, in dir.
func deviceFiles(t env.TB, bootstrap, dir, suffix string) []string {
	t.Helper()
	tags, err := oracle.ErofsDeviceTags(bootstrap)
	require.NoError(t, err)
	files := make([]string, len(tags))
	for i, tag := range tags {
		files[i] = filepath.Join(dir, tag+suffix)
		require.FileExists(t, files[i], "device %d", i+1)
	}
	return files
}

// EROFS superblock offsets for the device table.
const (
	erofsSuperOffset = 1024
	erofsDevtSlotOff = 88 // u16 slot offset, relative to the superblock
	erofsDevSlotSize = 128
	erofsDevSlotBlks = 64 // u32 block count, relative to the slot
)

// decodeNoneBlob rebuilds the device of a single-blob compressor-none image
// from the blob and its blob meta alone, independently of the nydus reader.
// The meta tables follow a 24-byte header back to back at 8-byte boundaries,
// each starting with a 16-byte header (kind, header size, entry size, entry
// count). Chunk groups (table 1) name their payload offset in the blob, first
// device block, first member and size; the chunk length table (2) splits a
// group into chunks, each starting a new block; the granule index (3) maps
// device blocks to groups. A terminator group carries the totals.
func decodeNoneBlob(t *testing.T, bootstrap, blob string) []byte {
	t.Helper()
	le := binary.LittleEndian
	header, err := os.ReadFile(bootstrap)
	require.NoError(t, err)
	slot := int(le.Uint16(header[erofsSuperOffset+erofsDevtSlotOff:])) * erofsDevSlotSize
	require.Less(t, slot+erofsDevSlotBlks+4, len(header), "device slot of %s", bootstrap)
	decodedSize := int(le.Uint32(header[slot+erofsDevSlotBlks:])) * blockSize

	fullBlob, err := os.ReadFile(blob)
	require.NoError(t, err)
	metadata, err := os.ReadFile(blob + ".blob.meta")
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(metadata), 24)
	require.Equal(t, "NDBLMETA", string(metadata[:8]))
	require.Zero(t, le.Uint32(metadata[12:]), "no incompat features")
	tables := map[uint16][]byte{}
	offset := 24
	for i := 0; i < int(le.Uint16(metadata[20:])); i++ {
		offset = (offset + 7) / 8 * 8
		require.LessOrEqual(t, offset+16, len(metadata))
		table := metadata[offset:]
		size := int(le.Uint16(table[2:])) + int(le.Uint32(table[8:]))*int(le.Uint32(table[12:]))
		require.LessOrEqual(t, offset+size, len(metadata))
		tables[le.Uint16(table)] = metadata[offset : offset+size]
		offset += size
	}
	entries := func(kind uint16, entrySize int) (header, entries []byte, count int) {
		table, ok := tables[kind]
		require.True(t, ok, "table %d", kind)
		headerSize := int(le.Uint16(table[2:]))
		require.Equal(t, entrySize, int(le.Uint32(table[8:])), "table %d entry size", kind)
		return table[:headerSize], table[headerSize:], int(le.Uint32(table[12:]))
	}
	groupHeader, groupTable, groupEntries := entries(1, 24)
	require.Zero(t, groupHeader[17], "compressor none")
	_, chunkTable, chunkCount := entries(2, 4)
	granuleHeader, indexTable, indexCount := entries(3, 4)

	groupCount := groupEntries - 1
	group := func(i int) (blobOffset, startBlock, firstMember, size int) {
		e := groupTable[i*24:]
		return int(le.Uint64(e)), int(le.Uint32(e[8:])), int(le.Uint32(e[12:])), int(le.Uint32(e[16:]))
	}
	blobEnd, totalBlocks, totalMembers, _ := group(groupCount)
	require.Equal(t, chunkCount, totalMembers, "terminator member count")
	require.Equal(t, decodedSize, totalBlocks*blockSize, "device blocks cover the groups")
	require.LessOrEqual(t, blobEnd, len(fullBlob))
	require.LessOrEqual(t, granuleHeader[16], groupHeader[16], "granule within the group span")
	granule := uint64(blockSize) << granuleHeader[16]
	require.Equal(t, (uint64(decodedSize)+granule-1)/granule, uint64(indexCount))

	decoded := make([]byte, decodedSize)
	for g := 0; g < groupCount; g++ {
		src, startBlock, firstMember, size := group(g)
		srcEnd, nextBlock, nextMember, _ := group(g + 1)
		require.Equal(t, srcEnd-src, size, "group %d is stored plain", g)
		require.Greater(t, nextMember, firstMember)
		for block := startBlock; block < nextBlock; block++ {
			candidate := int(le.Uint32(indexTable[int(uint64(block*blockSize)/granule)*4:]))
			require.Less(t, candidate, groupCount)
			if _, following, _, _ := group(candidate + 1); block >= following {
				candidate++
			}
			require.Equal(t, g, candidate, "granule index lookup of block %d", block)
		}
		dst := startBlock * blockSize
		for member := firstMember; member < nextMember; member++ {
			length := int(le.Uint32(chunkTable[member*4:]))
			require.Positive(t, length)
			require.LessOrEqual(t, src+length, srcEnd, "group %d payload", g)
			require.LessOrEqual(t, dst+length, nextBlock*blockSize, "group %d span", g)
			copy(decoded[dst:dst+length], fullBlob[src:src+length])
			src += length
			dst += (length + blockSize - 1) / blockSize * blockSize
		}
		require.Equal(t, srcEnd, src, "group %d payload is its chunks", g)
		require.Equal(t, nextBlock*blockSize, dst, "group %d spans its chunks' blocks", g)
	}
	return decoded
}
