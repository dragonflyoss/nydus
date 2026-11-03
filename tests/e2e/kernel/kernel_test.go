package kernel

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dragonflyoss/nydus/tests/e2e/util/env"
	"github.com/dragonflyoss/nydus/tests/e2e/util/erofs"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fixture"
	"github.com/dragonflyoss/nydus/tests/e2e/util/fstest"
	"github.com/dragonflyoss/nydus/tests/e2e/util/mount"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestNativeMount(t *testing.T) {
	t.Parallel()
	for _, layout := range fixture.Layouts {
		if !layout.Native {
			continue
		}

		t.Run(layout.Name, func(t *testing.T) {
			t.Parallel()
			requireKernelFor(t, layout)
			img := fixture.Get(t, layout.Name)
			mnt := mountEROFS(t, img.Bootstrap, deviceFiles(t, img.Bootstrap, img.BlobDir, ""))
			fstest.VerifyMount(t, mnt, img.Want, img.Compare())
		})
	}

	for _, name := range fixture.MergeLayouts {
		layout := fixture.MustLayout(t, name)
		if !layout.Native {
			continue
		}

		t.Run(fixture.MergedPrefix+name, func(t *testing.T) {
			t.Parallel()
			requireKernelFor(t, layout)
			img := fixture.Merged(t, layout)
			mnt := mountEROFS(t, img.Bootstrap, deviceFiles(t, img.Bootstrap, img.BlobDir, ""))
			fstest.VerifyMount(t, mnt, img.Want, img.Compare())
		})
	}

	t.Run("Decoded", func(t *testing.T) {
		t.Parallel()
		layout := fixture.MustLayout(t, "none-4k")
		requireKernelFor(t, layout)
		img := fixture.Get(t, layout.Name)
		dir := env.WorkDir(t)
		device := filepath.Join(dir, filepath.Base(img.Blob(t)))
		if !assert.NoError(t, os.WriteFile(device, decodeNoneBlob(t, img.Bootstrap, img.Blob(t)), 0o644)) {
			t.FailNow()
		}

		mnt := mountEROFS(t, img.Bootstrap, deviceFiles(t, img.Bootstrap, dir, ""))
		fstest.VerifyMount(t, mnt, img.Want, img.Compare())
	})
}

func TestFUSEVsKernel(t *testing.T) {
	t.Parallel()
	for _, name := range fixture.MergeLayouts {
		layout := fixture.MustLayout(t, name)
		if layout.Tar {
			continue
		}

		t.Run(fixture.MergedPrefix+name, func(t *testing.T) {
			t.Parallel()
			requireKernelFor(t, layout)
			img := fixture.Merged(t, layout)

			var fuse *mount.Mounted

			var devices []string
			if layout.Native {
				fuse = mount.Mount(t, mount.FUSE{}, img, mount.Options{})
				devices = deviceFiles(t, img.Bootstrap, img.BlobDir, "")
			} else {
				fuse = mount.Mount(t, mount.FUSE{}, img, mount.Options{Mode: mount.Warm})
				devices = deviceFiles(t, img.Bootstrap, fuse.CacheDir, mount.CacheDataSuffix)
			}

			kernel := mountEROFS(t, img.Bootstrap, devices)

			fstest.CompareTree(t, fstest.ScanTree(t, kernel), fstest.ScanTree(t, fuse.Root), fstest.CompareOptions{Nlink: true})
			fstest.VerifyMount(t, kernel, img.Want, img.Compare())
		})
	}
}

const blockSize = 4096

func requireKernelFor(t testing.TB, layout fixture.Layout) {
	t.Helper()
	env.RequireKernel(t, 5, 16, "EROFS chunk-based files on extra devices")

	switch layout.Compressor() {
	case "erofs-lz4":
		env.RequireKernel(t, 6, 1, "EROFS LZ4 fragments")

	case "erofs-zstd":
		env.RequireKernel(t, 6, 10, "EROFS zstd")
	}
}

func mountEROFS(t testing.TB, bootstrap string, devices []string) string {
	t.Helper()
	env.RequireRoot(t)
	env.RequireFilesystem(t, "erofs")
	losetup := env.RequireTool(t, "losetup")
	env.Require(t, os.Getpagesize() == blockSize, "EROFS images use 4KiB blocks, the page size is %d", os.Getpagesize())

	mnt := filepath.Join(env.WorkDir(t), "mnt")
	if !assert.NoError(t, os.Mkdir(mnt, 0o755)) {
		t.FailNow()
	}

	attach := func(path string) string {
		dev := strings.TrimSpace(env.Run(t, losetup, "--find", "--show", "--read-only", path))

		t.Cleanup(func() {
			assert.NoError(t, exec.Command(losetup, "--detach", dev).Run())
		})

		return dev
	}

	primary := attach(bootstrap)
	var opts []string

	for _, path := range devices {
		opts = append(opts, "device="+attach(path))
	}

	t.Cleanup(func() { mount.Unmount(mnt) })

	if !assert.NoError(t, unix.Mount(primary, mnt, "erofs", unix.MS_RDONLY, strings.Join(opts, ","))) {
		t.FailNow()
	}

	return mnt
}

func deviceFiles(t testing.TB, bootstrap, dir, suffix string) []string {
	t.Helper()
	tags, err := erofs.DeviceTags(bootstrap)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	files := make([]string, len(tags))

	for i, tag := range tags {
		files[i] = filepath.Join(dir, tag+suffix)
		assert.FileExists(t, files[i])
	}

	return files
}

func decodeNoneBlob(t testing.TB, bootstrap, blob string) []byte {
	t.Helper()
	le := binary.LittleEndian
	header, err := os.ReadFile(bootstrap)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	slot := erofs.DevtSlotOff(header)
	if !assert.Less(t, slot+erofs.DevSlotBlocksOff+4, len(header)) {
		t.FailNow()
	}

	decodedSize := int(le.Uint32(header[slot+erofs.DevSlotBlocksOff:])) * blockSize

	fullBlob, err := os.ReadFile(blob)
	if !assert.NoError(t, err) {
		t.FailNow()
	}

	meta := fixture.ReadBlobMeta(t, blob)
	if !assert.Zero(t, meta.Incompat) {
		t.FailNow()
	}

	groups := meta.Table(t, fixture.ChunkGroupTable, 24)
	if !assert.Zero(t, groups.Header[17]) {
		t.FailNow()
	}

	chunks := meta.Table(t, fixture.ChunkLengthTable, 4)
	index := meta.Table(t, fixture.ChunkGroupIndexTable, 4)
	groupCount := groups.Count - 1

	group := func(i int) (blobOffset, startBlock, firstMember, size int) {
		e := groups.Entries[i*24:]
		return int(le.Uint64(e)), int(le.Uint32(e[8:])), int(le.Uint32(e[12:])), int(le.Uint32(e[16:]))
	}

	blobEnd, totalBlocks, totalMembers, _ := group(groupCount)
	if !assert.Equal(t, chunks.Count, totalMembers) {
		t.FailNow()
	}
	if !assert.Equal(t, decodedSize, totalBlocks*blockSize) {
		t.FailNow()
	}
	if !assert.LessOrEqual(t, blobEnd, len(fullBlob)) {
		t.FailNow()
	}
	if !assert.LessOrEqual(t, index.Header[16], groups.Header[16]) {
		t.FailNow()
	}

	granule := uint64(blockSize) << index.Header[16]
	if !assert.Equal(t, (uint64(decodedSize)+granule-1)/granule, uint64(index.Count)) {
		t.FailNow()
	}

	decoded := make([]byte, decodedSize)

	for g := range groupCount {
		src, startBlock, firstMember, size := group(g)
		srcEnd, nextBlock, nextMember, _ := group(g + 1)
		if !assert.Equal(t, srcEnd-src, size) {
			t.FailNow()
		}
		if !assert.Greater(t, nextMember, firstMember) {
			t.FailNow()
		}

		for block := startBlock; block < nextBlock; block++ {
			candidate := int(le.Uint32(index.Entries[int(uint64(block*blockSize)/granule)*4:]))
			if !assert.Less(t, candidate, groupCount) {
				t.FailNow()
			}

			if _, following, _, _ := group(candidate + 1); block >= following {
				candidate++
			}

			assert.Equal(t, g, candidate)
		}

		dst := startBlock * blockSize

		for member := firstMember; member < nextMember; member++ {
			length := int(le.Uint32(chunks.Entries[member*4:]))
			if !assert.Positive(t, length) {
				t.FailNow()
			}
			if !assert.LessOrEqual(t, src+length, srcEnd) {
				t.FailNow()
			}
			if !assert.LessOrEqual(t, dst+length, nextBlock*blockSize) {
				t.FailNow()
			}

			copy(decoded[dst:dst+length], fullBlob[src:src+length])
			src += length
			dst += (length + blockSize - 1) / blockSize * blockSize
		}

		if !assert.Equal(t, srcEnd, src) {
			t.FailNow()
		}

		assert.Equal(t, nextBlock*blockSize, dst)
	}

	return decoded
}
