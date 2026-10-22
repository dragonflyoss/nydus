package util

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	// ErofsSuperOffset is the offset of the EROFS superblock in an image.
	ErofsSuperOffset = 1024

	// ErofsSuperMagic is the magic the EROFS superblock starts with.
	ErofsSuperMagic = 0xE0F5E1E2

	// ErofsDevSlotSize is the size of one device table slot.
	ErofsDevSlotSize = 128

	// erofsDevTagLen is the length of the tag naming a device in its slot.
	erofsDevTagLen = 64

	// ErofsDevBlocksOff is the offset of the block count in a device table
	// slot.
	ErofsDevBlocksOff = 64

	// erofsExtraDevicesOff is the offset of the device count in the superblock.
	erofsExtraDevicesOff = 86

	// ErofsDevtSlotOff is the offset of the device table slot index in the
	// superblock.
	ErofsDevtSlotOff = 88
)

// FullBlobPattern matches the full blob a build writes, named by its digest.
var FullBlobPattern = regexp.MustCompile("^[0-9a-f]{64}$")

// blobMetaFilePattern matches the blob meta sidecar a build writes.
var blobMetaFilePattern = regexp.MustCompile(`^[0-9a-f]{64}\.blob\.meta$`)

// BuildImage runs `nydus build` on source into blobDir with the given chunk
// size and any further builder flags, writing the bootstrap when its path is
// not empty, checks the image with fsck.erofs and returns the path of the one
// blob the build produced.
func BuildImage(t *testing.T, nydusBin, bootstrap, blobDir, source string, chunkSize int, extraArgs ...string) string {
	t.Helper()
	assert.NoError(t, os.MkdirAll(blobDir, 0o755))
	before := ListFiles(t, blobDir)

	args := []string{"build", "--blob-dir", blobDir, "--chunk-size", strconv.Itoa(chunkSize)}
	if bootstrap != "" {
		args = append(args, "--bootstrap", bootstrap)
	}
	args = append(args, extraArgs...)
	args = append(args, source)
	out, err := exec.Command(nydusBin, args...).CombinedOutput()
	assert.NoError(t, err, "nydus build failed: %s", out)

	blobs, blobMetas := NewBlobFiles(t, blobDir, before)
	assert.Len(t, blobMetas, 1, "expected exactly one new blob meta in blob-dir")
	if !assert.Len(t, blobs, 1, "expected exactly one new blob in blob-dir") {
		return ""
	}
	if bootstrap != "" {
		FsckImage(t, bootstrap, blobDir)
	}

	return blobs[0]
}

// NewBlobFiles returns the full blobs and blob metas a build added to blobDir
// since the ListFiles snapshot before, sorted, and fails the test on any
// other new file, which a build must not write.
func NewBlobFiles(t *testing.T, blobDir string, before map[string]struct{}) (blobs, blobMetas []string) {
	t.Helper()
	var unexpected []string
	for path := range ListFiles(t, blobDir) {
		if _, existed := before[path]; existed {
			continue
		}

		switch base := filepath.Base(path); {
		case FullBlobPattern.MatchString(base):
			blobs = append(blobs, path)
		case blobMetaFilePattern.MatchString(base):
			blobMetas = append(blobMetas, path)
		default:
			unexpected = append(unexpected, path)
		}
	}
	assert.Empty(t, unexpected, "unexpected files created in blob-dir: %v", unexpected)
	slices.Sort(blobs)
	slices.Sort(blobMetas)

	return blobs, blobMetas
}

// MergeBootstrap runs `nydus merge` on the source bootstraps into bootstrap.
func MergeBootstrap(t *testing.T, nydusBin, bootstrap string, sources ...string) {
	t.Helper()
	args := append([]string{"merge", "--bootstrap", bootstrap}, sources...)
	out, err := exec.Command(nydusBin, args...).CombinedOutput()
	assert.NoError(t, err, "nydus merge failed: %s", out)
}

// FsckImage validates the bootstrap with fsck.erofs, an oracle independent of
// the nydus reader that catches encoding bugs the reader happens to tolerate.
// It is skipped when erofs-utils is not installed.
func FsckImage(t *testing.T, bootstrap, blobDir string) {
	t.Helper()
	fsck, err := exec.LookPath("fsck.erofs")
	if err != nil {
		t.Logf("fsck.erofs not found, skipping structural validation of %s", bootstrap)
		return
	}

	devices, err := ErofsDeviceArgs(bootstrap, blobDir)
	assert.NoError(t, err, "reading the device table of %s", bootstrap)
	args := append([]string{"--extract"}, devices...)
	args = append(args, bootstrap)
	out, err := exec.Command(fsck, args...).CombinedOutput()
	assert.NoError(t, err, "fsck.erofs rejected %s: %s", bootstrap, out)

	// fsck.erofs still exits 0 after reporting structural problems such as a
	// wrong dirent name order, so the output has to be scanned as well.
	assert.NotContains(t, string(out), "filesystem corruption", "fsck.erofs found corruption in %s", bootstrap)
}

// ErofsDeviceArgs builds the fsck.erofs --device flags from the image's own
// device table. Listing the blob directory instead would be wrong for merged
// images: the directory accumulates the blobs of every layer, while a given
// bootstrap references only its own, and fsck rejects a count mismatch.
func ErofsDeviceArgs(bootstrap, blobDir string) ([]string, error) {
	f, err := os.Open(bootstrap)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	header := make([]byte, ErofsSuperOffset+128)
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, fmt.Errorf("reading superblock: %w", err)
	}

	sb := header[ErofsSuperOffset:]
	if magic := binary.LittleEndian.Uint32(sb); magic != ErofsSuperMagic {
		return nil, fmt.Errorf("bad EROFS magic 0x%08x in %s", magic, bootstrap)
	}

	count := int(binary.LittleEndian.Uint16(sb[erofsExtraDevicesOff:]))
	if count == 0 {
		return nil, nil
	}

	slotOff := int(binary.LittleEndian.Uint16(sb[ErofsDevtSlotOff:])) * ErofsDevSlotSize
	table := make([]byte, count*ErofsDevSlotSize)
	if _, err := f.ReadAt(table, int64(slotOff)); err != nil {
		return nil, fmt.Errorf("reading device table at %d: %w", slotOff, err)
	}

	args := make([]string, 0, count)
	for i := range count {
		tag := table[i*ErofsDevSlotSize : i*ErofsDevSlotSize+erofsDevTagLen]
		name := string(bytes.TrimRight(tag, "\x00"))
		if name == "" {
			return nil, fmt.Errorf("device slot %d of %s has an empty tag", i, bootstrap)
		}

		args = append(args, "--device="+filepath.Join(blobDir, name))
	}

	return args, nil
}

// CheckImage runs `nydus check` with args and logs its output.
func CheckImage(t *testing.T, nydusBin string, args ...string) {
	t.Helper()
	args = append([]string{"check"}, args...)
	out, err := exec.Command(nydusBin, args...).CombinedOutput()
	assert.NoError(t, err, "nydus check failed: %s", out)
	t.Logf("nydus %s output:\n%s", strings.Join(args, " "), out)
}
