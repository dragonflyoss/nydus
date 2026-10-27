package oracle

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/dragonflyoss/nydus/tests/e2e/internal/env"
	"github.com/stretchr/testify/require"
)

// FsckErofs validates a bootstrap with erofs-utils. A nydus image is plain
// EROFS, so fsck.erofs is a judge completely independent of the nydus
// reader: it catches encoding bugs the reader happens to tolerate.
func FsckErofs(t env.TB, bootstrap, blobDir string) {
	t.Helper()
	fsck := env.RequireTool(t, "fsck.erofs")

	devices, err := ErofsDeviceArgs(bootstrap, blobDir)
	require.NoError(t, err, "reading the device table of %s", bootstrap)

	args := append([]string{"--extract"}, devices...)
	args = append(args, bootstrap)
	out, err := exec.Command(fsck, args...).CombinedOutput()
	require.NoError(t, err, "fsck.erofs rejected %s: %s", bootstrap, out)
	// fsck.erofs still exits 0 after reporting structural problems such as
	// "wrong dirent name order", so the output has to be scanned as well.
	require.NotContains(t, string(out), "filesystem corruption", "fsck.erofs found corruption in %s", bootstrap)
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

// ErofsDeviceArgs builds --device=<blobDir>/<tag> flags (as fsck.erofs,
// erofsfuse and the kernel mount helpers take them) from the image's own
// device table. Listing the blob directory instead would be wrong for merged
// images: the directory accumulates the blobs of every layer, while a given
// bootstrap references only its own.
func ErofsDeviceArgs(bootstrap, blobDir string) ([]string, error) {
	tags, err := ErofsDeviceTags(bootstrap)
	if err != nil {
		return nil, err
	}
	args := make([]string, 0, len(tags))
	for _, tag := range tags {
		args = append(args, "--device="+filepath.Join(blobDir, tag))
	}
	return args, nil
}

// ErofsDeviceTags returns the blob names in the bootstrap's device table, in
// device-id order.
func ErofsDeviceTags(bootstrap string) ([]string, error) {
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
	slotOff := int64(binary.LittleEndian.Uint16(sb[erofsDevtSlotOffO:])) * erofsDevSlotSize
	table := make([]byte, count*erofsDevSlotSize)
	if _, err := f.ReadAt(table, slotOff); err != nil {
		return nil, fmt.Errorf("reading device table at %d: %w", slotOff, err)
	}

	tags := make([]string, 0, count)
	for i := 0; i < count; i++ {
		tag := table[i*erofsDevSlotSize : i*erofsDevSlotSize+erofsDevTagLen]
		name := string(bytes.TrimRight(tag, "\x00"))
		if name == "" {
			return nil, fmt.Errorf("device slot %d of %s has an empty tag", i, bootstrap)
		}
		tags = append(tags, name)
	}
	return tags, nil
}
