// Package erofs reads the EROFS superblock device table and checks images
// with fsck.erofs.
package erofs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	// SuperOffset is the byte offset of the superblock in a bootstrap.
	SuperOffset = 1024

	// SuperMagic is the magic number the superblock starts with.
	SuperMagic = 0xE0F5E1E2

	// DevSlotBlocksOff is the offset of the block count in a device slot.
	DevSlotBlocksOff = 64

	superSize       = 128
	devSlotSize     = 128
	devTagLen       = 64
	extraDevicesOff = 86
	devtSlotOff     = 88
)

// DevtSlotOff returns the offset of the device table in the bootstrap
// header, which must hold at least the superblock.
func DevtSlotOff(header []byte) int {
	return int(binary.LittleEndian.Uint16(header[SuperOffset+devtSlotOff:])) * devSlotSize
}

// DeviceTags returns the blob names in the bootstrap's device table, in
// device-id order.
func DeviceTags(bootstrap string) ([]string, error) {
	f, err := os.Open(bootstrap)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()
	header := make([]byte, SuperOffset+superSize)
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, fmt.Errorf("reading superblock: %w", err)
	}

	sb := header[SuperOffset:]
	if magic := binary.LittleEndian.Uint32(sb); magic != SuperMagic {
		return nil, fmt.Errorf("bad EROFS magic 0x%08x in %s", magic, bootstrap)
	}

	count := int(binary.LittleEndian.Uint16(sb[extraDevicesOff:]))
	if count == 0 {
		return nil, nil
	}

	slotOff := DevtSlotOff(header)
	table := make([]byte, count*devSlotSize)
	if _, err := f.ReadAt(table, int64(slotOff)); err != nil {
		return nil, fmt.Errorf("reading device table at %d: %w", slotOff, err)
	}

	tags := make([]string, 0, count)

	for i := range count {
		tag := table[i*devSlotSize : i*devSlotSize+devTagLen]
		name := string(bytes.TrimRight(tag, "\x00"))
		if name == "" {
			return nil, fmt.Errorf("device slot %d of %s has an empty tag", i, bootstrap)
		}

		tags = append(tags, name)
	}

	return tags, nil
}
