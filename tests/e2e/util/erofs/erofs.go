// Package erofs reads the EROFS superblock and device table, locates inodes
// and checks images with fsck.erofs.
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
	rootNidOff      = 14
	metaBlkAddrOff  = 40
	extraDevicesOff = 86
	devtSlotOff     = 88

	blockSize         = 4096
	inodeSlotSize     = 32
	compressedFull    = 1
	xattrIbodyHeader  = 12
	lclusterIndexSize = 8
)

// RootNid returns the NID of the root inode from the bootstrap header, which
// must hold at least the superblock.
func RootNid(header []byte) uint64 {
	return uint64(binary.LittleEndian.Uint16(header[SuperOffset+rootNidOff:]))
}

// InodeOff returns the byte offset in the bootstrap of the inode nid; the
// kernel reports nid as the inode number.
func InodeOff(header []byte, nid uint64) int64 {
	return int64(binary.LittleEndian.Uint32(header[SuperOffset+metaBlkAddrOff:]))*blockSize + int64(nid)*inodeSlotSize
}

// LclusterIndexOff returns the byte offset in bootstrap, the whole file, of
// the index of logical cluster lcn of the compressed inode nid.
func LclusterIndexOff(bootstrap []byte, nid uint64, lcn int) (int64, error) {
	off := InodeOff(bootstrap, nid)
	if off+inodeSlotSize > int64(len(bootstrap)) {
		return 0, fmt.Errorf("inode %d lies past the bootstrap", nid)
	}

	format := binary.LittleEndian.Uint16(bootstrap[off:])
	if layout := format >> 1 & 7; layout != compressedFull {
		return 0, fmt.Errorf("inode %d has data layout %d, not compressed", nid, layout)
	}

	// The low bit selects the 64-byte inode; shared xattrs follow the
	// header four bytes each.
	end := off + inodeSlotSize<<(format&1)
	if n := int64(binary.LittleEndian.Uint16(bootstrap[off+2:])); n > 0 {
		end += xattrIbodyHeader + (n-1)*4
	}

	// The 8-byte map header and 8 bytes of padding precede the indexes.
	return (end+7)&^7 + 16 + int64(lcn)*lclusterIndexSize, nil
}

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
