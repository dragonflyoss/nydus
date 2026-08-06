/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package converter

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// nydus blob footer layout (see src/metadata/blob_footer.rs). The footer is the
// last NydusBlobFooterSize bytes of a full blob and records the absolute
// offsets of the data / bootstrap / blob-meta regions.
const (
	// NydusBlobFooterSize is the fixed byte size of the trailing footer of a
	// nydus full blob.
	NydusBlobFooterSize = 4096
	// NydusBlockSize is the nydus/EROFS block size in bytes.
	NydusBlockSize = 4096
	// footerIncompatMask selects the incompatible half of the u32 flags field
	// at offset 12: unknown incompat bits mean the footer cannot be parsed.
	// The version at offset 8 is informational and not gated on.
	footerIncompatMask = 0x0000FFFF
	// bootstrapOffsetField is the byte offset of the u64 bootstrap_offset field
	// within the footer.
	bootstrapOffsetField = 32
	// blobMetaOffsetField is the byte offset of the u64 blob_meta_offset field
	// within the footer.
	blobMetaOffsetField = 40
	// blobMetaBlocksField is the byte offset of the u32 blob_meta_blocks field
	// within the footer.
	blobMetaBlocksField = 60
)

// NydusBlobFooterMagic is the 8 raw ASCII bytes at the start of the footer,
// written as-is (same style as the "LPBLMETA" blob meta and "LPGRPMAP"
// groupmap sidecars).
var NydusBlobFooterMagic = []byte("LPFOOTER")

// BlobMetaFile is a per-layer blob meta artifact packed into the bootstrap layer
// alongside image.boot, named "<full_blob_sha256>.blob.meta".
type BlobMetaFile struct {
	Name string
	Data []byte
}

// AppendFile describes a file to bundle into the bootstrap layer tar alongside
// image.boot and the blob meta artifacts.
type AppendFile struct {
	Name string // basename, placed under "image/"
	Data []byte
}

// readFooter reads and validates the trailing footer of a nydus full blob.
func readFooter(ra io.ReaderAt, size int64) ([]byte, error) {
	if size < NydusBlobFooterSize {
		return nil, errors.Errorf("blob is too small for a nydus footer (%d bytes)", size)
	}
	footer := make([]byte, NydusBlobFooterSize)
	if _, err := ra.ReadAt(footer, size-NydusBlobFooterSize); err != nil {
		return nil, errors.Wrap(err, "read nydus footer")
	}
	if !bytes.Equal(footer[0:8], NydusBlobFooterMagic) {
		return nil, errors.Errorf("not a nydus blob: bad footer magic %q", footer[0:8])
	}
	if incompat := binary.LittleEndian.Uint32(footer[12:16]) & footerIncompatMask; incompat != 0 {
		return nil, errors.Errorf("unsupported nydus footer incompat flags %#x", incompat)
	}
	return footer, nil
}

// StageNydusMetadata stages a nydus full blob for `nydus merge` without
// materializing the (large) compressed data region.
//
// A nydus full blob is laid out as [compressed data][bootstrap][blob meta]
// [footer]. `nydus merge` only reads the bootstrap and blob meta (located via
// the footer), never the compressed data. So we read just the footer to find
// the bootstrap offset, then write a sparse file that keeps the metadata tail at
// its original absolute offset while leaving [0, bootstrapOffset) as a hole. The
// file is named digestHex (the blob's lowercase hex sha256), which `nydus
// merge` records verbatim in the device slot so a registry backend can address
// the blob by the same digest.
func StageNydusMetadata(ra io.ReaderAt, size int64, digestHex, dir string) (string, error) {
	footer, err := readFooter(ra, size)
	if err != nil {
		return "", err
	}
	bootstrapOffset := int64(binary.LittleEndian.Uint64(footer[bootstrapOffsetField : bootstrapOffsetField+8]))
	if bootstrapOffset < 0 || bootstrapOffset > size {
		return "", errors.Errorf("invalid bootstrap offset %d (blob size %d)", bootstrapOffset, size)
	}

	tmp, err := os.CreateTemp(dir, "stage-*")
	if err != nil {
		return "", errors.Wrap(err, "create stage temp file")
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	// The staged file content is bootstrapOffset zero bytes (a sparse hole)
	// followed by the metadata tail at its original absolute offset.
	if _, err := tmp.Seek(bootstrapOffset, io.SeekStart); err != nil {
		return "", errors.Wrap(err, "seek to bootstrap offset")
	}
	tail := io.NewSectionReader(ra, bootstrapOffset, size-bootstrapOffset)
	if _, err := io.Copy(tmp, tail); err != nil {
		return "", errors.Wrap(err, "stage nydus metadata")
	}
	if err := tmp.Close(); err != nil {
		return "", errors.Wrap(err, "close stage temp file")
	}

	// Name the staged source by the blob's full digest; `nydus merge` uses the
	// file name as the device slot blob id.
	dst := filepath.Join(dir, digestHex)
	if err := os.Rename(tmpPath, dst); err != nil {
		return "", errors.Wrap(err, "rename staged blob")
	}
	committed = true
	return dst, nil
}

// ExtractBlobMeta reads the blob meta region of a nydus full blob, locating it
// via the trailing footer. The returned bytes are the exact
// `<full_blob_sha256>.blob.meta` artifact produced by `nydus build`.
func ExtractBlobMeta(ra io.ReaderAt, size int64) ([]byte, error) {
	footer, err := readFooter(ra, size)
	if err != nil {
		return nil, err
	}
	blobMetaOffset := int64(binary.LittleEndian.Uint64(footer[blobMetaOffsetField : blobMetaOffsetField+8]))
	blobMetaSize := int64(binary.LittleEndian.Uint32(footer[blobMetaBlocksField:blobMetaBlocksField+4])) * NydusBlockSize
	if blobMetaOffset < 0 || blobMetaSize <= 0 || blobMetaOffset+blobMetaSize > size {
		return nil, errors.Errorf("invalid blob meta region [%d,+%d) (blob size %d)", blobMetaOffset, blobMetaSize, size)
	}

	buf := make([]byte, blobMetaSize)
	if _, err := ra.ReadAt(buf, blobMetaOffset); err != nil {
		return nil, errors.Wrap(err, "read blob meta region")
	}
	return buf, nil
}
