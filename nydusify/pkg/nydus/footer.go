/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package nydus

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// nydus blob footer layout (see nydus-format/src/blob/footer.rs). The footer is the
// last NydusBlobFooterSize bytes of a full blob and records the absolute
// offsets and byte sizes of the data / bootstrap / blob-meta regions. There
// is no version: the feature_compat word at offset 8 is ignored and unknown
// feature_incompat bits reject the footer.
const (
	// NydusBlobFooterSize is the fixed byte size of the trailing footer of a
	// nydus full blob.
	NydusBlobFooterSize = 4096
	// footerIncompatBootstrapZstd marks the embedded bootstrap region as one zstd
	// frame. Staging copies the region verbatim (nydus merge decodes it), so
	// the feature is understood, not acted on, here.
	footerIncompatBootstrapZstd = 1 << 0
	// footerFlagRawDevice marks a native EROFS layer: the data region is the
	// raw device and there is no blob meta region.
	footerFlagRawDevice = 1 << 1
	// footerIncompatField is the byte offset of the u32 feature_incompat field
	// within the footer.
	footerIncompatField = 12
	// footerSupportedIncompat is the set of incompat feature bits this staging
	// code can pass through.
	footerSupportedIncompat = footerIncompatBootstrapZstd | footerFlagRawDevice
	// bootstrapOffsetField is the byte offset of the u64 bootstrap_offset field
	// within the footer.
	bootstrapOffsetField = 40
	// blobMetaOffsetField is the byte offset of the u64 blob_metadata_offset
	// field within the footer.
	blobMetaOffsetField = 64
	// blobMetaSizeField is the byte offset of the u64 blob_metadata_size field
	// within the footer.
	blobMetaSizeField = 72
)

// NydusBlobFooterMagic is the 8 raw ASCII bytes at the start of the footer,
// written as-is (same style as the "NDBLMETA" blob meta and "NDGRPMAP"
// chunk map sidecars).
const NydusBlobFooterMagic = "NDFOOTER"

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
	if string(footer[0:8]) != NydusBlobFooterMagic {
		return nil, errors.Errorf("not a nydus blob: bad footer magic %q", footer[0:8])
	}
	if incompat := binary.LittleEndian.Uint32(footer[footerIncompatField : footerIncompatField+4]); incompat&^footerSupportedIncompat != 0 {
		return nil, errors.Errorf("unsupported nydus footer incompat features %#x", incompat&^footerSupportedIncompat)
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

// IsRawDeviceBlob reports whether a nydus full blob is a native EROFS layer:
// its data region is the raw device and it carries no blob meta (footer
// RAW_DEVICE flag). Such layers are never served on demand by the nydus
// daemons; they are mounted through the kernel or read from a local store.
func IsRawDeviceBlob(ra io.ReaderAt, size int64) (bool, error) {
	footer, err := readFooter(ra, size)
	if err != nil {
		return false, err
	}
	return binary.LittleEndian.Uint32(footer[footerIncompatField:footerIncompatField+4])&footerFlagRawDevice != 0, nil
}

// ExtractBlobMeta reads the blob meta region of a nydus full blob, locating it
// via the trailing footer. The returned bytes are the exact
// `<full_blob_sha256>.blob.meta` artifact produced by `nydus build`. A native
// layer (footer RAW_DEVICE flag, no blob meta region) yields nil bytes.
func ExtractBlobMeta(ra io.ReaderAt, size int64) ([]byte, error) {
	footer, err := readFooter(ra, size)
	if err != nil {
		return nil, err
	}
	if binary.LittleEndian.Uint32(footer[footerIncompatField:footerIncompatField+4])&footerFlagRawDevice != 0 {
		return nil, nil
	}
	blobMetaOffset := int64(binary.LittleEndian.Uint64(footer[blobMetaOffsetField : blobMetaOffsetField+8]))
	blobMetaSize := int64(binary.LittleEndian.Uint64(footer[blobMetaSizeField : blobMetaSizeField+8]))
	if blobMetaOffset < 0 || blobMetaSize <= 0 || blobMetaOffset+blobMetaSize > size {
		return nil, errors.Errorf("invalid blob meta region [%d,+%d) (blob size %d)", blobMetaOffset, blobMetaSize, size)
	}

	buf := make([]byte, blobMetaSize)
	if _, err := ra.ReadAt(buf, blobMetaOffset); err != nil {
		return nil, errors.Wrap(err, "read blob meta region")
	}
	return buf, nil
}
