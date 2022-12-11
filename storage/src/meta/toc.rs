// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Rafs filesystem TOC entry layout and data structures.

use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::{Error, Read, Result, Write};
use std::mem::size_of;
use std::path::Path;
use std::slice;
use std::sync::Arc;

use nydus_utils::compress::Decoder;
use nydus_utils::digest::{DigestHasher, RafsDigest};
use nydus_utils::{compress, digest};
use serde::Serialize;
use tar::{EntryType, Header};

use crate::backend::{BlobBufReader, BlobReader};
use crate::utils::alloc_buf;

/// File name for RAFS data chunks.
pub const ENTRY_BLOB_RAW: &str = "image.blob";
/// File name for RAFS meta/bootstrap.
pub const ENTRY_BOOTSTRAP: &str = "image.boot";
/// File name for RAFS blob compression information.
pub const ENTRY_BLOB_META: &str = "blob.meta";
/// File name for RAFS blob compression information.
pub const ENTRY_BLOB_META_HEADER: &str = "blob.meta.header";
/// File name for RAFS blob ToC table.
pub const ENTRY_TOC: &str = "rafs.blob.toc";

bitflags! {
    #[derive(Serialize)]
    pub struct TocEntryFlags: u32 {
        /// Entry data is not compressed.
        const COMPRESSION_NONE = 0x0001;
        /// Entry data is compressed with zstd.
        const COMPRESSION_ZSTD = 0x0002;
        /// Entry data is compressed with lz4.
        const COMPRESSION_LZ4_BLOCK = 0x0004;
    }
}

impl TryFrom<compress::Algorithm> for TocEntryFlags {
    type Error = Error;

    fn try_from(c: compress::Algorithm) -> std::result::Result<Self, Self::Error> {
        match c {
            compress::Algorithm::None => Ok(Self::COMPRESSION_NONE),
            compress::Algorithm::Zstd => Ok(Self::COMPRESSION_ZSTD),
            compress::Algorithm::Lz4Block => Ok(Self::COMPRESSION_LZ4_BLOCK),
            _ => return Err(eother!(format!("unsupported compressor {}", c,))),
        }
    }
}

impl TocEntry {
    /// Get ToC entry name.
    pub fn name(&self) -> Result<String> {
        String::from_utf8(self.name.to_vec())
            .map(|v| v.trim_end_matches('\0').to_string())
            .map_err(|_e| eother!(format!("failed to get ToC entry name")))
    }

    /// Get digest of uncompressed content.
    pub fn uncompressed_digest(&self) -> RafsDigest {
        RafsDigest {
            data: self.uncompressed_digest,
        }
    }

    /// Get size of uncompressed content.
    pub fn uncompressed_size(&self) -> u64 {
        self.uncompressed_size
    }

    /// Get offset of compressed content.
    pub fn compressed_offset(&self) -> u64 {
        self.compressed_offset
    }

    /// Get size of compressed content.
    pub fn compressed_size(&self) -> u64 {
        self.compressed_size
    }

    /// Get compression algorithm for the associated data.
    pub fn compressor(&self) -> compress::Algorithm {
        if self.flags & TocEntryFlags::COMPRESSION_ZSTD.bits() != 0 {
            compress::Algorithm::Zstd
        } else if self.flags & TocEntryFlags::COMPRESSION_LZ4_BLOCK.bits() != 0 {
            compress::Algorithm::Lz4Block
        } else {
            compress::Algorithm::None
        }
    }

    /// Set compression algorithm for the associated data.
    pub fn set_compressor(&mut self, compressor: compress::Algorithm) -> Result<()> {
        let c: TocEntryFlags = compressor.try_into()?;

        self.flags &= !TocEntryFlags::COMPRESSION_NONE.bits();
        self.flags &= !TocEntryFlags::COMPRESSION_ZSTD.bits();
        self.flags &= !TocEntryFlags::COMPRESSION_LZ4_BLOCK.bits();
        self.flags |= c.bits();

        Ok(())
    }
}

/// RAFS TOC entry on-disk format, 128 bytes.
///
/// The structure is designed to seek TOC data with the `name` field.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TocEntry {
    /// Possible values: COMPRESSOR
    flags: u32,
    reserved1: u32,
    /// Name of entry file
    name: [u8; 16],
    /// Sha256 of uncompressed data
    uncompressed_digest: [u8; 32],
    /// Offset of compressed data
    compressed_offset: u64,
    /// Size of compressed data
    compressed_size: u64,
    /// Size of uncompressed data
    uncompressed_size: u64,
    reserved2: [u8; 44],
}

impl Default for TocEntry {
    fn default() -> Self {
        TocEntry {
            flags: 0,
            reserved1: 0,
            name: [0u8; 16],
            uncompressed_digest: [0u8; 32],
            compressed_offset: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            reserved2: [0u8; 44],
        }
    }
}

impl TocEntry {
    /// Extract the content from a reader into a writer.
    pub fn extract_from_reader<W: Write>(
        &self,
        reader: Arc<dyn BlobReader>,
        writer: &mut W,
    ) -> Result<()> {
        let mut hasher = digest::RafsDigest::hasher(digest::Algorithm::Sha256);
        let mut count = 0;
        let buf_size = std::cmp::min(0x1000000u64, self.compressed_size) as usize;
        let mut buf_reader = BlobBufReader::new(
            buf_size,
            reader,
            self.compressed_offset,
            self.compressed_size,
        );

        if self.flags & TocEntryFlags::COMPRESSION_ZSTD.bits() != 0 {
            let mut decoder = Decoder::new(buf_reader, compress::Algorithm::Zstd)
                .map_err(|_| eother!("failed to create decode"))?;
            let mut buf = alloc_buf(0x40000);
            loop {
                let sz = decoder
                    .read(&mut buf)
                    .map_err(|e| eother!(format!("failed to decompress data, {}", e)))?;
                if sz == 0 {
                    break;
                }
                hasher.digest_update(&buf[..sz]);
                writer
                    .write_all(&buf[..sz])
                    .map_err(|e| eother!(format!("failed to write decompressed data, {}", e)))?;
                count += sz as u64;
            }
        } else if self.flags & TocEntryFlags::COMPRESSION_LZ4_BLOCK.bits() != 0 {
            return Err(eother!("unsupported compression algorithm lz4_block."));
        } else if self.flags & TocEntryFlags::COMPRESSION_NONE.bits() != 0 {
            let mut buf = alloc_buf(0x40000);
            loop {
                let sz = buf_reader
                    .read(&mut buf)
                    .map_err(|e| eother!(format!("failed to decompress data, {}", e)))?;
                if sz == 0 {
                    break;
                }
                hasher.digest_update(&buf[..sz]);
                writer
                    .write_all(&buf[..sz])
                    .map_err(|e| eother!(format!("failed to write decompressed data, {}", e)))?;
                count += sz as u64;
            }
        } else {
            return Err(eother!("unsupported compression algorithm."));
        }

        if count != self.uncompressed_size {
            return Err(eother!(format!(
                "size of decompressed content doesn't match, expect {}, got {}",
                self.uncompressed_size, count,
            )));
        }
        let digest = hasher.digest_finalize();
        if digest.data != self.uncompressed_digest {
            return Err(eother!("digest of decompressed content doesn't match"));
        }

        Ok(())
    }

    /// Extract  content from a buffer into a writer.
    pub fn extract_from_buf<W: Write>(&self, buf: &[u8], writer: &mut W) -> Result<()> {
        let mut hasher = digest::RafsDigest::hasher(digest::Algorithm::Sha256);
        let mut count = 0;

        if self.flags & TocEntryFlags::COMPRESSION_ZSTD.bits() != 0 {
            let mut decoder = Decoder::new(buf, compress::Algorithm::Zstd)
                .map_err(|_| eother!("failed to create decode"))?;
            let mut buf = alloc_buf(0x40000);
            loop {
                let sz = decoder
                    .read(&mut buf)
                    .map_err(|e| eother!(format!("failed to decompress data, {}", e)))?;
                if sz == 0 {
                    break;
                }
                hasher.digest_update(&buf[..sz]);
                writer
                    .write_all(&buf[..sz])
                    .map_err(|e| eother!(format!("failed to write decompressed data, {}", e)))?;
                count += sz as u64;
            }
        } else if self.flags & TocEntryFlags::COMPRESSION_LZ4_BLOCK.bits() != 0 {
            return Err(eother!("unsupported compression algorithm lz4_block."));
        } else if self.flags & TocEntryFlags::COMPRESSION_NONE.bits() != 0 {
            hasher.digest_update(buf);
            writer
                .write_all(buf)
                .map_err(|e| eother!(format!("failed to write decompressed data, {}", e)))?;
            count = buf.len() as u64;
        } else {
            return Err(eother!("unsupported compression algorithm."));
        }

        if count != self.uncompressed_size {
            return Err(eother!(format!(
                "size of decompressed content doesn't match, expect {}, got {}",
                self.uncompressed_size, count,
            )));
        }
        let digest = hasher.digest_finalize();
        if digest.data != self.uncompressed_digest {
            return Err(eother!("digest of decompressed content doesn't match"));
        }

        Ok(())
    }
}

/// Container to host a list of ToC entries.
pub struct TocEntryList {
    entries: Vec<TocEntry>,
}

impl Default for TocEntryList {
    fn default() -> Self {
        Self::new()
    }
}

impl TocEntryList {
    /// Create a new instance of `EntryList`.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a ToC entry into the list.
    pub fn add(
        &mut self,
        name: &str,
        compressor: compress::Algorithm,
        uncompressed_digest: RafsDigest,
        compressed_offset: u64,
        compressed_size: u64,
        uncompressed_size: u64,
    ) -> Result<&mut TocEntry> {
        let name_size = name.as_bytes().len();
        if name_size > 16 {
            return Err(eother!(format!("invalid entry name length {}", name_size)));
        }

        let last = self.entries.len();
        let target = &mut [0u8; 16];
        target[..name_size].clone_from_slice(name.as_bytes());
        let mut entry = TocEntry {
            flags: 0,
            reserved1: 0,
            name: *target,
            uncompressed_digest: uncompressed_digest.data,
            compressed_offset,
            compressed_size,
            uncompressed_size,
            reserved2: [0u8; 44],
        };
        entry.set_compressor(compressor)?;
        self.entries.push(entry);

        Ok(&mut self.entries[last])
    }

    /// Convert object to a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        let (_, data, _) = unsafe { self.entries.align_to::<u8>() };
        data
    }

    /// Read a `TocEntryList` from a reader.
    pub fn read_from_blob(
        reader: &dyn BlobReader,
        offset: u64,
        size: u64,
        digest: &RafsDigest,
    ) -> Result<Self> {
        if !(512..=0x10000).contains(&size) || size % 128 != 0 {
            return Err(eother!(format!("invalid size {} of blob ToC", size)));
        }

        let size = size as usize;
        let mut buf = alloc_buf(size);
        let sz = reader
            .read(&mut buf, offset)
            .map_err(|e| eother!(format!("failed to read data from backend, {:?}", e)))?;

        if sz != size {
            return Err(eother!(format!(
                "failed to read data from backend, expect {}, got {} bytes",
                size, sz
            )));
        }

        let dv = digest::RafsDigest::from_buf(&buf, digest::Algorithm::Sha256);
        if &dv != digest {
            return Err(eother!("toc content digest value doesn't match"));
        }

        let size = size - 512;
        let header = Header::from_byte_slice(&buf[size..]);
        let entry_type = header.entry_type();
        if entry_type != EntryType::Regular {
            return Err(eother!("Tar entry type for ToC is not a regular file"));
        }
        let entry_size = header
            .entry_size()
            .map_err(|_| eother!("failed to get entry size from tar header"))?;
        if entry_size != size as u64 {
            return Err(eother!(format!(
                "invalid toc entry size in tar header, expect {}, got {}",
                size, entry_size
            )));
        }
        let name = header
            .path()
            .map_err(|_| eother!("failed to get ToC file name from tar header"))?;
        if name != Path::new(ENTRY_TOC) {
            return Err(eother!(format!(
                "ToC file name from tar header doesn't match, {}",
                name.display()
            )));
        }
        let _header = header
            .as_gnu()
            .ok_or_else(|| eother!("invalid GNU tar header for ToC"))?;

        let mut list = TocEntryList::new();
        let mut pos = 0;
        while pos < size {
            let mut entry = TocEntry::default();
            let s = unsafe {
                slice::from_raw_parts_mut(&mut entry as *mut _ as *mut u8, size_of::<TocEntry>())
            };
            s.copy_from_slice(&buf[pos..pos + size_of::<TocEntry>()]);
            list.entries.push(entry);
            pos += size_of::<TocEntry>();
        }

        Ok(list)
    }

    /// Get ToC entry with specified name.
    pub fn get_entry(&self, name: &str) -> Option<&TocEntry> {
        for toc in self.entries.iter() {
            if let Ok(n) = toc.name() {
                if n == name {
                    return Some(toc);
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory::BlobFactory;
    use nydus_api::{BackendConfigV2, LocalFsConfig};

    #[test]
    fn test_read_toc_list() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = Path::new(root_dir).join("../tests/texture/toc");
        let id = "2fa78cad554b75ac91a4a125ed148d0ddeb25efa4aaa8bd80e5dc292690a4dca";
        let digest = RafsDigest {
            data: [
                79u8, 223, 187, 54, 239, 116, 163, 198, 58, 40, 226, 171, 175, 165, 64, 68, 199,
                89, 65, 85, 190, 182, 221, 173, 159, 54, 130, 92, 254, 88, 40, 108,
            ],
        };
        let config = BackendConfigV2 {
            backend_type: "localfs".to_string(),
            localfs: Some(LocalFsConfig {
                blob_file: "".to_string(),
                dir: path.to_str().unwrap().to_string(),
                alt_dirs: vec![],
            }),
            oss: None,
            registry: None,
            s3: None,
        };
        let blob_mgr = BlobFactory::new_backend(&config, id).unwrap();
        let blob = blob_mgr.get_reader(id).unwrap();
        let list = TocEntryList::read_from_blob(blob.as_ref(), 9010, 1024, &digest).unwrap();
        assert_eq!(list.entries.len(), 4);

        assert!(list.get_entry(ENTRY_BLOB_RAW).is_some());
        assert!(list.get_entry(ENTRY_BOOTSTRAP).is_some());
        assert!(list.get_entry(ENTRY_BLOB_META).is_some());
        assert!(list.get_entry(ENTRY_BLOB_META_HEADER).is_some());

        let mut buf = Vec::new();
        let entry = list.get_entry(ENTRY_BLOB_META).unwrap();
        assert_eq!(entry.uncompressed_size, 0x30);
        entry.extract_from_reader(blob.clone(), &mut buf).unwrap();
        assert!(!buf.is_empty());

        let mut buf = Vec::new();
        let entry = list.get_entry(ENTRY_BLOB_META_HEADER).unwrap();
        assert_eq!(entry.uncompressed_size, 0x1000);
        entry.extract_from_reader(blob.clone(), &mut buf).unwrap();
        assert!(!buf.is_empty());
    }
}
