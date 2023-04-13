// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Rafs filesystem TOC entry layout and data structures.

use std::convert::{TryFrom, TryInto};
use std::fs::{self, File, OpenOptions};
use std::io::{Error, ErrorKind, Read, Result, Write};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::slice;
use std::sync::Arc;

use nydus_api::ConfigV2;
use nydus_utils::compress::{self, Decoder};
use nydus_utils::digest::{self, DigestHasher, RafsDigest};
use serde::Serialize;
use tar::{EntryType, Header};

use crate::backend::{BlobBufReader, BlobReader};
use crate::factory::BlobFactory;
use crate::utils::alloc_buf;

/// File name for RAFS data chunks.
pub const TOC_ENTRY_BLOB_RAW: &str = "image.blob";
/// File name for RAFS meta/bootstrap.
pub const TOC_ENTRY_BOOTSTRAP: &str = "image.boot";
/// File name for RAFS blob compression context table.
pub const TOC_ENTRY_BLOB_META: &str = "blob.meta";
/// File name for RAFS blob compression context table header.
pub const TOC_ENTRY_BLOB_META_HEADER: &str = "blob.meta.header";
/// File name for RAFS chunk digest table.
pub const TOC_ENTRY_BLOB_DIGEST: &str = "blob.digest";
/// File name for RAFS blob ToC table.
pub const TOC_ENTRY_BLOB_TOC: &str = "rafs.blob.toc";

bitflags! {
    #[derive(Serialize)]
    /// Feature flags for ToC entry.
    pub struct TocEntryFlags: u32 {
        /// Entry data is not compressed.
        const COMPRESSION_NONE = 0x0001;
        /// Entry data is compressed with zstd.
        const COMPRESSION_ZSTD = 0x0002;
        /// Entry data is compressed with lz4.
        const COMPRESSION_LZ4_BLOCK = 0x0004;
        /// Bit mask for compression algorithms.
        const COMPRESSION_MASK = 0x000f;
    }
}

impl TryFrom<compress::Algorithm> for TocEntryFlags {
    type Error = Error;

    fn try_from(c: compress::Algorithm) -> std::result::Result<Self, Self::Error> {
        match c {
            compress::Algorithm::None => Ok(Self::COMPRESSION_NONE),
            compress::Algorithm::Zstd => Ok(Self::COMPRESSION_ZSTD),
            compress::Algorithm::Lz4Block => Ok(Self::COMPRESSION_LZ4_BLOCK),
            _ => Err(eother!(format!("unsupported compressor {}", c,))),
        }
    }
}

/// Blob ToC entry on-disk format, 128 bytes.
///
/// The structure is designed to seek ToC data with the `name` field.
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
    reserved2: [u8; 48],
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
            reserved2: [0u8; 48],
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

    /// Get compression algorithm to process entry  data.
    pub fn compressor(&self) -> Result<compress::Algorithm> {
        let flags = TocEntryFlags::from_bits(self.flags)
            .ok_or_else(|| einval!("unknown compression algorithm for TOC entry"))?;
        let algo = match flags & TocEntryFlags::COMPRESSION_MASK {
            TocEntryFlags::COMPRESSION_ZSTD => compress::Algorithm::Zstd,
            TocEntryFlags::COMPRESSION_LZ4_BLOCK => compress::Algorithm::Lz4Block,
            TocEntryFlags::COMPRESSION_NONE => compress::Algorithm::None,
            _ => return Err(einval!("unknown compression algorithm for TOC entry")),
        };
        Ok(algo)
    }

    /// Set compression algorithm to process entry data.
    pub fn set_compressor(&mut self, compressor: compress::Algorithm) -> Result<()> {
        let c: TocEntryFlags = compressor.try_into()?;

        self.flags &= !TocEntryFlags::COMPRESSION_MASK.bits();
        self.flags |= c.bits();

        Ok(())
    }

    /// Extract entry data from a `BlobReader` into a writer.
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
                .map_err(|_| eother!("failed to create decoder"))?;
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
        if digest.data != self.uncompressed_digest
            && self.uncompressed_digest != RafsDigest::default().data
        {
            return Err(eother!("digest of decompressed content doesn't match"));
        }

        Ok(())
    }

    /// Extract entry data from a data buffer into a writer.
    pub fn extract_from_buf<W: Write>(&self, buf: &[u8], writer: &mut W) -> Result<()> {
        let mut hasher = digest::RafsDigest::hasher(digest::Algorithm::Sha256);
        let mut count = 0;

        if self.flags & TocEntryFlags::COMPRESSION_ZSTD.bits() != 0 {
            let mut decoder = Decoder::new(buf, compress::Algorithm::Zstd)
                .map_err(|_| eother!("failed to create decoder"))?;
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

/// Container to host a group of ToC entries.
pub struct TocEntryList {
    entries: Vec<TocEntry>,
    toc_digest: RafsDigest,
    toc_size: u32,
}

impl Default for TocEntryList {
    fn default() -> Self {
        Self::new()
    }
}

impl TocEntryList {
    /// Create a new instance of [TocEntryList].
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            toc_digest: RafsDigest::default(),
            toc_size: 0,
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
            reserved2: [0u8; 48],
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

    /// Get digest of ToC content.
    pub fn toc_digest(&self) -> &RafsDigest {
        &self.toc_digest
    }

    /// Get size of ToC content.
    pub fn toc_size(&self) -> u32 {
        self.toc_size
    }

    /// Read a [TocEntryList] from a [BlobReader].
    pub fn read_from_blob<W: Write>(
        reader: &dyn BlobReader,
        cache_file: Option<&mut W>,
        location: &TocLocation,
    ) -> Result<Self> {
        let (buf, _) = Self::read_toc_header(reader, location)?;
        if let Some(writer) = cache_file {
            writer.write_all(&buf)?;
        }
        Self::parse_toc_header(&buf, location)
    }

    /// Read a [TocEntryList] from cache file, and fallback to storage backend.
    pub fn read_from_cache_file<P: AsRef<Path>>(
        path: P,
        reader: &dyn BlobReader,
        location: &TocLocation,
    ) -> Result<Self> {
        location.validate()?;

        if let Ok(mut file) = OpenOptions::new().read(true).open(path.as_ref()) {
            let md = file.metadata()?;
            let size = md.len();
            if size > 512 && size % 128 == 0 && md.len() <= 0x1000 {
                let mut buf = alloc_buf(size as usize);
                file.read_exact(&mut buf)
                    .map_err(|e| eother!(format!("failed to read ToC from cache, {}", e)))?;
                if let Ok(toc) = Self::parse_toc_header(&buf, location) {
                    return Ok(toc);
                }
            }
        }

        let p = path
            .as_ref()
            .to_path_buf()
            .with_extension("toc_downloading");
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(p.as_path())
        {
            match Self::read_from_blob(reader, Some(&mut file), location) {
                Ok(v) => {
                    let _ = fs::rename(p, path.as_ref());
                    Ok(v)
                }
                Err(e) => {
                    let _ = fs::remove_file(p);
                    Err(e)
                }
            }
        } else {
            Self::read_from_blob::<File>(reader, None, location)
        }
    }

    fn read_toc_header(reader: &dyn BlobReader, location: &TocLocation) -> Result<(Vec<u8>, u64)> {
        location.validate()?;
        let (offset, size) = if location.auto_detect {
            let blob_size = reader
                .blob_size()
                .map_err(|e| eio!(format!("failed to get blob size, {}", e)))?;
            let size = if blob_size > 0x1000 {
                0x1000
            } else {
                blob_size >> 7 << 7
            };
            (blob_size - size, size)
        } else {
            (location.offset, location.size)
        };

        let size = size as usize;
        let mut buf = alloc_buf(size);
        let sz = reader
            .read(&mut buf, offset)
            .map_err(|e| eother!(format!("failed to read ToC from backend, {}", e)))?;
        if sz != size {
            return Err(eother!(format!(
                "failed to read ToC from backend, expect {}, got {} bytes",
                size, sz
            )));
        }

        Ok((buf, offset + 0x1000))
    }

    fn parse_toc_header(buf: &[u8], location: &TocLocation) -> Result<Self> {
        if buf.len() < 512 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("blob ToC size {} is too small", buf.len()),
            ));
        }
        let size = buf.len() - 512;
        let header = Header::from_byte_slice(&buf[size..]);
        let entry_type = header.entry_type();
        if entry_type != EntryType::Regular {
            return Err(Error::new(
                ErrorKind::Other,
                "Tar entry type for ToC is not a regular file",
            ));
        }
        let entry_size = header.entry_size().map_err(|_| {
            Error::new(ErrorKind::Other, "failed to get entry size from tar header")
        })?;
        if entry_size > size as u64 {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "invalid toc entry size in tar header, expect {}, got {}",
                    size, entry_size
                ),
            ));
        }
        let name = header.path().map_err(|_| {
            Error::new(
                ErrorKind::Other,
                "failed to get ToC file name from tar header",
            )
        })?;
        if name != Path::new(TOC_ENTRY_BLOB_TOC) {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "ToC file name from tar header doesn't match, {}",
                    name.display()
                ),
            ));
        }
        let _header = header
            .as_gnu()
            .ok_or_else(|| Error::new(ErrorKind::Other, "invalid GNU tar header for ToC"))?;

        let mut pos = size - entry_size as usize;
        let mut list = TocEntryList::new();
        list.toc_digest = digest::RafsDigest::from_buf(&buf[pos..], digest::Algorithm::Sha256);
        list.toc_size = (entry_size + 512) as u32;
        if location.validate_digest && list.toc_digest != location.digest {
            return Err(eother!(format!(
                "toc content digest value doesn't match, expect {:?}, got {:?}",
                location.digest.data, list.toc_digest.data
            )));
        }

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

    /// Extract `image.boot` and/or `blob.digest` from a [BlobReader] into files.
    pub fn extract_from_blob<P: AsRef<Path>>(
        &self,
        reader: Arc<dyn BlobReader>,
        bootstrap: Option<P>,
        digest: Option<P>,
    ) -> Result<()> {
        if let Some(path) = bootstrap {
            let bootstrap = self
                .get_entry(TOC_ENTRY_BOOTSTRAP)
                .ok_or_else(|| enoent!("`image.boot` doesn't exist in the ToC list"))?;
            let compressor = bootstrap.compressor()?;
            if compressor == compress::Algorithm::None
                && bootstrap.compressed_size() != bootstrap.uncompressed_size()
            {
                return Err(einval!("invalid ToC entry for `image.boot`"));
            }

            let mut ready = false;
            if path.as_ref().exists() {
                let mut file = OpenOptions::new().read(true).open(path.as_ref())?;
                let digest = RafsDigest::from_reader(&mut file, digest::Algorithm::Sha256)?;
                if digest.data == bootstrap.uncompressed_digest {
                    ready = true;
                }
            }
            if !ready {
                let p = path
                    .as_ref()
                    .to_path_buf()
                    .with_extension("toc_downloading");
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(p.as_path())?;
                bootstrap
                    .extract_from_reader(reader.clone(), &mut file)
                    .map_err(|e| {
                        let _ = fs::remove_file(&p);
                        e
                    })?;
                fs::rename(&p, path).map_err(|e| {
                    let _ = fs::remove_file(&p);
                    e
                })?;
            }
        }

        if let Some(path) = digest {
            let cda = self
                .get_entry(TOC_ENTRY_BLOB_DIGEST)
                .ok_or_else(|| enoent!("`blob.digest` doesn't exist in the ToC list"))?;
            let compressor = cda.compressor()?;
            if compressor == compress::Algorithm::None
                && cda.compressed_size() != cda.uncompressed_size()
            {
                return Err(einval!("invalid ToC entry for `blob.digest`"));
            }

            let mut ready = false;
            if path.as_ref().exists() {
                let mut file = OpenOptions::new().read(true).open(path.as_ref())?;
                let digest = RafsDigest::from_reader(&mut file, digest::Algorithm::Sha256)?;
                if digest.data == cda.uncompressed_digest {
                    ready = true;
                }
            }
            if !ready {
                let p = path
                    .as_ref()
                    .to_path_buf()
                    .with_extension("toc_downloading");
                let mut file = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(p.as_path())?;
                cda.extract_from_reader(reader.clone(), &mut file)
                    .map_err(|e| {
                        let _ = fs::remove_file(&p);
                        e
                    })?;
                fs::rename(&p, path).map_err(|e| {
                    let _ = fs::remove_file(&p);
                    e
                })?;
            }
        }

        Ok(())
    }

    /// Extract inlined RAFS metadata from data blobs.
    pub fn extract_rafs_meta(id: &str, config: Arc<ConfigV2>) -> Result<PathBuf> {
        let backend_config = config.get_backend_config()?;
        let workdir = config.get_cache_working_directory()?;
        let path = PathBuf::from(workdir);
        if !path.is_dir() {
            return Err(Error::new(
                ErrorKind::NotFound,
                "invalid cache working directory",
            ));
        }
        let path = path.join(id).with_extension(TOC_ENTRY_BOOTSTRAP);

        let blob_mgr = BlobFactory::new_backend(backend_config, "extract_rafs_meta")?;
        let reader = blob_mgr
            .get_reader(id)
            .map_err(|e| eother!(format!("failed to get reader for blob {}, {}", id, e)))?;
        let location = TocLocation::default();
        let (buf, blob_size) = Self::read_toc_header(reader.as_ref(), &location)?;

        if let Ok(toc) = Self::parse_toc_header(&buf, &location) {
            toc.extract_from_blob(reader, Some(path.clone()), None)?;
        } else {
            if buf.len() < 512 {
                return Err(einval!(format!("blob ToC size {} is too small", buf.len())));
            }
            let header = Header::from_byte_slice(&buf[buf.len() - 512..]);
            let entry_type = header.entry_type();
            if entry_type != EntryType::Regular {
                return Err(eother!(
                    "Tar entry type for `image.boot` is not a regular file"
                ));
            }
            let name = header
                .path()
                .map_err(|_| eother!("failed to get `image.boot` file name from tar header"))?;
            if name != Path::new(TOC_ENTRY_BOOTSTRAP) {
                return Err(eother!(format!(
                    "file name from tar header doesn't match `image.boot`, {}",
                    name.display()
                )));
            }
            let _header = header
                .as_gnu()
                .ok_or_else(|| eother!("invalid GNU tar header for ToC"))?;
            let entry_size = header
                .entry_size()
                .map_err(|_| eother!("failed to get entry size from tar header"))?;
            if entry_size > blob_size - 512 {
                return Err(eother!(format!(
                    "invalid `image.boot` entry size in tar header, max {}, got {}",
                    blob_size - 512,
                    entry_size
                )));
            }
            let offset = blob_size - 512 - entry_size;

            let mut toc = TocEntryList::new();
            toc.add(
                TOC_ENTRY_BOOTSTRAP,
                compress::Algorithm::None,
                RafsDigest::default(),
                offset,
                entry_size,
                entry_size,
            )?;
            toc.extract_from_blob(reader, Some(path.clone()), None)?;
        }

        Ok(path)
    }
}

/// Information to locate and validate ToC content.
#[derive(Debug)]
pub struct TocLocation {
    /// Enable validating digest of the ToC content.
    pub validate_digest: bool,
    /// Auto detect location of ToC content.
    pub auto_detect: bool,
    /// Offset of the ToC content in the data blob.
    pub offset: u64,
    /// Size of the ToC content.
    pub size: u64,
    /// SHA256 digest of ToC content.
    pub digest: RafsDigest,
}

impl Default for TocLocation {
    fn default() -> Self {
        TocLocation {
            validate_digest: false,
            auto_detect: true,
            offset: 0,
            size: 0,
            digest: RafsDigest::default(),
        }
    }
}

impl TocLocation {
    /// Create a [TocLocation] object with offset and size.
    pub fn new(offset: u64, size: u64) -> Self {
        TocLocation {
            validate_digest: false,
            auto_detect: false,
            offset,
            size,
            digest: RafsDigest::default(),
        }
    }

    /// Create a [TocLocation] object with offset, size and digest.
    pub fn with_digest(offset: u64, size: u64, digest: RafsDigest) -> Self {
        TocLocation {
            validate_digest: true,
            auto_detect: false,
            offset,
            size,
            digest,
        }
    }

    fn validate(&self) -> Result<()> {
        if !self.auto_detect && (!(512..=0x10000).contains(&self.size) || self.size % 128 != 0) {
            return Err(eother!(format!("invalid size {} of blob ToC", self.size)));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory::BlobFactory;
    use nydus_api::{BackendConfigV2, LocalFsConfig};
    use vmm_sys_util::tempfile::TempFile;

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
            localdisk: None,
            oss: None,
            registry: None,
            s3: None,
            http_proxy: None,
        };
        let blob_mgr = BlobFactory::new_backend(&config, id).unwrap();
        let blob = blob_mgr.get_reader(id).unwrap();
        let location = TocLocation::with_digest(9010, 1024, digest);
        let list =
            TocEntryList::read_from_blob::<fs::File>(blob.as_ref(), None, &location).unwrap();
        assert_eq!(list.entries.len(), 4);

        assert!(list.get_entry(TOC_ENTRY_BLOB_RAW).is_some());
        assert!(list.get_entry(TOC_ENTRY_BOOTSTRAP).is_some());
        assert!(list.get_entry(TOC_ENTRY_BLOB_META).is_some());
        assert!(list.get_entry(TOC_ENTRY_BLOB_META_HEADER).is_some());

        let mut buf = Vec::new();
        let entry = list.get_entry(TOC_ENTRY_BLOB_META).unwrap();
        assert_eq!(entry.uncompressed_size, 0x30);
        entry.extract_from_reader(blob.clone(), &mut buf).unwrap();
        assert!(!buf.is_empty());

        let mut buf = Vec::new();
        let entry = list.get_entry(TOC_ENTRY_BLOB_META_HEADER).unwrap();
        assert_eq!(entry.uncompressed_size, 0x1000);
        entry.extract_from_reader(blob.clone(), &mut buf).unwrap();
        assert!(!buf.is_empty());
    }

    #[test]
    fn test_parse_toc_list() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = Path::new(root_dir).join("../tests/texture/toc");
        let id = "2fa78cad554b75ac91a4a125ed148d0ddeb25efa4aaa8bd80e5dc292690a4dca";
        let mut digest = RafsDigest {
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
            http_proxy: None,
            localdisk: None,
        };
        let blob_mgr = BlobFactory::new_backend(&config, id).unwrap();
        let blob = blob_mgr.get_reader(id).unwrap();

        digest.data[0] = 0;
        let location = TocLocation::with_digest(9010, 1024, digest);
        assert!(TocEntryList::read_from_blob::<fs::File>(blob.as_ref(), None, &location).is_err());
        digest.data[0] = 79u8;

        let location = TocLocation::new(9000, 1024);
        assert!(TocEntryList::read_from_blob::<fs::File>(blob.as_ref(), None, &location).is_err());

        let location = Default::default();
        let list =
            TocEntryList::read_from_blob::<fs::File>(blob.as_ref(), None, &location).unwrap();
        assert_eq!(list.entries.len(), 4);
    }

    #[test]
    fn test_read_from_cache_file() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = Path::new(root_dir).join("../tests/texture/toc");
        let id = "2fa78cad554b75ac91a4a125ed148d0ddeb25efa4aaa8bd80e5dc292690a4dca";
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
            localdisk: None,
            http_proxy: None,
        };
        let blob_mgr = BlobFactory::new_backend(&config, id).unwrap();
        let blob = blob_mgr.get_reader(id).unwrap();

        let tempfile = TempFile::new().unwrap();
        let path = tempfile.as_path().to_path_buf();
        let mut file = tempfile.into_file();
        file.write_all(&[0u8; 32]).unwrap();

        let location = Default::default();
        let list = TocEntryList::read_from_cache_file(&path, blob.as_ref(), &location).unwrap();
        assert_eq!(list.entries.len(), 4);
        assert_eq!(path.metadata().unwrap().len(), 0x1000);
        let list = TocEntryList::read_from_cache_file(&path, blob.as_ref(), &location).unwrap();
        assert_eq!(list.entries.len(), 4);

        list.extract_from_blob(blob.clone(), Some(path.as_path()), None)
            .unwrap();
        assert_eq!(path.metadata().unwrap().len(), 20480);
        list.extract_from_blob(blob.clone(), Some(path.as_path()), None)
            .unwrap();
        assert_eq!(path.metadata().unwrap().len(), 20480);
    }

    #[test]
    fn test_toc_entry_flags() {
        let flags = TocEntryFlags::try_from(compress::Algorithm::None).unwrap();
        assert_eq!(flags, TocEntryFlags::COMPRESSION_NONE);
        let flags = TocEntryFlags::try_from(compress::Algorithm::Lz4Block).unwrap();
        assert_eq!(flags, TocEntryFlags::COMPRESSION_LZ4_BLOCK);
        let flags = TocEntryFlags::try_from(compress::Algorithm::Zstd).unwrap();
        assert_eq!(flags, TocEntryFlags::COMPRESSION_ZSTD);
        let _e = TocEntryFlags::try_from(compress::Algorithm::GZip).unwrap_err();
    }
}
