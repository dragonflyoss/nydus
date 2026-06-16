//! Host-side accessor for lepton images backing guest virtio-pmem devices.
//!
//! A guest kernel mounts the lepton bootstrap as an EROFS image whose external
//! devices are virtio-pmem devices backed by the host-side cache data files
//! (`{cache_dir}/{hex}.blob.data`). Each cache file mirrors the blob's dense
//! decoded block address space, so a guest read of block `N` lands at byte
//! `N * 4096` of the backing file. [`LeptonAccessor`] exposes the device
//! table needed to wire up those pmem devices and a [`blob.fetch`] entry point
//! that guarantees a block-aligned range is decoded and resident before the
//! guest touches it.
//!
//! [`blob.fetch`]: BlobAccessor::fetch

use std::collections::HashMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};

use crate::config::Config;
use crate::fs::{BlobInfo as ReaderBlobInfo, ErofsReader};
use crate::metadata::{
    ErofsInode, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE, EROFS_FT_BLKDEV, EROFS_FT_CHRDEV,
    EROFS_FT_DIR, EROFS_FT_FIFO, EROFS_FT_REG_FILE, EROFS_FT_SOCK, EROFS_FT_SYMLINK,
    EROFS_INODE_CHUNK_BASED, EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN,
};
use crate::storage::backend::build_backend;
use crate::utils::{hex_string, parse_sha256_hex};

/// Blob digest used by public accessor APIs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BlobID([u8; EROFS_BLOB_ID_SIZE]);

impl BlobID {
    pub fn new(bytes: [u8; EROFS_BLOB_ID_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; EROFS_BLOB_ID_SIZE] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; EROFS_BLOB_ID_SIZE] {
        self.0
    }

    pub fn to_hex(self) -> String {
        hex_string(&self.0)
    }
}

impl From<[u8; EROFS_BLOB_ID_SIZE]> for BlobID {
    fn from(value: [u8; EROFS_BLOB_ID_SIZE]) -> Self {
        Self::new(value)
    }
}

impl From<BlobID> for [u8; EROFS_BLOB_ID_SIZE] {
    fn from(value: BlobID) -> Self {
        value.into_bytes()
    }
}

impl FromStr for BlobID {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(parse_sha256_hex(value)?))
    }
}

impl fmt::Display for BlobID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex_string(&self.0))
    }
}

/// One blob entry from the bootstrap device table.
#[derive(Clone, Debug)]
pub struct BlobInfo {
    /// 1-based blob index, matching the EROFS device table order.
    pub index: u16,
    /// Blob digest recorded in the device slot.
    pub id: BlobID,
    /// Dense uncompressed size in 4 KiB blocks (the pmem device size).
    pub blocks: u64,
    /// Size in bytes of the cache data file (`blocks * 4096`).
    pub cache_size: u64,
    /// Host path of the sparse cache data file backing the pmem device.
    pub cache_path: PathBuf,
    /// True when this is an "ondemand" redirect blob produced by
    /// `lepton optimize`. Its data file is never read by the guest (no chunk
    /// index points at it); it only feeds the phase-0 prefetch that warms the
    /// source blobs' caches.
    pub is_redirect: bool,
}

/// File type exposed by the static accessor API, independent of FUSE types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileType {
    RegularFile,
    Directory,
    Symlink,
    BlockDevice,
    CharDevice,
    Fifo,
    Socket,
}

impl FileType {
    fn from_erofs_file_type(file_type: u8) -> Result<Self> {
        match file_type {
            EROFS_FT_REG_FILE => Ok(Self::RegularFile),
            EROFS_FT_DIR => Ok(Self::Directory),
            EROFS_FT_SYMLINK => Ok(Self::Symlink),
            EROFS_FT_BLKDEV => Ok(Self::BlockDevice),
            EROFS_FT_CHRDEV => Ok(Self::CharDevice),
            EROFS_FT_FIFO => Ok(Self::Fifo),
            EROFS_FT_SOCK => Ok(Self::Socket),
            other => bail!("unsupported EROFS file type: {other}"),
        }
    }

    fn from_mode(mode: u16) -> Result<Self> {
        match mode & libc::S_IFMT as u16 {
            x if x == libc::S_IFREG as u16 => Ok(Self::RegularFile),
            x if x == libc::S_IFDIR as u16 => Ok(Self::Directory),
            x if x == libc::S_IFLNK as u16 => Ok(Self::Symlink),
            x if x == libc::S_IFBLK as u16 => Ok(Self::BlockDevice),
            x if x == libc::S_IFCHR as u16 => Ok(Self::CharDevice),
            x if x == libc::S_IFIFO as u16 => Ok(Self::Fifo),
            x if x == libc::S_IFSOCK as u16 => Ok(Self::Socket),
            other => bail!("unsupported inode mode file type: {other:#o}"),
        }
    }
}

/// Owned metadata for a static filesystem entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Metadata {
    pub ino: u64,
    pub file_type: FileType,
    pub mode: u16,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u64,
    pub mtime_nsec: u32,
    pub rdev: u32,
}

/// Owned directory entry for the static filesystem API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntry {
    pub name: String,
    pub ino: u64,
    pub file_type: FileType,
}

/// Resolved static filesystem entry. Reuse this handle for repeated operations
/// on the same path to avoid resolving the path for every `read_at` call.
#[derive(Clone)]
pub struct FsEntry {
    reader: Arc<ErofsReader>,
    ino: u64,
}

/// Read-side handle over a lepton image, split into blob data access and
/// static filesystem metadata/data access.
pub struct LeptonAccessor {
    /// Blob table and decoded-cache preparation/fetch APIs.
    pub blob: BlobAccessor,
    /// Static path-based filesystem APIs.
    pub fs: FsAccessor,
}

/// Blob table and decoded-cache preparation/fetch APIs.
pub struct BlobAccessor {
    reader: Arc<ErofsReader>,
    blob_infos: Vec<ReaderBlobInfo>,
    index_by_blob_id: HashMap<BlobID, u16>,
}

/// Static path-based filesystem APIs.
pub struct FsAccessor {
    reader: Arc<ErofsReader>,
}

impl LeptonAccessor {
    /// Parse the bootstrap and config and build the blob table,
    /// deferring all per-blob work: no blob meta is downloaded and no cache
    /// file is created until [`blobs`], [`fetch`], or [`prefetch`] first
    /// touches a blob.
    ///
    /// `config` uses the same structure as `lepton fuse --config` and must
    /// provide both the backend serving the blobs and a persistent local cache
    /// directory.
    ///
    /// [`blobs`]: Self::blobs
    /// [`fetch`]: Self::fetch
    pub fn new(bootstrap: &Path, config: Config) -> Result<Self> {
        let backend = build_backend(&config.backend).context("failed to build blob backend")?;
        let cache_dir = config
            .cache_dir()
            .context("failed to resolve cache directory from config")?;
        std::fs::create_dir_all(&cache_dir).with_context(|| {
            format!("failed to create cache directory: {}", cache_dir.display())
        })?;

        let reader = ErofsReader::open(None, Some(bootstrap), Some(backend), Some(&cache_dir))
            .context("failed to open lepton bootstrap")?;
        let blob_infos = reader.blob_infos().context("failed to read blob table")?;
        if blob_infos.is_empty() {
            bail!("bootstrap contains no blobs");
        }
        let index_by_blob_id = blob_infos
            .iter()
            .map(|info| (BlobID::from(info.blob_id), info.blob_index))
            .collect();
        let reader = Arc::new(reader);
        Ok(Self {
            blob: BlobAccessor {
                reader: reader.clone(),
                blob_infos,
                index_by_blob_id,
            },
            fs: FsAccessor { reader },
        })
    }
}

impl BlobAccessor {
    /// Describe every blob in device-table order, preparing each on first
    /// use: the blob meta is downloaded and validated, and the sparse cache
    /// data file is created and sized to the dense uncompressed address
    /// space. Idempotent.
    pub fn entries(&self) -> Result<Vec<BlobInfo>> {
        self.blob_infos
            .iter()
            .map(|info| {
                let cache = self
                    .reader
                    .blob_cache(info.blob_index)
                    .with_context(|| format!("failed to open blob {}", info.blob_index))?;
                let cache_path = cache.prepare().with_context(|| {
                    format!("failed to prepare cache file for blob {}", info.blob_index)
                })?;
                Ok(BlobInfo {
                    index: info.blob_index,
                    id: BlobID::from(info.blob_id),
                    blocks: info.blocks,
                    cache_size: info.blocks * EROFS_BLOCK_SIZE as u64,
                    cache_path,
                    is_redirect: cache.is_redirect_blob(),
                })
            })
            .collect()
    }

    /// Ensure `[offset, offset + len)` of the blob's dense uncompressed
    /// address space is decoded, CRC-validated, and written to its cache data
    /// file, fetching missing groups through the backend. Both `offset` and
    /// `len` must be 4 KiB block aligned; the fetch rounds outward to whole
    /// blob meta groups. Idempotent and safe to call concurrently.
    pub fn fetch(&self, id: &BlobID, offset: u64, len: u64) -> Result<()> {
        let block_size = EROFS_BLOCK_SIZE as u64;
        if offset % block_size != 0 || len % block_size != 0 {
            bail!("fetch range must be 4 KiB block aligned: offset={offset} len={len}");
        }
        if len == 0 {
            return Ok(());
        }

        let blob_index = *self
            .index_by_blob_id
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("blob is not referenced by the bootstrap"))?;
        let cache = self
            .reader
            .blob_cache(blob_index)
            .with_context(|| format!("failed to open blob {blob_index}"))?;
        cache
            .ensure_range(offset, len)
            .with_context(|| format!("failed to fetch blob {blob_index} range [{offset}, +{len})"))
    }
}

impl FsAccessor {
    /// Resolve `path` once and return a reusable entry handle.
    pub fn open(&self, path: impl AsRef<Path>) -> Result<FsEntry> {
        let ino = self.resolve_path(path.as_ref())?;
        Ok(FsEntry {
            reader: self.reader.clone(),
            ino,
        })
    }

    fn inode(&self, ino: u64) -> Result<ErofsInode<'_>> {
        self.reader
            .inode(ino)
            .with_context(|| format!("failed to read inode {ino}"))
    }

    fn resolve_path(&self, path: &Path) -> Result<u64> {
        let mut ino = self.reader.sb().root_nid();
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => continue,
                Component::Normal(name) => {
                    let wanted = name
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("path component is not valid UTF-8"))?;
                    let inode = self.inode(ino)?;
                    if FileType::from_mode(inode.mode())? != FileType::Directory {
                        bail!("path component is not a directory: {wanted}");
                    }
                    let entries = self.reader.read_dir(ino, &inode)?;
                    let entry = entries
                        .into_iter()
                        .find(|entry| entry.name == wanted)
                        .ok_or_else(|| anyhow::anyhow!("path not found: {}", path.display()))?;
                    ino = entry.nid;
                }
                Component::ParentDir | Component::Prefix(_) => {
                    bail!("unsupported path component in {}", path.display())
                }
            }
        }
        Ok(ino)
    }
}

impl FsEntry {
    /// Inode number of this resolved entry.
    pub fn ino(&self) -> u64 {
        self.ino
    }

    /// Return owned metadata for this entry.
    pub fn metadata(&self) -> Result<Metadata> {
        let inode = self.inode()?;
        metadata_from_inode(&self.reader, self.ino, &inode)
    }

    /// List this directory's entries.
    pub fn read_dir(&self) -> Result<Vec<DirEntry>> {
        let inode = self.inode()?;
        if FileType::from_mode(inode.mode())? != FileType::Directory {
            bail!("not a directory");
        }
        self.reader
            .read_dir(self.ino, &inode)
            .with_context(|| format!("failed to read directory inode {}", self.ino))?
            .into_iter()
            .map(|entry| {
                Ok(DirEntry {
                    name: entry.name,
                    ino: entry.nid,
                    file_type: FileType::from_erofs_file_type(entry.file_type)?,
                })
            })
            .collect()
    }

    /// Read the whole file.
    pub fn read(&self) -> Result<Vec<u8>> {
        let inode = self.inode()?;
        self.read_inode(&inode, 0, u32::MAX)
    }

    /// Read file data at `offset` into `buf`, returning bytes read.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let inode = self.inode()?;
        let data = self.read_inode(&inode, offset, buf.len() as u32)?;
        let n = data.len();
        buf[..n].copy_from_slice(&data);
        Ok(n)
    }

    /// Ensure this regular file's `[offset, offset + len)` byte range is
    /// decoded into the underlying blob cache files without returning data.
    pub fn fetch(&self, offset: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let inode = self.inode()?;
        if FileType::from_mode(inode.mode())? != FileType::RegularFile {
            bail!("not a regular file");
        }
        if offset >= inode.size() {
            return Ok(());
        }

        let actual_end = offset.saturating_add(len).min(inode.size());
        match inode.data_layout() {
            EROFS_INODE_FLAT_PLAIN | EROFS_INODE_FLAT_INLINE => Ok(()),
            EROFS_INODE_CHUNK_BASED => self.fetch_chunk_data(&inode, offset, actual_end - offset),
            other => bail!("unsupported data layout: {other}"),
        }
    }

    /// Read this symlink target as raw bytes.
    pub fn read_link(&self) -> Result<Vec<u8>> {
        let inode = self.inode()?;
        if FileType::from_mode(inode.mode())? != FileType::Symlink {
            bail!("not a symlink");
        }
        self.reader
            .read_symlink(self.ino, &inode)
            .with_context(|| format!("failed to read symlink inode {}", self.ino))
    }

    /// Read inline xattrs as `(full_name, value)` byte vectors.
    pub fn xattrs(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let inode = self.inode()?;
        self.reader
            .read_xattrs(self.ino, &inode)
            .with_context(|| format!("failed to read xattrs for inode {}", self.ino))
    }

    fn inode(&self) -> Result<ErofsInode<'_>> {
        self.reader
            .inode(self.ino)
            .with_context(|| format!("failed to read inode {}", self.ino))
    }

    fn read_inode(&self, inode: &ErofsInode<'_>, offset: u64, size: u32) -> Result<Vec<u8>> {
        if FileType::from_mode(inode.mode())? != FileType::RegularFile {
            bail!("not a regular file");
        }
        self.reader
            .read_file_data_sync(self.ino, inode, offset, size)
            .with_context(|| format!("failed to read file inode {}", self.ino))
    }

    fn fetch_chunk_data(&self, inode: &ErofsInode<'_>, offset: u64, len: u64) -> Result<()> {
        let chunkbits = self.reader.sb().blkszbits as u32 + (inode.chunk_format() as u32 & 0x1F);
        let chunksize = 1u64 << chunkbits;
        let chunk_indexes = self
            .reader
            .read_chunk_indexes(self.ino, inode)
            .with_context(|| format!("failed to read chunk indexes for inode {}", self.ino))?;

        let mut remaining = len;
        let mut file_pos = offset;
        while remaining > 0 {
            let file_chunk_index = (file_pos / chunksize) as usize;
            let chunk_off = file_pos % chunksize;
            let to_fetch = remaining.min(chunksize - chunk_off);
            let Some(chunk_index) = chunk_indexes.get(file_chunk_index) else {
                break;
            };

            if chunk_index.blkaddr != u64::MAX && chunk_index.device_id > 0 {
                let blob_offset = chunk_index
                    .blkaddr
                    .checked_mul(EROFS_BLOCK_SIZE as u64)
                    .and_then(|base| base.checked_add(chunk_off))
                    .ok_or_else(|| anyhow::anyhow!("blob fetch offset overflow"))?;
                self.reader
                    .blob_cache(chunk_index.device_id)
                    .with_context(|| format!("failed to open blob {}", chunk_index.device_id))?
                    .ensure_range(blob_offset, to_fetch)
                    .with_context(|| {
                        format!(
                            "failed to fetch inode {} blob {} range [{}, +{})",
                            self.ino, chunk_index.device_id, blob_offset, to_fetch
                        )
                    })?;
            }

            file_pos += to_fetch;
            remaining -= to_fetch;
        }
        Ok(())
    }
}

fn metadata_from_inode(reader: &ErofsReader, ino: u64, inode: &ErofsInode<'_>) -> Result<Metadata> {
    Ok(Metadata {
        ino,
        file_type: FileType::from_mode(inode.mode())?,
        mode: inode.mode(),
        size: inode.size(),
        uid: inode.uid(),
        gid: inode.gid(),
        nlink: inode.nlink(),
        mtime: inode.mtime(reader.sb().epoch()),
        mtime_nsec: inode.effective_mtime_nsec(reader.sb().fixed_nsec()),
        rdev: inode.rdev(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::blob_chunk::BlobWriter;
    use crate::build::bootstrap::render_bootstrap;
    use crate::build::inode::{build_tree, set_root_prefetch_blobs_xattr};
    use crate::config::Config;
    use crate::metadata::{BlobMetaCompressor, ErofsDeviceSlot};
    use crate::utils::hex_string;
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    /// Build a minimal single-blob lepton image (blob dir + bootstrap +
    /// config) and return (bootstrap, config, data blob id, expected file bytes).
    fn build_test_image(
        root: &Path,
    ) -> (
        PathBuf,
        Config,
        [u8; EROFS_BLOB_ID_SIZE],
        HashMap<String, Vec<u8>>,
    ) {
        let corpus_dir = root.join("corpus");
        fs::create_dir_all(&corpus_dir).unwrap();
        // Two ~1.1 MiB incompressible-ish files so the blob spans multiple
        // 1 MiB groups.
        let mut corpus = HashMap::new();
        for seed in 1u64..=2 {
            let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let mut data = vec![0u8; (1 << 20) + 64 * 1024];
            for byte in data.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            fs::write(corpus_dir.join(format!("file{seed}")), &data).unwrap();
            corpus.insert(format!("file{seed}"), data);
        }
        fs::create_dir_all(corpus_dir.join("dir")).unwrap();
        fs::write(corpus_dir.join("dir/small.txt"), b"small file").unwrap();
        corpus.insert("dir/small.txt".to_string(), b"small file".to_vec());
        fs::write(corpus_dir.join("tiny.txt"), b"hello").unwrap();
        corpus.insert("tiny.txt".to_string(), b"hello".to_vec());
        fs::write(corpus_dir.join("empty.txt"), b"").unwrap();
        corpus.insert("empty.txt".to_string(), Vec::new());
        symlink("file1", corpus_dir.join("link_to_file1")).unwrap();

        let blob_dir = root.join("blobs");
        fs::create_dir_all(&blob_dir).unwrap();
        let staging = blob_dir.join("staging");
        let mut writer = BlobWriter::new_with_compressor(
            &staging,
            crate::metadata::BLOB_META_DEFAULT_CHUNK_SIZE,
            BlobMetaCompressor::Zstd,
        )
        .unwrap();
        let mut inodes = build_tree(
            &corpus_dir,
            &mut writer,
            crate::metadata::BLOB_META_DEFAULT_CHUNK_SIZE,
        )
        .unwrap();
        writer.finish().unwrap();

        let blob_id = writer.data_digest();
        let blob_meta = writer.blob_meta(blob_id, 0).unwrap();
        let blocks = writer.total_blocks();
        fs::rename(&staging, blob_dir.join(hex_string(&blob_id))).unwrap();
        blob_meta
            .save(&blob_dir.join(format!("{}.blob.meta", hex_string(&blob_id))))
            .unwrap();

        set_root_prefetch_blobs_xattr(&mut inodes[0], &[1]).unwrap();
        let device_slots = [ErofsDeviceSlot::with_blob_id(blocks, &blob_id)];
        let bootstrap_bytes = render_bootstrap(
            &mut inodes,
            0,
            crate::metadata::BLOB_META_DEFAULT_CHUNK_SIZE.trailing_zeros(),
            &device_slots,
            &[0u8; 16],
        )
        .unwrap();
        let bootstrap = root.join("bootstrap");
        fs::write(&bootstrap, &bootstrap_bytes).unwrap();

        let config = Config::from_yaml(&format!(
            "backend:\n  type: local\n  config:\n    dir: {}\ncache:\n  type: local\n  config:\n    dir: {}\nprefetch:\n  enable: false\n",
            blob_dir.display(),
            root.join("cache").display(),
        ))
        .unwrap();

        (bootstrap, config, blob_id, corpus)
    }

    #[test]
    fn accessor_describes_devices_and_fetches_aligned_ranges() {
        let dir = tempdir().unwrap();
        let (bootstrap, config, blob_id, _corpus) = build_test_image(dir.path());
        let blob_id = BlobID::from(blob_id);

        let accessor = LeptonAccessor::new(&bootstrap, config).unwrap();
        let blobs = accessor.blob.entries().unwrap();
        assert_eq!(blobs.len(), 1);
        let descriptor = &blobs[0];
        assert_eq!(descriptor.index, 1);
        assert_eq!(descriptor.id, blob_id);
        assert!(!descriptor.is_redirect);
        assert_eq!(
            descriptor.cache_size,
            descriptor.blocks * EROFS_BLOCK_SIZE as u64
        );
        let meta = fs::metadata(&descriptor.cache_path).unwrap();
        assert_eq!(meta.len(), descriptor.cache_size);

        // Fetch a block-aligned range in the middle; the cache file should be
        // populated for that range and a second fetch is idempotent. The dense
        // blob address space is independent of path order, so exact file
        // content is covered by the static read API test below.
        let block = EROFS_BLOCK_SIZE as u64;
        let (offset, len) = (256 * block, 16 * block);
        accessor.blob.fetch(&blob_id, offset, len).unwrap();
        let cached = fs::read(&descriptor.cache_path).unwrap();
        assert!(cached[offset as usize..(offset + len) as usize]
            .iter()
            .any(|byte| *byte != 0));

        // Idempotent re-fetch and zero-length fetch are fine.
        accessor.blob.fetch(&blob_id, offset, len).unwrap();
        accessor.blob.fetch(&blob_id, 0, 0).unwrap();

        // Unaligned ranges and unknown blobs are rejected.
        assert!(accessor.blob.fetch(&blob_id, 1, block).is_err());
        assert!(accessor.blob.fetch(&blob_id, 0, block + 1).is_err());
        assert!(accessor
            .blob
            .fetch(&BlobID::from([0u8; 32]), 0, block)
            .is_err());

        // Out-of-range fetch fails rather than fabricating data.
        assert!(accessor
            .blob
            .fetch(&blob_id, descriptor.cache_size, block)
            .is_err());
    }

    #[test]
    fn accessor_static_filesystem_api_reads_metadata_and_data() {
        let dir = tempdir().unwrap();
        let (bootstrap, config, blob_id, corpus) = build_test_image(dir.path());
        let blob_id = BlobID::from(blob_id);

        let accessor = LeptonAccessor::new(&bootstrap, config).unwrap();

        let root_entry = accessor.fs.open("/").unwrap();
        let root = root_entry.metadata().unwrap();
        assert_eq!(root.file_type, FileType::Directory);

        let entries = root_entry.read_dir().unwrap();
        let names = entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"file1"));
        assert!(names.contains(&"dir"));
        assert!(names.contains(&"link_to_file1"));

        let file1_entry = accessor.fs.open("file1").unwrap();
        let file1 = file1_entry.metadata().unwrap();
        assert_eq!(file1.file_type, FileType::RegularFile);
        assert!(file1.size >= corpus["file1"].len() as u64);

        let all = file1_entry.read().unwrap();
        assert_eq!(&all[..corpus["file1"].len()], corpus["file1"].as_slice());
        assert!(all[corpus["file1"].len()..].iter().all(|byte| *byte == 0));

        let mut buf = vec![0u8; 4097];
        let read = file1_entry.read_at(12345, &mut buf).unwrap();
        assert_eq!(read, buf.len());
        assert_eq!(&buf, &corpus["file1"][12345..12345 + read]);
        let mut second = vec![0u8; 32];
        let read = file1_entry.read_at(777, &mut second).unwrap();
        assert_eq!(read, second.len());
        assert_eq!(&second, &corpus["file1"][777..777 + read]);

        let tiny = accessor.fs.open("tiny.txt").unwrap().read().unwrap();
        assert_eq!(
            &tiny[..corpus["tiny.txt"].len()],
            corpus["tiny.txt"].as_slice()
        );
        assert!(tiny[corpus["tiny.txt"].len()..]
            .iter()
            .all(|byte| *byte == 0));
        assert!(accessor
            .fs
            .open("empty.txt")
            .unwrap()
            .read()
            .unwrap()
            .is_empty());
        let small = accessor.fs.open("dir/small.txt").unwrap().read().unwrap();
        assert_eq!(
            &small[..corpus["dir/small.txt"].len()],
            corpus["dir/small.txt"].as_slice()
        );
        assert!(small[corpus["dir/small.txt"].len()..]
            .iter()
            .all(|byte| *byte == 0));

        let link_entry = accessor.fs.open("link_to_file1").unwrap();
        let link = link_entry.read_link().unwrap();
        assert_eq!(link, b"file1");
        assert_eq!(link_entry.read_link().unwrap(), b"file1");
        let link_meta = link_entry.metadata().unwrap();
        assert_eq!(link_meta.file_type, FileType::Symlink);

        let xattrs = root_entry.xattrs().unwrap();
        assert!(xattrs.iter().any(|(name, value)| {
            name.as_slice() == b"trusted.lepton.prefetch.blobs" && value.as_slice() == b"1"
        }));

        let blobs = accessor.blob.entries().unwrap();
        let cached = fs::read(&blobs[0].cache_path).unwrap();
        assert!(cached.iter().any(|byte| *byte != 0));
        assert_eq!(blobs[0].id, blob_id);
    }

    #[test]
    fn fs_entry_fetch_populates_blob_cache_without_reading_data() {
        let dir = tempdir().unwrap();
        let (bootstrap, config, _blob_id, _corpus) = build_test_image(dir.path());

        let accessor = LeptonAccessor::new(&bootstrap, config).unwrap();
        let blobs = accessor.blob.entries().unwrap();
        let before = fs::read(&blobs[0].cache_path).unwrap();
        assert!(before.iter().all(|byte| *byte == 0));

        let file1_entry = accessor.fs.open("file1").unwrap();
        file1_entry.fetch(12345, 4097).unwrap();

        let after = fs::read(&blobs[0].cache_path).unwrap();
        assert!(after.iter().any(|byte| *byte != 0));
        file1_entry.fetch(0, 0).unwrap();
        accessor.fs.open("/").unwrap().fetch(0, 4096).unwrap_err();
    }
}
