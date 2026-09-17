use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, ErrorKind, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileExt;
use std::path::{Component, Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;

use crate::build::blob_chunk::{
    validate_chunk_size, BlobLayout, BlobWriter, DEFAULT_CHUNK_GROUP_MIN_SIZE,
};
use crate::build::bootstrap::render_bootstrap;
use crate::build::inode::set_root_prefetch_blobs_xattr;
use crate::build::inode::{
    flatten_tree, ChildRef, InodeData, InodeInfo, NamedChildren, NodeAttrs, TreeNode,
};
use crate::build::{save_blob_metadata_sidecar, HashingWriter};
use crate::reader::RawDirEntry;
use crate::ErofsReader;
use nydus_error::{Context, Error, Result};
use nydus_format::blob::{self, BlobMetadata, BlobMetadataCompressor, BlobMetadataDigester};
use nydus_format::erofs::{
    erofs_xattr_name_split, mode_to_erofs_file_type, needs_erofs_extended_inode, ErofsChunkAddr,
    ErofsDeviceSlot, ErofsInode, XattrEntry, EROFS_BLOB_ID_SIZE, EROFS_FT_BLKDEV, EROFS_FT_CHRDEV,
    EROFS_FT_DIR, EROFS_FT_FIFO, EROFS_FT_REG_FILE, EROFS_FT_SOCK, EROFS_FT_SYMLINK,
    EROFS_INODE_CHUNK_BASED, EROFS_NULL_ADDR,
};
use nydus_format::utils::hex_string;

struct FinishedUpperBlob {
    full_blob_digest: [u8; EROFS_BLOB_ID_SIZE],
    blob_metadata: BlobMetadata,
    blob_blocks: u64,
}

pub struct IncrementalWriterOptions {
    /// Directory where commit writes `image.boot`, digest-named upper blob, and
    /// the `<digest>.blob.meta` sidecar when the update contains upper data.
    pub output_dir: PathBuf,
    /// File chunk size and chunk-group slot size.
    pub chunk_size: u32,
    /// Compression algorithm for chunk-group payloads.
    pub compressor: BlobMetadataCompressor,
    /// Per-chunk digest algorithm recorded in the blob metadata.
    pub digester: BlobMetadataDigester,
}

/// Metadata assigned to a regular file created by an incremental writer.
#[derive(Clone, Debug)]
pub struct CreateFileOptions {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub mtime_nsec: u32,
}

impl Default for CreateFileOptions {
    fn default() -> Self {
        Self {
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
        }
    }
}

#[derive(Default)]
struct FileOverlay {
    replace: Option<Vec<u8>>,
    chunks: BTreeMap<usize, ChunkOverlay>,
}

#[derive(Default)]
struct ChunkOverlay {
    source: Option<DirtyChunk>,
    patches: Vec<ChunkPatch>,
}

struct ChunkPatch {
    offset: usize,
    source: DirtyChunk,
}

enum DirtyChunk {
    Owned(Vec<u8>),
    FileRange {
        file: Arc<File>,
        offset: u64,
        len: usize,
    },
    MemoryRange {
        addr: usize,
        len: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChunkBase {
    Null,
    Parent,
    Sealed,
}

impl DirtyChunk {
    fn len(&self) -> usize {
        match self {
            Self::Owned(data) => data.len(),
            Self::FileRange { len, .. } | Self::MemoryRange { len, .. } => *len,
        }
    }

    unsafe fn memory_range_slice<'a>(addr: usize, len: usize) -> &'a [u8] {
        // SAFETY: callers only use this for `DirtyChunk::MemoryRange`, whose
        // public write API requires the memory range to remain valid and
        // immutable until seal or commit consumes it.
        unsafe { std::slice::from_raw_parts(addr as *const u8, len) }
    }

    fn read_into(&self, data: &mut [u8]) -> Result<()> {
        if data.len() != self.len() {
            return Err(Error::InvalidParameter(format!(
                "dirty chunk buffer length mismatch: got {}, expected {}",
                data.len(),
                self.len()
            )));
        }

        match self {
            Self::Owned(source) => data.copy_from_slice(source),
            Self::FileRange { file, offset, .. } => read_exact_from_file_at(file, *offset, data)?,
            Self::MemoryRange { addr, len } => {
                // SAFETY: upheld by the `DirtyChunk::MemoryRange` contract.
                let source = unsafe { Self::memory_range_slice(*addr, *len) };
                data.copy_from_slice(source);
            }
        }

        Ok(())
    }

    fn into_vec(self) -> Result<Vec<u8>> {
        match self {
            Self::Owned(data) => Ok(data),
            source @ (Self::FileRange { .. } | Self::MemoryRange { .. }) => {
                let mut data = vec![0; source.len()];
                source.read_into(&mut data)?;
                Ok(data)
            }
        }
    }
}

/// Builds a nydus image from staged file updates, optionally using a parent.
///
/// The writer is a single-writer builder: all mutation APIs take `&mut self`,
/// and callers that share one writer across threads must serialize calls
/// externally. Multiple independent writers may share the same parent reader,
/// but they must use distinct output paths.
///
/// Writes are staged in an in-memory overlay. Full-chunk writes replace the
/// staged base for that chunk, while partial writes are recorded in order and
/// applied when commit materializes the chunk. The parent
/// `NydusCore` or `ErofsReader` remains read-only and does not observe staged
/// changes; callers must open the committed bootstrap/blob as a new image to
/// read the merged result.
///
/// [`seal_blob`](Self::seal_blob) materializes the current updates as one
/// prefetched data blob without rendering a bootstrap. The final blob produced
/// by commit is left on demand. Whole-file and whole-chunk overwrites remain
/// available afterwards; partial writes over sealed chunks use logical zeroes
/// instead of reading sealed blob data as their base.
pub struct IncrementalWriter {
    inodes: Vec<InodeInfo>,
    path_index: HashMap<PathBuf, usize>,
    parent_nids: Vec<u64>,
    parent_reader: Option<Arc<ErofsReader>>,
    overlay: BTreeMap<usize, FileOverlay>,
    device_slots: Vec<ErofsDeviceSlot>,
    parent_device_count: usize,
    prefetch_blob_indexes: Vec<u16>,
    has_changes: bool,
    poisoned: bool,
    blob_writer: Option<BlobWriter<File>>,
    // Inode/chunk indexes whose small packed group is still open. Full-slot
    // chunks are resolved immediately and never enter this list.
    pending_blob_chunks: Vec<(usize, usize)>,
    output_dir: PathBuf,
    upper_blob_temp_path: Option<PathBuf>,
    chunk_size: u32,
    compressor: BlobMetadataCompressor,
    digester: BlobMetadataDigester,
    epoch: u64,
    uuid: [u8; 16],
}

/// A resolved regular file in an [`IncrementalWriter`].
///
/// The handle keeps the inode index resolved by [`IncrementalWriter::open_file`],
/// so repeated offset writes to the same large file avoid path normalization and
/// `path_index` lookups. It borrows the writer mutably, preserving the writer's
/// single-writer ordering semantics.
pub struct IncrementalWriterFile<'a> {
    writer: &'a mut IncrementalWriter,
    inode_index: usize,
}

impl IncrementalWriterFile<'_> {
    /// Stage a byte-range update at `offset` in this file.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<usize> {
        self.writer.write_at_inode(self.inode_index, offset, data)
    }

    /// Stage an owned byte-range update at `offset` in this file.
    pub fn write_at_owned(&mut self, offset: u64, data: Vec<u8>) -> Result<usize> {
        self.writer
            .write_at_owned_inode(self.inode_index, offset, data)
    }

    /// Stage a byte range backed by a source file.
    pub fn write_file_range(
        &mut self,
        dst_offset: u64,
        source: Arc<File>,
        source_offset: u64,
        len: u64,
    ) -> Result<usize> {
        self.writer
            .write_file_range_inode(self.inode_index, dst_offset, source, source_offset, len)
    }

    /// Stage a byte range backed by caller-owned memory.
    ///
    /// # Safety
    ///
    /// `ptr..ptr+len` must remain readable and stable until `seal_blob` or
    /// `commit` consumes the staged range, or another write replaces the same
    /// chunk. The memory must not be mutated concurrently while it is consumed.
    pub unsafe fn write_memory_range(
        &mut self,
        dst_offset: u64,
        ptr: NonNull<u8>,
        len: usize,
    ) -> Result<usize> {
        // SAFETY: the caller upholds the memory lifetime and immutability
        // contract documented on this method.
        unsafe {
            self.writer
                .write_memory_range_inode(self.inode_index, dst_offset, ptr, len)
        }
    }
}

impl IncrementalWriter {
    /// Create a writer without a parent image.
    ///
    /// The resulting filesystem initially contains only its root directory.
    /// Files can be added with [`create_file`](Self::create_file); unwritten
    /// ranges in those files are logical zeroes and do not consume blob data.
    pub fn create(options: IncrementalWriterOptions) -> Result<Self> {
        validate_chunk_size(options.chunk_size)?;
        let root = InodeInfo {
            mode: (libc::S_IFDIR | 0o755) as u16,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 0,
            mtime_nsec: 0,
            nlink: 2,
            ino: 1,
            nid: 0,
            meta_offset: 0,
            is_extended: false,
            data: InodeData::Directory {
                children: Vec::new(),
                startblk: 0,
                data_size: 0,
                parent_nid: 0,
                inline_len: 0,
                inline_tail: Vec::new(),
            },
            xattrs: Vec::new(),
        };
        let mut path_index = HashMap::new();
        path_index.insert(PathBuf::new(), 0);

        Ok(Self {
            inodes: vec![root],
            path_index,
            parent_nids: Vec::new(),
            parent_reader: None,
            overlay: BTreeMap::new(),
            device_slots: Vec::new(),
            parent_device_count: 0,
            prefetch_blob_indexes: Vec::new(),
            has_changes: false,
            poisoned: false,
            blob_writer: None,
            pending_blob_chunks: Vec::new(),
            output_dir: options.output_dir,
            upper_blob_temp_path: None,
            chunk_size: options.chunk_size,
            compressor: options.compressor,
            digester: options.digester,
            epoch: 0,
            uuid: [0; 16],
        })
    }

    /// Open a writer from parent metadata only.
    ///
    /// This mode can replace whole files and stage writes that cover a full
    /// logical chunk. It cannot serve partial writes that need parent data
    /// because no parent blob backend is available.
    pub fn open_metadata_only(
        parent_bootstrap: &Path,
        options: IncrementalWriterOptions,
    ) -> Result<Self> {
        validate_chunk_size(options.chunk_size)?;
        let reader = ErofsReader::open_metadata_only(parent_bootstrap).with_context(|| {
            format!(
                "failed to open parent bootstrap: {}",
                parent_bootstrap.display()
            )
        })?;
        Self::from_reader(Arc::new(reader), options, false)
    }

    pub(crate) fn from_parent_reader(
        reader: Arc<ErofsReader>,
        options: IncrementalWriterOptions,
    ) -> Result<Self> {
        validate_chunk_size(options.chunk_size)?;
        Self::from_reader(reader, options, true)
    }

    fn from_reader(
        reader: Arc<ErofsReader>,
        options: IncrementalWriterOptions,
        keep_parent_reader: bool,
    ) -> Result<Self> {
        let sb = reader.superblock();
        let epoch = sb.epoch();
        let uuid = sb.uuid;
        let parent_blob_infos = reader
            .blob_infos()
            .context("failed to read parent blob table")?;
        let parent_device_slots: Vec<ErofsDeviceSlot> = parent_blob_infos
            .iter()
            .map(|info| ErofsDeviceSlot::with_blob_id(info.blocks, &info.blob_id))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let parent_device_count = parent_device_slots.len();
        let prefetch_blob_indexes = reader.read_prefetch_order();

        let root_nid = sb.root_nid();
        let mut parent_tree = ParentTreeContext::new();
        let inodes = flatten_tree(
            ParentTreeNode::new(reader.as_ref(), epoch, root_nid, PathBuf::new()),
            &mut parent_tree,
        )?;
        if parent_tree.nids.len() != inodes.len() {
            return Err(Error::InvalidImage(
                "parent inode map does not match flattened inode table".to_string(),
            ));
        }
        let path_index = parent_tree.path_index;
        let parent_nids = parent_tree.nids;

        Ok(Self {
            inodes,
            path_index,
            parent_nids,
            parent_reader: keep_parent_reader.then_some(reader),
            overlay: BTreeMap::new(),
            device_slots: parent_device_slots,
            parent_device_count,
            prefetch_blob_indexes,
            has_changes: false,
            poisoned: false,
            blob_writer: None,
            pending_blob_chunks: Vec::new(),
            output_dir: options.output_dir,
            upper_blob_temp_path: None,
            chunk_size: options.chunk_size,
            compressor: options.compressor,
            digester: options.digester,
            epoch,
            uuid,
        })
    }

    /// Create a zero-filled regular file with a fixed logical size.
    ///
    /// The parent directory must already exist. Creating directories and
    /// extending a file after creation are intentionally outside this API.
    pub fn create_file(
        &mut self,
        path: &Path,
        size: u64,
        options: CreateFileOptions,
    ) -> Result<()> {
        self.ensure_healthy()?;
        let key = normalize_relative_path(path)?;
        if key.as_os_str().is_empty() {
            return Err(Error::InvalidParameter(
                "file path must not refer to the root directory".to_string(),
            ));
        }
        if self.path_index.contains_key(&key) {
            return Err(Error::InvalidParameter(format!(
                "path already exists: {}",
                path.display()
            )));
        }

        let parent_key = key.parent().unwrap_or_else(|| Path::new(""));
        let parent_index = *self.path_index.get(parent_key).ok_or_else(|| {
            Error::NotFound(format!(
                "parent directory not found: {}",
                parent_key.display()
            ))
        })?;
        if !matches!(self.inodes[parent_index].data, InodeData::Directory { .. }) {
            return Err(Error::InvalidParameter(format!(
                "parent path is not a directory: {}",
                parent_key.display()
            )));
        }

        let chunk_count = usize::try_from(size.div_ceil(self.chunk_size as u64))
            .map_err(|err| Error::Overflow(format!("file chunk count exceeds usize: {err}")))?;
        let mode = (libc::S_IFREG as u16) | (options.mode & 0o7777);
        let ino = u32::try_from(self.inodes.len() + 1)
            .map_err(|err| Error::Overflow(format!("inode number overflow: {err}")))?;
        let inode_index = self.inodes.len();
        self.inodes.push(InodeInfo {
            mode,
            uid: options.uid,
            gid: options.gid,
            size,
            mtime: options.mtime,
            mtime_nsec: options.mtime_nsec,
            nlink: 1,
            ino,
            nid: 0,
            meta_offset: 0,
            is_extended: needs_erofs_extended_inode(size, options.uid, options.gid, 1),
            data: InodeData::RegularFile {
                chunk_index_entries: vec![
                    ErofsChunkAddr {
                        blkaddr: EROFS_NULL_ADDR,
                        device_id: 0,
                    };
                    chunk_count
                ],
                chunk_size_bits: self.chunk_size.trailing_zeros(),
            },
            xattrs: Vec::new(),
        });
        let name = key
            .file_name()
            .expect("non-empty normalized path")
            .as_bytes()
            .to_vec();
        let InodeData::Directory { children, .. } = &mut self.inodes[parent_index].data else {
            unreachable!();
        };
        children.push(ChildRef {
            name,
            file_type: EROFS_FT_REG_FILE,
            inode_index,
        });
        self.path_index.insert(key, inode_index);
        self.has_changes = true;
        Ok(())
    }

    /// Open a regular file for repeated offset writes.
    ///
    /// This resolves the path once and returns a handle whose write methods skip
    /// path normalization and `path_index` lookups. Whole-file replacement stays
    /// on [`IncrementalWriter::replace_file`] because it is path-oriented and
    /// usually low frequency.
    pub fn open_file(&mut self, path: &Path) -> Result<IncrementalWriterFile<'_>> {
        self.ensure_healthy()?;
        let key = normalize_relative_path(path)?;
        let inode_index = self.regular_inode_index_by_key(&key, path)?;
        self.validate_inode_chunk_size(inode_index, path)?;
        Ok(IncrementalWriterFile {
            writer: self,
            inode_index,
        })
    }

    /// Stage a byte-range update for `path`.
    ///
    /// The write is clipped at EOF and returns the number of bytes staged. A
    /// partial chunk update is based on the current writer view: existing dirty
    /// data first, replacement file data second, and parent image data last.
    /// Therefore sequential writes on one writer observe earlier writes.
    pub fn write_at(&mut self, path: &Path, offset: u64, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let inode_index = self.resolve_regular_inode_for_write(path)?;
        self.write_at_inode(inode_index, offset, data)
    }

    /// Stage an owned byte-range update for `path`.
    ///
    /// A single chunk-aligned full-chunk write moves `data` into the overlay
    /// without copying. Other writes fall back to [`write_at`](Self::write_at)
    /// because they need slicing or parent-data patching.
    pub fn write_at_owned(&mut self, path: &Path, offset: u64, data: Vec<u8>) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let inode_index = self.resolve_regular_inode_for_write(path)?;
        self.write_at_owned_inode(inode_index, offset, data)
    }

    /// Stage a byte range backed by a source file.
    ///
    /// Chunk-aligned full-chunk writes keep only the source file range in the
    /// overlay. Partial writes read the source range and patch a full logical
    /// chunk, as required by the chunk-level upper image format.
    pub fn write_file_range(
        &mut self,
        path: &Path,
        dst_offset: u64,
        source: Arc<File>,
        source_offset: u64,
        len: u64,
    ) -> Result<usize> {
        if len == 0 {
            return Ok(0);
        }
        let inode_index = self.resolve_regular_inode_for_write(path)?;
        self.write_file_range_inode(inode_index, dst_offset, source, source_offset, len)
    }

    /// Stage a byte range backed by caller-owned memory.
    ///
    /// # Safety
    ///
    /// `ptr..ptr+len` must remain readable and stable until `seal_blob` or
    /// `commit` consumes the staged range, or another write replaces the same
    /// chunk. The memory must not be mutated concurrently while it is consumed.
    pub unsafe fn write_memory_range(
        &mut self,
        path: &Path,
        dst_offset: u64,
        ptr: NonNull<u8>,
        len: usize,
    ) -> Result<usize> {
        if len == 0 {
            return Ok(0);
        }
        let inode_index = self.resolve_regular_inode_for_write(path)?;
        // SAFETY: the caller upholds the memory lifetime and immutability
        // contract documented on this method.
        unsafe { self.write_memory_range_inode(inode_index, dst_offset, ptr, len) }
    }

    fn write_at_inode(&mut self, inode_index: usize, offset: u64, data: &[u8]) -> Result<usize> {
        self.ensure_healthy()?;
        if data.is_empty() {
            return Ok(0);
        }

        let Some(actual_len) = self.clipped_write_len(inode_index, offset, data.len())? else {
            return Ok(0);
        };
        let mut written = 0usize;

        while written < actual_len {
            let (chunk_index, chunk_off, logical_chunk_len) =
                self.chunk_write_geometry(inode_index, offset, written)?;
            let step = (actual_len - written).min(logical_chunk_len - chunk_off);

            if chunk_off == 0 && step == logical_chunk_len {
                self.record_chunk_source(
                    inode_index,
                    chunk_index,
                    DirtyChunk::Owned(data[written..written + step].to_vec()),
                )?;
            } else {
                self.record_chunk_patch(
                    inode_index,
                    chunk_index,
                    chunk_off,
                    DirtyChunk::Owned(data[written..written + step].to_vec()),
                )?;
            }
            written += step;
        }

        Ok(written)
    }

    fn write_at_owned_inode(
        &mut self,
        inode_index: usize,
        offset: u64,
        mut data: Vec<u8>,
    ) -> Result<usize> {
        self.ensure_healthy()?;
        if data.is_empty() {
            return Ok(0);
        }

        let Some(actual_len) = self.clipped_write_len(inode_index, offset, data.len())? else {
            return Ok(0);
        };
        let (chunk_index, chunk_off, logical_chunk_len) =
            self.chunk_write_geometry(inode_index, offset, 0)?;
        if actual_len <= logical_chunk_len - chunk_off {
            data.truncate(actual_len);
            if chunk_off == 0 && actual_len == logical_chunk_len {
                self.record_chunk_source(inode_index, chunk_index, DirtyChunk::Owned(data))?;
            } else {
                self.record_chunk_patch(
                    inode_index,
                    chunk_index,
                    chunk_off,
                    DirtyChunk::Owned(data),
                )?;
            }
            return Ok(actual_len);
        }

        self.write_at_inode(inode_index, offset, &data[..actual_len])
    }

    fn write_file_range_inode(
        &mut self,
        inode_index: usize,
        dst_offset: u64,
        source: Arc<File>,
        source_offset: u64,
        len: u64,
    ) -> Result<usize> {
        self.ensure_healthy()?;
        let len = usize::try_from(len)
            .map_err(|err| Error::Overflow(format!("file range length exceeds usize: {err}")))?;
        if len == 0 {
            return Ok(0);
        }

        let Some(actual_len) = self.clipped_write_len(inode_index, dst_offset, len)? else {
            return Ok(0);
        };
        source_offset
            .checked_add(actual_len as u64)
            .ok_or_else(|| Error::Overflow("source file range overflow".to_string()))?;

        let mut written = 0usize;
        while written < actual_len {
            let (chunk_index, chunk_off, logical_chunk_len) =
                self.chunk_write_geometry(inode_index, dst_offset, written)?;
            let step = (actual_len - written).min(logical_chunk_len - chunk_off);
            let source_pos = source_offset
                .checked_add(written as u64)
                .ok_or_else(|| Error::Overflow("source file offset overflow".to_string()))?;

            if chunk_off == 0 && step == logical_chunk_len {
                self.record_chunk_source(
                    inode_index,
                    chunk_index,
                    DirtyChunk::FileRange {
                        file: source.clone(),
                        offset: source_pos,
                        len: step,
                    },
                )?;
            } else {
                self.record_chunk_patch(
                    inode_index,
                    chunk_index,
                    chunk_off,
                    DirtyChunk::FileRange {
                        file: source.clone(),
                        offset: source_pos,
                        len: step,
                    },
                )?;
            }
            written += step;
        }

        Ok(written)
    }

    unsafe fn write_memory_range_inode(
        &mut self,
        inode_index: usize,
        dst_offset: u64,
        ptr: NonNull<u8>,
        len: usize,
    ) -> Result<usize> {
        self.ensure_healthy()?;
        if len == 0 {
            return Ok(0);
        }

        let Some(actual_len) = self.clipped_write_len(inode_index, dst_offset, len)? else {
            return Ok(0);
        };

        let base = ptr.as_ptr() as usize;
        base.checked_add(actual_len)
            .ok_or_else(|| Error::Overflow("source memory range overflow".to_string()))?;

        let mut written = 0usize;
        while written < actual_len {
            let (chunk_index, chunk_off, logical_chunk_len) =
                self.chunk_write_geometry(inode_index, dst_offset, written)?;
            let step = (actual_len - written).min(logical_chunk_len - chunk_off);
            let addr = base
                .checked_add(written)
                .ok_or_else(|| Error::Overflow("source memory offset overflow".to_string()))?;

            if chunk_off == 0 && step == logical_chunk_len {
                self.record_chunk_source(
                    inode_index,
                    chunk_index,
                    DirtyChunk::MemoryRange { addr, len: step },
                )?;
            } else {
                self.record_chunk_patch(
                    inode_index,
                    chunk_index,
                    chunk_off,
                    DirtyChunk::MemoryRange { addr, len: step },
                )?;
            }
            written += step;
        }

        Ok(written)
    }

    /// Replace the whole file contents in the upper image.
    ///
    /// Existing staged chunk updates for the file are cleared. Later chunk or
    /// range writes apply on top of this replacement data before commit.
    pub fn replace_file(&mut self, path: &Path, data: Vec<u8>) -> Result<()> {
        self.ensure_healthy()?;
        let inode_index = self.regular_inode_index(path)?;
        self.overlay.insert(
            inode_index,
            FileOverlay {
                replace: Some(data),
                chunks: BTreeMap::new(),
            },
        );
        self.has_changes = true;
        Ok(())
    }

    /// Finish the current data blob and mark it for prefetch without rendering
    /// `image.boot`.
    ///
    /// Later writes refer to the next blob device in the final bootstrap.
    /// Replacing a file or a complete chunk remains valid, while a partial
    /// write whose previous data belongs to a sealed blob starts from logical
    /// zeroes and does not read that blob.
    pub fn seal_blob(&mut self) -> Result<()> {
        self.ensure_healthy()?;
        if self.overlay.is_empty() {
            return Err(Error::InvalidParameter(
                "incremental writer has no data changes to seal".to_string(),
            ));
        }
        let old_slot_count = self.device_slots.len();
        let result = self
            .materialize_overlay()
            .and_then(|_| self.finish_current_blob(false));
        if let Err(err) = result {
            self.poisoned = true;
            self.discard_current_blob();
            return Err(err);
        }
        if self.device_slots.len() > old_slot_count {
            let blob_index = u16::try_from(self.device_slots.len())
                .map_err(|err| Error::Overflow(format!("prefetch blob index overflow: {err}")))?;
            self.prefetch_blob_indexes.push(blob_index);
        }
        Ok(())
    }

    /// Materialize staged changes and write the child bootstrap/blob.
    ///
    /// Commit consumes the writer. It fails if no changes were staged, which
    /// avoids creating an upper image that is indistinguishable from the parent
    /// except for empty output artifacts.
    pub fn commit(mut self) -> Result<()> {
        let result = self.commit_inner();
        if result.is_err() {
            self.discard_current_blob();
        }
        result
    }

    fn commit_inner(&mut self) -> Result<()> {
        self.ensure_healthy()?;
        if !self.has_changes {
            return Err(Error::InvalidParameter(
                "incremental writer has no changes to commit".to_string(),
            ));
        }
        fs::create_dir_all(&self.output_dir).with_context(|| {
            format!(
                "failed to create incremental output directory: {}",
                self.output_dir.display()
            )
        })?;
        if !self.overlay.is_empty() {
            self.materialize_overlay()?;
        }
        let keep_empty_blob = self.device_slots.is_empty() && self.parent_device_count == 0;
        if keep_empty_blob {
            self.ensure_blob_writer()?;
        }
        self.finish_current_blob(keep_empty_blob)?;

        self.sort_directory_children();
        set_root_prefetch_blobs_xattr(&mut self.inodes[0], &self.prefetch_blob_indexes)?;
        let final_bootstrap =
            render_bootstrap(&mut self.inodes, self.epoch, &self.device_slots, &self.uuid)?;
        let bootstrap_path = self.output_dir.join("image.boot");
        fs::write(&bootstrap_path, final_bootstrap).with_context(|| {
            format!(
                "failed to write incremental bootstrap: {}",
                bootstrap_path.display()
            )
        })?;

        Ok(())
    }

    fn discard_current_blob(&mut self) {
        self.blob_writer.take();
        if let Some(path) = self.upper_blob_temp_path.take() {
            let _ = fs::remove_file(path);
        }
    }

    fn finish_current_blob(&mut self, keep_empty: bool) -> Result<()> {
        if self
            .blob_writer
            .as_ref()
            .is_some_and(|blob_writer| blob_writer.is_empty())
            && !keep_empty
        {
            self.blob_writer.take();
            if let Some(path) = self.upper_blob_temp_path.take() {
                fs::remove_file(path).context("failed to remove empty upper blob")?;
            }
            return Ok(());
        }
        let Some(blob_writer) = self.blob_writer.take() else {
            return Ok(());
        };
        let device_id = self.current_device_id()?;
        let mut blob_writer = blob_writer;
        blob_writer.finish()?;
        for (inode_index, chunk_index) in std::mem::take(&mut self.pending_blob_chunks) {
            let InodeData::RegularFile {
                chunk_index_entries,
                ..
            } = &mut self.inodes[inode_index].data
            else {
                return Err(Error::InvalidImage(
                    "pending blob chunk refers to a non-regular inode".to_string(),
                ));
            };
            let entry = chunk_index_entries.get_mut(chunk_index).ok_or_else(|| {
                Error::InvalidImage(format!(
                    "pending blob chunk index {chunk_index} is out of range"
                ))
            })?;
            blob_writer.resolve_chunk_addr_for_device(entry, device_id)?;
        }
        let finished = finish_upper_blob(blob_writer)?;
        let temp_path = self
            .upper_blob_temp_path
            .take()
            .ok_or_else(|| Error::InvalidImage("upper blob temp path is missing".to_string()))?;
        let final_blob_path =
            finalize_digest_named_blob(&temp_path, &self.output_dir, &finished.full_blob_digest)?;
        save_blob_metadata_sidecar(&finished.blob_metadata, &final_blob_path)?;
        self.device_slots.push(ErofsDeviceSlot::with_blob_id(
            finished.blob_blocks,
            &finished.full_blob_digest,
        )?);
        Ok(())
    }

    fn record_chunk_source(
        &mut self,
        inode_index: usize,
        chunk_index: usize,
        source: DirtyChunk,
    ) -> Result<()> {
        let logical_len = self.logical_chunk_len(inode_index, chunk_index)?;
        if source.len() != logical_len {
            return Err(Error::InvalidParameter(format!(
                "chunk data for index {chunk_index} length mismatch: got {}, expected {logical_len}",
                source.len()
            )));
        }
        self.overlay.entry(inode_index).or_default().chunks.insert(
            chunk_index,
            ChunkOverlay {
                source: Some(source),
                patches: Vec::new(),
            },
        );
        self.has_changes = true;
        Ok(())
    }

    fn record_chunk_patch(
        &mut self,
        inode_index: usize,
        chunk_index: usize,
        offset: usize,
        source: DirtyChunk,
    ) -> Result<()> {
        let logical_len = self.logical_chunk_len(inode_index, chunk_index)?;
        let end = offset
            .checked_add(source.len())
            .ok_or_else(|| Error::Overflow("chunk patch range overflow".to_string()))?;
        if end > logical_len {
            return Err(Error::InvalidParameter(format!(
                "chunk patch for index {chunk_index} exceeds logical chunk length {logical_len}: {offset}..{end}"
            )));
        }

        let has_upper_base = self.overlay.get(&inode_index).is_some_and(|file_overlay| {
            file_overlay.replace.is_some()
                || file_overlay
                    .chunks
                    .get(&chunk_index)
                    .is_some_and(|chunk| chunk.source.is_some())
        });
        if !has_upper_base
            && self.chunk_base(inode_index, chunk_index)? == ChunkBase::Parent
            && self.parent_reader.is_none()
        {
            return Err(Error::InvalidParameter(
                "partial write requires a data-capable parent reader; use NydusCore::writer"
                    .to_string(),
            ));
        }

        self.overlay
            .entry(inode_index)
            .or_default()
            .chunks
            .entry(chunk_index)
            .or_default()
            .patches
            .push(ChunkPatch { offset, source });
        self.has_changes = true;
        Ok(())
    }

    fn ensure_blob_writer(&mut self) -> Result<()> {
        if self.blob_writer.is_some() {
            return Ok(());
        }
        fs::create_dir_all(&self.output_dir).with_context(|| {
            format!(
                "failed to create incremental output directory: {}",
                self.output_dir.display()
            )
        })?;
        let (blob_path, blob_file) = self.create_temp_blob()?;
        self.blob_writer = Some(BlobWriter::new(
            blob_file,
            self.chunk_size,
            self.compressor,
            self.digester,
            true,
            BlobLayout::ChunkGroups {
                chunk_group_min_size: DEFAULT_CHUNK_GROUP_MIN_SIZE,
            },
        )?);
        self.upper_blob_temp_path = Some(blob_path);
        Ok(())
    }

    fn create_temp_blob(&self) -> Result<(PathBuf, File)> {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|err| Error::InvalidParameter(format!("system time before epoch: {err}")))?
            .as_nanos();
        for attempt in 0..1024u16 {
            let path = self.output_dir.join(format!(
                ".nydus-incremental-{}-{seed}-{attempt}.tmp",
                std::process::id(),
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to create upper blob: {}", path.display())
                    })
                }
            }
        }
        Err(Error::InvalidParameter(
            "failed to allocate a unique upper blob temp path".to_string(),
        ))
    }

    fn write_upper_chunk_addr(&mut self, data: &[u8]) -> Result<ErofsChunkAddr> {
        if data.iter().all(|&byte| byte == 0) {
            return Ok(ErofsChunkAddr {
                blkaddr: EROFS_NULL_ADDR,
                device_id: 0,
            });
        }

        self.write_nonzero_upper_chunk(data)
    }

    fn write_upper_source_chunk_addr(&mut self, source: DirtyChunk) -> Result<ErofsChunkAddr> {
        match source {
            DirtyChunk::Owned(data) => self.write_upper_owned_chunk_addr(data),
            DirtyChunk::FileRange { file, offset, len } => {
                self.write_upper_chunk_addr_from_source(len, true, |data| {
                    read_exact_from_file_at(&file, offset, data)
                })
            }
            DirtyChunk::MemoryRange { addr, len } => {
                // SAFETY: upheld by the `DirtyChunk::MemoryRange` contract.
                let source = unsafe { DirtyChunk::memory_range_slice(addr, len) };
                if source.iter().all(|&byte| byte == 0) {
                    return Ok(ErofsChunkAddr {
                        blkaddr: EROFS_NULL_ADDR,
                        device_id: 0,
                    });
                }
                self.write_upper_chunk_addr_from_source(len, false, |data| {
                    data.copy_from_slice(source);
                    Ok(())
                })
            }
        }
    }

    fn write_upper_owned_chunk_addr(&mut self, data: Vec<u8>) -> Result<ErofsChunkAddr> {
        if data.iter().all(|&byte| byte == 0) {
            return Ok(ErofsChunkAddr {
                blkaddr: EROFS_NULL_ADDR,
                device_id: 0,
            });
        }

        let device_id = self.current_device_id()?;
        self.ensure_blob_writer()?;
        let blob_writer = self.blob_writer.as_mut().expect("blob writer initialized");
        Ok(ErofsChunkAddr {
            blkaddr: blob_writer.write_data_chunk_owned(data)?,
            device_id,
        })
    }

    fn write_upper_chunk_addr_from_source<F>(
        &mut self,
        len: usize,
        detect_zero: bool,
        fill: F,
    ) -> Result<ErofsChunkAddr>
    where
        F: FnOnce(&mut [u8]) -> Result<()>,
    {
        let device_id = self.current_device_id()?;
        self.ensure_blob_writer()?;
        let blob_writer = self.blob_writer.as_mut().expect("blob writer initialized");
        let placement = if detect_zero {
            blob_writer.write_nonzero_data_chunk_from_source(len, fill)?
        } else {
            Some(blob_writer.write_data_chunk_from_source(len, fill)?)
        };
        match placement {
            Some(blkaddr) => Ok(ErofsChunkAddr { blkaddr, device_id }),
            None => Ok(ErofsChunkAddr {
                blkaddr: EROFS_NULL_ADDR,
                device_id: 0,
            }),
        }
    }

    fn write_nonzero_upper_chunk(&mut self, data: &[u8]) -> Result<ErofsChunkAddr> {
        let device_id = self.current_device_id()?;
        self.ensure_blob_writer()?;
        let blob_writer = self.blob_writer.as_mut().expect("blob writer initialized");
        Ok(ErofsChunkAddr {
            blkaddr: blob_writer.write_data_chunk(data)?,
            device_id,
        })
    }

    fn materialize_overlay(&mut self) -> Result<()> {
        let overlays = std::mem::take(&mut self.overlay);
        for (inode_index, overlay) in overlays {
            self.materialize_file_overlay(inode_index, overlay)?;
        }
        Ok(())
    }

    fn materialize_file_overlay(&mut self, inode_index: usize, overlay: FileOverlay) -> Result<()> {
        if let Some(data) = overlay.replace {
            let chunk_count = data.len().div_ceil(self.chunk_size as usize);
            let mut chunk_index_entries = Vec::with_capacity(chunk_count);
            let mut chunks = overlay.chunks;
            for chunk_index in 0..chunk_count {
                let start = chunk_index * self.chunk_size as usize;
                let end = (start + self.chunk_size as usize).min(data.len());
                let mut addr = match chunks.remove(&chunk_index) {
                    Some(chunk) => {
                        let source = self.materialize_chunk_overlay(
                            inode_index,
                            chunk_index,
                            Some(&data[start..end]),
                            chunk,
                        )?;
                        self.write_upper_source_chunk_addr(source)?
                    }
                    None => self.write_upper_chunk_addr(&data[start..end])?,
                };
                self.resolve_or_track_blob_chunk(inode_index, chunk_index, &mut addr)?;
                chunk_index_entries.push(addr);
            }
            let inode = &mut self.inodes[inode_index];
            inode.size = data.len() as u64;
            inode.data = InodeData::RegularFile {
                chunk_index_entries,
                chunk_size_bits: self.chunk_size.trailing_zeros(),
            };
            return Ok(());
        }

        let chunk_count = match &self.inodes[inode_index].data {
            InodeData::RegularFile {
                chunk_index_entries,
                ..
            } => chunk_index_entries.len(),
            _ => unreachable!(),
        };
        for (chunk_index, chunk) in overlay.chunks {
            if chunk_index >= chunk_count {
                return Err(Error::InvalidParameter(format!(
                    "chunk index {chunk_index} out of range {chunk_count}"
                )));
            }
            let source = self.materialize_chunk_overlay(inode_index, chunk_index, None, chunk)?;
            let mut addr = self.write_upper_source_chunk_addr(source)?;
            self.resolve_or_track_blob_chunk(inode_index, chunk_index, &mut addr)?;
            let InodeData::RegularFile {
                chunk_index_entries,
                ..
            } = &mut self.inodes[inode_index].data
            else {
                unreachable!();
            };
            chunk_index_entries[chunk_index] = addr;
        }
        Ok(())
    }

    fn materialize_chunk_overlay(
        &self,
        inode_index: usize,
        chunk_index: usize,
        replacement: Option<&[u8]>,
        chunk: ChunkOverlay,
    ) -> Result<DirtyChunk> {
        if chunk.patches.is_empty() {
            return chunk.source.ok_or_else(|| {
                Error::InvalidImage(format!(
                    "dirty chunk {chunk_index} has neither a source nor patches"
                ))
            });
        }

        let chunk_len = match replacement {
            Some(data) => data.len(),
            None => self.logical_chunk_len(inode_index, chunk_index)?,
        };
        let mut data = match chunk.source {
            Some(source) => source.into_vec()?,
            None => match replacement {
                Some(data) => data.to_vec(),
                None => self.materialize_base_chunk(inode_index, chunk_index, chunk_len)?,
            },
        };
        if data.len() != chunk_len {
            return Err(Error::InvalidImage(format!(
                "dirty chunk {chunk_index} length mismatch: got {}, expected {chunk_len}",
                data.len()
            )));
        }

        for patch in chunk.patches {
            let end = patch.offset + patch.source.len();
            patch.source.read_into(&mut data[patch.offset..end])?;
        }
        Ok(DirtyChunk::Owned(data))
    }

    fn materialize_base_chunk(
        &self,
        inode_index: usize,
        chunk_index: usize,
        chunk_len: usize,
    ) -> Result<Vec<u8>> {
        if self.chunk_base(inode_index, chunk_index)? != ChunkBase::Parent {
            return Ok(vec![0; chunk_len]);
        }
        if inode_index >= self.parent_nids.len() {
            return Err(Error::InvalidImage(
                "new file has a non-null parent chunk".to_string(),
            ));
        }
        let reader = self.parent_reader.as_ref().ok_or_else(|| {
            Error::InvalidParameter(
                "partial write requires a data-capable parent reader; use NydusCore::writer"
                    .to_string(),
            )
        })?;
        let nid = self.parent_nids[inode_index];
        let chunk_start = (chunk_index as u64)
            .checked_mul(self.chunk_size as u64)
            .ok_or_else(|| Error::Overflow("chunk start overflow".to_string()))?;
        let inode = reader
            .inode(nid)
            .with_context(|| format!("failed to read parent inode {nid}"))?;
        let data = reader
            .read_file_data(nid, &inode, chunk_start, chunk_len as u32)
            .with_context(|| format!("failed to read parent chunk at offset {chunk_start}"))?;
        if data.len() != chunk_len {
            return Err(Error::InvalidImage(format!(
                "short parent chunk read at offset {chunk_start}: got {}, expected {chunk_len}",
                data.len()
            )));
        }
        Ok(data)
    }

    fn chunk_addr(&self, inode_index: usize, chunk_index: usize) -> Result<ErofsChunkAddr> {
        let InodeData::RegularFile {
            chunk_index_entries,
            ..
        } = &self.inodes[inode_index].data
        else {
            unreachable!();
        };
        let addr = chunk_index_entries.get(chunk_index).ok_or_else(|| {
            Error::InvalidParameter(format!("chunk index {chunk_index} out of range"))
        })?;
        Ok(ErofsChunkAddr {
            blkaddr: addr.blkaddr,
            device_id: addr.device_id,
        })
    }

    fn chunk_base(&self, inode_index: usize, chunk_index: usize) -> Result<ChunkBase> {
        let addr = self.chunk_addr(inode_index, chunk_index)?;
        if addr.blkaddr == EROFS_NULL_ADDR {
            Ok(ChunkBase::Null)
        } else if addr.device_id as usize <= self.parent_device_count {
            Ok(ChunkBase::Parent)
        } else {
            Ok(ChunkBase::Sealed)
        }
    }

    fn current_device_id(&self) -> Result<u16> {
        u16::try_from(self.device_slots.len() + 1)
            .map_err(|err| Error::Overflow(format!("upper blob device id overflow: {err}")))
    }

    fn resolve_or_track_blob_chunk(
        &mut self,
        inode_index: usize,
        chunk_index: usize,
        addr: &mut ErofsChunkAddr,
    ) -> Result<()> {
        if addr.device_id == 0 {
            return Ok(());
        }
        let device_id = self.current_device_id()?;
        if addr.device_id != device_id {
            return Err(Error::InvalidImage(format!(
                "upper chunk uses device {}, expected {device_id}",
                addr.device_id
            )));
        }
        let blob_writer = self
            .blob_writer
            .as_ref()
            .ok_or_else(|| Error::InvalidImage("upper blob writer is missing".to_string()))?;
        if !blob_writer.try_resolve_chunk_addr_for_device(addr, device_id)? {
            self.pending_blob_chunks.push((inode_index, chunk_index));
        }
        Ok(())
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::InvalidParameter(
                "incremental writer cannot continue after a failed seal".to_string(),
            ));
        }
        Ok(())
    }

    fn sort_directory_children(&mut self) {
        for inode in &mut self.inodes {
            if let InodeData::Directory { children, .. } = &mut inode.data {
                children.sort_by(|left, right| left.name.cmp(&right.name));
            }
        }
    }

    fn clipped_write_len(
        &self,
        inode_index: usize,
        offset: u64,
        source_len: usize,
    ) -> Result<Option<usize>> {
        let file_size = self.current_file_size(inode_index);
        if offset >= file_size {
            return Ok(None);
        }
        Ok(Some(
            source_len.min(
                usize::try_from(file_size - offset)
                    .map_err(|err| Error::Overflow(format!("write range exceeds usize: {err}")))?,
            ),
        ))
    }

    fn chunk_write_geometry(
        &self,
        inode_index: usize,
        offset: u64,
        written: usize,
    ) -> Result<(usize, usize, usize)> {
        let file_pos = offset
            .checked_add(written as u64)
            .ok_or_else(|| Error::Overflow("write offset overflow".to_string()))?;
        let chunk_size = self.chunk_size as u64;
        let chunk_index = usize::try_from(file_pos / chunk_size)
            .map_err(|err| Error::Overflow(format!("chunk index exceeds usize: {err}")))?;
        let chunk_off = usize::try_from(file_pos % chunk_size)
            .map_err(|err| Error::Overflow(format!("chunk offset exceeds usize: {err}")))?;
        let logical_chunk_len = self.logical_chunk_len(inode_index, chunk_index)?;
        Ok((chunk_index, chunk_off, logical_chunk_len))
    }

    fn current_file_size(&self, inode_index: usize) -> u64 {
        self.overlay
            .get(&inode_index)
            .and_then(|overlay| overlay.replace.as_ref().map(|data| data.len() as u64))
            .unwrap_or(self.inodes[inode_index].size)
    }

    fn logical_chunk_len(&self, inode_index: usize, chunk_index: usize) -> Result<usize> {
        let file_size = self.current_file_size(inode_index);
        let chunk_size = self.chunk_size as u64;
        let chunk_count = file_size.div_ceil(chunk_size) as usize;
        if chunk_index >= chunk_count {
            return Err(Error::InvalidParameter(format!(
                "chunk index {chunk_index} out of range {chunk_count}"
            )));
        }
        let chunk_start = (chunk_index as u64)
            .checked_mul(chunk_size)
            .ok_or_else(|| Error::Overflow("chunk start overflow".to_string()))?;
        usize::try_from((file_size - chunk_start).min(chunk_size))
            .map_err(|err| Error::Overflow(format!("chunk length exceeds usize: {err}")))
    }

    fn validate_inode_chunk_size(&self, inode_index: usize, path: &Path) -> Result<()> {
        let InodeData::RegularFile {
            chunk_size_bits, ..
        } = &self.inodes[inode_index].data
        else {
            unreachable!();
        };
        if *chunk_size_bits != self.chunk_size.trailing_zeros() {
            return Err(Error::InvalidParameter(format!(
                "chunk size {} does not match parent file {} chunk size {}",
                self.chunk_size,
                path.display(),
                1u64 << *chunk_size_bits
            )));
        }
        Ok(())
    }

    fn resolve_regular_inode_for_write(&self, path: &Path) -> Result<usize> {
        let index = self.regular_inode_index(path)?;
        self.validate_inode_chunk_size(index, path)?;
        Ok(index)
    }

    fn regular_inode_index(&self, path: &Path) -> Result<usize> {
        let key = normalize_relative_path(path)?;
        self.regular_inode_index_by_key(&key, path)
    }

    fn regular_inode_index_by_key(&self, key: &Path, display_path: &Path) -> Result<usize> {
        let index = *self.path_index.get(key).ok_or_else(|| {
            Error::NotFound(format!(
                "path not found in writer filesystem: {}",
                display_path.display()
            ))
        })?;
        if !matches!(self.inodes[index].data, InodeData::RegularFile { .. }) {
            return Err(Error::InvalidParameter(format!(
                "path is not a regular file: {}",
                display_path.display()
            )));
        }
        Ok(index)
    }
}

fn read_exact_from_file_at(file: &File, mut offset: u64, mut data: &mut [u8]) -> Result<()> {
    while !data.is_empty() {
        let read = file
            .read_at(data, offset)
            .context("failed to read source file range")?;
        if read == 0 {
            return Err(Error::InvalidImage(
                "short read from source file range".to_string(),
            ));
        }
        let tmp = data;
        data = &mut tmp[read..];
        offset += read as u64;
    }
    Ok(())
}

fn digest_named_blob_path(blob_dir: &Path, full_blob_digest: &[u8; EROFS_BLOB_ID_SIZE]) -> PathBuf {
    blob_dir.join(hex_string(full_blob_digest))
}

fn finalize_digest_named_blob(
    temp_blob_path: &Path,
    blob_dir: &Path,
    full_blob_digest: &[u8; EROFS_BLOB_ID_SIZE],
) -> Result<PathBuf> {
    let full_blob_path = digest_named_blob_path(blob_dir, full_blob_digest);
    if full_blob_path.exists() {
        fs::remove_file(temp_blob_path).with_context(|| {
            format!(
                "failed to remove temporary blob after dedup hit: {}",
                temp_blob_path.display()
            )
        })?;
        return Ok(full_blob_path);
    }

    fs::rename(temp_blob_path, &full_blob_path).with_context(|| {
        format!(
            "failed to rename blob {} to {}",
            temp_blob_path.display(),
            full_blob_path.display()
        )
    })?;
    Ok(full_blob_path)
}

fn finish_upper_blob<W: Write>(blob_writer: BlobWriter<W>) -> Result<FinishedUpperBlob> {
    let blob_blocks = blob_writer.total_blocks();
    let compressed_data_size = blob_writer.data_size();
    let (blob_file, full_blob_hasher, blob_metadata) = blob_writer.into_incremental_parts()?;
    let full_blob_hasher = full_blob_hasher
        .ok_or_else(|| Error::InvalidImage("upper blob data hashing is disabled".to_string()))?;
    let mut blob_writer_stream =
        HashingWriter::new(BufWriter::new(blob_file), Some(full_blob_hasher));
    blob::finish_full_blob(
        &mut blob_writer_stream,
        compressed_data_size,
        &[],
        Some(&blob_metadata),
    )?;
    let full_blob_digest = blob_writer_stream
        .finish()
        .context("failed to flush upper blob")?
        .expect("upper blob hashing is enabled");

    Ok(FinishedUpperBlob {
        full_blob_digest,
        blob_metadata,
        blob_blocks,
    })
}

struct ParentTreeContext {
    path_index: HashMap<PathBuf, usize>,
    nids: Vec<u64>,
}

impl ParentTreeContext {
    fn new() -> Self {
        Self {
            path_index: HashMap::new(),
            nids: Vec::new(),
        }
    }
}

struct ParentTreeNode<'a> {
    reader: &'a ErofsReader,
    epoch: u64,
    nid: u64,
    path: PathBuf,
}

impl<'a> ParentTreeNode<'a> {
    fn new(reader: &'a ErofsReader, epoch: u64, nid: u64, path: PathBuf) -> Self {
        Self {
            reader,
            epoch,
            nid,
            path,
        }
    }

    fn read_xattrs(&self, inode: &ErofsInode<'_>) -> Result<Vec<XattrEntry>> {
        let mut entries = Vec::new();
        for (name, value) in self
            .reader
            .read_xattrs(self.nid, inode)
            .context("failed to read xattrs")?
        {
            let (name_index, suffix) = erofs_xattr_name_split(&name).ok_or_else(|| {
                Error::Unsupported(format!(
                    "unsupported parent xattr name: {}",
                    String::from_utf8_lossy(&name)
                ))
            })?;
            entries.push(XattrEntry {
                name_index,
                suffix: suffix.to_vec(),
                value,
            });
        }
        Ok(entries)
    }
}

impl<'a> TreeNode<ParentTreeContext> for ParentTreeNode<'a> {
    type LinkKey = u64;

    fn attrs(&mut self) -> Result<NodeAttrs> {
        let inode = self
            .reader
            .inode(self.nid)
            .context("failed to read parent inode")?;
        Ok(NodeAttrs {
            mode: inode.mode(),
            uid: inode.uid(),
            gid: inode.gid(),
            size: inode.size(),
            mtime: inode.mtime(self.epoch),
            mtime_nsec: inode.effective_mtime_nsec(self.reader.superblock().fixed_nsec()),
            nlink: inode.nlink(),
            xattrs: self.read_xattrs(&inode)?,
        })
    }

    fn link_key(&mut self) -> Result<Option<Self::LinkKey>> {
        let inode = self
            .reader
            .inode(self.nid)
            .context("failed to read parent inode")?;
        Ok(
            (mode_to_erofs_file_type(inode.mode()) != EROFS_FT_DIR && inode.nlink() > 1)
                .then_some(self.nid),
        )
    }

    fn children(&mut self, _ctx: &mut ParentTreeContext) -> Result<Option<NamedChildren<Self>>> {
        let inode = self
            .reader
            .inode(self.nid)
            .context("failed to read parent inode")?;
        if mode_to_erofs_file_type(inode.mode()) != EROFS_FT_DIR {
            return Ok(None);
        }

        let mut children = Vec::new();
        for RawDirEntry {
            nid: child_nid,
            name,
            ..
        } in self
            .reader
            .read_dir(self.nid, &inode)
            .context("failed to read parent directory")?
        {
            if name == b"." || name == b".." {
                continue;
            }
            let child_path = if self.path.as_os_str().is_empty() {
                PathBuf::from(std::ffi::OsString::from_vec(name.clone()))
            } else {
                self.path.join(std::ffi::OsString::from_vec(name.clone()))
            };
            children.push((
                name,
                ParentTreeNode::new(self.reader, self.epoch, child_nid, child_path),
            ));
        }
        children.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(Some(children))
    }

    fn leaf_data(&mut self, _ctx: &mut ParentTreeContext) -> Result<InodeData> {
        let inode = self
            .reader
            .inode(self.nid)
            .context("failed to read parent inode")?;
        match mode_to_erofs_file_type(inode.mode()) {
            EROFS_FT_REG_FILE => {
                if inode.size() == 0 {
                    return Ok(InodeData::RegularFile {
                        chunk_index_entries: Vec::new(),
                        chunk_size_bits: self.reader.chunk_bits(&inode),
                    });
                }
                if inode.data_layout() != EROFS_INODE_CHUNK_BASED {
                    return Err(Error::Unsupported(format!(
                        "incremental writer only supports chunk-based regular files: {}",
                        self.path.display()
                    )));
                }
                Ok(InodeData::RegularFile {
                    chunk_index_entries: self
                        .reader
                        .read_chunk_index_entries(self.nid, &inode)
                        .context("failed to read parent chunk indexes")?,
                    chunk_size_bits: self.reader.chunk_bits(&inode),
                })
            }
            EROFS_FT_SYMLINK => Ok(InodeData::Symlink {
                target: self
                    .reader
                    .read_symlink(self.nid, &inode)
                    .context("failed to read parent symlink")?,
                startblk: 0,
            }),
            EROFS_FT_CHRDEV | EROFS_FT_BLKDEV => Ok(InodeData::Device { rdev: inode.rdev() }),
            EROFS_FT_FIFO | EROFS_FT_SOCK => Ok(InodeData::FifoOrSocket),
            _ => Err(Error::Unsupported(format!(
                "unsupported inode type for {}",
                self.path.display()
            ))),
        }
    }

    fn mapped_index(&mut self, ctx: &mut ParentTreeContext, index: usize) -> Result<()> {
        ctx.path_index.insert(self.path.clone(), index);
        if ctx.nids.len() <= index {
            ctx.nids.resize(index + 1, 0);
        }
        ctx.nids[index] = self.nid;
        Ok(())
    }
}

fn normalize_relative_path(path: &Path) -> Result<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => normalized.push(name),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::InvalidParameter(format!(
                    "path must be relative and must not contain parent components: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(normalized)
}
