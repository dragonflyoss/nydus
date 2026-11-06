mod compact;

pub(crate) use compact::RepackBackend;
pub use compact::RepackResult;

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, ErrorKind, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::FileExt;
use std::path::{Component, Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;

use crate::build::blob_chunk::{
    is_zero, validate_chunk_group_min_size, validate_chunk_size, BlobLayout, BlobWriter,
    DEFAULT_CHUNK_GROUP_MIN_SIZE,
};
use crate::build::bootstrap::render_bootstrap_remapped;
use crate::build::inode::{
    flatten_tree, ChildRef, InodeData, InodeInfo, NamedChildren, NodeAttrs, TreeNode,
};
use crate::build::{save_blob_metadata_sidecar, HashingWriter};
use crate::reader::{parse_prefetch_blobs_value, RawDirEntry};
use crate::ErofsReader;
use nydus_error::{Context, Error, Result};
use nydus_format::blob::{self, BlobMetadata, BlobMetadataCompressor, BlobMetadataDigester};
use nydus_format::erofs::{
    ErofsChunkAddr, ErofsDeviceSlot, ErofsInode, ErofsInodeExtended, XattrEntry,
    EROFS_BLOB_ID_SIZE, EROFS_FT_BLKDEV, EROFS_FT_CHRDEV, EROFS_FT_DIR, EROFS_FT_FIFO,
    EROFS_FT_REG_FILE, EROFS_FT_SOCK, EROFS_FT_SYMLINK, EROFS_INODE_CHUNK_BASED, EROFS_NULL_ADDR,
};

// Replacement buffers describe a prefix; truncate extension stays sparse.
fn replacement_chunk(data: &[u8], start: usize, len: usize) -> std::borrow::Cow<'_, [u8]> {
    if start <= data.len() && len <= data.len() - start {
        return std::borrow::Cow::Borrowed(&data[start..start + len]);
    }
    let mut chunk = vec![0; len];
    if start < data.len() {
        chunk[..data.len() - start].copy_from_slice(&data[start..]);
    }
    std::borrow::Cow::Owned(chunk)
}

struct FinishedUpperBlob {
    full_blob_digest: [u8; EROFS_BLOB_ID_SIZE],
    blob_metadata: BlobMetadata,
    blob_blocks: u64,
}

pub struct IncrementalWriterOptions {
    /// Directory where commit writes `image.boot` and, when needed, a
    /// digest-named upper blob with its `<digest>.blob.meta` sidecar. A
    /// parentless image also keeps an empty blob so it has a backing device.
    pub output_dir: PathBuf,
    /// File chunk size. Defaults to 2 MiB in [`Self::new`].
    pub chunk_size: u32,
    /// Minimum chunk-group span. Defaults to 2 MiB in [`Self::new`].
    pub chunk_group_min_size: u32,
    /// Compression algorithm for chunk-group payloads. Defaults to Zstd in
    /// [`Self::new`].
    pub compressor: BlobMetadataCompressor,
    /// Per-group digest algorithm recorded in the blob metadata. Defaults to
    /// BLAKE3 in [`Self::new`].
    pub digester: Option<BlobMetadataDigester>,
    /// Remove unreferenced parent devices on commit. Disabled by default.
    pub prune: bool,
}

impl IncrementalWriterOptions {
    /// Create writer options using the same geometry and algorithms as
    /// `nydus build` defaults.
    pub fn new(output_dir: PathBuf) -> Self {
        Self {
            output_dir,
            chunk_size: BlobMetadata::DEFAULT_CHUNK_SIZE,
            chunk_group_min_size: DEFAULT_CHUNK_GROUP_MIN_SIZE,
            compressor: BlobMetadataCompressor::Zstd,
            digester: Some(BlobMetadataDigester::Blake3),
            prune: false,
        }
    }

    fn validate(&self) -> Result<()> {
        validate_chunk_size(self.chunk_size)?;
        validate_chunk_group_min_size(self.chunk_group_min_size)
    }
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

impl ChunkOverlay {
    fn truncate(&mut self, size: usize) -> bool {
        if let Some(source) = &mut self.source {
            source.truncate(size);
        }
        self.patches.retain_mut(|patch| {
            if patch.offset >= size {
                return false;
            }
            patch.source.truncate(size - patch.offset);
            true
        });
        self.source.is_some() || !self.patches.is_empty()
    }
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

impl DirtyChunk {
    fn truncate(&mut self, size: usize) {
        match self {
            Self::Owned(data) => data.truncate(size),
            Self::FileRange { len, .. } | Self::MemoryRange { len, .. } => *len = (*len).min(size),
        }
    }

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
/// [`commit`](Self::commit) materializes all staged updates into at most one
/// upper data blob and renders the final bootstrap.
pub struct IncrementalWriter {
    inodes: Vec<InodeInfo>,
    path_index: HashMap<PathBuf, usize>,
    parent_nids: Vec<u64>,
    parent_reader: Option<Arc<ErofsReader>>,
    overlay: BTreeMap<usize, FileOverlay>,
    device_slots: Vec<ErofsDeviceSlot>,
    has_changes: bool,
    blob_writer: Option<BlobWriter<File>>,
    // Inode/chunk indexes whose small packed group is still open. Full-slot
    // chunks are resolved immediately and never enter this list.
    pending_blob_chunks: Vec<(usize, usize)>,
    output_dir: PathBuf,
    upper_blob_temp_path: Option<PathBuf>,
    compact_artifacts: Option<compact::CompactArtifacts>,
    chunk_size: u32,
    chunk_group_min_size: u32,
    compressor: BlobMetadataCompressor,
    digester: Option<BlobMetadataDigester>,
    prune: bool,
    epoch: u64,
    uuid: [u8; 16],
}

/// A resolved regular file in an [`IncrementalWriter`].
///
/// The handle keeps the inode index created by [`IncrementalWriter::create_file`]
/// or resolved by [`IncrementalWriter::open_file`], so repeated offset writes
/// avoid path normalization and `path_index` lookups. It borrows the writer
/// mutably, preserving the writer's single-writer ordering semantics.
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
    /// `ptr..ptr+len` must remain readable and stable until `commit` consumes
    /// the staged range, unless a later full-chunk write clears the whole chunk
    /// overlay first. A partially overlapping write does not release this
    /// requirement. The memory must not be mutated concurrently while it is
    /// consumed.
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
        options.validate()?;
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
            has_changes: false,
            blob_writer: None,
            pending_blob_chunks: Vec::new(),
            output_dir: options.output_dir,
            upper_blob_temp_path: None,
            compact_artifacts: None,
            chunk_size: options.chunk_size,
            chunk_group_min_size: options.chunk_group_min_size,
            compressor: options.compressor,
            digester: options.digester,
            prune: options.prune,
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
        options.validate()?;
        let reader = ErofsReader::open_metadata_only(parent_bootstrap).with_context(|| {
            format!(
                "failed to open parent bootstrap: {}",
                parent_bootstrap.display()
            )
        })?;
        Self::from_reader(Arc::new(reader), options, ParentMode::MetadataOnly)
    }

    pub(crate) fn from_parent_reader(
        reader: Arc<ErofsReader>,
        options: IncrementalWriterOptions,
    ) -> Result<Self> {
        options.validate()?;
        Self::from_reader(reader, options, ParentMode::Writer)
    }

    fn from_reader(
        reader: Arc<ErofsReader>,
        options: IncrementalWriterOptions,
        mode: ParentMode,
    ) -> Result<Self> {
        let sb = reader.superblock();
        let epoch = sb.epoch();
        let uuid = sb.uuid;
        let parent_blob_infos = reader
            .blob_infos()
            .context("failed to read parent blob table")?;
        let parent_device_slots: Vec<ErofsDeviceSlot> = parent_blob_infos
            .iter()
            .map(|info| {
                ErofsDeviceSlot::with_blob_id_and_mapped_blkaddr(
                    info.blocks,
                    &info.blob_id,
                    info.mapped_blkaddr,
                )
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let root_nid = sb.root_nid();
        let mut parent_tree = ParentTreeContext::new(mode);
        let inodes = flatten_tree(
            ParentTreeNode::new(reader.as_ref(), epoch, root_nid, PathBuf::new()),
            &mut parent_tree,
        )?;
        if parent_tree.nids.len() != inodes.len() {
            return Err(Error::InvalidImage(
                "parent inode map does not match flattened inode table".to_string(),
            ));
        }
        let path_index = parent_tree.path_index.unwrap_or_default();
        let parent_nids = parent_tree.nids;

        Ok(Self {
            inodes,
            path_index,
            parent_nids,
            parent_reader: matches!(mode, ParentMode::Writer).then_some(reader),
            overlay: BTreeMap::new(),
            device_slots: parent_device_slots,
            has_changes: false,
            blob_writer: None,
            pending_blob_chunks: Vec::new(),
            output_dir: options.output_dir,
            upper_blob_temp_path: None,
            compact_artifacts: matches!(mode, ParentMode::Compact)
                .then(compact::CompactArtifacts::default),
            chunk_size: options.chunk_size,
            chunk_group_min_size: options.chunk_group_min_size,
            compressor: options.compressor,
            digester: options.digester,
            prune: options.prune,
            epoch,
            uuid,
        })
    }

    /// Create a zero-filled regular file with a fixed logical size.
    ///
    /// The parent directory must already exist; creating directories is outside
    /// this API. Use [`truncate_file`](Self::truncate_file) to change the length
    /// later. The returned handle stages writes without resolving `path` again.
    pub fn create_file(
        &mut self,
        path: &Path,
        size: u64,
        options: CreateFileOptions,
    ) -> Result<IncrementalWriterFile<'_>> {
        let key = normalize_relative_path(path)?;
        let inode_index = self.create_file_inode(key, path, size, options)?;
        Ok(IncrementalWriterFile {
            writer: self,
            inode_index,
        })
    }

    fn create_file_inode(
        &mut self,
        key: PathBuf,
        display_path: &Path,
        size: u64,
        options: CreateFileOptions,
    ) -> Result<usize> {
        if key.as_os_str().is_empty() {
            return Err(Error::InvalidParameter(
                "file path must not refer to the root directory".to_string(),
            ));
        }
        if self.path_index.contains_key(&key) {
            return Err(Error::InvalidParameter(format!(
                "path already exists: {}",
                display_path.display()
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
            is_extended: ErofsInodeExtended::is_needed(size, options.uid, options.gid, 1),
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
        Ok(inode_index)
    }

    /// Open a regular file for repeated offset writes.
    ///
    /// This resolves the path once and returns a handle whose write methods skip
    /// path normalization and `path_index` lookups. Whole-file replacement stays
    /// on [`IncrementalWriter::replace_file`] because it is path-oriented and
    /// usually low frequency.
    pub fn open_file(&mut self, path: &Path) -> Result<IncrementalWriterFile<'_>> {
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
    /// `ptr..ptr+len` must remain readable and stable until `commit` consumes
    /// the staged range, unless a later full-chunk write clears the whole chunk
    /// overlay first. A partially overlapping write does not release this
    /// requirement. The memory must not be mutated concurrently while it is
    /// consumed.
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

    /// Set an existing regular file's length, preserving the retained prefix.
    /// Extension reads as zero, including bytes discarded by an earlier truncation.
    /// A non-aligned extension may need a data-capable parent reader to preserve
    /// the previous EOF chunk. Aligned extension and shrinking are metadata-only.
    pub fn truncate_file(&mut self, path: &Path, size: u64) -> Result<()> {
        let key = normalize_relative_path(path)?;
        let index = self.regular_inode_index_by_key(&key, path)?;
        self.validate_inode_chunk_size(index, path)?;
        let old_size = self.current_file_size(index);
        if size == old_size {
            return Ok(());
        }
        let chunk_size = u64::from(self.chunk_size);
        let count = usize::try_from(size.div_ceil(chunk_size))
            .map_err(|err| Error::Overflow(format!("file chunk count exceeds usize: {err}")))?;

        // Read the old writer view before changing EOF. Only this boundary chunk
        // needs copying; aligned growth and truncate-to-zero never read RAM/data.
        let tail = if size > old_size && old_size % chunk_size != 0 {
            let chunk_index = (old_size / chunk_size) as usize;
            let overlay = self.overlay.get(&index);
            let has_staged_chunk =
                overlay.is_some_and(|file| file.chunks.contains_key(&chunk_index));
            let has_base_data = match overlay.and_then(|file| file.replace.as_ref()) {
                Some(data) => chunk_index as u64 * chunk_size < data.len() as u64,
                None => self.chunk_has_parent_data(index, chunk_index)?,
            };
            if has_staged_chunk || has_base_data {
                let new_len = (size - chunk_index as u64 * chunk_size).min(chunk_size) as usize;
                let data = self.current_chunk_data(index, chunk_index, new_len)?;
                Some((chunk_index, data))
            } else {
                None
            }
        } else {
            None
        };

        let inode = &mut self.inodes[index];
        let InodeData::RegularFile {
            chunk_index_entries,
            ..
        } = &mut inode.data
        else {
            unreachable!()
        };
        chunk_index_entries
            .try_reserve(count.saturating_sub(chunk_index_entries.len()))
            .map_err(|err| Error::Overflow(format!("file chunk allocation failed: {err}")))?;
        chunk_index_entries.resize(
            count,
            ErofsChunkAddr {
                blkaddr: EROFS_NULL_ADDR,
                device_id: 0,
            },
        );
        inode.size = size;
        inode.is_extended |=
            ErofsInodeExtended::is_needed(size, inode.uid, inode.gid, u64::from(inode.nlink));

        if size == 0 {
            self.overlay.remove(&index);
        } else if size < old_size {
            if let Some(overlay) = self.overlay.get_mut(&index) {
                if let Some(data) = &mut overlay.replace {
                    if size < data.len() as u64 {
                        data.truncate(size as usize);
                    }
                }
                overlay.chunks.retain(|&chunk_index, chunk| {
                    if chunk_index >= count {
                        return false;
                    }
                    let len = (size - chunk_index as u64 * chunk_size).min(chunk_size) as usize;
                    chunk.truncate(len)
                });
            }
        }
        if let Some((chunk_index, data)) = tail {
            self.overlay.entry(index).or_default().chunks.insert(
                chunk_index,
                ChunkOverlay {
                    source: Some(DirtyChunk::Owned(data)),
                    patches: Vec::new(),
                },
            );
        }
        self.has_changes = true;
        Ok(())
    }

    /// Replace the whole file contents in the upper image.
    ///
    /// If `path` does not exist, a regular file is created with
    /// [`CreateFileOptions::default`] metadata and a size matching `data`.
    /// Its parent directory must already exist.
    ///
    /// Existing staged chunk updates for the file are cleared. Later chunk or
    /// range writes apply on top of this replacement data before commit.
    pub fn replace_file(&mut self, path: &Path, data: Vec<u8>) -> Result<()> {
        let key = normalize_relative_path(path)?;
        let inode_index = if self.path_index.contains_key(&key) {
            let inode_index = self.regular_inode_index_by_key(&key, path)?;
            self.validate_inode_chunk_size(inode_index, path)?;
            inode_index
        } else {
            let size = u64::try_from(data.len()).map_err(|err| {
                Error::Overflow(format!("replacement file size exceeds u64: {err}"))
            })?;
            self.create_file_inode(key, path, size, CreateFileOptions::default())?
        };
        self.inodes[inode_index].size = data.len() as u64;
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

    /// Materialize staged changes and write the child bootstrap/blob.
    ///
    /// Commit consumes the writer. It fails if no changes were staged, which
    /// avoids creating an upper image that is indistinguishable from the parent
    /// except for empty output artifacts.
    ///
    /// On failure, temporary blobs are removed. Complete digest-named blobs
    /// may remain if writing the sidecar or bootstrap failed; a fresh writer
    /// can reuse them when retrying the same changes.
    pub fn commit(mut self) -> Result<()> {
        self.commit_output()
    }

    fn commit_output(&mut self) -> Result<()> {
        if !self.has_changes {
            return Err(Error::InvalidParameter(
                "incremental writer has no changes to commit".to_string(),
            ));
        }
        fs::create_dir_all(&self.output_dir)?;
        let bootstrap = match self.commit_inner() {
            Ok(bootstrap) => bootstrap,
            Err(err) => {
                self.discard_current_blob();
                return Err(err);
            }
        };
        self.save_bootstrap(&bootstrap)
    }

    // Publish only after all output bytes are ready. Renaming a new inode keeps
    // any open source reader's mmap valid during an in-place compact.
    fn save_bootstrap(&mut self, data: &[u8]) -> Result<()> {
        let path = self.output_dir.join("image.boot");
        let (temp_path, mut file) = self.create_temp_file("bootstrap")?;
        let result = (|| -> Result<()> {
            match fs::metadata(&path) {
                Ok(metadata) => file.set_permissions(metadata.permissions())?,
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(err.into()),
            }
            file.write_all(data).context("write temporary bootstrap")?;
            fs::rename(&temp_path, &path)
                .with_context(|| format!("failed to publish bootstrap: {}", path.display()))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        } else if let Some(artifacts) = &mut self.compact_artifacts {
            artifacts.keep();
        }
        result
    }

    fn publish_blob_artifact(
        &mut self,
        temp: &Path,
        digest: &[u8; EROFS_BLOB_ID_SIZE],
        metadata: &BlobMetadata,
    ) -> Result<()> {
        if let Some(artifacts) = &mut self.compact_artifacts {
            artifacts.publish(temp, &self.output_dir, digest, metadata)?;
        } else {
            let path = finalize_digest_named_blob(temp, &self.output_dir, digest)?;
            save_blob_metadata_sidecar(metadata, &path)?;
        }
        Ok(())
    }

    fn commit_inner(&mut self) -> Result<Vec<u8>> {
        if !self.overlay.is_empty() {
            self.materialize_overlay()?;
        }
        let parent_device_count = self.device_slots.len();
        let keep_empty_blob = self.device_slots.is_empty();
        if keep_empty_blob {
            self.ensure_blob_writer()?;
        }
        self.finish_current_blob(keep_empty_blob)?;
        let device_ids = if self.prune {
            self.prune_parent_devices(parent_device_count)?
        } else {
            None
        };

        self.sort_directory_children();
        render_bootstrap_remapped(
            &mut self.inodes,
            self.epoch,
            &self.device_slots,
            &self.uuid,
            device_ids.as_deref(),
        )
    }

    /// Analyze final chunk metadata; new blob data is already known to be live.
    /// Return a device ID map only when pruning changes the device table.
    fn prune_parent_devices(&mut self, parent_device_count: usize) -> Result<Option<Vec<u16>>> {
        if parent_device_count == 0 {
            return Ok(None);
        }
        // Reuse the liveness markers as the eventual old-to-new ID map.
        let mut device_ids = vec![0u16; self.device_slots.len()];
        device_ids[parent_device_count..].fill(1);
        let mut remaining = parent_device_count;
        let mut mapped = None;
        'inodes: for inode in &self.inodes {
            let InodeData::RegularFile {
                chunk_index_entries,
                ..
            } = &inode.data
            else {
                continue;
            };
            for entry in chunk_index_entries.iter().filter(|entry| !entry.is_hole()) {
                if usize::from(entry.device_id) == parent_device_count + 1
                    && self.device_slots.len() > parent_device_count
                {
                    continue;
                }
                let index = if entry.device_id == 0 {
                    // Only flattened chunks need a sorted address lookup.
                    let ranges = mapped.get_or_insert_with(|| {
                        let mut ranges: Vec<_> = self.device_slots[..parent_device_count]
                            .iter()
                            .enumerate()
                            .filter(|(_, slot)| slot.mapped_blkaddr() != 0)
                            .map(|(index, slot)| (slot.mapped_blkaddr(), slot.blocks(), index))
                            .collect();
                        ranges.sort_unstable_by_key(|range| range.0);
                        ranges
                    });
                    let end = ranges.partition_point(|range| range.0 <= entry.blkaddr);
                    let range = end
                        .checked_sub(1)
                        .and_then(|index| ranges.get(index))
                        .filter(|range| entry.blkaddr - range.0 < range.1)
                        .ok_or_else(|| {
                            Error::InvalidImage(
                                "flattened chunk is outside parent device mappings".to_string(),
                            )
                        })?;
                    range.2
                } else {
                    usize::from(entry.device_id) - 1
                };
                let live = device_ids.get_mut(index).ok_or_else(|| {
                    Error::InvalidImage(format!(
                        "chunk refers to missing device {}",
                        entry.device_id
                    ))
                })?;
                if *live == 0 {
                    *live = 1;
                    remaining -= 1;
                    if remaining == 0 {
                        break 'inodes;
                    }
                }
            }
        }
        if remaining == 0 {
            return Ok(None);
        }

        let mut next_id = 0u16;
        for id in &mut device_ids {
            if *id != 0 {
                next_id += 1;
                *id = next_id;
            }
        }
        // Chunk IDs are remapped while serializing, without rewriting the
        // in-memory chunk table or scanning it a second time.
        let root = &mut self.inodes[0];
        root.xattrs.retain_mut(|entry| {
            if !entry.is_nydus_prefetch_blobs() {
                return true;
            }
            use std::fmt::Write as _;
            let mut value = String::with_capacity(entry.value.len());
            for id in parse_prefetch_blobs_value(&entry.value) {
                let Some(&id) = device_ids.get(usize::from(id) - 1).filter(|id| **id != 0) else {
                    continue;
                };
                if !value.is_empty() {
                    value.push(',');
                }
                write!(&mut value, "{id}").expect("writing to String cannot fail");
            }
            entry.value = value.into_bytes();
            !entry.value.is_empty()
        });
        let mut index = 0;
        self.device_slots.retain(|_| {
            let keep = device_ids[index] != 0;
            index += 1;
            keep
        });
        Ok(Some(device_ids))
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
            .as_ref()
            .ok_or_else(|| Error::InvalidImage("upper blob temp path is missing".to_string()))?;
        let temp_path = temp_path.clone();
        self.publish_blob_artifact(
            &temp_path,
            &finished.full_blob_digest,
            &finished.blob_metadata,
        )?;
        self.upper_blob_temp_path.take();
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
            && self.chunk_has_parent_data(inode_index, chunk_index)?
            && self.parent_reader.is_none()
        {
            return Err(Error::InvalidParameter(
                "partial write requires a data-capable parent reader; use NydusCore::writer"
                    .to_string(),
            ));
        }

        let chunk = self
            .overlay
            .entry(inode_index)
            .or_default()
            .chunks
            .entry(chunk_index)
            .or_default();
        chunk.patches.retain(|patch| {
            let patch_end = patch
                .offset
                .checked_add(patch.source.len())
                .expect("validated chunk patch range");
            offset > patch.offset || end < patch_end
        });
        chunk.patches.push(ChunkPatch { offset, source });
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
        let (blob_path, blob_file) = self.create_temp_file("incremental")?;
        self.blob_writer = Some(BlobWriter::new(
            blob_file,
            self.chunk_size,
            self.compressor,
            self.digester,
            true,
            BlobLayout::ChunkGroups {
                chunk_group_min_size: self.chunk_group_min_size,
            },
        )?);
        self.upper_blob_temp_path = Some(blob_path);
        Ok(())
    }

    fn create_temp_file(&self, kind: &str) -> Result<(PathBuf, File)> {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|err| Error::InvalidParameter(format!("system time before epoch: {err}")))?
            .as_nanos();
        for attempt in 0..1024u16 {
            let path = self.output_dir.join(format!(
                ".nydus-{kind}-{}-{seed}-{attempt}.tmp",
                std::process::id(),
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to create temporary {kind} file: {}", path.display())
                    })
                }
            }
        }
        Err(Error::InvalidParameter(format!(
            "failed to allocate a unique temporary {kind} path"
        )))
    }

    fn write_upper_chunk_addr(&mut self, data: &[u8]) -> Result<ErofsChunkAddr> {
        if is_zero(data) {
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
                if is_zero(source) {
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
        if is_zero(&data) {
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
            let replacement_size = self.inodes[inode_index].size;
            let chunk_count = replacement_size.div_ceil(u64::from(self.chunk_size)) as usize;
            let mut chunk_index_entries = Vec::with_capacity(chunk_count);
            let mut chunks = overlay.chunks;
            for chunk_index in 0..chunk_count {
                let start = chunk_index * self.chunk_size as usize;
                let len = self.logical_chunk_len(inode_index, chunk_index)?;
                let mut addr = match chunks.remove(&chunk_index) {
                    Some(chunk) => {
                        let replacement = if chunk.source.is_none() {
                            Some(replacement_chunk(&data, start, len))
                        } else {
                            None
                        };
                        let source = self.materialize_chunk_overlay(
                            inode_index,
                            chunk_index,
                            replacement,
                            chunk,
                        )?;
                        self.write_upper_source_chunk_addr(source)?
                    }
                    None if start >= data.len() => ErofsChunkAddr {
                        blkaddr: EROFS_NULL_ADDR,
                        device_id: 0,
                    },
                    None => self.write_upper_chunk_addr(&replacement_chunk(&data, start, len))?,
                };
                self.resolve_or_track_blob_chunk(inode_index, chunk_index, &mut addr)?;
                chunk_index_entries.push(addr);
            }
            let inode = &mut self.inodes[inode_index];
            inode.size = replacement_size;
            inode.is_extended |= ErofsInodeExtended::is_needed(
                replacement_size,
                inode.uid,
                inode.gid,
                inode.nlink as u64,
            );
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
        replacement: Option<std::borrow::Cow<'_, [u8]>>,
        chunk: ChunkOverlay,
    ) -> Result<DirtyChunk> {
        if chunk.patches.is_empty() {
            return chunk.source.ok_or_else(|| {
                Error::InvalidImage(format!(
                    "dirty chunk {chunk_index} has neither a source nor patches"
                ))
            });
        }

        let chunk_len = match &replacement {
            Some(data) => data.len(),
            None => self.logical_chunk_len(inode_index, chunk_index)?,
        };
        let mut data = match chunk.source {
            Some(source) => source.into_vec()?,
            None => match replacement {
                Some(data) => data.into_owned(),
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

    fn current_chunk_data(
        &self,
        inode_index: usize,
        chunk_index: usize,
        target_len: usize,
    ) -> Result<Vec<u8>> {
        let len = self.logical_chunk_len(inode_index, chunk_index)?;
        let overlay = self.overlay.get(&inode_index);
        let chunk = overlay.and_then(|file| file.chunks.get(&chunk_index));
        let mut data = vec![0; target_len];
        if let Some(source) = chunk.and_then(|chunk| chunk.source.as_ref()) {
            source.read_into(&mut data[..len])?;
        } else if let Some(replace) = overlay.and_then(|file| file.replace.as_ref()) {
            let start = chunk_index * self.chunk_size as usize;
            let count = replace.len().saturating_sub(start).min(len);
            if count > 0 {
                data[..count].copy_from_slice(&replace[start..start + count]);
            }
        } else {
            self.read_base_chunk_into(inode_index, chunk_index, &mut data[..len])?;
        }
        if let Some(chunk) = chunk {
            for patch in &chunk.patches {
                patch
                    .source
                    .read_into(&mut data[patch.offset..patch.offset + patch.source.len()])?;
            }
        }
        Ok(data)
    }

    fn materialize_base_chunk(
        &self,
        inode_index: usize,
        chunk_index: usize,
        chunk_len: usize,
    ) -> Result<Vec<u8>> {
        let mut data = vec![0; chunk_len];
        self.read_base_chunk_into(inode_index, chunk_index, &mut data)?;
        Ok(data)
    }

    fn read_base_chunk_into(
        &self,
        inode_index: usize,
        chunk_index: usize,
        data: &mut [u8],
    ) -> Result<()> {
        if !self.chunk_has_parent_data(inode_index, chunk_index)? {
            data.fill(0);
            return Ok(());
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
        let chunk_len = data.len();
        let count = reader
            .write_file_data_to(
                nid,
                &inode,
                chunk_start,
                chunk_len as u32,
                &mut &mut data[..],
            )
            .with_context(|| format!("failed to read parent chunk at offset {chunk_start}"))?;
        if count != chunk_len {
            return Err(Error::InvalidImage(format!(
                "short parent chunk read at offset {chunk_start}: got {count}, expected {chunk_len}"
            )));
        }
        Ok(())
    }

    fn chunk_has_parent_data(&self, inode_index: usize, chunk_index: usize) -> Result<bool> {
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
        Ok(addr.blkaddr != EROFS_NULL_ADDR)
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
        self.inodes[inode_index].size
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
    blob_dir.join(hex::encode(full_blob_digest))
}

fn finalize_digest_named_blob(
    temp_blob_path: &Path,
    blob_dir: &Path,
    full_blob_digest: &[u8; EROFS_BLOB_ID_SIZE],
) -> Result<PathBuf> {
    let full_blob_path = digest_named_blob_path(blob_dir, full_blob_digest);
    if full_blob_path.is_file() {
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
    let blob_blocks = blob_writer.total_block_count();
    let compressed_data_size = blob_writer.data_size();
    let (blob_file, full_blob_hasher, blob_metadata) = blob_writer.into_incremental_parts()?;
    let full_blob_hasher = full_blob_hasher
        .ok_or_else(|| Error::InvalidImage("upper blob data hashing is disabled".to_string()))?;
    let mut blob_writer_stream =
        HashingWriter::new(BufWriter::new(blob_file), Some(full_blob_hasher));
    blob::finish_full_blob(
        &mut blob_writer_stream,
        compressed_data_size,
        None,
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

#[derive(Clone, Copy)]
enum ParentMode {
    Writer,
    MetadataOnly,
    Compact,
}

struct ParentTreeContext {
    path_index: Option<HashMap<PathBuf, usize>>,
    nids: Vec<u64>,
}

impl ParentTreeContext {
    fn new(mode: ParentMode) -> Self {
        Self {
            path_index: (!matches!(mode, ParentMode::Compact)).then(HashMap::new),
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
        self.reader
            .read_xattrs(self.nid, inode)
            .context("failed to read xattrs")
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
            mtime_nsec: inode.mtime_nsec(self.reader.superblock().fixed_nsec()),
            nlink: inode.nlink(),
            xattrs: self.read_xattrs(&inode)?,
        })
    }

    fn link_key(&mut self) -> Result<Option<Self::LinkKey>> {
        let inode = self
            .reader
            .inode(self.nid)
            .context("failed to read parent inode")?;
        Ok((inode.file_type() != EROFS_FT_DIR && inode.nlink() > 1).then_some(self.nid))
    }

    fn children(&mut self, ctx: &mut ParentTreeContext) -> Result<Option<NamedChildren<Self>>> {
        let inode = self
            .reader
            .inode(self.nid)
            .context("failed to read parent inode")?;
        if inode.file_type() != EROFS_FT_DIR {
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
            // Compact uses inode IDs, not path lookup. Keep an allocation-free
            // empty path instead of cloning names and joining every ancestor.
            let child_path = if ctx.path_index.is_none() {
                PathBuf::new()
            } else if self.path.as_os_str().is_empty() {
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
        match inode.file_type() {
            EROFS_FT_REG_FILE => {
                if inode.size() == 0 {
                    return Ok(InodeData::RegularFile {
                        chunk_index_entries: Vec::new(),
                        chunk_size_bits: self.reader.chunk_bits(&inode),
                    });
                }
                if inode.data_layout() != EROFS_INODE_CHUNK_BASED {
                    return Err(Error::Unsupported(format!(
                        "incremental writer only supports chunk-based regular files: {} (inode {})",
                        self.path.display(),
                        self.nid
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
                "unsupported inode type for {} (inode {})",
                self.path.display(),
                self.nid
            ))),
        }
    }

    fn mapped_index(&mut self, ctx: &mut ParentTreeContext, index: usize) -> Result<()> {
        if let Some(paths) = &mut ctx.path_index {
            paths.insert(std::mem::take(&mut self.path), index);
        }
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

#[cfg(test)]
mod prune_tests {
    use super::*;

    #[test]
    fn parent_paths_are_built_only_for_path_indexed_modes() {
        let temp = tempfile::tempdir().unwrap();
        let mut writer =
            IncrementalWriter::create(IncrementalWriterOptions::new(temp.path().to_path_buf()))
                .unwrap();
        writer
            .replace_file(Path::new("data"), b"payload".to_vec())
            .unwrap();
        writer.commit().unwrap();
        let reader = ErofsReader::open_metadata_only(&temp.path().join("image.boot")).unwrap();
        for mode in [
            ParentMode::Compact,
            ParentMode::Writer,
            ParentMode::MetadataOnly,
        ] {
            let mut context = ParentTreeContext::new(mode);
            let mut root = ParentTreeNode::new(
                &reader,
                reader.superblock().epoch(),
                reader.superblock().root_nid(),
                PathBuf::from("prefix"),
            );
            let children = root.children(&mut context).unwrap().unwrap();
            assert_eq!(children.len(), 1);
            assert_eq!(children[0].0, b"data");
            assert_eq!(
                children[0].1.path,
                if matches!(mode, ParentMode::Compact) {
                    PathBuf::new()
                } else {
                    PathBuf::from("prefix/data")
                }
            );
        }
    }

    #[test]
    fn prune_remaps_prefetch_and_chunk_ids_only_when_serializing() {
        let temp = tempfile::tempdir().unwrap();
        let mut writer =
            IncrementalWriter::create(IncrementalWriterOptions::new(temp.path().to_path_buf()))
                .unwrap();
        writer
            .create_file(Path::new("a"), 1, CreateFileOptions::default())
            .unwrap();
        writer.device_slots = (1..=3)
            .map(|value| ErofsDeviceSlot::with_blob_id(1, &[value; EROFS_BLOB_ID_SIZE]).unwrap())
            .collect();
        let index = *writer.path_index.get(Path::new("a")).unwrap();
        let InodeData::RegularFile {
            chunk_index_entries,
            ..
        } = &mut writer.inodes[index].data
        else {
            unreachable!()
        };
        chunk_index_entries[0] = ErofsChunkAddr {
            device_id: 2,
            blkaddr: 0,
        };
        crate::build::inode::set_root_prefetch_blobs_xattr(&mut writer.inodes[0], &[2, 1]).unwrap();
        let ids = writer.prune_parent_devices(2).unwrap().unwrap();
        assert_eq!(ids, vec![0, 1, 2]);
        assert_eq!(writer.device_slots.len(), 2);
        let InodeData::RegularFile {
            chunk_index_entries,
            ..
        } = &writer.inodes[index].data
        else {
            unreachable!()
        };
        assert_eq!(chunk_index_entries[0].device_id, 2);
        let bootstrap = render_bootstrap_remapped(
            &mut writer.inodes,
            writer.epoch,
            &writer.device_slots,
            &writer.uuid,
            Some(&ids),
        )
        .unwrap();
        let path = temp.path().join("pruned.boot");
        fs::write(&path, bootstrap).unwrap();
        let reader = ErofsReader::open_metadata_only(&path).unwrap();
        assert_eq!(reader.read_prefetch_order(), vec![1]);
        let nid = writer.inodes[index].nid;
        let inode = reader.inode(nid).unwrap();
        assert_eq!(
            reader.read_chunk_index_entries(nid, &inode).unwrap()[0].device_id,
            1
        );
    }
}

#[cfg(test)]
mod truncate_tests {
    use super::*;
    use nydus_backend::Local;
    const FILE: &str = "memory.bin";

    fn options(dir: &Path) -> IncrementalWriterOptions {
        let mut options = IncrementalWriterOptions::new(dir.to_path_buf());
        options.chunk_size = 4096;
        options
    }

    fn reader(dir: &Path) -> Arc<ErofsReader> {
        Arc::new(
            ErofsReader::open_bootstrap(
                &dir.join("image.boot"),
                Arc::new(Local::new(
                    dir.to_path_buf(),
                    Arc::new(nydus_telemetry::metrics::Metrics::new()),
                )),
                Some(&dir.join("cache")),
                None,
                nydus_storage::cache::CacheOptions::default(),
            )
            .unwrap(),
        )
    }

    fn contents(image: &ErofsReader) -> Vec<u8> {
        let root = image.superblock().root_nid();
        let nid = image
            .lookup_dir_entry(root, &image.inode(root).unwrap(), FILE.as_bytes())
            .unwrap()
            .unwrap();
        let inode = image.inode(nid).unwrap();
        image
            .read_file_data(nid, &inode, 0, inode.size() as u32)
            .unwrap()
    }

    fn seed(dir: &Path, data: &[u8]) -> Arc<ErofsReader> {
        let mut writer = IncrementalWriter::create(options(dir)).unwrap();
        writer.replace_file(Path::new(FILE), data.to_vec()).unwrap();
        writer.commit().unwrap();
        reader(dir)
    }

    fn pattern(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i % 251 + 1) as u8).collect()
    }

    #[test]
    fn truncate_aligned_growth_inherits_chunks_and_zero_extends() {
        let root = tempfile::tempdir().unwrap();
        let initial = pattern(8192);
        let parent = seed(root.path(), &initial);
        let mut writer = IncrementalWriter::open_metadata_only(
            &root.path().join("image.boot"),
            options(root.path()),
        )
        .unwrap();
        let index = writer
            .regular_inode_index_by_key(Path::new(FILE), Path::new(FILE))
            .unwrap();
        let refs = match &writer.inodes[index].data {
            InodeData::RegularFile {
                chunk_index_entries,
                ..
            } => chunk_index_entries
                .iter()
                .map(|v| (v.device_id, v.blkaddr))
                .collect::<Vec<_>>(),
            _ => unreachable!(),
        };
        writer.truncate_file(Path::new(FILE), 12288).unwrap();
        let InodeData::RegularFile {
            chunk_index_entries,
            ..
        } = &writer.inodes[index].data
        else {
            unreachable!()
        };
        assert_eq!(
            refs,
            chunk_index_entries[..2]
                .iter()
                .map(|v| (v.device_id, v.blkaddr))
                .collect::<Vec<_>>()
        );
        assert_eq!(chunk_index_entries[2].blkaddr, EROFS_NULL_ADDR);
        writer.commit().unwrap();
        let mut expected = initial.clone();
        expected.resize(12288, 0);
        assert_eq!(contents(&reader(root.path())), expected);
        assert_eq!(contents(&parent), initial);
    }

    #[test]
    fn truncate_repeated_aligned_growth_preserves_staged_source_and_patches() {
        let root = tempfile::tempdir().unwrap();
        let mut writer = IncrementalWriter::create(options(root.path())).unwrap();
        writer.replace_file(Path::new(FILE), vec![7; 8192]).unwrap();
        writer
            .write_at_owned(Path::new(FILE), 0, vec![3; 4096])
            .unwrap();
        writer.write_at(Path::new(FILE), 100, &[5; 20]).unwrap();
        let index = writer.path_index[Path::new(FILE)];
        let source_ptr = match writer.overlay[&index].chunks[&0].source.as_ref().unwrap() {
            DirtyChunk::Owned(data) => data.as_ptr(),
            _ => unreachable!(),
        };
        for chunks in 3..20 {
            writer
                .truncate_file(Path::new(FILE), chunks * 4096)
                .unwrap();
        }
        let chunk = &writer.overlay[&index].chunks[&0];
        match chunk.source.as_ref().unwrap() {
            DirtyChunk::Owned(data) => assert_eq!(data.as_ptr(), source_ptr),
            _ => unreachable!(),
        }
        assert_eq!(chunk.patches.len(), 1);
        assert_eq!(chunk.patches[0].source.len(), 20);
        assert_eq!(writer.overlay[&index].replace.as_ref().unwrap().len(), 8192);
        writer.commit().unwrap();
        let mut expected = vec![7; 8192];
        expected[..4096].fill(3);
        expected[100..120].fill(5);
        expected.resize(19 * 4096, 0);
        assert_eq!(contents(&reader(root.path())), expected);
    }

    #[test]
    fn truncate_sparse_replacement_with_overriding_source_and_patches() {
        let root = tempfile::tempdir().unwrap();
        let mut writer = IncrementalWriter::create(options(root.path())).unwrap();
        writer.replace_file(Path::new(FILE), vec![7; 1]).unwrap();
        writer.truncate_file(Path::new(FILE), 12288).unwrap();
        // Sources override both a padded replacement chunk and an entirely sparse chunk.
        writer
            .write_at_owned(Path::new(FILE), 0, vec![3; 4096])
            .unwrap();
        writer
            .write_at_owned(Path::new(FILE), 8192, vec![4; 4096])
            .unwrap();
        writer.write_at(Path::new(FILE), 100, &[5; 20]).unwrap();
        writer.write_at(Path::new(FILE), 8200, &[6; 20]).unwrap();
        // A patch without a source still needs a zero-padded replacement base.
        writer.write_at(Path::new(FILE), 5000, &[8; 20]).unwrap();
        writer.commit().unwrap();
        let mut expected = vec![0; 12288];
        expected[..4096].fill(3);
        expected[8192..].fill(4);
        expected[100..120].fill(5);
        expected[8200..8220].fill(6);
        expected[5000..5020].fill(8);
        assert_eq!(contents(&reader(root.path())), expected);
    }

    #[test]
    fn truncate_shrink_and_regrow_do_not_resurrect_parent_bytes() {
        for length in [0usize, 1, 4095, 4096, 4097, 5000, 8191] {
            let root = tempfile::tempdir().unwrap();
            let initial = pattern(8192);
            let parent = seed(root.path(), &initial);
            let mut writer =
                IncrementalWriter::from_parent_reader(parent, options(root.path())).unwrap();
            writer
                .truncate_file(Path::new(FILE), length as u64)
                .unwrap();
            writer.truncate_file(Path::new(FILE), 10003).unwrap();
            writer.commit().unwrap();
            let mut expected = initial[..length].to_vec();
            expected.resize(10003, 0);
            assert_eq!(contents(&reader(root.path())), expected, "EOF={length}");
        }
    }

    #[test]
    fn truncate_committed_partial_tail_then_extend() {
        let root = tempfile::tempdir().unwrap();
        let initial = pattern(8192);
        seed(root.path(), &initial);
        let mut writer = IncrementalWriter::open_metadata_only(
            &root.path().join("image.boot"),
            options(root.path()),
        )
        .unwrap();
        writer.truncate_file(Path::new(FILE), 5000).unwrap();
        writer.commit().unwrap();
        let parent = reader(root.path());
        assert_eq!(contents(&parent), initial[..5000]);
        let mut writer =
            IncrementalWriter::from_parent_reader(parent, options(root.path())).unwrap();
        writer.truncate_file(Path::new(FILE), 8192).unwrap();
        writer.commit().unwrap();
        let mut expected = initial[..5000].to_vec();
        expected.resize(8192, 0);
        assert_eq!(contents(&reader(root.path())), expected);
    }

    #[test]
    fn truncate_partial_growth_reads_staged_patches_and_clips_truncated_patches() {
        let root = tempfile::tempdir().unwrap();
        let mut expected = pattern(8192);
        let parent = seed(root.path(), &expected);
        let mut writer =
            IncrementalWriter::from_parent_reader(parent, options(root.path())).unwrap();
        writer.write_at(Path::new(FILE), 4100, &[9; 500]).unwrap();
        expected[4100..4600].fill(9);
        writer.write_at(Path::new(FILE), 6800, &[7; 1000]).unwrap();
        writer.truncate_file(Path::new(FILE), 4300).unwrap();
        expected.truncate(4300);
        writer.truncate_file(Path::new(FILE), 8000).unwrap();
        expected.resize(8000, 0);
        writer.write_at(Path::new(FILE), 4600, &[3; 100]).unwrap();
        expected[4600..4700].fill(3);
        writer.commit().unwrap();
        assert_eq!(contents(&reader(root.path())), expected);
    }

    #[test]
    fn truncate_discards_an_empty_partial_chunk_overlay() {
        let root = tempfile::tempdir().unwrap();
        let initial = pattern(8192);
        let parent = seed(root.path(), &initial);
        let mut writer =
            IncrementalWriter::from_parent_reader(parent, options(root.path())).unwrap();
        writer.write_at(Path::new(FILE), 4100, &[9; 10]).unwrap();
        writer.truncate_file(Path::new(FILE), 4097).unwrap();
        writer.commit().unwrap();
        assert_eq!(contents(&reader(root.path())), initial[..4097]);
    }

    #[test]
    fn truncate_owned_file_and_borrowed_memory_sources() {
        for source in ["owned", "file", "memory"] {
            let root = tempfile::tempdir().unwrap();
            let data = pattern(8192);
            let mut writer = IncrementalWriter::create(options(root.path())).unwrap();
            writer
                .create_file(Path::new(FILE), 8192, CreateFileOptions::default())
                .unwrap();
            match source {
                "owned" => {
                    writer
                        .write_at_owned(Path::new(FILE), 0, data[..4096].to_vec())
                        .unwrap();
                    writer
                        .write_at_owned(Path::new(FILE), 4096, data[4096..].to_vec())
                        .unwrap();
                }
                "file" => {
                    let path = root.path().join("source");
                    fs::write(&path, &data).unwrap();
                    writer
                        .write_file_range(
                            Path::new(FILE),
                            0,
                            Arc::new(File::open(path).unwrap()),
                            0,
                            8192,
                        )
                        .unwrap();
                }
                "memory" => unsafe {
                    writer
                        .write_memory_range(
                            Path::new(FILE),
                            0,
                            NonNull::new(data.as_ptr() as *mut u8).unwrap(),
                            data.len(),
                        )
                        .unwrap();
                },
                _ => unreachable!(),
            }
            writer.truncate_file(Path::new(FILE), 5000).unwrap();
            writer.truncate_file(Path::new(FILE), 7000).unwrap();
            writer.commit().unwrap();
            let mut expected = data[..5000].to_vec();
            expected.resize(7000, 0);
            assert_eq!(contents(&reader(root.path())), expected, "source={source}");
        }
    }

    #[test]
    fn truncate_pending_replacement_stays_sparse_when_extended() {
        let root = tempfile::tempdir().unwrap();
        let parent = seed(root.path(), &pattern(8192));
        let mut writer =
            IncrementalWriter::from_parent_reader(parent, options(root.path())).unwrap();
        writer.replace_file(Path::new(FILE), vec![7; 5000]).unwrap();
        writer.write_at(Path::new(FILE), 4090, &[3; 30]).unwrap();
        writer.truncate_file(Path::new(FILE), 4210).unwrap();
        writer.truncate_file(Path::new(FILE), 10000).unwrap();
        let index = writer
            .regular_inode_index_by_key(Path::new(FILE), Path::new(FILE))
            .unwrap();
        assert_eq!(writer.overlay[&index].replace.as_ref().unwrap().len(), 4210);
        assert_eq!(
            writer.write_at(Path::new(FILE), 9000, &[5; 10]).unwrap(),
            10
        );
        writer.commit().unwrap();
        let mut expected = vec![7; 4210];
        expected[4090..4120].fill(3);
        expected.resize(10000, 0);
        expected[9000..9010].fill(5);
        assert_eq!(contents(&reader(root.path())), expected);
    }

    #[test]
    fn truncate_zero_discards_all_staged_and_inherited_data() {
        let root = tempfile::tempdir().unwrap();
        let parent = seed(root.path(), &[9; 8192]);
        let mut writer =
            IncrementalWriter::from_parent_reader(parent, options(root.path())).unwrap();
        writer.replace_file(Path::new(FILE), vec![7; 8192]).unwrap();
        writer.write_at(Path::new(FILE), 0, &[3; 4096]).unwrap();
        writer.truncate_file(Path::new(FILE), 0).unwrap();
        assert!(writer.overlay.is_empty());
        writer.truncate_file(Path::new(FILE), 1 << 30).unwrap();
        assert!(writer.overlay.is_empty());
        let index = writer
            .regular_inode_index_by_key(Path::new(FILE), Path::new(FILE))
            .unwrap();
        let InodeData::RegularFile {
            chunk_index_entries,
            ..
        } = &writer.inodes[index].data
        else {
            unreachable!()
        };
        assert!(chunk_index_entries
            .iter()
            .all(|v| v.blkaddr == EROFS_NULL_ADDR));
        writer.truncate_file(Path::new(FILE), 7000).unwrap();
        writer.commit().unwrap();
        assert_eq!(contents(&reader(root.path())), vec![0; 7000]);
    }

    #[test]
    fn truncate_metadata_only_growth_failure_leaves_file_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let initial = pattern(3000);
        seed(root.path(), &initial);
        let mut writer = IncrementalWriter::open_metadata_only(
            &root.path().join("image.boot"),
            options(root.path()),
        )
        .unwrap();
        assert!(writer.truncate_file(Path::new(FILE), 8192).is_err());
        assert_eq!(
            writer.current_file_size(writer.path_index[Path::new(FILE)]),
            3000
        );
        assert!(!writer.has_changes);
        writer.truncate_file(Path::new(FILE), 0).unwrap();
        writer.truncate_file(Path::new(FILE), 8192).unwrap();
        writer.commit().unwrap();
        assert_eq!(contents(&reader(root.path())), vec![0; 8192]);
    }

    #[test]
    fn truncate_empty_partial_hole_and_missing_file() {
        let root = tempfile::tempdir().unwrap();
        let mut writer = IncrementalWriter::create(options(root.path())).unwrap();
        assert!(writer.truncate_file(Path::new("missing"), 10).is_err());
        assert!(writer.truncate_file(Path::new(""), 10).is_err());
        writer
            .create_file(Path::new(FILE), 3, CreateFileOptions::default())
            .unwrap();
        writer.truncate_file(Path::new(FILE), 8192).unwrap();
        writer.truncate_file(Path::new(FILE), 0).unwrap();
        writer.truncate_file(Path::new(FILE), 0).unwrap();
        writer.commit().unwrap();
        assert!(contents(&reader(root.path())).is_empty());
    }

    #[test]
    fn truncate_promotes_compact_inode_past_four_gib() {
        let root = tempfile::tempdir().unwrap();
        let mut writer = IncrementalWriter::create(options(root.path())).unwrap();
        writer
            .create_file(Path::new(FILE), 4096, CreateFileOptions::default())
            .unwrap();
        let index = writer.path_index[Path::new(FILE)];
        assert!(!writer.inodes[index].is_extended);
        writer
            .truncate_file(Path::new(FILE), (1u64 << 32) + 4096)
            .unwrap();
        assert!(writer.inodes[index].is_extended);
        writer.commit().unwrap();
        let image = ErofsReader::open_metadata_only(&root.path().join("image.boot")).unwrap();
        let root_nid = image.superblock().root_nid();
        let nid = image
            .lookup_dir_entry(root_nid, &image.inode(root_nid).unwrap(), FILE.as_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(image.inode(nid).unwrap().size(), (1u64 << 32) + 4096);
    }

    #[test]
    fn replacement_patch_reuses_owned_padding_buffer() {
        for padded in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let mut writer = IncrementalWriter::create(options(root.path())).unwrap();
            writer
                .create_file(Path::new(FILE), 4096, CreateFileOptions::default())
                .unwrap();
            let index = writer.path_index[Path::new(FILE)];
            let prefix = vec![7; if padded { 1 } else { 4096 }];
            let base = replacement_chunk(&prefix, 0, 4096);
            assert_eq!(matches!(&base, std::borrow::Cow::Owned(_)), padded);
            let ptr = base.as_ptr();
            let result = writer
                .materialize_chunk_overlay(
                    index,
                    0,
                    Some(base),
                    ChunkOverlay {
                        source: None,
                        patches: vec![ChunkPatch {
                            offset: 100,
                            source: DirtyChunk::Owned(vec![9; 20]),
                        }],
                    },
                )
                .unwrap();
            let DirtyChunk::Owned(data) = result else {
                unreachable!()
            };
            if padded {
                assert_eq!(data.as_ptr(), ptr);
            } else {
                assert_ne!(data.as_ptr(), prefix.as_ptr());
            }
            let mut expected = prefix;
            expected.resize(4096, 0);
            expected[100..120].fill(9);
            assert_eq!(data, expected);
        }
    }

    #[test]
    fn truncate_sparse_replacement_eof_does_not_materialize_parent_or_zeroes() {
        let root = tempfile::tempdir().unwrap();
        let initial = pattern(12288);
        let parent = seed(root.path(), &initial);
        let mut writer = IncrementalWriter::open_metadata_only(
            &root.path().join("image.boot"),
            options(root.path()),
        )
        .unwrap();
        writer.replace_file(Path::new(FILE), vec![7]).unwrap();
        writer.truncate_file(Path::new(FILE), 4097).unwrap();
        let index = writer.path_index[Path::new(FILE)];
        assert_eq!(writer.overlay[&index].chunks.len(), 1);
        for size in [5000, 7000, 8192, 8193, 12288] {
            writer.truncate_file(Path::new(FILE), size).unwrap();
            assert_eq!(writer.overlay[&index].chunks.len(), 1);
            assert!(writer.overlay[&index].chunks.contains_key(&0));
        }
        writer.commit().unwrap();
        let mut expected = vec![0; 12288];
        expected[0] = 7;
        assert_eq!(contents(&reader(root.path())), expected);
        // In-place publication must keep the original reader's mmap valid.
        assert_eq!(contents(&parent), initial);
    }

    #[test]
    fn truncate_prune_remaps_surviving_parent_and_prefetch_then_extends() {
        for prune in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let original = seed(root.path(), &pattern(8192));
            let mut writer =
                IncrementalWriter::from_parent_reader(original.clone(), options(root.path()))
                    .unwrap();
            writer.write_at(Path::new(FILE), 0, &[7; 4096]).unwrap();
            writer.commit().unwrap();
            let parent = reader(root.path());
            let parent_blobs = parent.blob_infos().unwrap();
            assert_eq!(parent_blobs.len(), 2);
            let mut settings = options(root.path());
            settings.prune = prune;
            let mut writer =
                IncrementalWriter::from_parent_reader(parent.clone(), settings).unwrap();
            crate::build::inode::set_root_prefetch_blobs_xattr(&mut writer.inodes[0], &[1, 2])
                .unwrap();
            writer.truncate_file(Path::new(FILE), 4096).unwrap();
            writer.commit().unwrap();
            let child = reader(root.path());
            let blobs = child.blob_infos().unwrap();
            if prune {
                assert_eq!(blobs.len(), 1);
                assert_eq!(blobs[0].blob_id, parent_blobs[1].blob_id);
                assert_eq!(child.read_prefetch_order(), vec![1]);
            } else {
                assert_eq!(blobs.len(), 2);
                assert_eq!(child.read_prefetch_order(), vec![1, 2]);
            }
            let root_nid = child.superblock().root_nid();
            let nid = child
                .lookup_dir_entry(root_nid, &child.inode(root_nid).unwrap(), FILE.as_bytes())
                .unwrap()
                .unwrap();
            let chunks = child
                .read_chunk_index_entries(nid, &child.inode(nid).unwrap())
                .unwrap();
            assert_eq!(chunks[0].device_id, if prune { 1 } else { 2 });
            assert_eq!(contents(&child), vec![7; 4096]);
            assert_eq!(contents(&parent).len(), 8192);
            assert_eq!(contents(&original), pattern(8192));

            let mut settings = options(root.path());
            settings.prune = prune;
            let mut writer = IncrementalWriter::from_parent_reader(child, settings).unwrap();
            writer.truncate_file(Path::new(FILE), 8192).unwrap();
            writer.write_at(Path::new(FILE), 6000, &[9]).unwrap();
            writer.commit().unwrap();
            let final_image = reader(root.path());
            let mut expected = vec![7; 4096];
            expected.resize(8192, 0);
            expected[6000] = 9;
            assert_eq!(contents(&final_image), expected);
            assert_eq!(
                final_image.blob_infos().unwrap().len(),
                if prune { 2 } else { 3 }
            );
        }
    }

    #[test]
    fn truncate_prune_drops_last_parent_reference_and_handles_sparse_rewrite() {
        for prune in [false, true] {
            for size in [0, 8192] {
                for rewrite in [false, true] {
                    if rewrite && size == 0 {
                        continue;
                    }
                    let root = tempfile::tempdir().unwrap();
                    let initial = pattern(8192);
                    let parent = seed(root.path(), &initial);
                    let mut settings = options(root.path());
                    settings.prune = prune;
                    let mut writer =
                        IncrementalWriter::from_parent_reader(parent.clone(), settings).unwrap();
                    writer.truncate_file(Path::new(FILE), 0).unwrap();
                    writer.truncate_file(Path::new(FILE), size).unwrap();
                    let mut expected = vec![0; size as usize];
                    if rewrite {
                        writer.write_at(Path::new(FILE), 100, &[9; 20]).unwrap();
                        expected[100..120].fill(9);
                    }
                    writer.commit().unwrap();
                    let child = reader(root.path());
                    assert_eq!(contents(&child), expected);
                    assert_eq!(
                        child.blob_infos().unwrap().len(),
                        usize::from(!prune) + usize::from(rewrite)
                    );
                    assert_eq!(contents(&parent), initial);
                    let mut settings = options(root.path());
                    settings.prune = prune;
                    let mut writer =
                        IncrementalWriter::from_parent_reader(child, settings).unwrap();
                    writer.truncate_file(Path::new(FILE), size + 4096).unwrap();
                    writer.commit().unwrap();
                    expected.resize((size + 4096) as usize, 0);
                    assert_eq!(contents(&reader(root.path())), expected);
                }
            }
        }
    }

    #[test]
    fn truncate_matches_a_byte_vector_across_repeated_commits() {
        let root = tempfile::tempdir().unwrap();
        let mut expected = pattern(9000);
        let parent = seed(root.path(), &expected);
        let mut writer =
            IncrementalWriter::from_parent_reader(parent, options(root.path())).unwrap();
        let mut random = 7u64;
        for iteration in 0..180 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            let size = ((random >> 32) % 12000) as usize;
            match random % 3 {
                0 => {
                    writer.truncate_file(Path::new(FILE), size as u64).unwrap();
                    expected.resize(size, 0);
                }
                1 => {
                    let offset = ((random >> 16) % 13000) as usize;
                    let data = vec![iteration as u8; size % 5000];
                    let written = writer
                        .write_at(Path::new(FILE), offset as u64, &data)
                        .unwrap();
                    let count = expected.len().saturating_sub(offset).min(data.len());
                    assert_eq!(written, count);
                    if count > 0 {
                        expected[offset..offset + count].copy_from_slice(&data[..count]);
                    }
                }
                _ => {
                    expected = vec![iteration as u8; size];
                    writer
                        .replace_file(Path::new(FILE), expected.clone())
                        .unwrap();
                }
            }
            if iteration % 11 == 0 && writer.has_changes {
                writer.commit().unwrap();
                let image = reader(root.path());
                assert_eq!(contents(&image), expected, "iteration={iteration}");
                writer =
                    IncrementalWriter::from_parent_reader(image, options(root.path())).unwrap();
            }
        }
        if writer.has_changes {
            writer.commit().unwrap();
        }
        assert_eq!(contents(&reader(root.path())), expected);
    }
}
