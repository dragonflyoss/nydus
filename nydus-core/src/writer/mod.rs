use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, ErrorKind, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::build::blob_chunk::BlobWriter;
use crate::build::bootstrap::render_bootstrap;
use crate::build::inode::set_root_prefetch_blobs_xattr;
use crate::build::inode::{flatten_tree, InodeData, InodeInfo, NamedChildren, NodeAttrs, TreeNode};
use crate::build::{
    finalize_digest_named_blob, save_blob_metadata_sidecar, validate_chunk_geometry, HashingWriter,
};
use crate::reader::RawDirEntry;
use crate::ErofsReader;
use nydus_error::{Context, Error, Result};
use nydus_format::blob::{self, BlobMetadata, BlobMetadataCompressor};
use nydus_format::erofs::{
    erofs_xattr_name_split, mode_to_erofs_file_type, ErofsChunkAddr, ErofsDeviceSlot, ErofsInode,
    XattrEntry, EROFS_BLOB_ID_SIZE, EROFS_FT_BLKDEV, EROFS_FT_CHRDEV, EROFS_FT_DIR, EROFS_FT_FIFO,
    EROFS_FT_REG_FILE, EROFS_FT_SOCK, EROFS_FT_SYMLINK, EROFS_INODE_CHUNK_BASED, EROFS_NULL_ADDR,
};
struct FinishedUpperBlob {
    full_blob_digest: [u8; EROFS_BLOB_ID_SIZE],
    blob_metadata: BlobMetadata,
    blob_blocks: u64,
}

pub struct IncrementalWriterOptions {
    /// Directory where commit writes `image.boot`, digest-named upper blob, and
    /// the `<digest>.blob.meta` sidecar when the update contains upper data.
    pub output_dir: PathBuf,
    pub chunk_size: u32,
    pub compress_size: u32,
    pub compressor: BlobMetadataCompressor,
}

#[derive(Default)]
struct FileOverlay {
    replace: Option<Vec<u8>>,
    chunks: BTreeMap<usize, DirtyChunk>,
}

enum DirtyChunk {
    Data(Vec<u8>),
}

/// Incrementally builds a child nydus image from a parent image.
///
/// The writer is a single-writer builder: all mutation APIs take `&mut self`,
/// and callers that share one writer across threads must serialize calls
/// externally. Multiple independent writers may share the same parent reader,
/// but they must use distinct output paths.
///
/// Writes are staged in an in-memory overlay. Later writes to the same logical
/// chunk replace earlier staged data for that chunk, and partial writes read the
/// staged chunk first before falling back to the parent image. The parent
/// `NydusCore` or `ErofsReader` remains read-only and does not observe staged
/// changes; callers must open the committed bootstrap/blob as a new image to
/// read the merged result.
pub struct IncrementalWriter {
    inodes: Vec<InodeInfo>,
    path_index: HashMap<PathBuf, usize>,
    parent_nids: Vec<u64>,
    parent_reader: Option<Arc<ErofsReader>>,
    overlay: BTreeMap<usize, FileOverlay>,
    parent_device_slots: Vec<ErofsDeviceSlot>,
    blob_writer: Option<BlobWriter<File>>,
    output_dir: PathBuf,
    upper_blob_temp_path: Option<PathBuf>,
    chunk_size: u32,
    compress_size: u32,
    compressor: BlobMetadataCompressor,
    epoch: u64,
    uuid: [u8; 16],
    upper_device_id: u16,
}

impl IncrementalWriter {
    /// Open a writer from parent metadata only.
    ///
    /// This mode can replace whole files and stage writes that cover a full
    /// logical chunk. It cannot serve partial writes that need parent data
    /// because no parent blob backend is available.
    pub fn open_metadata_only(
        parent_bootstrap: &Path,
        options: IncrementalWriterOptions,
    ) -> Result<Self> {
        validate_chunk_geometry(options.chunk_size, options.compress_size)?;
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
        validate_chunk_geometry(options.chunk_size, options.compress_size)?;
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
            .collect();
        let upper_device_id = u16::try_from(parent_device_slots.len() + 1)
            .map_err(|err| Error::Overflow(format!("upper blob device id overflow: {err}")))?;

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
            parent_reader: keep_parent_reader.then_some(reader.clone()),
            overlay: BTreeMap::new(),
            parent_device_slots,
            blob_writer: None,
            output_dir: options.output_dir,
            upper_blob_temp_path: None,
            chunk_size: options.chunk_size,
            compress_size: options.compress_size,
            compressor: options.compressor,
            epoch,
            uuid,
            upper_device_id,
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

        let inode_index = self.regular_inode_index(path)?;
        self.validate_inode_chunk_size(inode_index, path)?;
        let file_size = self.current_file_size(inode_index);
        if offset >= file_size {
            return Ok(0);
        }

        let actual_len = data.len().min(
            usize::try_from(file_size - offset)
                .map_err(|err| Error::Overflow(format!("write range exceeds usize: {err}")))?,
        );
        let chunk_size = self.chunk_size as u64;
        let mut written = 0usize;

        while written < actual_len {
            let file_pos = offset
                .checked_add(written as u64)
                .ok_or_else(|| Error::Overflow("write offset overflow".to_string()))?;
            let chunk_index = usize::try_from(file_pos / chunk_size)
                .map_err(|err| Error::Overflow(format!("chunk index exceeds usize: {err}")))?;
            let chunk_off = usize::try_from(file_pos % chunk_size)
                .map_err(|err| Error::Overflow(format!("chunk offset exceeds usize: {err}")))?;
            let chunk_start = (chunk_index as u64)
                .checked_mul(chunk_size)
                .ok_or_else(|| Error::Overflow("chunk start overflow".to_string()))?;
            let logical_chunk_len = usize::try_from((file_size - chunk_start).min(chunk_size))
                .map_err(|err| Error::Overflow(format!("chunk length exceeds usize: {err}")))?;
            let step = (actual_len - written).min(logical_chunk_len - chunk_off);

            if chunk_off == 0 && step == logical_chunk_len {
                self.record_chunk_data(
                    inode_index,
                    chunk_index,
                    data[written..written + step].to_vec(),
                )?;
            } else {
                let mut chunk = self.read_current_chunk(
                    inode_index,
                    chunk_index,
                    chunk_start,
                    logical_chunk_len,
                )?;
                chunk[chunk_off..chunk_off + step].copy_from_slice(&data[written..written + step]);
                self.record_chunk_data(inode_index, chunk_index, chunk)?;
            }
            written += step;
        }

        Ok(written)
    }

    /// Replace the whole file contents in the upper image.
    ///
    /// Existing staged chunk updates for the file are cleared. Later chunk or
    /// range writes apply on top of this replacement data before commit.
    pub fn replace_file(&mut self, path: &Path, data: &[u8]) -> Result<()> {
        let inode_index = self.regular_inode_index(path)?;
        self.overlay.insert(
            inode_index,
            FileOverlay {
                replace: Some(data.to_vec()),
                chunks: BTreeMap::new(),
            },
        );
        Ok(())
    }

    /// Materialize staged changes and write the child bootstrap/blob.
    ///
    /// Commit consumes the writer. It fails if no changes were staged, which
    /// avoids creating an upper image that is indistinguishable from the parent
    /// except for empty output artifacts.
    pub fn commit(mut self) -> Result<()> {
        if self.overlay.is_empty() {
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
        self.materialize_overlay()?;

        let mut final_slots = self.parent_device_slots.clone();
        if let Some(blob_writer) = self.blob_writer.take() {
            let finished = finish_upper_blob(blob_writer)?;
            let temp_path = self.upper_blob_temp_path.take().ok_or_else(|| {
                Error::InvalidImage("upper blob temp path is missing".to_string())
            })?;
            let final_blob_path = finalize_digest_named_blob(
                &temp_path,
                &self.output_dir,
                &finished.full_blob_digest,
            )?;
            save_blob_metadata_sidecar(&finished.blob_metadata, &final_blob_path)?;

            final_slots.push(ErofsDeviceSlot::with_blob_id(
                finished.blob_blocks,
                &finished.full_blob_digest,
            ));
        }

        set_root_prefetch_blobs_xattr(
            &mut self.inodes[0],
            &(1..=final_slots.len())
                .map(|index| index as u16)
                .collect::<Vec<_>>(),
        )?;
        let final_bootstrap =
            render_bootstrap(&mut self.inodes, self.epoch, &final_slots, &self.uuid)?;
        let bootstrap_path = self.output_dir.join("image.boot");
        fs::write(&bootstrap_path, final_bootstrap).with_context(|| {
            format!(
                "failed to write incremental bootstrap: {}",
                bootstrap_path.display()
            )
        })?;

        Ok(())
    }

    fn record_chunk_data(
        &mut self,
        inode_index: usize,
        chunk_index: usize,
        mut data: Vec<u8>,
    ) -> Result<()> {
        let logical_len = self.logical_chunk_len(inode_index, chunk_index)?;
        if data.len() < logical_len {
            return Err(Error::InvalidParameter(format!(
                "chunk data for index {chunk_index} is shorter than logical chunk length {logical_len}: {}",
                data.len()
            )));
        }
        data.truncate(logical_len);
        self.overlay
            .entry(inode_index)
            .or_default()
            .chunks
            .insert(chunk_index, DirtyChunk::Data(data));
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
        self.blob_writer = Some(BlobWriter::from_writer(
            blob_file,
            self.chunk_size,
            self.compress_size,
            self.compressor,
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

        self.ensure_blob_writer()?;
        let device_id = self.upper_device_id;
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
            for chunk_index in 0..chunk_count {
                let start = chunk_index * self.chunk_size as usize;
                let end = (start + self.chunk_size as usize).min(data.len());
                match overlay.chunks.get(&chunk_index) {
                    Some(DirtyChunk::Data(chunk)) => {
                        chunk_index_entries.push(self.write_upper_chunk_addr(chunk)?);
                    }
                    None => {
                        chunk_index_entries.push(self.write_upper_chunk_addr(&data[start..end])?);
                    }
                }
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
        for (chunk_index, dirty) in overlay.chunks {
            if chunk_index >= chunk_count {
                return Err(Error::InvalidParameter(format!(
                    "chunk index {chunk_index} out of range {chunk_count}"
                )));
            }
            let addr = match dirty {
                DirtyChunk::Data(data) => self.write_upper_chunk_addr(&data)?,
            };
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

    // Internal read-after-write view used by partial writes. This intentionally
    // does not update or consult the parent reader metadata after construction.
    fn read_current_chunk(
        &self,
        inode_index: usize,
        chunk_index: usize,
        chunk_start: u64,
        chunk_len: usize,
    ) -> Result<Vec<u8>> {
        if let Some(overlay) = self.overlay.get(&inode_index) {
            if let Some(dirty) = overlay.chunks.get(&chunk_index) {
                return match dirty {
                    DirtyChunk::Data(data) => {
                        if data.len() != chunk_len {
                            return Err(Error::InvalidImage(format!(
                                "dirty chunk {chunk_index} length mismatch: got {}, expected {chunk_len}",
                                data.len()
                            )));
                        }
                        Ok(data.clone())
                    }
                };
            }
            if let Some(data) = &overlay.replace {
                let start = usize::try_from(chunk_start)
                    .map_err(|err| Error::Overflow(format!("chunk start exceeds usize: {err}")))?;
                let end = (start + chunk_len).min(data.len());
                return Ok(data[start..end].to_vec());
            }
        }
        self.read_parent_chunk(inode_index, chunk_start, chunk_len)
    }

    fn read_parent_chunk(
        &self,
        inode_index: usize,
        chunk_start: u64,
        chunk_len: usize,
    ) -> Result<Vec<u8>> {
        let reader = self.parent_reader.as_ref().ok_or_else(|| {
            Error::InvalidParameter(
                "partial write requires a data-capable parent reader; use NydusCore::writer"
                    .to_string(),
            )
        })?;
        let nid = self.parent_nids[inode_index];
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

    fn regular_inode_index(&self, path: &Path) -> Result<usize> {
        let key = normalize_relative_path(path)?;
        let index = *self.path_index.get(&key).ok_or_else(|| {
            Error::NotFound(format!(
                "path not found in parent image: {}",
                path.display()
            ))
        })?;
        if !matches!(self.inodes[index].data, InodeData::RegularFile { .. }) {
            return Err(Error::InvalidParameter(format!(
                "path is not a regular file: {}",
                path.display()
            )));
        }
        Ok(index)
    }
}

fn finish_upper_blob<W: Write>(mut blob_writer: BlobWriter<W>) -> Result<FinishedUpperBlob> {
    blob_writer.finish()?;

    let blob_blocks = blob_writer.total_blocks();
    let compressed_data_size = blob_writer.data_size();
    let blob_metadata = blob_writer.incremental_blob_metadata(0)?;

    let (blob_file, full_blob_hasher) = blob_writer.into_parts();
    let mut blob_writer_stream = HashingWriter::new(BufWriter::new(blob_file), full_blob_hasher);
    blob::finish_full_blob(
        &mut blob_writer_stream,
        compressed_data_size,
        &[],
        &blob_metadata,
    )?;
    let full_blob_digest = blob_writer_stream
        .finish()
        .context("failed to flush upper blob")?;

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
