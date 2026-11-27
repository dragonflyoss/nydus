//! A decoded cache layout, encoded only after mutable sources are released.
use super::*;
use crate::build::bootstrap::patch_device_slots;
use nydus_format::erofs::{EROFS_DEVICESLOT_SIZE, EROFS_SUPER_OFFSET};
use serde::{Deserialize, Serialize};
use std::io::{BufReader, BufWriter, Read};
use std::os::unix::fs::PermissionsExt;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheChunkGroup {
    chunk_lengths: Vec<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheChunkGroupTable {
    version: u32,
    chunk_size: u32,
    chunk_group_minimum_size: u32,
    compressor: String,
    digester: String,
    chunk_groups: Vec<CacheChunkGroup>,
}

impl CacheChunkGroupTable {
    const VERSION: u32 = 1;
    const MAX_SIZE: u64 = 64 * 1024 * 1024;
}

#[derive(Default)]
pub struct EncodeOptions {
    /// Override the recorded chunk group compressor.
    pub compressor: Option<BlobMetadataCompressor>,
    pub prune: bool,
    /// Compact when the number of unique live blobs exceeds this nonzero limit.
    pub compact_max_layers: usize,
    /// Parent backend and decoded-cache configuration; required only for compact.
    pub config: Option<nydus_config::Config>,
}

pub(super) struct CacheLayoutState {
    cache: Box<dyn ChunkGroupCache>,
    chunk_groups: Vec<CacheChunkGroup>,
    budget: ChunkGroupTableBudget,
}

struct ChunkGroupTableBudget {
    bytes: u64,
    limit: u64,
}

impl Write for ChunkGroupTableBudget {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(data.len() as u64)
            .filter(|bytes| *bytes <= self.limit)
            .ok_or_else(|| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "cache layout chunk group table exceeds metadata limit",
                )
            })?;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CacheLayoutState {
    pub(super) fn new(cache: Box<dyn ChunkGroupCache>) -> Self {
        Self {
            cache,
            chunk_groups: Vec::new(),
            // Reserve the fixed chunk group table fields outside the group arrays.
            budget: ChunkGroupTableBudget {
                bytes: 512,
                limit: CacheChunkGroupTable::MAX_SIZE,
            },
        }
    }

    pub(super) fn write_chunk_group(
        &mut self,
        first_block: u64,
        lengths: &[u32],
        payload: &[u8],
    ) -> Result<()> {
        let chunk_group = CacheChunkGroup {
            chunk_lengths: lengths.to_vec(),
        };
        serde_json::to_writer(&mut self.budget, &chunk_group)
            .map_err(|err| Error::Runtime(err.to_string()))?;
        self.budget.write_all(b",")?;
        self.cache
            .write_chunk_group(first_block, lengths, payload)
            .map_err(|err| Error::Runtime(format!("cache layout data failed: {err}")))?;
        self.chunk_groups.push(chunk_group);
        Ok(())
    }
}

impl IncrementalWriter {
    /// Write decoded data from mutable sources into `cache.data` without compression or
    /// payload digests. Retain the cache layout files after releasing the source.
    /// The commit does not sync files or directories:
    /// successful writes release the mutable source, but do not promise crash
    /// durability. The caller handles incomplete output and syncs the
    /// decoded files before publishing ready cache state. `cache.boot` is
    /// provisional, not mountable.
    /// The default sink writes `cache.data` atomically in `output_dir`.
    /// Later, [`CacheLayout::encode`] encodes these exact groups without rewriting
    /// the cache or changing any inode chunk addresses.
    pub fn commit_cache_to_dir(self) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        fs::create_dir_all(&self.output_dir)?;
        let output_dir = self.output_dir.clone();
        if fs::symlink_metadata(output_dir.join(CacheLayout::DATA)).is_ok() {
            return Err(Error::InvalidParameter(
                "cache layout data already exists".to_string(),
            ));
        }
        let temporary = output_dir.join(".cache.data.tmp");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let staged = StagedCache(temporary);
        let data = file.try_clone()?;
        let result = self.commit_cache(FileChunkGroupCache { file, blocks: 0 });
        if result.is_err() {
            let _ = fs::remove_file(output_dir.join(CacheLayout::CHUNK_GROUP_TABLE));
            return result;
        }
        let result = (|| -> Result<()> {
            data.set_len(data.metadata()?.len().div_ceil(4096) * 4096)?;
            fs::hard_link(&staged.0, output_dir.join(CacheLayout::DATA))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(output_dir.join(CacheLayout::CHUNK_GROUP_TABLE));
        }
        result
    }

    /// Write a cache layout with a caller-provided decoded data sink.
    /// The caller must retain the sink's bytes and seal its final block size.
    pub fn commit_cache<C: ChunkGroupCache + 'static>(mut self, cache: C) -> Result<()> {
        if self
            .device_slots
            .iter()
            .any(|slot| slot.blob_id().is_ok_and(|id| id == CacheLayout::BLOB_ID))
        {
            return Err(Error::InvalidImage(
                "parent uses reserved cache layout blob ID".to_string(),
            ));
        }
        fs::create_dir_all(&self.output_dir)?;
        self.cache_layout = Some(Arc::new(Mutex::new(CacheLayoutState::new(Box::new(cache)))));
        let bootstrap = self.commit_inner()?;
        let state = self
            .cache_layout
            .take()
            .expect("cache layout state initialized");
        let state = Arc::try_unwrap(state)
            .map_err(|_| Error::Runtime("cache layout state still borrowed".to_string()))?
            .into_inner()
            .map_err(|_| Error::Runtime("cache layout lock poisoned".to_string()))?;
        let chunk_group_table = CacheChunkGroupTable {
            version: CacheChunkGroupTable::VERSION,
            chunk_size: self.chunk_size,
            chunk_group_minimum_size: self.chunk_group_min_size,
            compressor: self.compressor.to_string(),
            digester: self
                .digester
                .map_or_else(|| "none".to_string(), |digester| digester.to_string()),
            chunk_groups: state.chunk_groups,
        };
        self.save_bootstrap_file(CacheLayout::BOOTSTRAP, &bootstrap, false)?;
        let output_dir = self.output_dir.clone();
        drop(bootstrap);
        drop(self);
        save_output_file_with(&output_dir, CacheLayout::CHUNK_GROUP_TABLE, false, |file| {
            let mut writer = BufWriter::new(file);
            serde_json::to_writer(&mut writer, &chunk_group_table)
                .map_err(|err| Error::Runtime(err.to_string()))?;
            writer.flush()?;
            Ok(())
        })?;
        Ok(())
    }
}

struct FileChunkGroupCache {
    file: File,
    blocks: u64,
}

impl ChunkGroupCache for FileChunkGroupCache {
    fn write_chunk_group(
        &mut self,
        first: u64,
        lengths: &[u32],
        payload: &[u8],
    ) -> std::io::Result<()> {
        if first != self.blocks {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "invalid cache layout group order",
            ));
        }
        self.blocks =
            nydus_storage::cache::write_decoded_group(&self.file, first, lengths, payload)?;
        Ok(())
    }
}

fn read_chunk_group_table(path: &Path) -> Result<CacheChunkGroupTable> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > CacheChunkGroupTable::MAX_SIZE {
        return Err(Error::InvalidImage(
            "cache layout metadata exceeds size limit".to_string(),
        ));
    }
    serde_json::from_reader(BufReader::new(
        file.take(CacheChunkGroupTable::MAX_SIZE + 1),
    ))
    .map_err(|err| Error::InvalidImage(format!("invalid cache layout chunk group table: {err}")))
}

/// A sealed decoded cache layout ready for deferred encoding.
pub struct CacheLayout {
    dir: PathBuf,
    chunk_group_table: CacheChunkGroupTable,
    data: File,
    reader: Arc<ErofsReader>,
    bootstrap: memmap2::MmapMut,
    slots: Vec<ErofsDeviceSlot>,
    device_index: Option<usize>,
    blocks: u64,
    compressor: BlobMetadataCompressor,
    digester: Option<BlobMetadataDigester>,
}

impl CacheLayout {
    pub const BOOTSTRAP: &'static str = "cache.boot";
    pub const DATA: &'static str = "cache.data";
    pub const CHUNK_GROUP_TABLE: &'static str = "cache.json";
    pub const BLOB_ID: [u8; 32] = [0; 32];

    /// Open and validate the layout before writing any encoded bytes.
    pub fn open(dir: &Path) -> Result<Self> {
        let chunk_group_table = read_chunk_group_table(&dir.join(Self::CHUNK_GROUP_TABLE))?;
        let data = File::open(dir.join(Self::DATA))?;
        if chunk_group_table.version != CacheChunkGroupTable::VERSION {
            return Err(Error::InvalidImage(
                "unsupported cache layout version".to_string(),
            ));
        }
        validate_chunk_size(chunk_group_table.chunk_size)?;
        validate_chunk_group_min_size(chunk_group_table.chunk_group_minimum_size)?;
        let compressor = match chunk_group_table.compressor.as_str() {
            "none" => BlobMetadataCompressor::None,
            "zstd" => BlobMetadataCompressor::Zstd,
            "lz4" => BlobMetadataCompressor::Lz4Block,
            _ => {
                return Err(Error::InvalidImage(
                    "invalid cache layout compressor".to_string(),
                ))
            }
        };
        let digester = match chunk_group_table.digester.as_str() {
            "none" => None,
            "blake3" => Some(BlobMetadataDigester::Blake3),
            _ => {
                return Err(Error::InvalidImage(
                    "invalid cache layout digester".to_string(),
                ))
            }
        };
        let bootstrap_file = File::open(dir.join(CacheLayout::BOOTSTRAP))?;
        let reader = Arc::new(ErofsReader::open_metadata_only(
            &dir.join(CacheLayout::BOOTSTRAP),
        )?);
        if reader.sb_offset != EROFS_SUPER_OFFSET as usize
            || bootstrap_file.metadata()?.len() != reader.mmap.len() as u64
        {
            return Err(Error::InvalidImage(
                "cache layout requires a standalone bootstrap".to_string(),
            ));
        }
        // SAFETY: the sealed cache layout remains immutable through finalization.
        // Only patched device-table/checksum pages need private copies.
        let bootstrap = unsafe { memmap2::MmapOptions::new().map_copy(&bootstrap_file)? };
        let sb = reader.superblock();
        let offset = sb.devt_slotoff() as usize * EROFS_DEVICESLOT_SIZE;
        let mut slots = Vec::with_capacity(sb.extra_devices() as usize);
        let mut device_index = None;
        for index in 0..sb.extra_devices() as usize {
            let start = offset + index * EROFS_DEVICESLOT_SIZE;
            let bytes = bootstrap
                .get(start..start + EROFS_DEVICESLOT_SIZE)
                .ok_or_else(|| {
                    Error::InvalidImage("truncated cache layout device table".to_string())
                })?;
            let slot = *ErofsDeviceSlot::from_bytes(bytes)?;
            if slot.blob_id()? == CacheLayout::BLOB_ID && device_index.replace(index).is_some() {
                return Err(Error::InvalidImage(
                    "duplicate cache layout devices".to_string(),
                ));
            }
            slots.push(slot);
        }
        let mut blocks = 0u64;
        let max_span = u64::from(chunk_group_table.chunk_size)
            .max(u64::from(chunk_group_table.chunk_group_minimum_size) * 4)
            / 4096;
        for chunk_group in &chunk_group_table.chunk_groups {
            let group = &chunk_group.chunk_lengths;
            if group.is_empty()
                || group
                    .iter()
                    .any(|len| *len == 0 || *len > chunk_group_table.chunk_size)
            {
                return Err(Error::InvalidImage(
                    "invalid chunk group layout".to_string(),
                ));
            }
            let span = group
                .iter()
                .map(|len| u64::from(*len).div_ceil(4096))
                .sum::<u64>();
            if span > max_span {
                return Err(Error::InvalidImage(
                    "cache layout group exceeds geometry".to_string(),
                ));
            }
            blocks = blocks
                .checked_add(span)
                .filter(|end| *end <= u32::MAX as u64)
                .ok_or_else(|| {
                    Error::InvalidImage("cache layout block count overflow".to_string())
                })?;
        }
        if let Some(index) = device_index {
            if slots[index].blocks() != blocks {
                return Err(Error::InvalidImage(
                    "cache layout device does not match layout".to_string(),
                ));
            }
        } else if !chunk_group_table.chunk_groups.is_empty() {
            return Err(Error::InvalidImage(
                "parent-only cache layout has upper data".to_string(),
            ));
        }
        let metadata = data.metadata()?;
        if !metadata.is_file() || metadata.len() != blocks * 4096 {
            return Err(Error::InvalidImage(
                "decoded cache length differs from layout".to_string(),
            ));
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            chunk_group_table,
            data,
            reader,
            bootstrap,
            slots,
            device_index,
            blocks,
            compressor,
            digester,
        })
    }

    /// Encode to the supplied sink and publish image.boot and decoded sidecars.
    /// This does not publish the image or modify the input files.
    pub fn encode<W: Write>(self, sink: W, options: EncodeOptions) -> Result<()> {
        let Self {
            dir,
            chunk_group_table,
            data,
            reader,
            mut bootstrap,
            mut slots,
            device_index,
            blocks,
            compressor,
            digester,
        } = self;
        let dir = dir.as_path();
        ensure_not_published(dir)?;
        let compressor = options.compressor.unwrap_or(compressor);
        let mut writer_options = IncrementalWriterOptions::new(dir.to_path_buf());
        writer_options.chunk_size = chunk_group_table.chunk_size;
        writer_options.chunk_group_min_size = chunk_group_table.chunk_group_minimum_size;
        writer_options.compressor = compressor;
        writer_options.digester = digester;
        let mut imported = if options.prune || options.compact_max_layers > 0 {
            Some(IncrementalWriter::from_reader(
                reader.clone(),
                writer_options,
                ParentMode::Compact,
            )?)
        } else {
            None
        };
        let device_ids = if let Some(writer) = imported.as_mut() {
            writer.prune_parent_devices(writer.device_slots.len())?
        } else {
            None
        };
        let pruned = device_ids.is_some();
        if options.compact_max_layers > 0
            && imported
                .as_ref()
                .expect("compact enabled")
                .repack_blob_ids()?
                .len()
                > options.compact_max_layers
        {
            // Compaction uses the imported writer, not the original encoded layout.
            drop(chunk_group_table);
            drop(bootstrap);
            drop(slots);
            drop(device_ids);
            return compact_cache_layout(
                dir,
                &data,
                sink,
                options,
                &reader,
                imported.expect("compact enabled"),
            );
        }
        if let Some(index) = device_index {
            let mut writer = BlobWriter::new(
                sink,
                chunk_group_table.chunk_size,
                compressor,
                digester,
                true,
                BlobLayout::ChunkGroups {
                    chunk_group_min_size: chunk_group_table.chunk_group_minimum_size,
                },
            )?;
            let mut first_block = 0;
            for chunk_group in &chunk_group_table.chunk_groups {
                let lengths = &chunk_group.chunk_lengths;
                let size = lengths.iter().map(|len| *len as usize).sum();
                let mut payload = writer.take_source_buffer();
                payload.resize(size, 0);
                let mut block = first_block;
                let mut cursor = 0;
                let mut run_cursor = 0;
                let mut run_block = block;
                for &len in lengths {
                    cursor += len as usize;
                    block += u64::from(len).div_ceil(4096);
                    if len % 4096 != 0 {
                        data.read_exact_at(&mut payload[run_cursor..cursor], run_block * 4096)?;
                        run_cursor = cursor;
                        run_block = block;
                    }
                }
                if run_cursor < cursor {
                    data.read_exact_at(&mut payload[run_cursor..cursor], run_block * 4096)?;
                }
                writer.write_placed_group(first_block, lengths, payload)?;
                first_block = block;
            }
            writer.finish()?;
            let finished = finish_upper_blob(writer)?;
            if finished.blob_blocks != blocks
                || finished.blob_metadata.chunk_group_count()
                    != chunk_group_table.chunk_groups.len()
            {
                return Err(Error::InvalidImage(
                    "encoded cache layout changed".to_string(),
                ));
            }
            slots[index].set_blob_id(&finished.full_blob_digest);
            patch_device_slots(&mut bootstrap, &slots)?;
            let digest = hex::encode(finished.full_blob_digest);
            publish_sidecar(dir, &digest, &finished.blob_metadata)?;
            publish_decoded(
                dir,
                &dir.join(CacheLayout::DATA),
                &digest,
                &finished.blob_metadata,
            )?;
        }
        if pruned {
            let mut imported = imported.expect("prune enabled");
            if let Some(index) = device_index {
                for slot in &mut imported.device_slots {
                    if slot.blob_id()? == CacheLayout::BLOB_ID {
                        slot.set_blob_id(&slots[index].blob_id()?);
                    }
                }
            }
            let rendered = render_bootstrap_remapped(
                &mut imported.inodes,
                imported.epoch,
                &imported.device_slots,
                &imported.uuid,
                device_ids.as_deref(),
            )?;
            return publish_bootstrap(dir, &rendered);
        }
        publish_bootstrap(dir, &bootstrap)
    }
}

fn publish_bootstrap(dir: &Path, bootstrap: &[u8]) -> Result<()> {
    save_output_file(dir, "image.boot", bootstrap, true)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

// A published layout is immutable. Only nydusify writes image.json.
fn ensure_not_published(dir: &Path) -> Result<()> {
    match fs::symlink_metadata(dir.join("image.json")) {
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
        Ok(_) => Err(Error::InvalidParameter(
            "cache layout already has image.json".to_string(),
        )),
    }
}

fn publish_sidecar(dir: &Path, digest: &str, metadata: &BlobMetadata) -> Result<()> {
    save_output_file_with(
        dir,
        &format!("{digest}{}", BlobMetadata::SUFFIX),
        true,
        |file| {
            metadata.write_to(file)?;
            Ok(())
        },
    )
}

fn publish_decoded(dir: &Path, source: &Path, digest: &str, metadata: &BlobMetadata) -> Result<()> {
    // Publish a new inode through rename; retries must not truncate an inode
    // already hardlinked into the snapshotter's cache.
    let (temporary, file) = create_temp_file(dir, "decoded-link")?;
    let staged = StagedCache(temporary);
    drop(file);
    fs::remove_file(&staged.0)?;
    fs::hard_link(source, &staged.0)?;
    fs::rename(&staged.0, dir.join(format!("{digest}.blob.data")))?;
    let (temporary, file) = create_temp_file(dir, "ready-map")?;
    let staged = StagedCache(temporary);
    drop(file);
    nydus_storage::chunk_group_map::ChunkGroupMap::create_ready(
        &staged.0,
        metadata.chunk_group_count(),
    )?;
    fs::rename(&staged.0, dir.join(format!("{digest}.group.map")))?;
    Ok(())
}

fn compact_cache_layout<W: Write>(
    dir: &Path,
    data: &File,
    sink: W,
    options: EncodeOptions,
    reader: &ErofsReader,
    mut imported: IncrementalWriter,
) -> Result<()> {
    let config = options.config.ok_or_else(|| {
        Error::InvalidParameter("cache layout compact requires config".to_string())
    })?;
    if config.storage.dir.is_none() {
        return Err(Error::InvalidConfig(
            "cache layout compact requires storage.dir for lazy parent reads".to_string(),
        ));
    }
    let cache_options = crate::CacheOptions::from(&config.storage);
    let fallback_reader = std::cell::OnceCell::<ErofsReader>::new();
    let parent_reader = || -> std::io::Result<&ErofsReader> {
        if fallback_reader.get().is_none() {
            let backend =
                <dyn nydus_backend::Backend>::new(&config, None, Arc::new(crate::Metrics::new()))?;
            let reader = ErofsReader::open_bootstrap(
                &dir.join(CacheLayout::BOOTSTRAP),
                backend,
                config.storage.dir.as_deref(),
                None,
                cache_options,
            )?;
            // Single-threaded repack; no background prefetch or filesystem view.
            assert!(fallback_reader.set(reader).is_ok());
        }
        Ok(fallback_reader.get().expect("fallback reader initialized"))
    };
    let infos = reader.blob_infos()?;
    let (cache_path, cache) = create_temp_file(dir, "compact-cache")?;
    let staged_cache = StagedCache(cache_path);
    cache.set_permissions(fs::Permissions::from_mode(0o600))?;
    let cache = Arc::new(cache);
    let cache_output = cache.clone();
    imported.prepare_compact_chunk_size()?;
    let mut output = BlobWriter::new(
        sink,
        imported.chunk_size,
        imported.compressor,
        imported.digester,
        true,
        BlobLayout::ChunkGroups {
            chunk_group_min_size: imported.chunk_group_min_size,
        },
    )?;
    output.set_decoded_group_callback(move |first, lengths, payload| {
        nydus_storage::cache::write_decoded_group(&cache_output, first, lengths, payload)?;
        Ok(())
    });
    imported.prepare_compact_output();
    imported.compact_decoded(reader, &mut output, |nid, inode, source, offset, dst| {
        // The new blob always has an explicit device. Device zero
        // may instead refer to flattened parent data or bootstrap-local bytes.
        if source.device_id > 0
            && infos
                .get(usize::from(source.device_id) - 1)
                .is_some_and(|info| info.blob_id == CacheLayout::BLOB_ID)
        {
            data.read_exact_at(
                dst,
                source.blkaddr.checked_mul(4096).ok_or_else(|| {
                    Error::Overflow("cache layout chunk address overflow".to_string())
                })?,
            )?;
            return Ok(());
        }
        let len = dst.len();
        let written =
            parent_reader()?.write_file_data_to(nid, inode, offset, len as u32, &mut &mut *dst)?;
        if written != len {
            return Err(Error::InvalidImage("short compact parent read".to_string()));
        }
        Ok(())
    })?;
    let finished = finish_upper_blob(output)?;
    cache.set_len(finished.blob_blocks * 4096)?;
    cache.sync_all()?;
    imported.device_slots.push(ErofsDeviceSlot::with_blob_id(
        finished.blob_blocks,
        &finished.full_blob_digest,
    )?);
    let bootstrap = render_bootstrap_remapped(
        &mut imported.inodes,
        imported.epoch,
        &imported.device_slots,
        &imported.uuid,
        None,
    )?;
    let digest = hex::encode(finished.full_blob_digest);
    publish_sidecar(dir, &digest, &finished.blob_metadata)?;
    publish_decoded(dir, &staged_cache.0, &digest, &finished.blob_metadata)?;
    publish_bootstrap(dir, &bootstrap)
}

struct StagedCache(PathBuf);

impl Drop for StagedCache {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountCache(Arc<AtomicUsize>);
    impl ChunkGroupCache for CountCache {
        fn write_chunk_group(&mut self, _: u64, _: &[u32], _: &[u8]) -> std::io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn chunk_group_table_limit_is_checked_before_writing_the_next_group() {
        let writes = Arc::new(AtomicUsize::new(0));
        let mut state = CacheLayoutState::new(Box::new(CountCache(writes.clone())));
        let chunk_group = CacheChunkGroup {
            chunk_lengths: vec![4096],
        };
        state.budget.limit =
            state.budget.bytes + serde_json::to_vec(&chunk_group).unwrap().len() as u64 + 1;
        state.write_chunk_group(0, &[4096], &[42; 4096]).unwrap();
        assert!(state.write_chunk_group(1, &[4096], &[42; 4096]).is_err());
        assert_eq!(state.chunk_groups.len(), 1);
        assert_eq!(writes.load(Ordering::Relaxed), 1);
    }
}
