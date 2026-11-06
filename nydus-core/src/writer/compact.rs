//! Copy compatible encoded groups without opening decoded caches.
use super::*;
use crate::layout::{FlatLayout, Segment};
use crate::reader::data::{locate_chunk, ChunkLocation};
use crate::reader::RawBlobInfo;
use nydus_backend::Backend;
use nydus_format::blob::{BlobMetadataChunkGroup, BlobMetadataChunkLength};
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use sha2::{Digest, Sha256};
use std::ops::Range;

const UNUSED: u64 = u64::MAX;
const LIVE: u64 = u64::MAX - 1;
const COPY_WINDOW: usize = 4 * 1024 * 1024;
// Bound index amplification caused by short tails becoming interior groups.
const MAX_EXTRA_INDEX_BYTES: u64 = 16 * 1024 * 1024;

/// Metadata-only preparation and final outcome of an image repack.
#[derive(Debug)]
pub struct RepackResult {
    pub pruned: bool,
    pub compacted: bool,
    /// Unique live blob digests; after compact, the single output digest.
    pub blobs: Vec<crate::BlobId>,
}

// Repack can reuse metadata staged by packaging without constructing decoded
// caches. Fallback reads use the reader's existing cache and the same sidecars.
pub(crate) struct RepackBackend<'a> {
    inner: &'a dyn Backend,
    cache_dir: Option<&'a Path>,
}

impl<'a> RepackBackend<'a> {
    pub(crate) fn new(inner: &'a dyn Backend, cache_dir: Option<&'a Path>) -> Self {
        Self { inner, cache_dir }
    }
}

impl Backend for RepackBackend<'_> {
    fn metrics(&self) -> &Arc<nydus_telemetry::metrics::Metrics> {
        self.inner.metrics()
    }

    fn read_blob_metadata(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
    ) -> std::io::Result<nydus_format::blob::BlobMetadata> {
        if let Some(dir) = self.cache_dir {
            let id = self.inner.full_blob_id(blob_id)?;
            let path = dir.join(format!(
                "{}{}",
                crate::BlobId::from(id),
                nydus_format::blob::BlobMetadata::SUFFIX
            ));
            match std::fs::read(&path) {
                Ok(bytes) => {
                    return nydus_format::blob::BlobMetadata::from_bytes(bytes)
                        .map_err(std::io::Error::other);
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
        }
        self.inner.read_blob_metadata(blob_id)
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        buf: &mut [u8],
    ) -> std::io::Result<()> {
        self.inner.read_range_into(blob_id, offset, buf)
    }

    fn prefetch_range_into_reader(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        length: u64,
    ) -> std::io::Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>> {
        self.inner
            .prefetch_range_into_reader(blob_id, offset, length)
    }

    fn runtime(&self) -> Option<&tokio::runtime::Handle> {
        self.inner.runtime()
    }
}

// Field order keeps this key at 16 bytes rather than a padded tuple.
#[derive(Hash, PartialEq, Eq)]
struct ChunkKey {
    block: u64,
    len: u32,
    device: u16,
}

struct Source {
    metadata: BlobMetadata,
    // One destination block per group, not a hash entry per chunk.
    groups: Vec<u64>,
}

impl IncrementalWriter {
    fn compact_existing(
        &mut self,
        reader: &ErofsReader,
        backend: &dyn Backend,
        layout: &FlatLayout,
    ) -> Result<()> {
        for inode in &self.inodes {
            if let InodeData::RegularFile {
                chunk_size_bits, ..
            } = &inode.data
            {
                let size = 1u32
                    .checked_shl(*chunk_size_bits)
                    .ok_or_else(|| Error::InvalidImage("invalid file chunk size".to_string()))?;
                self.chunk_size = self.chunk_size.max(size);
            }
        }
        validate_chunk_size(self.chunk_size)?;
        if self.try_compact_groups(reader, backend, layout)? {
            return Ok(());
        }
        self.prepare_compact_output();
        let result = (|| -> Result<()> {
            let mut copied = HashMap::new();
            for inode_index in 0..self.inodes.len() {
                let (count, chunk_size) = match &self.inodes[inode_index].data {
                    InodeData::RegularFile {
                        chunk_index_entries,
                        chunk_size_bits,
                    } => (chunk_index_entries.len(), 1u64 << chunk_size_bits),
                    _ => continue,
                };
                let nid = self.parent_nids[inode_index];
                let source_inode = reader.inode(nid).context("read compact source inode")?;
                for chunk_index in 0..count {
                    let InodeData::RegularFile {
                        chunk_index_entries,
                        ..
                    } = &self.inodes[inode_index].data
                    else {
                        unreachable!()
                    };
                    let source = chunk_index_entries[chunk_index];
                    if source.is_hole() {
                        continue;
                    }
                    let offset = chunk_index as u64 * chunk_size;
                    let len = (source_inode.size() - offset).min(chunk_size) as u32;
                    let key = ChunkKey {
                        block: source.blkaddr,
                        len,
                        device: source.device_id,
                    };
                    let mut addr = if let Some(&blkaddr) = copied.get(&key) {
                        // Compaction has a single output device; retain only
                        // its block/token, not a padded address per map entry.
                        ErofsChunkAddr {
                            blkaddr,
                            device_id: if blkaddr == EROFS_NULL_ADDR { 0 } else { 1 },
                        }
                    } else {
                        let addr = self.write_upper_chunk_addr_from_source(
                            len as usize,
                            true,
                            |mut dst| {
                                let written = reader
                                    .write_file_data_to(nid, &source_inode, offset, len, &mut dst)
                                    .context("read live compact chunk")?;
                                if written != len as usize {
                                    return Err(Error::InvalidImage(
                                        "short compact chunk read".to_string(),
                                    ));
                                }
                                Ok(())
                            },
                        )?;
                        copied.insert(key, addr.blkaddr);
                        addr
                    };
                    self.resolve_or_track_blob_chunk(inode_index, chunk_index, &mut addr)?;
                    let InodeData::RegularFile {
                        chunk_index_entries,
                        ..
                    } = &mut self.inodes[inode_index].data
                    else {
                        unreachable!()
                    };
                    chunk_index_entries[chunk_index] = addr;
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.discard_current_blob();
            return Err(error);
        }
        self.has_changes = true;
        self.commit_output()
    }

    pub(crate) fn repack_from_reader(
        reader: Arc<ErofsReader>,
        backend: &dyn Backend,
        layout: &FlatLayout,
        options: IncrementalWriterOptions,
        compact_max_layers: usize,
        prepare: impl FnOnce(&RepackResult) -> Result<()>,
    ) -> Result<RepackResult> {
        options.validate()?;
        let limit = compact_max_layers;
        let mut writer = Self::from_reader(reader.clone(), options, ParentMode::Compact)?;
        let device_count = writer.device_slots.len();
        let device_ids = if writer.prune || limit > 0 {
            writer.prune_parent_devices(device_count)?
        } else {
            None
        };
        let mut result = RepackResult {
            pruned: device_ids.is_some(),
            compacted: false,
            blobs: writer.repack_blob_ids()?,
        };
        result.compacted = limit > 0 && result.blobs.len() > limit;
        // The callback stages only live source blobs, while this inode tree
        // and the original reader/device addressing stay resident.
        prepare(&result)?;
        if result.compacted {
            writer.compact_existing(&reader, backend, layout)?;
            result.blobs = writer.repack_blob_ids()?;
        } else if result.pruned {
            let bootstrap = render_bootstrap_remapped(
                &mut writer.inodes,
                writer.epoch,
                &writer.device_slots,
                &writer.uuid,
                device_ids.as_deref(),
            )?;
            fs::create_dir_all(&writer.output_dir)?;
            writer.save_bootstrap(&bootstrap)?;
        }
        Ok(result)
    }

    fn repack_blob_ids(&self) -> Result<Vec<crate::BlobId>> {
        let mut seen = std::collections::HashSet::new();
        let mut blobs = Vec::new();
        for slot in &self.device_slots {
            let id = crate::BlobId::from(slot.blob_id()?);
            if seen.insert(id) {
                blobs.push(id);
            }
        }
        Ok(blobs)
    }

    fn prepare_compact_output(&mut self) {
        let old_device_count = self.device_slots.len();
        self.device_slots.clear();
        // Every retained prefetch target now belongs to the single output blob.
        self.inodes[0].xattrs.retain_mut(|entry| {
            if !entry.is_nydus_prefetch_blobs() {
                return true;
            }
            let keep = parse_prefetch_blobs_value(&entry.value)
                .iter()
                .any(|id| usize::from(*id) <= old_device_count);
            if keep {
                entry.value = b"1".to_vec();
            }
            keep
        });
    }

    /// Returns false before creating output when compression/digest conversion
    /// needs the decoded path. Partially live groups are copied whole.
    fn try_compact_groups(
        &mut self,
        reader: &ErofsReader,
        backend: &dyn Backend,
        layout: &FlatLayout,
    ) -> Result<bool> {
        let infos = reader.blob_infos().context("read compact blob table")?;
        let mut sources: Vec<Option<Source>> = (0..infos.len()).map(|_| None).collect();
        let mut copy_buffer_size = 0usize;
        let mut live_blocks = 0u64;
        let mut source_index_bytes = 0u64;
        let mut max_blocks = 0u32;
        let mut minimum = u32::MAX;
        let mut second_minimum = u32::MAX;
        let mut smallest = None;
        let mut natural_last = None;
        for inode in &self.inodes {
            let InodeData::RegularFile {
                chunk_index_entries,
                chunk_size_bits,
            } = &inode.data
            else {
                continue;
            };
            for (chunk_index, entry) in chunk_index_entries.iter().enumerate() {
                let (index, offset) = match locate_compact_chunk(infos, layout, entry)? {
                    ChunkLocation::Hole => continue,
                    ChunkLocation::Local { .. } => return Ok(false),
                    ChunkLocation::Blob { index, offset } => (usize::from(index) - 1, offset),
                };
                let source = sources.get_mut(index).ok_or_else(|| {
                    Error::InvalidImage("compact references missing blob".to_string())
                })?;
                if source.is_none() {
                    let metadata = backend
                        .read_blob_metadata(&infos[index].blob_id)
                        .context("read compact source metadata")?;
                    if metadata.is_ondemand()
                        || (self.digester.is_some() && metadata.digester()? != self.digester)
                    {
                        return Ok(false);
                    }
                    source_index_bytes += metadata
                        .logical_block_count()
                        .div_ceil(u64::from(metadata.blocks_per_chunk_group_index()))
                        * 4;
                    max_blocks = max_blocks.max(metadata.max_blocks_per_chunk_group());
                    let groups = vec![UNUSED; metadata.chunk_group_count()];
                    *source = Some(Source { metadata, groups });
                }
                let source = source.as_mut().expect("source initialized");
                let group_index = source.metadata.chunk_group_index(offset).ok_or_else(|| {
                    Error::InvalidImage("compact chunk is outside source groups".to_string())
                })?;
                let group = source
                    .metadata
                    .chunk_group(group_index)
                    .expect("group index validated");
                if !group.is_uncompressed(&source.metadata)
                    && source.metadata.compressor() != self.compressor
                {
                    return Ok(false);
                }
                let size = 1u64 << chunk_size_bits;
                let len = (inode.size - chunk_index as u64 * size).min(size);
                // A source filesystem chunk may span multiple encoding groups.
                // Reencoding handles that layout without retaining adjacency.
                if offset
                    .checked_add(len)
                    .is_none_or(|end| end > group.logical_offset() + group.logical_size())
                {
                    return Ok(false);
                }
                if source.groups[group_index] == UNUSED {
                    let pair = (index, group_index);
                    let count = group.logical_block_count();
                    live_blocks += u64::from(count);
                    if count < minimum {
                        second_minimum = minimum;
                        minimum = count;
                        smallest = Some(pair);
                    } else {
                        second_minimum = second_minimum.min(count);
                        if count == minimum && Some(pair) > smallest {
                            smallest = Some(pair);
                        }
                    }
                    natural_last = natural_last.max(Some(pair));
                    source.groups[group_index] = LIVE;
                    copy_buffer_size = copy_buffer_size
                        .saturating_add(group.compressed_size() as usize)
                        .min(COPY_WINDOW);
                }
            }
        }
        if copy_buffer_size == 0 {
            return Ok(false);
        }

        let Some(stride) =
            compact_index_stride(live_blocks, second_minimum, max_blocks, source_index_bytes)?
        else {
            return Ok(false);
        };
        let deferred = smallest.filter(|pair| Some(*pair) != natural_last);

        fs::create_dir_all(&self.output_dir)?;
        let (temp_path, file) = self.create_temp_file("incremental")?;
        let result = (|| -> Result<()> {
            let mut output = HashingWriter::new(BufWriter::new(file), Some(Sha256::new()));
            let mut scratch = vec![0; copy_buffer_size];
            let mut rows = Vec::new();
            let mut lengths = Vec::new();
            let mut digests = Vec::new();
            let mut compressed = 0u64;
            let mut blocks = 0u32;
            // Copy in source order, deferring only the smallest group so its
            // short size need not constrain the output index stride.
            for pass in 0..sources.len() + usize::from(deferred.is_some()) {
                let (index, only_tail) = if pass == sources.len() {
                    (deferred.expect("tail pass").0, true)
                } else {
                    (pass, false)
                };
                let Some(source) = &mut sources[index] else {
                    continue;
                };
                let range = if only_tail {
                    let tail = deferred.expect("tail pass").1;
                    tail..tail + 1
                } else {
                    0..source.metadata.chunk_group_count()
                };
                let mut pending: Option<Range<u64>> = None;
                for group_index in range {
                    if source.groups[group_index] != LIVE
                        || (!only_tail && deferred == Some((index, group_index)))
                    {
                        continue;
                    }
                    let group = source
                        .metadata
                        .chunk_group(group_index)
                        .expect("live group");
                    rows.push(BlobMetadataChunkGroup::new(
                        compressed,
                        blocks,
                        u32::try_from(lengths.len()).map_err(|_| {
                            Error::Overflow("compact holds too many chunks".to_string())
                        })?,
                        group.uncompressed_size(),
                        group.uncompressed_crc32(),
                    ));
                    let range = group.compressed_range();
                    if let Some(run) = &mut pending {
                        if run.end == range.start && range.end - run.start <= COPY_WINDOW as u64 {
                            run.end = range.end;
                        } else {
                            copy_encoded_range(
                                &mut output,
                                backend,
                                &infos[index].blob_id,
                                run.clone(),
                                &mut scratch,
                            )?;
                            *run = range;
                        }
                    } else {
                        pending = Some(range);
                    }
                    source.groups[group_index] = u64::from(blocks);
                    compressed = compressed
                        .checked_add(u64::from(group.compressed_size()))
                        .ok_or_else(|| {
                            Error::Overflow("compact payload size overflow".to_string())
                        })?;
                    blocks = blocks
                        .checked_add(group.logical_block_count())
                        .ok_or_else(|| {
                            Error::Overflow("compact logical block space exceeds u32".to_string())
                        })?;
                    for member in group.chunk_range() {
                        let length = source.metadata.chunk_length(member).ok_or_else(|| {
                            Error::InvalidImage(
                                "compact source chunk length is missing".to_string(),
                            )
                        })?;
                        lengths.push(BlobMetadataChunkLength::new(length));
                    }
                    if self.digester.is_some() {
                        digests.push(source.metadata.chunk_group_digest(group_index).ok_or_else(
                            || {
                                Error::InvalidImage(
                                    "compact source group digest is missing".to_string(),
                                )
                            },
                        )?);
                    }
                }
                if let Some(run) = pending {
                    copy_encoded_range(
                        &mut output,
                        backend,
                        &infos[index].blob_id,
                        run,
                        &mut scratch,
                    )?;
                }
            }
            rows.push(BlobMetadataChunkGroup::new(
                compressed,
                blocks,
                u32::try_from(lengths.len())
                    .map_err(|_| Error::Overflow("compact holds too many chunks".to_string()))?,
                0,
                0,
            ));
            drop(scratch);
            let metadata = BlobMetadata::new_upper(
                max_blocks,
                stride,
                self.compressor,
                self.digester,
                rows,
                lengths,
                digests,
            )?;
            blob::finish_full_blob(&mut output, compressed, None, Some(&metadata))?;
            let digest = output
                .finish()
                .context("flush compact blob")?
                .expect("compact hashing enabled");
            self.publish_blob_artifact(&temp_path, &digest, &metadata)?;
            drop(metadata);

            self.prepare_compact_output();
            for inode in &mut self.inodes {
                let InodeData::RegularFile {
                    chunk_index_entries,
                    ..
                } = &mut inode.data
                else {
                    continue;
                };
                for entry in chunk_index_entries {
                    let (index, offset) = match locate_compact_chunk(infos, layout, entry)? {
                        ChunkLocation::Hole => continue,
                        ChunkLocation::Blob { index, offset } => (usize::from(index) - 1, offset),
                        ChunkLocation::Local { .. } => {
                            unreachable!("local chunks use decoded path")
                        }
                    };
                    let source = sources[index].as_ref().expect("live source");
                    let group_index = source
                        .metadata
                        .chunk_group_index(offset)
                        .expect("live group");
                    let group = source
                        .metadata
                        .chunk_group(group_index)
                        .expect("live group");
                    entry.blkaddr = source.groups[group_index]
                        + (offset - group.logical_offset()) / u64::from(EROFS_BLOCK_SIZE);
                    entry.device_id = 1;
                }
            }
            self.device_slots
                .push(ErofsDeviceSlot::with_blob_id(u64::from(blocks), &digest)?);
            drop(sources);
            let bootstrap = render_bootstrap_remapped(
                &mut self.inodes,
                self.epoch,
                &self.device_slots,
                &self.uuid,
                None,
            )?;
            self.save_bootstrap(&bootstrap)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result.map(|_| true)
    }
}

/// All but the final group must span at least one index stride. The smallest
/// group is deferred; the second smallest therefore determines that stride.
fn compact_index_stride(
    blocks: u64,
    second_minimum: u32,
    max_blocks: u32,
    source_index_bytes: u64,
) -> Result<Option<u32>> {
    u32::try_from(blocks)
        .map_err(|_| Error::Overflow("compact logical block space exceeds u32".to_string()))?;
    let stride = if second_minimum == u32::MAX {
        max_blocks
    } else {
        1u32 << second_minimum
            .checked_ilog2()
            .ok_or_else(|| Error::InvalidImage("compact source group is empty".to_string()))?
    };
    let bytes = blocks.div_ceil(u64::from(stride)) * 4;
    Ok((bytes.saturating_sub(source_index_bytes) <= MAX_EXTRA_INDEX_BYTES).then_some(stride))
}

/// Resolve mapped chunks through the existing binary-search layout iterator.
/// Unmapped (legacy) slots must not turn bootstrap-local bytes into blob data.
fn locate_compact_chunk(
    infos: &[RawBlobInfo],
    layout: &FlatLayout,
    entry: &ErofsChunkAddr,
) -> Result<ChunkLocation> {
    if entry.is_hole() || entry.device_id != 0 {
        return Ok(locate_chunk(infos, entry.blkaddr, entry.device_id)?);
    }
    let offset = entry
        .blkaddr
        .checked_mul(u64::from(EROFS_BLOCK_SIZE))
        .ok_or_else(|| Error::Overflow("compact chunk address overflow".to_string()))?;
    if let Some(Segment::Blob { range, .. }) = layout.segments(offset, 1)?.next() {
        if infos[usize::from(range.index) - 1].mapped_blkaddr != 0 {
            return Ok(ChunkLocation::Blob {
                index: range.index,
                offset: range.offset,
            });
        }
    }
    Ok(ChunkLocation::Local { offset })
}

fn copy_encoded_range(
    output: &mut dyn Write,
    backend: &dyn Backend,
    id: &[u8; EROFS_BLOB_ID_SIZE],
    range: Range<u64>,
    scratch: &mut [u8],
) -> Result<()> {
    let mut pos = range.start;
    while pos < range.end {
        let len = (range.end - pos).min(scratch.len() as u64) as usize;
        backend
            .read_range_into(id, pos, &mut scratch[..len])
            .context("copy encoded compact groups")?;
        output.write_all(&scratch[..len])?;
        pos += len as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_telemetry::metrics::Metrics;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingBackend {
        local: nydus_backend::Local,
        reads: AtomicUsize,
        metadata_reads: AtomicUsize,
        fail_after: usize,
        largest_read: AtomicUsize,
    }

    impl Backend for CountingBackend {
        fn metrics(&self) -> &Arc<Metrics> {
            self.local.metrics()
        }

        fn read_blob_metadata(&self, id: &[u8; EROFS_BLOB_ID_SIZE]) -> io::Result<BlobMetadata> {
            self.metadata_reads.fetch_add(1, Ordering::Relaxed);
            self.local.read_blob_metadata(id)
        }

        fn read_range_into(
            &self,
            id: &[u8; EROFS_BLOB_ID_SIZE],
            offset: u64,
            buf: &mut [u8],
        ) -> io::Result<()> {
            self.largest_read.fetch_max(buf.len(), Ordering::Relaxed);
            if self.reads.fetch_add(1, Ordering::Relaxed) >= self.fail_after {
                return Err(io::Error::other("injected compact read failure"));
            }
            self.local.read_range_into(id, offset, buf)
        }

        fn prefetch_range_into_reader(
            &self,
            id: &[u8; EROFS_BLOB_ID_SIZE],
            offset: u64,
            length: u64,
        ) -> io::Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>> {
            self.largest_read
                .fetch_max(length as usize, Ordering::Relaxed);
            if self.reads.fetch_add(1, Ordering::Relaxed) >= self.fail_after {
                return Err(io::Error::other("injected compact read failure"));
            }
            self.local.prefetch_range_into_reader(id, offset, length)
        }
    }

    #[test]
    fn repack_reuses_metadata_and_rejects_invalid_sidecars() {
        let temp = tempfile::tempdir().unwrap();
        let mut writer =
            IncrementalWriter::create(IncrementalWriterOptions::new(temp.path().to_path_buf()))
                .unwrap();
        writer
            .replace_file(Path::new("data"), vec![b'A'; 4096])
            .unwrap();
        writer.commit().unwrap();
        let reader = ErofsReader::open_metadata_only(&temp.path().join("image.boot")).unwrap();
        let id = reader.blob_infos().unwrap()[0].blob_id;
        let backend = CountingBackend {
            local: nydus_backend::Local::new(temp.path().to_path_buf(), Arc::new(Metrics::new())),
            reads: AtomicUsize::new(0),
            metadata_reads: AtomicUsize::new(0),
            fail_after: usize::MAX,
            largest_read: AtomicUsize::new(0),
        };
        let metadata = backend.local.read_blob_metadata(&id).unwrap();
        for (name, contents, expected_reads) in [
            ("missing", None, 1),
            ("cached", Some(true), 0),
            ("invalid", Some(false), 0),
        ] {
            let cache = temp.path().join(name);
            fs::create_dir(&cache).unwrap();
            let sidecar = cache.join(format!(
                "{}{}",
                crate::BlobId::from(id),
                BlobMetadata::SUFFIX
            ));
            match contents {
                Some(true) => metadata.save(&sidecar).unwrap(),
                Some(false) => fs::write(&sidecar, b"invalid").unwrap(),
                None => {}
            }
            backend.metadata_reads.store(0, Ordering::Relaxed);
            let cached = RepackBackend::new(&backend, Some(&cache));
            assert_eq!(
                cached.read_blob_metadata(&id).is_ok(),
                contents != Some(false)
            );
            assert_eq!(
                backend.metadata_reads.load(Ordering::Relaxed),
                expected_reads
            );
        }
        let uncached = RepackBackend::new(&backend, None);
        uncached.read_blob_metadata(&id).unwrap();
        assert_eq!(backend.metadata_reads.load(Ordering::Relaxed), 1);
        let mut bytes = [0; 16];
        uncached.read_range_into(&id, 0, &mut bytes).unwrap();
        let source = fs::read(temp.path().join(crate::BlobId::from(id).to_string())).unwrap();
        assert_eq!(bytes, source[..16]);
    }

    #[test]
    fn compact_index_preflight_bounds_amplification_and_address_space() {
        assert_eq!(std::mem::size_of::<ChunkKey>(), 16);
        assert_eq!(compact_index_stride(1025, 512, 512, 16).unwrap(), Some(512));
        assert_eq!(
            compact_index_stride(1, u32::MAX, 512, 4).unwrap(),
            Some(512)
        );
        let boundary = MAX_EXTRA_INDEX_BYTES / 4 + 1;
        assert_eq!(compact_index_stride(boundary, 1, 512, 4).unwrap(), Some(1));
        assert_eq!(compact_index_stride(boundary + 1, 1, 512, 4).unwrap(), None);
        assert!(compact_index_stride(u64::from(u32::MAX) + 1, 512, 512, 4).is_err());
    }

    #[test]
    fn compact_bounds_reads_for_large_runs_and_large_groups() {
        for (size, count) in [(COPY_WINDOW / 2, 3), (COPY_WINDOW * 2, 1)] {
            let temp = tempfile::tempdir().unwrap();
            let mut options = IncrementalWriterOptions::new(temp.path().to_path_buf());
            options.chunk_size = size as u32;
            options.chunk_group_min_size = size as u32;
            options.compressor = BlobMetadataCompressor::None;
            let mut writer = IncrementalWriter::create(options).unwrap();
            writer
                .replace_file(Path::new("data"), vec![b'A'; size * count])
                .unwrap();
            writer.commit().unwrap();
            let path = temp.path().join("image.boot");
            let reader = Arc::new(ErofsReader::open_metadata_only(&path).unwrap());
            let layout = FlatLayout::new(
                fs::metadata(&path).unwrap().len(),
                reader.blob_infos().unwrap(),
            )
            .unwrap();
            let backend = CountingBackend {
                local: nydus_backend::Local::new(
                    temp.path().to_path_buf(),
                    Arc::new(Metrics::new()),
                ),
                reads: AtomicUsize::new(0),
                metadata_reads: AtomicUsize::new(0),
                fail_after: usize::MAX,
                largest_read: AtomicUsize::new(0),
            };
            let mut imported = IncrementalWriter::from_reader(
                reader.clone(),
                IncrementalWriterOptions::new(temp.path().to_path_buf()),
                ParentMode::Compact,
            )
            .unwrap();
            assert!(imported
                .try_compact_groups(&reader, &backend, &layout)
                .unwrap());
            assert_eq!(backend.reads.load(Ordering::Relaxed), 2);
            assert_eq!(backend.largest_read.load(Ordering::Relaxed), COPY_WINDOW);
        }
    }

    #[test]
    fn compact_coalesces_live_runs_and_cleans_up_mid_copy_failure() {
        for (gap, fail_after, expected_reads) in
            [(false, usize::MAX, 1), (true, usize::MAX, 2), (true, 1, 2)]
        {
            let temp = tempfile::tempdir().unwrap();
            let mut options = IncrementalWriterOptions::new(temp.path().to_path_buf());
            options.chunk_size = EROFS_BLOCK_SIZE;
            options.chunk_group_min_size = EROFS_BLOCK_SIZE;
            let mut writer = IncrementalWriter::create(options).unwrap();
            let data = vec![b'A'; EROFS_BLOCK_SIZE as usize * 4];
            writer.replace_file(Path::new("data"), data).unwrap();
            writer.commit().unwrap();
            let path = temp.path().join("image.boot");
            let reader = Arc::new(ErofsReader::open_metadata_only(&path).unwrap());
            let before = fs::read(&path).unwrap();
            // Turn the second chunk into a hole after build, leaving its encoded
            // group in the source blob so the copy must not bridge that gap.
            let mut imported = IncrementalWriter::from_reader(
                reader.clone(),
                IncrementalWriterOptions::new(temp.path().to_path_buf()),
                ParentMode::Compact,
            )
            .unwrap();
            assert!(imported.path_index.is_empty());
            assert!(imported.parent_reader.is_none());
            if gap {
                let InodeData::RegularFile {
                    chunk_index_entries,
                    ..
                } = &mut imported.inodes[1].data
                else {
                    panic!("regular file")
                };
                // The second stored group remains unreferenced, between live groups.
                chunk_index_entries[1] = ErofsChunkAddr {
                    device_id: 0,
                    blkaddr: EROFS_NULL_ADDR,
                };
            }
            let layout =
                FlatLayout::new(before.len() as u64, reader.blob_infos().unwrap()).unwrap();
            let backend = CountingBackend {
                local: nydus_backend::Local::new(
                    temp.path().to_path_buf(),
                    Arc::new(Metrics::new()),
                ),
                reads: AtomicUsize::new(0),
                metadata_reads: AtomicUsize::new(0),
                fail_after,
                largest_read: AtomicUsize::new(0),
            };
            let result = imported.try_compact_groups(&reader, &backend, &layout);
            assert_eq!(backend.reads.load(Ordering::Relaxed), expected_reads);
            if fail_after == usize::MAX {
                assert!(result.unwrap());
            } else {
                assert!(result.is_err());
                assert_eq!(fs::read(&path).unwrap(), before);
            }
            assert!(!fs::read_dir(temp.path()).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".nydus-")
            }));
        }
    }
}

// Tracks only files this compact created. Existing data blobs are never
// overwritten or removed; sidecars are atomically regenerated from metadata.
#[derive(Default)]
pub(super) struct CompactArtifacts {
    created: Vec<PathBuf>,
}

impl CompactArtifacts {
    pub(super) fn publish(
        &mut self,
        temp: &Path,
        dir: &Path,
        digest: &[u8; EROFS_BLOB_ID_SIZE],
        metadata: &BlobMetadata,
    ) -> Result<()> {
        self.created.push(temp.to_path_buf());
        let path = digest_named_blob_path(dir, digest);
        match fs::hard_link(temp, &path) {
            Ok(()) => self.created.push(path.clone()),
            Err(err) if err.kind() == ErrorKind::AlreadyExists && path.is_file() => {}
            Err(err) => return Err(err.into()),
        }
        fs::remove_file(temp)?;
        let sidecar = crate::build::blob_metadata_sidecar_path(&path);
        let existed = match fs::symlink_metadata(&sidecar) {
            Ok(_) => true,
            Err(err) if err.kind() == ErrorKind::NotFound => false,
            Err(err) => return Err(err.into()),
        };
        // Regenerate even an existing sidecar: an interrupted old publisher
        // may have left a truncated file under the correct digest name.
        let staged = temp.with_extension("meta.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)?;
        self.created.push(staged.clone());
        metadata.write_to(&mut file)?;
        drop(file);
        fs::rename(&staged, &sidecar)?;
        if !existed {
            self.created.push(sidecar);
        }
        Ok(())
    }

    pub(super) fn keep(&mut self) {
        self.created.clear();
    }
}

impl Drop for CompactArtifacts {
    fn drop(&mut self) {
        for path in self.created.iter().rev() {
            let _ = fs::remove_file(path);
        }
    }
}
