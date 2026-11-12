//! A decoded-cache capture, encoded only after mutable sources are released.
use super::*;
use crate::build::bootstrap::patch_device_slots;
use nydus_format::erofs::{EROFS_DEVICESLOT_SIZE, EROFS_SUPER_OFFSET};
use serde::{Deserialize, Serialize};
use std::io::{BufReader, BufWriter, Read};

pub(super) const CAPTURE_BLOB_ID: [u8; 32] = [0; 32];
const MAX_PLAN_SIZE: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CapturedGroup {
    pub first_block: u64,
    pub lengths: Vec<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    version: u32,
    chunk_size: u32,
    chunk_group_minimum_size: u32,
    compressor: String,
    digester: Option<String>,
    groups: Vec<CapturedGroup>,
    device_index: Option<usize>,
}

#[derive(Serialize)]
struct Finalized {
    digest: String,
    size: u64,
    groups: usize,
    data_size: u64,
    meta_size: u64,
    map_size: u64,
}

pub(super) struct CaptureState {
    cache: Box<dyn ChunkGroupCache>,
    groups: Vec<CapturedGroup>,
    budget: PlanBudget,
}

struct PlanBudget {
    bytes: u64,
    limit: u64,
}

impl Write for PlanBudget {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(data.len() as u64)
            .filter(|bytes| *bytes <= self.limit)
            .ok_or_else(|| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "capture plan exceeds metadata limit",
                )
            })?;
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CaptureState {
    pub(super) fn new(cache: Box<dyn ChunkGroupCache>) -> Self {
        Self {
            cache,
            groups: Vec::new(),
            // Reserve the fixed fields, including the widest device index.
            budget: PlanBudget {
                bytes: 512,
                limit: MAX_PLAN_SIZE,
            },
        }
    }

    pub(super) fn write_group(
        &mut self,
        first_block: u64,
        lengths: &[u32],
        payload: &[u8],
    ) -> Result<()> {
        let group = CapturedGroup {
            first_block,
            lengths: lengths.to_vec(),
        };
        serde_json::to_writer(&mut self.budget, &group)
            .map_err(|err| Error::Runtime(err.to_string()))?;
        self.budget.write_all(b",")?;
        self.cache
            .write_group(first_block, lengths, payload)
            .map_err(|err| Error::Runtime(format!("capture data failed: {err}")))?;
        self.groups.push(group);
        Ok(())
    }
}

impl IncrementalWriter {
    /// Capture mutable sources into a caller-owned decoded cache without
    /// compression or payload digests. The caller must seal and retain the cache
    /// before resuming its VM. Capture does not sync files or directories:
    /// successful writes release the mutable source, but do not promise crash
    /// durability. The checkpoint owner handles incomplete output and syncs the
    /// decoded files before publishing ready cache state. `capture.boot` is
    /// provisional, not mountable.
    /// Later, [`encode_cache`] encodes these exact groups without rewriting
    /// the cache or changing any inode chunk addresses.
    pub fn commit_capture<C: ChunkGroupCache + 'static>(mut self, cache: C) -> Result<()> {
        if self
            .device_slots
            .iter()
            .any(|slot| slot.blob_id().is_ok_and(|id| id == CAPTURE_BLOB_ID))
        {
            return Err(Error::InvalidImage(
                "parent uses reserved capture blob ID".to_string(),
            ));
        }
        fs::create_dir_all(&self.output_dir)?;
        self.capture = Some(Arc::new(Mutex::new(CaptureState::new(Box::new(cache)))));
        let bootstrap = self.commit_inner()?;
        let state = self.capture.take().expect("capture state initialized");
        let state = Arc::try_unwrap(state)
            .map_err(|_| Error::Runtime("capture state still borrowed".to_string()))?
            .into_inner()
            .map_err(|_| Error::Runtime("capture layout lock poisoned".to_string()))?;
        let capture = Capture {
            version: 1,
            chunk_size: self.chunk_size,
            chunk_group_minimum_size: self.chunk_group_min_size,
            compressor: self.compressor.to_string(),
            digester: self.digester.map(|digester| digester.to_string()),
            groups: state.groups,
            device_index: self
                .device_slots
                .iter()
                .position(|slot| slot.blob_id().is_ok_and(|id| id == CAPTURE_BLOB_ID)),
        };
        self.save_bootstrap_file("capture.boot", &bootstrap, false)?;
        let output_dir = self.output_dir.clone();
        drop(bootstrap);
        drop(self);
        save_output_file_with(&output_dir, "capture.json", false, |file| {
            let mut writer = BufWriter::new(file);
            serde_json::to_writer(&mut writer, &capture)
                .map_err(|err| Error::Runtime(err.to_string()))?;
            writer.flush()?;
            Ok(())
        })?;
        Ok(())
    }
}

fn read_capture(path: &Path) -> Result<Capture> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_PLAN_SIZE {
        return Err(Error::InvalidImage(
            "capture metadata exceeds size limit".to_string(),
        ));
    }
    serde_json::from_reader(BufReader::new(file.take(MAX_PLAN_SIZE + 1)))
        .map_err(|err| Error::InvalidImage(format!("invalid capture plan: {err}")))
}

/// Encode a sealed capture into `sink`, writing `image.boot`, the metadata
/// sidecar and `cache-result.json` beside the plan. `data` is the retained
/// decoded-cache file, not a guest mapping; it is never modified. No compressed
/// blob is stored locally. Publish neither the cache nor OCI manifest until
/// the caller has verified and committed the streamed upload.
pub fn encode_cache<W: Write>(path: &Path, data: Option<&File>, sink: W) -> Result<()> {
    let plan = read_capture(path)?;
    if plan.version != 1 {
        return Err(Error::InvalidImage(
            "unsupported capture version".to_string(),
        ));
    }
    validate_chunk_size(plan.chunk_size)?;
    validate_chunk_group_min_size(plan.chunk_group_minimum_size)?;
    let compressor = match plan.compressor.as_str() {
        "none" => BlobMetadataCompressor::None,
        "zstd" => BlobMetadataCompressor::Zstd,
        "lz4" => BlobMetadataCompressor::Lz4Block,
        _ => {
            return Err(Error::InvalidImage(
                "invalid capture compressor".to_string(),
            ))
        }
    };
    let digester = match plan.digester.as_deref() {
        None => None,
        Some("blake3") => Some(BlobMetadataDigester::Blake3),
        _ => return Err(Error::InvalidImage("invalid capture digester".to_string())),
    };
    let dir = path
        .parent()
        .ok_or_else(|| Error::InvalidParameter("capture has no directory".to_string()))?;
    let bootstrap_file = File::open(dir.join("capture.boot"))?;
    let reader = ErofsReader::open_metadata_only(&dir.join("capture.boot"))?;
    if reader.sb_offset != EROFS_SUPER_OFFSET as usize
        || bootstrap_file.metadata()?.len() != reader.mmap.len() as u64
    {
        return Err(Error::InvalidImage(
            "capture requires a standalone bootstrap".to_string(),
        ));
    }
    // SAFETY: the sealed capture remains immutable through finalization.
    // Only patched device-table/checksum pages need private copies.
    let mut bootstrap = unsafe { memmap2::MmapOptions::new().map_copy(&bootstrap_file)? };
    let sb = reader.superblock();
    let offset = sb.devt_slotoff() as usize * EROFS_DEVICESLOT_SIZE;
    let mut slots = Vec::with_capacity(sb.extra_devices() as usize);
    for index in 0..sb.extra_devices() as usize {
        let start = offset + index * EROFS_DEVICESLOT_SIZE;
        let bytes = bootstrap
            .get(start..start + EROFS_DEVICESLOT_SIZE)
            .ok_or_else(|| Error::InvalidImage("truncated capture device table".to_string()))?;
        slots.push(*ErofsDeviceSlot::from_bytes(bytes)?);
    }
    let mut blocks = 0u64;
    let max_span =
        u64::from(plan.chunk_size).max(u64::from(plan.chunk_group_minimum_size) * 4) / 4096;
    for group in &plan.groups {
        if group.first_block != blocks
            || group.lengths.is_empty()
            || group
                .lengths
                .iter()
                .any(|len| *len == 0 || *len > plan.chunk_size)
        {
            return Err(Error::InvalidImage(
                "invalid capture group layout".to_string(),
            ));
        }
        let span = group
            .lengths
            .iter()
            .map(|len| u64::from(*len).div_ceil(4096))
            .sum::<u64>();
        if span > max_span {
            return Err(Error::InvalidImage(
                "capture group exceeds geometry".to_string(),
            ));
        }
        blocks = blocks
            .checked_add(span)
            .filter(|end| *end <= u32::MAX as u64)
            .ok_or_else(|| Error::InvalidImage("capture block count overflow".to_string()))?;
    }
    let result = if let Some(index) = plan.device_index {
        let slot = slots
            .get(index)
            .ok_or_else(|| Error::InvalidImage("capture device missing".to_string()))?;
        if slot.blob_id()? != CAPTURE_BLOB_ID
            || slot.blocks() != blocks
            || slots.iter().enumerate().any(|(other, slot)| {
                other != index && slot.blob_id().is_ok_and(|id| id == CAPTURE_BLOB_ID)
            })
        {
            return Err(Error::InvalidImage(
                "capture device does not match layout".to_string(),
            ));
        }
        let data = data.ok_or_else(|| {
            Error::InvalidParameter("capture requires a decoded cache FD".to_string())
        })?;
        let data_size = blocks * 4096;
        if !data.metadata()?.is_file() || data.metadata()?.len() != data_size {
            return Err(Error::InvalidImage(
                "decoded cache length differs from capture".to_string(),
            ));
        }
        let mut writer = BlobWriter::new(
            sink,
            plan.chunk_size,
            compressor,
            digester,
            true,
            BlobLayout::ChunkGroups {
                chunk_group_min_size: plan.chunk_group_minimum_size,
            },
        )?;
        for group in &plan.groups {
            let size = group.lengths.iter().map(|len| *len as usize).sum();
            let mut payload = writer.take_source_buffer();
            payload.resize(size, 0);
            let mut block = group.first_block;
            let mut cursor = 0;
            let mut run_cursor = 0;
            let mut run_block = block;
            for &len in &group.lengths {
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
            writer.write_placed_group(group.first_block, &group.lengths, payload)?;
        }
        writer.finish()?;
        let finished = finish_upper_blob(writer)?;
        if finished.blob_blocks != blocks
            || finished.blob_metadata.chunk_group_count() != plan.groups.len()
        {
            return Err(Error::InvalidImage(
                "encoded capture layout changed".to_string(),
            ));
        }
        slots[index].set_blob_id(&finished.full_blob_digest);
        patch_device_slots(&mut bootstrap, &slots)?;
        let digest = hex::encode(finished.full_blob_digest);
        save_blob_metadata_sidecar(&finished.blob_metadata, &dir.join(&digest))?;
        Finalized {
            digest: format!("sha256:{digest}"),
            size: finished.blob_size,
            groups: plan.groups.len(),
            data_size,
            meta_size: finished.blob_metadata.size(),
            map_size: 4096 + (plan.groups.len() as u64).div_ceil(8),
        }
    } else {
        if !plan.groups.is_empty()
            || slots
                .iter()
                .any(|slot| slot.blob_id().is_ok_and(|id| id == CAPTURE_BLOB_ID))
        {
            return Err(Error::InvalidImage(
                "parent-only capture has upper data".to_string(),
            ));
        }
        Finalized {
            digest: String::new(),
            size: 0,
            groups: 0,
            data_size: 0,
            meta_size: 0,
            map_size: 0,
        }
    };
    save_output_file(dir, "image.boot", &bootstrap, true)?;
    let result = serde_json::to_vec(&result).map_err(|err| Error::Runtime(err.to_string()))?;
    save_output_file(dir, "cache-result.json", &result, true)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountCache(Arc<AtomicUsize>);
    impl ChunkGroupCache for CountCache {
        fn write_group(&mut self, _: u64, _: &[u32], _: &[u8]) -> std::io::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn plan_limit_is_checked_before_writing_the_next_group() {
        let writes = Arc::new(AtomicUsize::new(0));
        let mut state = CaptureState::new(Box::new(CountCache(writes.clone())));
        let group = CapturedGroup {
            first_block: 0,
            lengths: vec![4096],
        };
        state.budget.limit =
            state.budget.bytes + serde_json::to_vec(&group).unwrap().len() as u64 + 1;
        state.write_group(0, &[4096], &[42; 4096]).unwrap();
        assert!(state.write_group(1, &[4096], &[42; 4096]).is_err());
        assert_eq!(state.groups.len(), 1);
        assert_eq!(writes.load(Ordering::Relaxed), 1);
    }
}
