//! The `optimize` pipeline: turning a recorded chunk group access trace into
//! an "ondemand" blob plus a rewritten bootstrap that prefetches it first.
//!
//! This is a top-level pipeline composing the read stack ([`nydus_core::reader`],
//! `nydus-storage`) with the builder ([`crate::build`]): access patterns
//! come from the apiserver `/trace` endpoint of a running `nydus fuse` mount
//! ([`load_patterns_from_apiserver`]) or from a saved JSON trace document
//! ([`load_patterns_from_file`]); [`build_ondemand_blob`] then copies the
//! accessed chunk groups out of the source blobs, byte for byte, into a
//! REDIRECT blob in access order, and assembles the ondemand artifact and
//! bootstrap in memory.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::build::assemble_ondemand_artifact;
use crate::build::merge::rewrite_bootstrap_with_ondemand_blob;
use crate::parse_unix_address;
use nydus_backend::{BlobBackend, ReadContext, ReadKind};
use nydus_core::reader::RawBlobInfo;
use nydus_core::ErofsReader;
use nydus_error::{Context, Error, Result};
use nydus_format::blob::{
    BlobFooter, BlobMetadata, BlobMetadataChunkGroup, BlobMetadataCompressor, BlobMetadataDigester,
    BlobMetadataRedirect,
};
use nydus_format::erofs::EROFS_BLOB_ID_SIZE;
use nydus_storage::access_trace::{TraceDocument, TraceEntry, TRACE_DOCUMENT_VERSION};
use nydus_storage::cache::{decode_chunk_group_from_window, LocalBlobCache};

/// Longest contiguous run of source chunk groups fetched in one backend
/// read while copying them into the ondemand blob.
const COPY_READ_SIZE: u64 = 16 * 1024 * 1024;

/// The result of [`build_ondemand_blob`]: the assembled ondemand artifact and
/// the rewritten bootstrap, ready to be written out by the caller.
pub struct OndemandBlob {
    /// The ondemand artifact bytes `[chunk groups][blob.meta][footer]`.
    pub artifact: Vec<u8>,
    /// SHA256 of the whole artifact (the ondemand blob's name).
    pub full_blob_digest: [u8; EROFS_BLOB_ID_SIZE],
    pub blob_metadata: BlobMetadata,
    pub footer: BlobFooter,
    /// The parent bootstrap rewritten so the runtime prefetches the ondemand
    /// blob first.
    pub bootstrap: Vec<u8>,
    /// Total size of the ondemand blob's address space in blocks.
    pub uncompressed_blocks: u64,
    /// Number of distinct source blobs the accessed chunk groups came from.
    pub source_blob_count: usize,
}

/// One validated chunk group reference from the trace: a [`TraceEntry`]
/// narrowed to the device-table index width, deduplicated and
/// order-preserving.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ChunkGroupRef {
    pub blob_index: u16,
    /// The chunk group's index within the source blob.
    pub chunk_group_index: u32,
}

/// Build an "ondemand" REDIRECT blob from a `/trace` access pattern and
/// rewrite the bootstrap so the runtime prefetches it first, landing the
/// access-ordered hot set in the source blobs' caches before on-demand reads
/// arrive.
///
/// Every traced chunk group's encoded payload is read from its source blob
/// (and decoded once to validate it), then appended verbatim to the new
/// blob in access order together with its chunk lengths and digests; the
/// redirect table names the source of every copy. The bootstrap keeps every
/// chunk index as it was: the ondemand blob is never read through it.
pub fn build_ondemand_blob(
    parent_bootstrap: &Path,
    patterns: &[ChunkGroupRef],
    backend: Arc<dyn BlobBackend>,
    cache_dir: &Path,
) -> Result<OndemandBlob> {
    let reader = ErofsReader::open_metadata_only(parent_bootstrap).with_context(|| {
        format!(
            "failed to open parent bootstrap: {}",
            parent_bootstrap.display()
        )
    })?;
    let blob_infos = reader.blob_infos()?.to_vec();
    let infos_by_index: HashMap<u16, &RawBlobInfo> = blob_infos
        .iter()
        .map(|info| (info.blob_index, info))
        .collect();
    drop(reader);

    // Open every source blob the trace names, for its blob meta. The copies
    // are byte-exact, so every source must share the ondemand blob's chunk
    // size and compressor; plain-stored groups fit under any compressor.
    let mut sources: HashMap<u16, LocalBlobCache> = HashMap::new();
    let mut wanted: HashMap<u16, BTreeSet<u32>> = HashMap::new();
    for reference in patterns {
        let blob_index = reference.blob_index;
        if let std::collections::hash_map::Entry::Vacant(slot) = sources.entry(blob_index) {
            let info = infos_by_index.get(&blob_index).ok_or_else(|| {
                Error::InvalidParameter(format!("pattern references unknown blob {blob_index}"))
            })?;
            let cache =
                LocalBlobCache::open(info.blob_id, blob_index as u32, cache_dir, backend.clone())
                    .with_context(|| format!("failed to open source blob: {blob_index}"))?;
            if cache.blob_metadata().is_redirect() {
                return Err(Error::InvalidImage(format!(
                    "source blob {blob_index} is already an ondemand blob; refusing to optimize"
                )));
            }
            slot.insert(cache);
        }
        let meta = sources[&blob_index].blob_metadata();
        if reference.chunk_group_index as usize >= meta.chunk_group_count() {
            return Err(Error::InvalidParameter(format!(
                "pattern references chunk group {} of blob {blob_index}, which has {} chunk groups",
                reference.chunk_group_index,
                meta.chunk_group_count()
            )));
        }
        wanted
            .entry(blob_index)
            .or_default()
            .insert(reference.chunk_group_index);
    }
    let mut chunk_block_count = None;
    let mut compressor = BlobMetadataCompressor::None;
    let mut digester = BlobMetadataDigester::Blake3;
    for (blob_index, cache) in &sources {
        let meta = cache.blob_metadata();
        match chunk_block_count {
            None => chunk_block_count = Some(meta.chunk_block_count()),
            Some(blocks) if blocks != meta.chunk_block_count() => {
                return Err(Error::InvalidImage(format!(
                    "source blob {blob_index} uses a {} byte chunk size, the other traced blobs {}",
                    meta.chunk_size(),
                    blocks * nydus_format::erofs::EROFS_BLOCK_SIZE
                )));
            }
            Some(_) => {}
        }
        match (compressor, meta.compressor()) {
            (_, BlobMetadataCompressor::None) => {}
            (BlobMetadataCompressor::None, source) => compressor = source,
            (current, source) if current != source => {
                return Err(Error::InvalidImage(format!(
                    "source blob {blob_index} is compressed with {source}, the other traced blobs with {current}"
                )));
            }
            _ => {}
        }
        if meta.digester() == BlobMetadataDigester::None {
            digester = BlobMetadataDigester::None;
        }
    }
    let Some(chunk_block_count) = chunk_block_count else {
        return Err(Error::InvalidParameter(
            "the trace names no chunk groups".to_string(),
        ));
    };

    // Fetch the encoded groups blob by blob, consecutive groups in one
    // backend read, and decode each once to validate the copy.
    let mut encoded: HashMap<ChunkGroupRef, Vec<u8>> = HashMap::with_capacity(patterns.len());
    for (blob_index, indexes) in &wanted {
        let cache = &sources[blob_index];
        let meta = cache.blob_metadata();
        let blob_id = infos_by_index[blob_index].blob_id;
        let indexes: Vec<u32> = indexes.iter().copied().collect();
        let mut start = 0;
        while start < indexes.len() {
            let first = meta.chunk_group(indexes[start] as usize).unwrap();
            let mut end = start + 1;
            while end < indexes.len() && indexes[end] == indexes[end - 1] + 1 {
                let next = meta.chunk_group(indexes[end] as usize).unwrap();
                if next.compressed_range().end - first.compressed_offset() > COPY_READ_SIZE {
                    break;
                }
                end += 1;
            }
            let last = meta.chunk_group(indexes[end - 1] as usize).unwrap();
            let len = usize::try_from(last.compressed_range().end - first.compressed_offset())
                .map_err(|err| Error::Overflow(format!("copy read exceeds usize: {err}")))?;
            let mut window = vec![0u8; len];
            let ctx = ReadContext::chunk_group(
                ReadKind::Prefetch,
                first.uncompressed_offset(),
                last.uncompressed_range().end - first.uncompressed_offset(),
            );
            backend
                .read_range_into(&blob_id, first.compressed_offset(), &mut window, ctx)
                .with_context(|| {
                    format!(
                        "failed to read chunk groups {}..={} of blob {blob_index}",
                        indexes[start],
                        indexes[end - 1]
                    )
                })?;
            let mut scratch = Vec::new();
            for &index in &indexes[start..end] {
                let group = meta.chunk_group(index as usize).unwrap();
                decode_chunk_group_from_window(
                    meta,
                    &backend,
                    &group,
                    first.compressed_offset(),
                    &window,
                    &mut scratch,
                )
                .with_context(|| {
                    format!("chunk group {index} of blob {blob_index} failed validation")
                })?;
                let range = group.compressed_range();
                let at = (range.start - first.compressed_offset()) as usize;
                encoded.insert(
                    ChunkGroupRef {
                        blob_index: *blob_index,
                        chunk_group_index: index,
                    },
                    window[at..at + group.compressed_size() as usize].to_vec(),
                );
            }
            start = end;
        }
    }

    // Lay the copies out in access order.
    let mut data = Vec::new();
    let mut chunk_groups = Vec::with_capacity(patterns.len());
    let mut chunks = Vec::new();
    let mut digests = Vec::new();
    for reference in patterns {
        let meta = sources[&reference.blob_index].blob_metadata();
        let group = meta
            .chunk_group(reference.chunk_group_index as usize)
            .expect("validated above");
        let payload = &encoded[reference];
        data.extend_from_slice(payload);
        chunk_groups.push(BlobMetadataChunkGroup::new(
            group.compressed_size(),
            group.chunk_count(),
            group.crc32(),
            Some(BlobMetadataRedirect::new(
                reference.blob_index,
                reference.chunk_group_index,
            )?),
        )?);
        chunks.extend_from_slice(&meta.chunks()[group.chunk_range()]);
        if digester == BlobMetadataDigester::Blake3 {
            digests.extend_from_slice(&meta.digests()[group.chunk_range()]);
        }
    }
    let blob_metadata = BlobMetadata::new(
        compressor,
        digester,
        chunk_block_count,
        chunk_groups,
        chunks,
        digests,
    )
    .context("failed to assemble ondemand blob meta")?;
    let uncompressed_blocks = blob_metadata.uncompressed_block_count();
    let (artifact, full_blob_digest, footer) = assemble_ondemand_artifact(&data, &blob_metadata)?;

    let bootstrap = rewrite_bootstrap_with_ondemand_blob(
        parent_bootstrap,
        &full_blob_digest,
        uncompressed_blocks,
    )
    .context("failed to rewrite bootstrap with ondemand device")?;

    Ok(OndemandBlob {
        artifact,
        full_blob_digest,
        blob_metadata,
        footer,
        bootstrap,
        uncompressed_blocks,
        source_blob_count: sources.len(),
    })
}

/// Fetch the `/trace` JSON from a running mount's apiserver and return the
/// deduplicated [`ChunkGroupRef`] list in first-access order.
pub fn load_patterns_from_apiserver(apiserver: &str) -> Result<Vec<ChunkGroupRef>> {
    let raw = fetch_trace(apiserver)
        .with_context(|| format!("failed to fetch /trace from apiserver {apiserver}"))?;
    parse_trace_document(&raw)
        .with_context(|| format!("failed to parse /trace response from {apiserver}"))
}

/// Load access patterns from a versioned JSON trace document
/// (`{"version":1,"patterns":[...]}`), exactly as produced by the
/// apiserver `/trace` endpoint.
pub fn load_patterns_from_file(path: &Path) -> Result<Vec<ChunkGroupRef>> {
    let raw =
        fs::read(path).with_context(|| format!("failed to read trace file: {}", path.display()))?;
    parse_trace_document(&raw)
        .with_context(|| format!("failed to parse trace file: {}", path.display()))
}

/// Parse the versioned trace document `{"version":1,"patterns":[...]}`.
fn parse_trace_document(raw: &[u8]) -> Result<Vec<ChunkGroupRef>> {
    let envelope: TraceDocument = serde_json::from_slice(raw)?;
    if envelope.version != TRACE_DOCUMENT_VERSION {
        return Err(Error::Unsupported(format!(
            "unsupported trace document version: {}",
            envelope.version
        )));
    }
    dedup_patterns(envelope.entries)
}

/// Deduplicate `(blob_index, chunk_group_index)` pairs while preserving
/// first-access order, validating that every blob index fits in a non-zero
/// `u16`.
fn dedup_patterns(patterns: Vec<TraceEntry>) -> Result<Vec<ChunkGroupRef>> {
    let mut ordered = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for pattern in patterns {
        let blob_index = u16::try_from(pattern.blob_index).map_err(|err| {
            Error::InvalidParameter(format!(
                "pattern blob index {} exceeds u16: {err}",
                pattern.blob_index
            ))
        })?;
        if blob_index == 0 {
            return Err(Error::InvalidParameter(
                "pattern blob index must be non-zero".to_string(),
            ));
        }
        let group = ChunkGroupRef {
            blob_index,
            chunk_group_index: pattern.chunk_group_index,
        };
        if seen.insert(group) {
            ordered.push(group);
        }
    }
    Ok(ordered)
}

/// Issue a `GET /trace` over the apiserver's Unix socket and return the
/// response body. A minimal HTTP/1.0 exchange is enough here: the server
/// replies with a complete body and closes the connection, so the body is
/// everything after the header terminator.
fn fetch_trace(apiserver: &str) -> Result<Vec<u8>> {
    let socket_path = parse_unix_address(apiserver)?;
    let mut stream = UnixStream::connect(&socket_path).with_context(|| {
        format!(
            "failed to connect to apiserver socket: {}",
            socket_path.display()
        )
    })?;
    let timeout = Some(Duration::from_secs(10));
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(timeout)?;

    stream.write_all(b"GET /trace HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| Error::Backend("malformed HTTP response from apiserver".to_string()))?;
    let status_line = response[..header_end]
        .split(|byte| *byte == b'\r')
        .next()
        .unwrap_or_default();
    let status_line = String::from_utf8_lossy(status_line);
    if !status_line.contains(" 200 ") {
        return Err(Error::Backend(format!(
            "apiserver /trace returned non-200 status: {status_line}"
        )));
    }
    Ok(response[header_end + 4..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trace_document_accepts_versioned_envelope_only() {
        let doc = br#"{"version":1,"patterns":[
            {"blob_index":1,"chunk_group_index":4},
            {"blob_index":1,"chunk_group_index":4},
            {"blob_index":2,"chunk_group_index":7}]}"#;
        let patterns = parse_trace_document(doc).unwrap();
        assert_eq!(
            patterns,
            vec![
                ChunkGroupRef {
                    blob_index: 1,
                    chunk_group_index: 4,
                },
                ChunkGroupRef {
                    blob_index: 2,
                    chunk_group_index: 7,
                }
            ]
        );

        // Wrong version is rejected.
        let err = parse_trace_document(br#"{"version":2,"patterns":[]}"#).unwrap_err();
        assert!(err.to_string().contains("version"), "{err}");

        // The legacy unversioned document is no longer accepted.
        assert!(parse_trace_document(br#"{"patterns":[]}"#).is_err());
    }
}
