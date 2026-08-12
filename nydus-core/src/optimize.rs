//! The `optimize` pipeline: turning a recorded group access trace into an
//! "ondemand" redirect blob plus a rewritten bootstrap that prefetches it.
//!
//! This is a top-level pipeline composing the read stack ([`crate::fs`],
//! [`crate::storage`]) with the builder ([`crate::build`]): access patterns
//! come from the apiserver `/trace` endpoint of a running `nydus fuse` mount
//! ([`load_patterns_from_apiserver`]) or from a saved JSON trace document
//! ([`load_patterns_from_file`]); [`build_ondemand_blob`] then pulls the
//! accessed groups through the regular blob cache and assembles the ondemand
//! artifact and bootstrap in memory.

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::blob::{
    BlobFooter, BlobMeta, BlobMetaCompressor, BlobMetaGroup, BLOB_META_DEFAULT_CHUNK_BLOCK_COUNT,
};
use crate::build::assemble_ondemand_artifact;
use crate::build::blob_chunk::compression_is_worthwhile;
use crate::build::merge::rewrite_bootstrap_with_ondemand_blob;
use crate::fs::{ErofsReader, RawBlobInfo};
use crate::metadata::EROFS_BLOB_ID_SIZE;
use crate::storage::backend::BlobBackend;
use crate::storage::cache::{BlobCache, LocalBlobCache};
use crate::telemetry::access_trace::{TraceDocument, TraceEntry, TRACE_DOCUMENT_VERSION};
use crate::utils::parse_unix_address;

/// The result of [`build_ondemand_blob`]: the assembled ondemand artifact and
/// the rewritten bootstrap, ready to be written out by the caller.
pub struct OndemandBlob {
    /// The ondemand artifact bytes `[group data][blob.meta][footer]`.
    pub artifact: Vec<u8>,
    /// SHA256 of the whole artifact (the ondemand blob's name).
    pub full_digest: [u8; EROFS_BLOB_ID_SIZE],
    pub blob_meta: BlobMeta,
    pub footer: BlobFooter,
    /// The parent bootstrap rewritten so the runtime prefetches the ondemand
    /// blob first.
    pub bootstrap: Vec<u8>,
    /// Total uncompressed size of the ondemand blob in blocks.
    pub uncompressed_blocks: u64,
    /// Number of distinct source blobs the accessed groups were pulled from.
    pub source_blob_count: usize,
}

/// Build an "ondemand" redirect blob from a `/trace` access pattern and rewrite
/// the bootstrap so the runtime prefetches it first, warming the source blobs'
/// caches in recorded access order before on-demand reads arrive.
pub fn build_ondemand_blob(
    parent_bootstrap: &Path,
    patterns: &[(u16, u32)],
    backend: Arc<dyn BlobBackend>,
    cache_dir: &Path,
) -> Result<OndemandBlob> {
    let reader = ErofsReader::open_metadata_only(parent_bootstrap).with_context(|| {
        format!(
            "failed to open parent bootstrap: {}",
            parent_bootstrap.display()
        )
    })?;
    let blob_infos = reader.blob_infos()?;
    let infos_by_index: HashMap<u16, &RawBlobInfo> = blob_infos
        .iter()
        .map(|info| (info.blob_index, info))
        .collect();
    drop(reader);

    // Pull each accessed group's decoded bytes through the regular blob cache:
    // warm groups are served from the cache directory, cold groups are fetched
    // from the backend, and CRC validation happens on every path.
    let mut source_caches: HashMap<u16, LocalBlobCache> = HashMap::new();
    let mut ondemand_data = Vec::new();
    let mut ondemand_groups = Vec::new();
    let mut next_block_offset = 0u64;
    let mut decoded = Vec::new();

    for (blob_index, group_index) in patterns {
        let info = infos_by_index
            .get(blob_index)
            .ok_or_else(|| anyhow!("pattern references unknown blob {blob_index}"))?;
        let cache = match source_caches.entry(*blob_index) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => entry.insert(
                LocalBlobCache::open(info.blob_id, *blob_index as u32, cache_dir, backend.clone())
                    .with_context(|| format!("failed to open source blob {blob_index}"))?,
            ),
        };

        let group = *cache
            .blob_meta()
            .group_at(*group_index as usize)
            .ok_or_else(|| {
                anyhow!("pattern references group {group_index} out of range for blob {blob_index}")
            })?;
        if group.is_redirect() {
            bail!("source blob {blob_index} is already an ondemand blob; refusing to optimize");
        }

        let decoded_len = usize::try_from(group.uncompressed_byte_size())
            .context("group uncompressed size exceeds usize")?;
        decoded.resize(decoded_len, 0);
        cache
            .read_at(group.uncompressed_byte_offset(), &mut decoded)
            .with_context(|| {
                format!("failed to read blob {blob_index} group {group_index} bytes")
            })?;

        // Recompress the decoded bytes for the ondemand artifact, storing them
        // plain when compression is not worthwhile (same policy as build).
        let compressed = zstd::bulk::compress(&decoded, 0)
            .context("failed to compress ondemand group with zstd")?;
        let encoded: &[u8] = if compression_is_worthwhile(compressed.len(), decoded.len()) {
            &compressed
        } else {
            &decoded
        };

        let compressed_offset = ondemand_data.len() as u64;
        ondemand_data.extend_from_slice(encoded);
        ondemand_groups.push(BlobMetaGroup::new_redirect(
            next_block_offset,
            group.uncompressed_block_count(),
            compressed_offset,
            u32::try_from(encoded.len()).context("ondemand group compressed size exceeds u32")?,
            group.crc32(),
            *blob_index,
            *group_index,
        )?);
        next_block_offset += group.uncompressed_block_count() as u64;
    }

    let mut data_hasher = Sha256::new();
    data_hasher.update(&ondemand_data);
    let mut data_digest = [0u8; EROFS_BLOB_ID_SIZE];
    data_digest.copy_from_slice(&data_hasher.finalize());

    let blob_meta = BlobMeta::from_parts_with_options(
        data_digest,
        BLOB_META_DEFAULT_CHUNK_BLOCK_COUNT,
        BlobMetaCompressor::Zstd,
        ondemand_groups,
        Vec::new(),
    )
    .context("failed to assemble ondemand blob meta")?;

    let (artifact, full_digest, footer) = assemble_ondemand_artifact(&ondemand_data, &blob_meta)?;

    let bootstrap =
        rewrite_bootstrap_with_ondemand_blob(parent_bootstrap, &full_digest, next_block_offset)
            .context("failed to rewrite bootstrap with ondemand device")?;

    Ok(OndemandBlob {
        artifact,
        full_digest,
        blob_meta,
        footer,
        bootstrap,
        uncompressed_blocks: next_block_offset,
        source_blob_count: source_caches.len(),
    })
}

/// Fetch the `/trace` JSON from a running mount's apiserver and return the
/// deduplicated `(blob_index, group_index)` list in first-access order.
pub fn load_patterns_from_apiserver(apiserver: &str) -> Result<Vec<(u16, u32)>> {
    let raw = fetch_trace(apiserver)
        .with_context(|| format!("failed to fetch /trace from apiserver {apiserver}"))?;
    parse_trace_document(&raw)
        .with_context(|| format!("failed to parse /trace response from {apiserver}"))
}

/// Load access patterns from a versioned JSON trace document
/// (`{"version":1,"trace":{"patterns":[...]}}`), exactly as produced by the
/// apiserver `/trace` endpoint.
pub fn load_patterns_from_file(path: &Path) -> Result<Vec<(u16, u32)>> {
    let raw =
        fs::read(path).with_context(|| format!("failed to read trace file: {}", path.display()))?;
    parse_trace_document(&raw)
        .with_context(|| format!("failed to parse trace file: {}", path.display()))
}

/// Parse the versioned trace document `{"version":1,"patterns":[...]}`.
fn parse_trace_document(raw: &[u8]) -> Result<Vec<(u16, u32)>> {
    let envelope: TraceDocument =
        serde_json::from_slice(raw).context("failed to parse trace document")?;
    if envelope.version != TRACE_DOCUMENT_VERSION {
        bail!("unsupported trace document version: {}", envelope.version);
    }
    dedup_patterns(envelope.patterns)
}

/// Deduplicate `(blob_index, group_index)` pairs while preserving first-access
/// order, validating that every blob index fits in a non-zero `u16`.
fn dedup_patterns(patterns: Vec<TraceEntry>) -> Result<Vec<(u16, u32)>> {
    let mut ordered = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for pattern in patterns {
        let blob_index = u16::try_from(pattern.blob_index)
            .with_context(|| format!("pattern blob index {} exceeds u16", pattern.blob_index))?;
        if blob_index == 0 {
            bail!("pattern blob index must be non-zero");
        }
        if seen.insert((blob_index, pattern.group_index)) {
            ordered.push((blob_index, pattern.group_index));
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
        .ok_or_else(|| anyhow!("malformed HTTP response from apiserver"))?;
    let status_line = response[..header_end]
        .split(|byte| *byte == b'\r')
        .next()
        .unwrap_or_default();
    let status_line = String::from_utf8_lossy(status_line);
    if !status_line.contains(" 200 ") {
        bail!("apiserver /trace returned non-200 status: {status_line}");
    }
    Ok(response[header_end + 4..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trace_document_accepts_versioned_envelope_only() {
        let doc = br#"{"version":1,"patterns":[
            {"blob_index":1,"group_index":4},
            {"blob_index":1,"group_index":4},
            {"blob_index":2,"group_index":7}]}"#;
        let patterns = parse_trace_document(doc).unwrap();
        assert_eq!(patterns, vec![(1, 4), (2, 7)]);

        // Wrong version is rejected.
        let err = parse_trace_document(br#"{"version":2,"patterns":[]}"#).unwrap_err();
        assert!(err.to_string().contains("version"), "{err}");

        // The legacy unversioned document is no longer accepted.
        assert!(parse_trace_document(br#"{"patterns":[]}"#).is_err());
    }
}
