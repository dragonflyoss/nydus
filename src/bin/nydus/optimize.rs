use anyhow::{bail, Context, Result};
use clap::Args;
use nydus::config::Config;
use nydus::fs::{BlobInfo, ErofsReader};
use nydus::merge::rewrite_bootstrap_with_ondemand_blob;
use nydus::metadata::*;
use nydus::storage::backend::build_backend;
use nydus::storage::cache::{BlobCache, LocalBlobCache};
use nydus::tracing::init_command_tracing;
use nydus::utils::hex_string;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, Level};

const MAX_COMPRESSED_SIZE_PERCENT: u128 = 70;

#[derive(Args)]
pub struct OptimizeArgs {
    /// Apiserver address of a running `nydus fuse` mount, e.g.
    /// `unix:///path/to/api.sock`. The access patterns are fetched live from
    /// its `/trace` endpoint. Mutually exclusive with `--trace-file`.
    #[arg(long, required_unless_present = "trace_file")]
    pub apiserver: Option<String>,

    /// Path to a JSON trace file containing access patterns. Accepts either the
    /// bare `{"patterns":[{"blob_index":..,"group_index":..}]}` document or a
    /// wrapper object exposing the same under a top-level `trace` field (as
    /// returned by a hypervisor's stats endpoint embedding the accessor trace).
    /// Mutually exclusive with `--apiserver`.
    #[arg(long, conflicts_with = "apiserver")]
    pub trace_file: Option<PathBuf>,

    /// Input merged bootstrap to optimize (left untouched).
    #[arg(long)]
    pub parent_bootstrap: PathBuf,

    /// Output path for the rewritten bootstrap.
    #[arg(long)]
    pub bootstrap: PathBuf,

    /// Output directory for the ondemand blob (named by its SHA256 digest)
    /// and its `.blob.meta` sidecar.
    #[arg(long)]
    pub blob_dir: PathBuf,

    /// Storage config YAML (same format as `nydus fuse --config`) providing
    /// the backend serving the source blobs and the local cache directory.
    #[arg(long)]
    pub config: PathBuf,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    pub log_level: Level,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        help = "Specify whether to print log"
    )]
    pub console: bool,
}

#[derive(Deserialize)]
struct TracePatterns {
    patterns: Vec<TracePattern>,
}

#[derive(Deserialize)]
struct TracePattern {
    blob_index: u32,
    group_index: u32,
}

/// Build an "ondemand" redirect blob from a `/trace` access pattern and rewrite
/// the bootstrap so the runtime prefetches it first, warming the source blobs'
/// caches in recorded access order before on-demand reads arrive.
pub fn run_optimize(args: OptimizeArgs) -> Result<()> {
    let _guards = init_command_tracing(args.log_level, args.console);

    if args.parent_bootstrap == args.bootstrap {
        bail!("--parent-bootstrap and --bootstrap must point to different files");
    }

    let patterns = match (&args.trace_file, &args.apiserver) {
        (Some(path), _) => load_patterns_from_file(path)?,
        (None, Some(apiserver)) => load_patterns(apiserver)?,
        (None, None) => bail!("either --trace-file or --apiserver must be provided"),
    };
    if patterns.is_empty() {
        bail!(
            "no group accesses found in the access trace; exercise the workload before optimizing"
        );
    }

    let storage_config =
        Config::from_file(&args.config).context("failed to load storage config")?;
    let backend = build_backend(&storage_config.backend).context("failed to build blob backend")?;
    let cache_dir = storage_config
        .cache_dir()
        .context("failed to resolve cache directory from config")?;
    fs::create_dir_all(&cache_dir)
        .with_context(|| format!("failed to create cache directory: {}", cache_dir.display()))?;

    let reader = ErofsReader::open_layer(&args.parent_bootstrap).with_context(|| {
        format!(
            "failed to open parent bootstrap: {}",
            args.parent_bootstrap.display()
        )
    })?;
    let blob_infos = reader.blob_infos()?;
    let infos_by_index: HashMap<u16, &BlobInfo> = blob_infos
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

    for (blob_index, group_index) in &patterns {
        let info = infos_by_index
            .get(blob_index)
            .ok_or_else(|| anyhow::anyhow!("pattern references unknown blob {blob_index}"))?;
        let cache = match source_caches.entry(*blob_index) {
            std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::hash_map::Entry::Vacant(entry) => entry.insert(
                LocalBlobCache::open(
                    info.blob_id,
                    *blob_index as u32,
                    &cache_dir,
                    backend.clone(),
                )
                .with_context(|| format!("failed to open source blob {blob_index}"))?,
            ),
        };

        let group = *cache
            .blob_meta()
            .group_at(*group_index as usize)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "pattern references group {group_index} out of range for blob {blob_index}"
                )
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

    let (artifact, full_digest, footer) = assemble_artifact(&ondemand_data, &blob_meta)?;
    let digest_hex = hex_string(&full_digest);

    fs::create_dir_all(&args.blob_dir).with_context(|| {
        format!(
            "failed to create blob directory: {}",
            args.blob_dir.display()
        )
    })?;
    let blob_path = args.blob_dir.join(&digest_hex);
    fs::write(&blob_path, &artifact)
        .with_context(|| format!("failed to write ondemand blob: {}", blob_path.display()))?;
    let blob_meta_path = args.blob_dir.join(format!("{digest_hex}.blob.meta"));
    blob_meta
        .save(&blob_meta_path)
        .with_context(|| format!("failed to save blob meta: {}", blob_meta_path.display()))?;

    let bootstrap_bytes = rewrite_bootstrap_with_ondemand_blob(
        &args.parent_bootstrap,
        &full_digest,
        next_block_offset,
    )
    .context("failed to rewrite bootstrap with ondemand device")?;
    fs::write(&args.bootstrap, &bootstrap_bytes).with_context(|| {
        format!(
            "failed to write rewritten bootstrap: {}",
            args.bootstrap.display()
        )
    })?;

    info!(
        "optimized {} groups from {} source blobs into ondemand blob",
        patterns.len(),
        source_caches.len()
    );
    println!("[ondemand blob]");
    println!("    ondemand_blob_digest: {digest_hex}");
    println!("    ondemand_blob_path: {}", blob_path.display());
    println!("    blob_meta_path: {}", blob_meta_path.display());
    println!("    bootstrap_path: {}", args.bootstrap.display());
    println!("    group_count: {}", patterns.len());
    println!(
        "    compressed_data_size: {}",
        footer.compressed_data_size()
    );
    println!(
        "    uncompressed_data_size: {}",
        next_block_offset * EROFS_BLOCK_SIZE as u64
    );
    Ok(())
}

/// Fetch the `/trace` JSON from a running mount's apiserver and return the
/// deduplicated `(blob_index, group_index)` list in first-access order.
fn load_patterns(apiserver: &str) -> Result<Vec<(u16, u32)>> {
    let raw = fetch_trace(apiserver)
        .with_context(|| format!("failed to fetch /trace from apiserver {apiserver}"))?;
    let trace: TracePatterns = serde_json::from_slice(&raw)
        .with_context(|| format!("failed to parse /trace response from {apiserver}"))?;
    dedup_patterns(trace.patterns)
}

/// Load access patterns from a JSON trace file. Accepts either the bare
/// `{"patterns":[...]}` document or a wrapper object exposing the same patterns
/// under a top-level `trace` field (as produced by a hypervisor's stats
/// endpoint embedding the accessor trace).
fn load_patterns_from_file(path: &std::path::Path) -> Result<Vec<(u16, u32)>> {
    let raw =
        fs::read(path).with_context(|| format!("failed to read trace file: {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&raw)
        .with_context(|| format!("failed to parse trace file as JSON: {}", path.display()))?;
    // Support both the bare document and the stats-endpoint wrapper.
    let trace_value = value.get("trace").unwrap_or(&value);
    let trace: TracePatterns = serde_json::from_value(trace_value.clone()).with_context(|| {
        format!(
            "trace file {} does not contain a `patterns` array",
            path.display()
        )
    })?;
    dedup_patterns(trace.patterns)
}

/// Deduplicate `(blob_index, group_index)` pairs while preserving first-access
/// order, validating that every blob index fits in a non-zero `u16`.
fn dedup_patterns(patterns: Vec<TracePattern>) -> Result<Vec<(u16, u32)>> {
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
    let socket_path = crate::apiserver::parse_unix_address(apiserver)?;
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
        .ok_or_else(|| anyhow::anyhow!("malformed HTTP response from apiserver"))?;
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

/// Assemble the ondemand artifact `[group data][blob.meta][footer]` (no
/// embedded bootstrap) and return its bytes, full SHA256 digest, and footer.
fn assemble_artifact(data: &[u8], blob_meta: &BlobMeta) -> Result<(Vec<u8>, [u8; 32], BlobFooter)> {
    let compressed_data_size = data.len() as u64;
    let bootstrap_offset = align_u64(compressed_data_size, NYDUS_BLOB_FOOTER_ALIGNMENT);
    let blob_meta_offset = bootstrap_offset;
    let blob_meta_size = blob_meta.metadata_size();
    let blob_meta_blocks = u32::try_from(blob_meta_size / EROFS_BLOCK_SIZE as u64)
        .context("blob meta exceeds u32 block count")?;

    let footer = BlobFooter::new(
        0,
        compressed_data_size,
        bootstrap_offset,
        0,
        blob_meta_offset,
        blob_meta_blocks,
    )?;

    let mut artifact = Vec::with_capacity(
        usize::try_from(blob_meta_offset + blob_meta_size).context("artifact exceeds usize")?
            + NYDUS_BLOB_FOOTER_SIZE,
    );
    artifact.extend_from_slice(data);
    artifact.resize(
        usize::try_from(bootstrap_offset).context("artifact padding exceeds usize")?,
        0,
    );
    blob_meta
        .write_to(&mut artifact)
        .context("failed to serialize ondemand blob meta")?;
    footer
        .write_to(&mut artifact)
        .context("failed to serialize ondemand blob footer")?;

    let mut hasher = Sha256::new();
    hasher.update(&artifact);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    Ok((artifact, digest, footer))
}

fn align_u64(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

fn compression_is_worthwhile(compressed_len: usize, uncompressed_len: usize) -> bool {
    (compressed_len as u128) * 100 <= (uncompressed_len as u128) * MAX_COMPRESSED_SIZE_PERCENT
}
