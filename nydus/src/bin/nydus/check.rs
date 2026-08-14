use clap::Parser;
use nydus::check::{check_image, BlobSummary, CheckReport, ImageKind, ImageStats};
use nydus::error::{Context, Error, Result};
use nydus_config::{BackendConfig, Config};
use nydus_format::erofs::{
    ErofsSuperblock, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE, EROFS_FEATURE_COMPAT_MTIME,
    EROFS_FEATURE_COMPAT_SB_CHKSUM, EROFS_FEATURE_INCOMPAT_CHUNKED_FILE,
    EROFS_FEATURE_INCOMPAT_DEVICE_TABLE,
};
use nydus_format::utils::hex_string;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The subcommand of check.
#[derive(Debug, Clone, Parser)]
pub struct CheckCommand {
    #[arg(
        long,
        env = "NYDUS_CHECK_BLOB",
        help = "Specify the file path to an nydus blob"
    )]
    blob: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_CHECK_BOOTSTRAP",
        help = "Specify the file path to an nydus bootstrap"
    )]
    bootstrap: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_CHECK_BLOB_DIR",
        help = "Specify the optional directory containing external blob files referenced by bootstrap"
    )]
    blob_dir: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_CHECK_CONFIG",
        help = "Specify the file path to a YAML storage config providing the backend directory. When set, --blob-dir can be omitted"
    )]
    config: Option<PathBuf>,
}

/// Implement the execute for CheckCommand.
impl CheckCommand {
    /// Executes the check sub command, statically inspecting the image.
    pub fn execute(&self) -> Result<()> {
        // `check` verifies blobs from a local directory. --blob-dir takes precedence
        // over the config; a config is only usable here when it has a local backend.
        let blob_dir = match &self.blob_dir {
            Some(dir) => Some(dir.clone()),
            None => match &self.config {
                Some(path) => {
                    let config = Config::load(path).context("failed to load storage config")?;
                    match &config.backend {
                        BackendConfig::Local(local) => Some(local.dir.clone()),
                        other => {
                            return Err(Error::InvalidConfig(format!(
                                "check only supports a local backend, but config backend is '{}'",
                                other.kind()
                            )));
                        }
                    }
                }
                None => None,
            },
        };

        let (kind, path) = match (&self.blob, &self.bootstrap, &blob_dir) {
            (Some(blob), None, None) => (ImageKind::Blob, blob.as_path()),
            (None, Some(bootstrap), None) => (ImageKind::Bootstrap, bootstrap.as_path()),
            (None, Some(bootstrap), Some(blob_dir)) if blob_dir.is_dir() => {
                (ImageKind::Bootstrap, bootstrap.as_path())
            }
            (None, Some(_), Some(blob_dir)) => {
                return Err(Error::InvalidParameter(format!(
                    "blob-dir {} is not a directory",
                    blob_dir.display()
                )))
            }
            _ => {
                return Err(Error::InvalidParameter(
                    "check expects either --blob <path> or --bootstrap <path> with a blob directory from --blob-dir or --config".to_string(),
                ))
            }
        };

        let report = check_image(kind, path, blob_dir.as_deref())?;

        print_header(kind, path, &report);
        print_superblock(&report.superblock);
        print_summary(&report.stats, &report.blobs);
        print_blobs(&report.blobs);
        print_inline_across_blocks(&report.stats);

        if !report.stats.inline_overflows.is_empty() {
            return Err(Error::InvalidImage(format!(
                "{} inode(s) have inline data crossing a metadata block; \
                 the kernel cannot read them",
                report.stats.inline_overflows.len()
            )));
        }

        Ok(())
    }
}

fn print_header(kind: ImageKind, path: &Path, report: &CheckReport) {
    println!("Image");
    println!(
        "  kind: {}",
        match kind {
            ImageKind::Blob => "blob",
            ImageKind::Bootstrap => "bootstrap",
        }
    );
    println!("  path: {}", path.display());
    println!("  file_size: {}", report.image_file_bytes);
    println!("  primary_image_size: {}", report.primary_image_bytes);
    if kind == ImageKind::Blob && report.blobs.len() == 1 {
        let blob = report.blobs.values().next().expect("single blob summary");
        println!(
            "  compressed_data_region_size: {}",
            blob.data_size_for_display()
        );
    }
    println!();
}

fn print_superblock(sb: &ErofsSuperblock) {
    println!("Superblock");
    println!("  magic: 0x{:08x}", sb.magic());
    println!("  checksum: 0x{:08x}", u32::from_le_bytes(sb.checksum));
    println!(
        "  feature_compat: 0x{:08x} ({})",
        sb.feature_compat(),
        compat_features(sb.feature_compat())
    );
    println!(
        "  feature_incompat: 0x{:08x} ({})",
        sb.feature_incompat(),
        incompat_features(sb.feature_incompat())
    );
    println!("  blkszbits: {}", sb.blkszbits);
    println!("  block_size: {}", 1u64 << sb.blkszbits);
    println!("  sb_extslots: {}", sb.sb_extslots);
    println!("  root_nid: {}", sb.root_nid());
    println!("  rootnid_2b: {}", u16::from_le_bytes(sb.rootnid_2b));
    println!("  rootnid_8b: {}", u64::from_le_bytes(sb.rootnid_8b));
    println!("  inos: {}", sb.inos());
    println!("  epoch: {}", sb.epoch());
    println!("  fixed_nsec: {}", u32::from_le_bytes(sb.fixed_nsec));
    println!("  blocks: {}", sb.blocks());
    println!("  meta_blkaddr: {}", sb.meta_blkaddr());
    println!("  xattr_blkaddr: {}", u32::from_le_bytes(sb.xattr_blkaddr));
    println!("  uuid: {}", hex_string(&sb.uuid));
    println!("  volume_name: {}", printable_bytes(&sb.volume_name));
    println!(
        "  compr_or_distance: {}",
        u16::from_le_bytes(sb.compr_or_distance)
    );
    println!("  extra_devices: {}", sb.extra_devices());
    println!("  devt_slotoff: {}", sb.devt_slotoff());
    println!("  dirblkbits: {}", sb.dirblkbits);
    println!("  xattr_prefix_count: {}", sb.xattr_prefix_count);
    println!(
        "  xattr_prefix_start: {}",
        u32::from_le_bytes(sb.xattr_prefix_start)
    );
    println!("  packed_nid: {}", u64::from_le_bytes(sb.packed_nid));
    println!("  xattr_filter_reserved: {}", sb.xattr_filter_reserved);
    println!("  build_time: {}", u64::from_le_bytes(sb.build_time));
    println!();
}

/// Print inodes whose inline tail crosses a metadata block. Only the first
/// entries are listed because a builder bug tends to hit many inodes at once.
fn print_inline_across_blocks(stats: &ImageStats) {
    if stats.inline_overflows.is_empty() {
        return;
    }

    const MAX_LISTED: usize = 20;
    println!(
        "Inline data across blocks ({} inode(s), block size {})",
        stats.inline_overflows.len(),
        EROFS_BLOCK_SIZE
    );
    for entry in stats.inline_overflows.iter().take(MAX_LISTED) {
        let end = entry.block_offset + entry.header_size + entry.xattr_size + entry.inline_size;
        println!(
            "  nid {}: block_offset {} + header {} + xattr {} + inline {} = {} (> {})",
            entry.nid,
            entry.block_offset,
            entry.header_size,
            entry.xattr_size,
            entry.inline_size,
            end,
            EROFS_BLOCK_SIZE
        );
    }
    if stats.inline_overflows.len() > MAX_LISTED {
        println!("  ... {} more", stats.inline_overflows.len() - MAX_LISTED);
    }
    println!();
}

fn print_summary(stats: &ImageStats, blobs: &BTreeMap<u16, BlobSummary>) {
    let total_unique_chunks = blobs
        .values()
        .map(|blob| blob.unique_blkaddrs.len() as u64)
        .sum::<u64>();
    println!("Summary");
    println!("  visited_inodes: {}", stats.visited_inodes);
    println!("  max_depth: {}", stats.max_depth);
    println!("  directory_entries: {}", stats.directory_entries);
    println!("  regular_files: {}", stats.regular_files);
    println!("  directories: {}", stats.directories);
    println!("  symlinks: {}", stats.symlinks);
    println!("  char_devices: {}", stats.char_devices);
    println!("  block_devices: {}", stats.block_devices);
    println!("  fifos: {}", stats.fifos);
    println!("  sockets: {}", stats.sockets);
    println!("  chunked_files: {}", stats.chunked_files);
    println!("  flat_plain_files: {}", stats.flat_plain_files);
    println!("  flat_inline_files: {}", stats.flat_inline_files);
    println!("  other_layout_files: {}", stats.other_layout_files);
    println!("  xattr_entries: {}", stats.xattr_entries);
    println!("  hardlink_inodes: {}", stats.hardlink_inodes);
    println!("  hardlink_paths: {}", stats.hardlink_paths);
    println!("  total_chunks: {}", stats.total_chunks);
    println!("  hole_chunks: {}", stats.hole_chunks);
    println!("  unique_chunks: {total_unique_chunks}");
    println!("  total_logical_bytes: {}", stats.total_logical_bytes);
    println!("  chunk_sizes: {}", format_u64_set(&stats.chunk_sizes));
    println!();
}

fn print_blobs(blobs: &BTreeMap<u16, BlobSummary>) {
    println!("Blobs");
    if blobs.is_empty() {
        println!("  (no external blobs recorded in device table)");
        println!();
        return;
    }

    for (index, (blob_index, blob)) in blobs.iter().enumerate() {
        print_blob_info(index, *blob_index, blob);
    }
    println!();
}

fn print_blob_info(index: usize, blob_index: u16, blob: &BlobSummary) {
    println!("  Blob {index}");
    println!("    entry: {index}");
    println!("    blob_index: {blob_index}");
    println!("    mapped_blkaddr: {}", blob.mapped_blkaddr);
    println!("    mapped_offset: {}", blob.mapped_offset);
    println!("    declared_blocks: {}", blob.declared_blocks);
    println!(
        "    declared_uncompressed_size: {}",
        blob.declared_data_size
    );
    println!("    slot_digest_kind: {}", blob.slot_sha256_kind.as_str());
    println!("    data_blob_digest: {}", data_blob_digest(blob));
    println!(
        "    full_blob_digest: {}",
        optional_digest(blob.blob_sha256)
    );
    println!(
        "    chunk_size: {}",
        blob_metadata_field(blob, |meta| meta.chunk_size)
    );
    println!(
        "    chunk_count: {}",
        blob_metadata_field(blob, |meta| meta.chunk_count)
    );
    println!(
        "    group_count: {}",
        blob_metadata_field(blob, |meta| meta.group_count)
    );
    println!(
        "    chunk_digester: {}",
        blob_metadata_field(blob, |meta| meta.digester)
    );
    println!(
        "    chunk_compressor: {}",
        blob_metadata_field(blob, |meta| meta.compressor)
    );
    println!(
        "    blob_compressed_size: {}",
        blob_metadata_field_or(blob, |meta| meta.total_compressed_size, blob.data_size)
    );
    println!(
        "    blob_uncompressed_size: {}",
        blob_metadata_field_or(
            blob,
            |meta| meta.total_uncompressed_size,
            Some(blob.declared_data_size),
        )
    );
    println!("    chunk_refs: {}", blob.chunk_refs);
    println!("    unique_chunks: {}", blob.unique_blkaddrs.len());
    println!("    logical_bytes: {}", blob.logical_bytes);
    println!("    chunk_sizes: {}", format_u64_set(&blob.chunk_sizes));
    if let Some(source) = &blob.resolved_path {
        println!("    source: {}", source.display());
    }
}

fn data_blob_digest(blob: &BlobSummary) -> String {
    blob.data_sha256
        .map(|sha256| hex_string(&sha256))
        .unwrap_or_else(|| digest_or_unknown(&blob.slot_sha256))
}

fn optional_digest(digest: Option<[u8; EROFS_BLOB_ID_SIZE]>) -> String {
    digest
        .map(|sha256| hex_string(&sha256))
        .unwrap_or_else(|| "<unresolved>".to_string())
}

fn digest_or_unknown(digest: &[u8; EROFS_BLOB_ID_SIZE]) -> String {
    if digest.iter().all(|byte| *byte == 0) {
        "<unknown>".to_string()
    } else {
        hex_string(digest)
    }
}

fn blob_metadata_field<T: ToString>(
    blob: &BlobSummary,
    field: impl FnOnce(&nydus::check::BlobMetadataSummary) -> T,
) -> String {
    blob.blob_metadata
        .as_ref()
        .map(|meta| field(meta).to_string())
        .unwrap_or_else(|| "<unresolved>".to_string())
}

fn blob_metadata_field_or<T: ToString>(
    blob: &BlobSummary,
    field: impl FnOnce(&nydus::check::BlobMetadataSummary) -> T,
    fallback: Option<T>,
) -> String {
    blob.blob_metadata
        .as_ref()
        .map(|meta| field(meta).to_string())
        .or_else(|| fallback.map(|value| value.to_string()))
        .unwrap_or_else(|| "<unresolved>".to_string())
}

fn compat_features(bits: u32) -> String {
    let mut features = Vec::new();
    if bits & EROFS_FEATURE_COMPAT_SB_CHKSUM != 0 {
        features.push("sb_checksum");
    }
    if bits & EROFS_FEATURE_COMPAT_MTIME != 0 {
        features.push("mtime");
    }
    if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    }
}

fn incompat_features(bits: u32) -> String {
    let mut features = Vec::new();
    if bits & EROFS_FEATURE_INCOMPAT_CHUNKED_FILE != 0 {
        features.push("chunked_file");
    }
    if bits & EROFS_FEATURE_INCOMPAT_DEVICE_TABLE != 0 {
        features.push("device_table");
    }
    if features.is_empty() {
        "none".to_string()
    } else {
        features.join(",")
    }
}

fn printable_bytes(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn format_u64_set(values: &BTreeSet<u64>) -> String {
    if values.is_empty() {
        return "-".to_string();
    }
    values
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}
