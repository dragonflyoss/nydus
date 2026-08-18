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
use tabled::{
    settings::{object::Rows, Alignment, Modify, Style},
    Table, Tabled,
};

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
    // Define the table struct for printing.
    #[derive(Debug, Tabled)]
    #[tabled(rename_all = "UPPERCASE")]
    struct ImageRow {
        kind: String,
        path: String,
        #[tabled(rename = "FILE SIZE")]
        file_size: String,
        #[tabled(rename = "PRIMARY IMAGE SIZE")]
        primary_image_size: String,
        #[tabled(rename = "COMPRESSED DATA REGION SIZE")]
        compressed_data_region_size: String,
    }

    let compressed_data_region_size = if kind == ImageKind::Blob && report.blobs.len() == 1 {
        let blob = report.blobs.values().next().expect("single blob summary");
        blob.data_size_for_display().to_string()
    } else {
        "-".to_string()
    };

    let row = ImageRow {
        kind: match kind {
            ImageKind::Blob => "blob",
            ImageKind::Bootstrap => "bootstrap",
        }
        .to_string(),
        path: path.display().to_string(),
        file_size: report.image_file_bytes.to_string(),
        primary_image_size: report.primary_image_bytes.to_string(),
        compressed_data_region_size,
    };

    // Create a table and print it.
    let mut table = Table::kv(vec![row]);
    table.with(Style::blank());
    println!("Image");
    println!("{table}");
    println!();
}

fn print_superblock(sb: &ErofsSuperblock) {
    // Define the table struct for printing.
    #[derive(Debug, Tabled)]
    #[tabled(rename_all = "UPPERCASE")]
    struct SuperblockRow {
        magic: String,
        checksum: String,
        #[tabled(rename = "FEATURE COMPAT")]
        feature_compat: String,
        #[tabled(rename = "FEATURE INCOMPAT")]
        feature_incompat: String,
        blkszbits: String,
        #[tabled(rename = "BLOCK SIZE")]
        block_size: String,
        #[tabled(rename = "SB EXTSLOTS")]
        sb_extslots: String,
        #[tabled(rename = "ROOT NID")]
        root_nid: String,
        #[tabled(rename = "ROOTNID 2B")]
        rootnid_2b: String,
        #[tabled(rename = "ROOTNID 8B")]
        rootnid_8b: String,
        inos: String,
        epoch: String,
        #[tabled(rename = "FIXED NSEC")]
        fixed_nsec: String,
        blocks: String,
        #[tabled(rename = "META BLKADDR")]
        meta_blkaddr: String,
        #[tabled(rename = "XATTR BLKADDR")]
        xattr_blkaddr: String,
        uuid: String,
        #[tabled(rename = "VOLUME NAME")]
        volume_name: String,
        #[tabled(rename = "COMPR OR DISTANCE")]
        compr_or_distance: String,
        #[tabled(rename = "EXTRA DEVICES")]
        extra_devices: String,
        #[tabled(rename = "DEVT SLOTOFF")]
        devt_slotoff: String,
        dirblkbits: String,
        #[tabled(rename = "XATTR PREFIX COUNT")]
        xattr_prefix_count: String,
        #[tabled(rename = "XATTR PREFIX START")]
        xattr_prefix_start: String,
        #[tabled(rename = "PACKED NID")]
        packed_nid: String,
        #[tabled(rename = "XATTR FILTER RESERVED")]
        xattr_filter_reserved: String,
        #[tabled(rename = "BUILD TIME")]
        build_time: String,
    }

    let row = SuperblockRow {
        magic: format!("0x{:08x}", sb.magic()),
        checksum: format!("0x{:08x}", u32::from_le_bytes(sb.checksum)),
        feature_compat: format!(
            "0x{:08x} ({})",
            sb.feature_compat(),
            compat_features(sb.feature_compat())
        ),
        feature_incompat: format!(
            "0x{:08x} ({})",
            sb.feature_incompat(),
            incompat_features(sb.feature_incompat())
        ),
        blkszbits: sb.blkszbits.to_string(),
        block_size: (1u64 << sb.blkszbits).to_string(),
        sb_extslots: sb.sb_extslots.to_string(),
        root_nid: sb.root_nid().to_string(),
        rootnid_2b: u16::from_le_bytes(sb.rootnid_2b).to_string(),
        rootnid_8b: u64::from_le_bytes(sb.rootnid_8b).to_string(),
        inos: sb.inos().to_string(),
        epoch: sb.epoch().to_string(),
        fixed_nsec: u32::from_le_bytes(sb.fixed_nsec).to_string(),
        blocks: sb.blocks().to_string(),
        meta_blkaddr: sb.meta_blkaddr().to_string(),
        xattr_blkaddr: u32::from_le_bytes(sb.xattr_blkaddr).to_string(),
        uuid: hex_string(&sb.uuid),
        volume_name: printable_bytes(&sb.volume_name),
        compr_or_distance: u16::from_le_bytes(sb.compr_or_distance).to_string(),
        extra_devices: sb.extra_devices().to_string(),
        devt_slotoff: sb.devt_slotoff().to_string(),
        dirblkbits: sb.dirblkbits.to_string(),
        xattr_prefix_count: sb.xattr_prefix_count.to_string(),
        xattr_prefix_start: u32::from_le_bytes(sb.xattr_prefix_start).to_string(),
        packed_nid: u64::from_le_bytes(sb.packed_nid).to_string(),
        xattr_filter_reserved: sb.xattr_filter_reserved.to_string(),
        build_time: u64::from_le_bytes(sb.build_time).to_string(),
    };

    // Create a table and print it.
    let mut table = Table::kv(vec![row]);
    table.with(Style::blank());
    println!("Superblock");
    println!("{table}");
    println!();
}

/// Print inodes whose inline tail crosses a metadata block. Only the first
/// entries are listed because a builder bug tends to hit many inodes at once.
fn print_inline_across_blocks(stats: &ImageStats) {
    if stats.inline_overflows.is_empty() {
        return;
    }

    // Define the table struct for printing.
    #[derive(Debug, Tabled)]
    #[tabled(rename_all = "UPPERCASE")]
    struct InlineOverflowRow {
        nid: u64,
        #[tabled(rename = "BLOCK OFFSET")]
        block_offset: u64,
        #[tabled(rename = "HEADER SIZE")]
        header_size: u64,
        #[tabled(rename = "XATTR SIZE")]
        xattr_size: u64,
        #[tabled(rename = "INLINE SIZE")]
        inline_size: u64,
        end: u64,
    }

    const MAX_LISTED: usize = 20;
    let rows: Vec<InlineOverflowRow> = stats
        .inline_overflows
        .iter()
        .take(MAX_LISTED)
        .map(|entry| InlineOverflowRow {
            nid: entry.nid,
            block_offset: entry.block_offset,
            header_size: entry.header_size,
            xattr_size: entry.xattr_size,
            inline_size: entry.inline_size,
            end: entry.block_offset + entry.header_size + entry.xattr_size + entry.inline_size,
        })
        .collect();

    // Create a table and print it.
    let mut table = Table::new(rows);
    table
        .with(Style::blank())
        .with(Modify::new(Rows::first()).with(Alignment::left()));
    println!(
        "Inline data across blocks ({} inode(s), block size {})",
        stats.inline_overflows.len(),
        EROFS_BLOCK_SIZE
    );
    println!("{table}");
    if stats.inline_overflows.len() > MAX_LISTED {
        println!("  ... {} more", stats.inline_overflows.len() - MAX_LISTED);
    }
    println!();
}

fn print_summary(stats: &ImageStats, blobs: &BTreeMap<u16, BlobSummary>) {
    // Define the table struct for printing.
    #[derive(Debug, Tabled)]
    #[tabled(rename_all = "UPPERCASE")]
    struct SummaryRow {
        #[tabled(rename = "VISITED INODES")]
        visited_inodes: String,
        #[tabled(rename = "MAX DEPTH")]
        max_depth: String,
        #[tabled(rename = "DIRECTORY ENTRIES")]
        directory_entries: String,
        #[tabled(rename = "REGULAR FILES")]
        regular_files: String,
        directories: String,
        symlinks: String,
        #[tabled(rename = "CHAR DEVICES")]
        char_devices: String,
        #[tabled(rename = "BLOCK DEVICES")]
        block_devices: String,
        fifos: String,
        sockets: String,
        #[tabled(rename = "CHUNKED FILES")]
        chunked_files: String,
        #[tabled(rename = "FLAT PLAIN FILES")]
        flat_plain_files: String,
        #[tabled(rename = "FLAT INLINE FILES")]
        flat_inline_files: String,
        #[tabled(rename = "OTHER LAYOUT FILES")]
        other_layout_files: String,
        #[tabled(rename = "XATTR ENTRIES")]
        xattr_entries: String,
        #[tabled(rename = "HARDLINK INODES")]
        hardlink_inodes: String,
        #[tabled(rename = "HARDLINK PATHS")]
        hardlink_paths: String,
        #[tabled(rename = "TOTAL CHUNKS")]
        total_chunks: String,
        #[tabled(rename = "HOLE CHUNKS")]
        hole_chunks: String,
        #[tabled(rename = "UNIQUE CHUNKS")]
        unique_chunks: String,
        #[tabled(rename = "TOTAL LOGICAL BYTES")]
        total_logical_bytes: String,
        #[tabled(rename = "CHUNK SIZES")]
        chunk_sizes: String,
    }

    let total_unique_chunks = blobs
        .values()
        .map(|blob| blob.unique_blkaddrs.len() as u64)
        .sum::<u64>();
    let row = SummaryRow {
        visited_inodes: stats.visited_inodes.to_string(),
        max_depth: stats.max_depth.to_string(),
        directory_entries: stats.directory_entries.to_string(),
        regular_files: stats.regular_files.to_string(),
        directories: stats.directories.to_string(),
        symlinks: stats.symlinks.to_string(),
        char_devices: stats.char_devices.to_string(),
        block_devices: stats.block_devices.to_string(),
        fifos: stats.fifos.to_string(),
        sockets: stats.sockets.to_string(),
        chunked_files: stats.chunked_files.to_string(),
        flat_plain_files: stats.flat_plain_files.to_string(),
        flat_inline_files: stats.flat_inline_files.to_string(),
        other_layout_files: stats.other_layout_files.to_string(),
        xattr_entries: stats.xattr_entries.to_string(),
        hardlink_inodes: stats.hardlink_inodes.to_string(),
        hardlink_paths: stats.hardlink_paths.to_string(),
        total_chunks: stats.total_chunks.to_string(),
        hole_chunks: stats.hole_chunks.to_string(),
        unique_chunks: total_unique_chunks.to_string(),
        total_logical_bytes: stats.total_logical_bytes.to_string(),
        chunk_sizes: format_u64_set(&stats.chunk_sizes),
    };

    // Create a table and print it.
    let mut table = Table::kv(vec![row]);
    table.with(Style::blank());
    println!("Summary");
    println!("{table}");
    println!();
}

fn print_blobs(blobs: &BTreeMap<u16, BlobSummary>) {
    println!("Blobs");
    if blobs.is_empty() {
        println!("  (no external blobs recorded in device table)");
        println!();
        return;
    }

    // Define the table struct for printing.
    #[derive(Debug, Tabled)]
    #[tabled(rename_all = "UPPERCASE")]
    struct BlobRow {
        entry: String,
        #[tabled(rename = "BLOB INDEX")]
        blob_index: String,
        #[tabled(rename = "MAPPED BLKADDR")]
        mapped_blkaddr: String,
        #[tabled(rename = "MAPPED OFFSET")]
        mapped_offset: String,
        #[tabled(rename = "DECLARED BLOCKS")]
        declared_blocks: String,
        #[tabled(rename = "DECLARED UNCOMPRESSED SIZE")]
        declared_uncompressed_size: String,
        #[tabled(rename = "SLOT DIGEST KIND")]
        slot_digest_kind: String,
        #[tabled(rename = "DATA BLOB DIGEST")]
        data_blob_digest: String,
        #[tabled(rename = "FULL BLOB DIGEST")]
        full_blob_digest: String,
        #[tabled(rename = "CHUNK SIZE")]
        chunk_size: String,
        #[tabled(rename = "CHUNK COUNT")]
        chunk_count: String,
        #[tabled(rename = "GROUP COUNT")]
        group_count: String,
        #[tabled(rename = "CHUNK DIGESTER")]
        chunk_digester: String,
        #[tabled(rename = "CHUNK COMPRESSOR")]
        chunk_compressor: String,
        #[tabled(rename = "BLOB COMPRESSED SIZE")]
        blob_compressed_size: String,
        #[tabled(rename = "BLOB UNCOMPRESSED SIZE")]
        blob_uncompressed_size: String,
        #[tabled(rename = "CHUNK REFS")]
        chunk_refs: String,
        #[tabled(rename = "UNIQUE CHUNKS")]
        unique_chunks: String,
        #[tabled(rename = "LOGICAL BYTES")]
        logical_bytes: String,
        #[tabled(rename = "CHUNK SIZES")]
        chunk_sizes: String,
        source: String,
    }

    for (index, (blob_index, blob)) in blobs.iter().enumerate() {
        let row = BlobRow {
            entry: index.to_string(),
            blob_index: blob_index.to_string(),
            mapped_blkaddr: blob.mapped_blkaddr.to_string(),
            mapped_offset: blob.mapped_offset.to_string(),
            declared_blocks: blob.declared_blocks.to_string(),
            declared_uncompressed_size: blob.declared_data_size.to_string(),
            slot_digest_kind: blob.slot_sha256_kind.as_str().to_string(),
            data_blob_digest: data_blob_digest(blob),
            full_blob_digest: optional_digest(blob.blob_sha256),
            chunk_size: blob_metadata_field(blob, |meta| meta.chunk_size),
            chunk_count: blob_metadata_field(blob, |meta| meta.chunk_count),
            group_count: blob_metadata_field(blob, |meta| meta.group_count),
            chunk_digester: blob_metadata_field(blob, |meta| meta.digester),
            chunk_compressor: blob_metadata_field(blob, |meta| meta.compressor),
            blob_compressed_size: blob_metadata_field_or(
                blob,
                |meta| meta.total_compressed_size,
                blob.data_size,
            ),
            blob_uncompressed_size: blob_metadata_field_or(
                blob,
                |meta| meta.total_uncompressed_size,
                Some(blob.declared_data_size),
            ),
            chunk_refs: blob.chunk_refs.to_string(),
            unique_chunks: blob.unique_blkaddrs.len().to_string(),
            logical_bytes: blob.logical_bytes.to_string(),
            chunk_sizes: format_u64_set(&blob.chunk_sizes),
            source: blob
                .resolved_path
                .as_ref()
                .map(|source| source.display().to_string())
                .unwrap_or_else(|| "-".to_string()),
        };

        // Create a table and print it.
        let mut table = Table::kv(vec![row]);
        table.with(Style::blank());
        println!("{table}");
        println!();
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
