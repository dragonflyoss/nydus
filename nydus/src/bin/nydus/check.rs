use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use memmap2::Mmap;
use nydus::build::inode::mode_to_erofs_file_type;
use nydus::config::Config;
use nydus::fs::{BlobInfo, ErofsReader};
use nydus::metadata::*;
use nydus::utils::{hex_string, sha256_bytes};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct CheckArgs {
    /// File path to an nydus blob.
    #[arg(long)]
    pub blob: Option<PathBuf>,

    /// File path to an nydus bootstrap.
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,

    /// Optional directory containing external blob files referenced by bootstrap.
    #[arg(long)]
    pub blob_dir: Option<PathBuf>,

    /// File path to a YAML storage config providing the backend directory.
    /// When set, --blob-dir can be omitted.
    #[arg(long)]
    pub config: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ImageKind {
    Blob,
    Bootstrap,
}

#[derive(Default)]
struct ImageStats {
    visited_inodes: u64,
    max_depth: u32,
    directory_entries: u64,
    regular_files: u64,
    directories: u64,
    symlinks: u64,
    char_devices: u64,
    block_devices: u64,
    fifos: u64,
    sockets: u64,
    chunked_files: u64,
    flat_plain_files: u64,
    flat_inline_files: u64,
    other_layout_files: u64,
    xattr_entries: u64,
    hardlink_inodes: u64,
    hardlink_paths: u64,
    total_chunks: u64,
    hole_chunks: u64,
    total_logical_bytes: u64,
    chunk_sizes: BTreeSet<u64>,
}

struct BlobSummary {
    slot_sha256: [u8; EROFS_BLOB_ID_SIZE],
    slot_sha256_kind: SlotSha256Kind,
    declared_blocks: u64,
    mapped_blkaddr: u64,
    mapped_offset: u64,
    declared_data_size: u64,
    resolved_path: Option<PathBuf>,
    blob_size: Option<u64>,
    blob_sha256: Option<[u8; EROFS_BLOB_ID_SIZE]>,
    data_sha256: Option<[u8; EROFS_BLOB_ID_SIZE]>,
    data_size: Option<u64>,
    blob_meta: Option<BlobMetaSummary>,
    verified: bool,
    chunk_refs: u64,
    unique_blkaddrs: HashSet<u64>,
    logical_bytes: u64,
    chunk_sizes: BTreeSet<u64>,
}

impl BlobSummary {
    fn new(blob: &BlobInfo) -> Self {
        let mapped_offset = blob.mapped_blkaddr * EROFS_BLOCK_SIZE as u64;
        Self {
            slot_sha256: blob.blob_id,
            slot_sha256_kind: SlotSha256Kind::Unknown,
            declared_blocks: blob.blocks,
            mapped_blkaddr: blob.mapped_blkaddr,
            mapped_offset,
            declared_data_size: blob.blocks * EROFS_BLOCK_SIZE as u64,
            resolved_path: None,
            blob_size: None,
            blob_sha256: None,
            data_sha256: None,
            data_size: None,
            blob_meta: None,
            verified: false,
            chunk_refs: 0,
            unique_blkaddrs: HashSet::new(),
            logical_bytes: 0,
            chunk_sizes: BTreeSet::new(),
        }
    }

    fn data_size_for_display(&self) -> u64 {
        self.data_size.unwrap_or(self.declared_data_size)
    }
}

#[derive(Clone)]
struct ResolvedBlob {
    path: PathBuf,
    blob_size: u64,
    blob_sha256: [u8; EROFS_BLOB_ID_SIZE],
    data_sha256: [u8; EROFS_BLOB_ID_SIZE],
    data_size: u64,
    blob_meta: Option<BlobMetaSummary>,
    slot_sha256_kind: SlotSha256Kind,
    verified: bool,
}

struct BlobInspection {
    data_sha256: [u8; EROFS_BLOB_ID_SIZE],
    data_size: u64,
    blob_sha256: [u8; EROFS_BLOB_ID_SIZE],
    blob_size: u64,
    blob_meta: Option<BlobMetaSummary>,
}

#[derive(Clone)]
struct BlobMetaSummary {
    chunk_count: usize,
    group_count: usize,
    chunk_size: u32,
    digester: BlobMetaDigester,
    compressor: BlobMetaCompressor,
    total_uncompressed_size: u64,
    total_compressed_size: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SlotSha256Kind {
    Blob,
    Data,
    Unknown,
}

impl SlotSha256Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "full_blob",
            Self::Data => "data_blob",
            Self::Unknown => "unknown",
        }
    }
}

pub fn run_check(args: CheckArgs) -> Result<()> {
    // `check` verifies blobs from a local directory. --blob-dir takes precedence
    // over the config; a config is only usable here when it has a local backend.
    let blob_dir = match &args.blob_dir {
        Some(dir) => Some(dir.clone()),
        None => match &args.config {
            Some(path) => {
                let config = Config::from_file(path).context("failed to load storage config")?;
                if config.backend.kind == "local" {
                    let dir = config
                        .backend
                        .config
                        .get("dir")
                        .and_then(|value| value.as_str())
                        .map(PathBuf::from)
                        .ok_or_else(|| anyhow!("local backend config is missing 'dir'"))?;
                    Some(dir)
                } else {
                    bail!(
                        "check only supports a local backend, but config backend is '{}'",
                        config.backend.kind
                    )
                }
            }
            None => None,
        },
    };

    let (kind, path) = match (&args.blob, &args.bootstrap, &blob_dir) {
        (Some(blob), None, None) => (ImageKind::Blob, blob.as_path()),
        (None, Some(bootstrap), None) => (ImageKind::Bootstrap, bootstrap.as_path()),
        (None, Some(bootstrap), Some(blob_dir)) if blob_dir.is_dir() => {
            (ImageKind::Bootstrap, bootstrap.as_path())
        }
        (None, Some(_), Some(blob_dir)) => {
            bail!("blob-dir {} is not a directory", blob_dir.display())
        }
        _ => {
            bail!("check expects either --blob <path> or --bootstrap <path> with a blob directory from --blob-dir or --config")
        }
    };

    let reader = ErofsReader::open_layer(path)
        .with_context(|| format!("failed to open image for inspection: {}", path.display()))?;
    let sb = reader.sb();
    let image_file_bytes = fs::metadata(path)
        .with_context(|| format!("failed to stat image: {}", path.display()))?
        .len();
    let primary_image_bytes = sb.blocks() * EROFS_BLOCK_SIZE as u64;
    let blob_infos = reader.blob_infos().context("failed to read device slots")?;
    let resolved_blobs = resolve_blobs(kind, path, blob_dir.as_deref(), &blob_infos)?;
    let mut blobs = blob_infos
        .iter()
        .map(|blob| {
            let mut summary = BlobSummary::new(blob);
            if let Some(resolved) = resolved_blobs.get(&blob.blob_index) {
                summary.resolved_path = Some(resolved.path.clone());
                summary.blob_size = Some(resolved.blob_size);
                summary.blob_sha256 = Some(resolved.blob_sha256);
                summary.data_sha256 = Some(resolved.data_sha256);
                summary.data_size = Some(resolved.data_size);
                summary.blob_meta = resolved.blob_meta.clone();
                summary.slot_sha256_kind = resolved.slot_sha256_kind;
                summary.verified = resolved.verified;
            }
            (blob.blob_index, summary)
        })
        .collect::<BTreeMap<_, _>>();

    let mut stats = ImageStats::default();
    let epoch = sb.epoch();
    let mut visited = HashSet::new();
    walk_inode(
        &reader,
        sb.root_nid(),
        epoch,
        0,
        &mut visited,
        &mut stats,
        &mut blobs,
    )?;

    print_header(kind, path, image_file_bytes, primary_image_bytes, &blobs);
    print_superblock(sb);
    print_summary(&stats, &blobs);
    print_blobs(&blobs);

    Ok(())
}

fn walk_inode(
    reader: &ErofsReader,
    nid: u64,
    epoch: u64,
    depth: u32,
    visited: &mut HashSet<u64>,
    stats: &mut ImageStats,
    blobs: &mut BTreeMap<u16, BlobSummary>,
) -> Result<()> {
    if !visited.insert(nid) {
        return Ok(());
    }

    let inode = reader
        .inode(nid)
        .with_context(|| format!("failed to read inode {nid}"))?;
    let file_type = mode_to_erofs_file_type(inode.mode());

    stats.visited_inodes += 1;
    stats.max_depth = stats.max_depth.max(depth);
    stats.xattr_entries += reader.read_xattrs(nid, &inode)?.len() as u64;
    if file_type != EROFS_FT_DIR && inode.nlink() > 1 {
        stats.hardlink_inodes += 1;
        stats.hardlink_paths += inode.nlink() as u64;
    }

    match file_type {
        EROFS_FT_DIR => {
            stats.directories += 1;
            for entry in reader.read_dir(nid, &inode)? {
                if entry.name == "." || entry.name == ".." {
                    continue;
                }
                stats.directory_entries += 1;
                walk_inode(reader, entry.nid, epoch, depth + 1, visited, stats, blobs)?;
            }
        }
        EROFS_FT_REG_FILE => {
            stats.regular_files += 1;
            match inode.data_layout() {
                EROFS_INODE_CHUNK_BASED => {
                    stats.chunked_files += 1;
                    let chunk_size = 1u64 << chunkbits(reader, &inode);
                    stats.chunk_sizes.insert(chunk_size);
                    let chunk_indexes = reader.read_chunk_indexes(nid, &inode)?;
                    stats.total_chunks += chunk_indexes.len() as u64;
                    stats.total_logical_bytes += inode.size();

                    for (index, chunk) in chunk_indexes.iter().enumerate() {
                        let remaining = inode.size().saturating_sub(index as u64 * chunk_size);
                        let logical_bytes = remaining.min(chunk_size);
                        // Hole chunks reference no blob at all (their on-disk
                        // device_id bits are part of the null sentinel), so
                        // they must not fabricate a blob summary entry.
                        if chunk.blkaddr == EROFS_NULL_ADDR {
                            stats.hole_chunks += 1;
                            continue;
                        }
                        let blob = blobs.entry(chunk.device_id).or_insert_with(|| BlobSummary {
                            slot_sha256: [0u8; EROFS_BLOB_ID_SIZE],
                            slot_sha256_kind: SlotSha256Kind::Unknown,
                            declared_blocks: 0,
                            mapped_blkaddr: 0,
                            mapped_offset: 0,
                            declared_data_size: 0,
                            resolved_path: None,
                            blob_size: None,
                            blob_sha256: None,
                            data_sha256: None,
                            data_size: None,
                            blob_meta: None,
                            verified: false,
                            chunk_refs: 0,
                            unique_blkaddrs: HashSet::new(),
                            logical_bytes: 0,
                            chunk_sizes: BTreeSet::new(),
                        });
                        blob.chunk_refs += 1;
                        blob.logical_bytes += logical_bytes;
                        blob.chunk_sizes.insert(chunk_size);
                        blob.unique_blkaddrs.insert(chunk.blkaddr);
                    }
                }
                EROFS_INODE_FLAT_PLAIN => {
                    stats.flat_plain_files += 1;
                }
                EROFS_INODE_FLAT_INLINE => {
                    stats.flat_inline_files += 1;
                }
                _ => {
                    stats.other_layout_files += 1;
                }
            }
        }
        EROFS_FT_SYMLINK => {
            let _ = inode.mtime(epoch);
            stats.symlinks += 1;
        }
        EROFS_FT_CHRDEV => {
            stats.char_devices += 1;
        }
        EROFS_FT_BLKDEV => {
            stats.block_devices += 1;
        }
        EROFS_FT_FIFO => {
            stats.fifos += 1;
        }
        EROFS_FT_SOCK => {
            stats.sockets += 1;
        }
        _ => {}
    }

    Ok(())
}

fn resolve_blobs(
    kind: ImageKind,
    image_path: &Path,
    blob_dir: Option<&Path>,
    blob_infos: &[BlobInfo],
) -> Result<HashMap<u16, ResolvedBlob>> {
    let mut resolved = HashMap::new();

    if kind == ImageKind::Blob && blob_infos.len() == 1 {
        if let Some(inspection) = inspect_blob(image_path)? {
            resolved.insert(
                blob_infos[0].blob_index,
                ResolvedBlob {
                    path: image_path.to_path_buf(),
                    blob_size: inspection.blob_size,
                    blob_sha256: inspection.blob_sha256,
                    data_sha256: inspection.data_sha256,
                    data_size: inspection.data_size,
                    blob_meta: inspection.blob_meta,
                    slot_sha256_kind: SlotSha256Kind::Data,
                    verified: inspection.data_sha256 == blob_infos[0].blob_id,
                },
            );
        }
    }

    let Some(blob_dir) = blob_dir else {
        return Ok(resolved);
    };

    let mut blob_sha_matches = HashMap::new();

    for entry in fs::read_dir(blob_dir)
        .with_context(|| format!("failed to read blob-dir: {}", blob_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let Some(inspection) = inspect_blob(&path)? else {
            continue;
        };

        blob_sha_matches
            .entry(inspection.blob_sha256)
            .or_insert_with(|| ResolvedBlob {
                path: path.clone(),
                blob_size: inspection.blob_size,
                blob_sha256: inspection.blob_sha256,
                data_sha256: inspection.data_sha256,
                data_size: inspection.data_size,
                blob_meta: inspection.blob_meta.clone(),
                slot_sha256_kind: SlotSha256Kind::Blob,
                verified: true,
            });
    }

    for blob in blob_infos {
        if let Some(match_by_blob) = blob_sha_matches.get(&blob.blob_id) {
            resolved
                .entry(blob.blob_index)
                .or_insert_with(|| match_by_blob.clone());
        }
    }

    Ok(resolved)
}

fn inspect_blob(path: &Path) -> Result<Option<BlobInspection>> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open blob candidate: {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }
        .with_context(|| format!("failed to map blob candidate: {}", path.display()))?;
    if mmap.len() < NYDUS_BLOB_FOOTER_SIZE {
        return Ok(None);
    }
    let footer_bytes = &mmap[mmap.len() - NYDUS_BLOB_FOOTER_SIZE..];
    if !BlobFooter::has_magic(footer_bytes) {
        return Ok(None);
    }

    let footer = BlobFooter::parse_from_tail(&mmap)?;
    let data_start = usize::try_from(footer.compressed_data_offset())
        .context("compressed data offset too large")?;
    let data_size =
        usize::try_from(footer.compressed_data_size()).context("compressed data size too large")?;
    let data_end = data_start
        .checked_add(data_size)
        .context("data range overflow")?;
    let meta_start =
        usize::try_from(footer.blob_meta_offset()).context("blob meta offset too large")?;
    let meta_end = meta_start
        .checked_add(footer.blob_meta_size() as usize)
        .context("blob meta range overflow")?;

    let data_digest = sha256_bytes(&mmap[data_start..data_end]);
    let blob_sha256 = sha256_bytes(&mmap);
    Ok(Some(BlobInspection {
        data_sha256: data_digest,
        data_size: footer.compressed_data_size(),
        blob_sha256,
        blob_size: mmap.len() as u64,
        blob_meta: Some(blob_meta_summary_from_bytes(&mmap[meta_start..meta_end])?),
    }))
}

fn blob_meta_summary_from_bytes(data: &[u8]) -> Result<BlobMetaSummary> {
    let blob_meta = BlobMeta::from_bytes_with_blob_id(data, [0u8; EROFS_BLOB_ID_SIZE])?;
    Ok(BlobMetaSummary {
        chunk_count: blob_meta.chunk_count(),
        group_count: blob_meta.group_count(),
        chunk_size: blob_meta.chunk_size(),
        digester: blob_meta.digester(),
        compressor: blob_meta.compressor(),
        total_uncompressed_size: blob_meta.total_uncompressed_size(),
        total_compressed_size: blob_meta.total_compressed_size(),
    })
}

fn chunkbits(reader: &ErofsReader, inode: &ErofsInode<'_>) -> u32 {
    reader.sb().blkszbits as u32 + (inode.chunk_format() as u32 & 0x1F)
}

fn print_header(
    kind: ImageKind,
    path: &Path,
    image_file_bytes: u64,
    primary_image_bytes: u64,
    blobs: &BTreeMap<u16, BlobSummary>,
) {
    println!("Image");
    println!(
        "  kind: {}",
        match kind {
            ImageKind::Blob => "blob",
            ImageKind::Bootstrap => "bootstrap",
        }
    );
    println!("  path: {}", path.display());
    println!("  file_size: {image_file_bytes}");
    println!("  primary_image_size: {primary_image_bytes}");
    if kind == ImageKind::Blob && blobs.len() == 1 {
        let blob = blobs.values().next().expect("single blob summary");
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
    println!("    device_table_index: {index}");
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
        blob_meta_field(blob, |meta| meta.chunk_size)
    );
    println!(
        "    chunk_count: {}",
        blob_meta_field(blob, |meta| meta.chunk_count)
    );
    println!(
        "    group_count: {}",
        blob_meta_field(blob, |meta| meta.group_count)
    );
    println!(
        "    chunk_digester: {}",
        blob_meta_field(blob, |meta| meta.digester)
    );
    println!(
        "    chunk_compressor: {}",
        blob_meta_field(blob, |meta| meta.compressor)
    );
    println!(
        "    blob_compressed_size: {}",
        blob_meta_field_or(blob, |meta| meta.total_compressed_size, blob.data_size)
    );
    println!(
        "    blob_uncompressed_size: {}",
        blob_meta_field_or(
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

fn blob_meta_field<T: ToString>(
    blob: &BlobSummary,
    field: impl FnOnce(&BlobMetaSummary) -> T,
) -> String {
    blob.blob_meta
        .as_ref()
        .map(|meta| field(meta).to_string())
        .unwrap_or_else(|| "<unresolved>".to_string())
}

fn blob_meta_field_or<T: ToString>(
    blob: &BlobSummary,
    field: impl FnOnce(&BlobMetaSummary) -> T,
    fallback: Option<T>,
) -> String {
    blob.blob_meta
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn resolve_bootstrap_blob_dir_by_full_blob_digest_only() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob");
        let (full_blob_digest, data_blob_digest) = write_minimal_blob(&blob_path);

        let full_blob_info = BlobInfo {
            blob_index: 1,
            blob_id: full_blob_digest,
            blocks: 1,
            mapped_blkaddr: 0,
        };
        let resolved = resolve_blobs(
            ImageKind::Bootstrap,
            Path::new("bootstrap.boot"),
            Some(dir.path()),
            &[full_blob_info],
        )
        .unwrap();
        let resolved_blob = resolved.get(&1).unwrap();

        assert_eq!(resolved_blob.slot_sha256_kind, SlotSha256Kind::Blob);
        assert_eq!(resolved_blob.blob_sha256, full_blob_digest);
        assert!(resolved_blob.verified);

        let data_blob_info = BlobInfo {
            blob_index: 2,
            blob_id: data_blob_digest,
            blocks: 1,
            mapped_blkaddr: 0,
        };
        let resolved = resolve_blobs(
            ImageKind::Bootstrap,
            Path::new("bootstrap.boot"),
            Some(dir.path()),
            &[data_blob_info],
        )
        .unwrap();

        assert!(!resolved.contains_key(&2));
    }

    fn write_minimal_blob(path: &Path) -> ([u8; EROFS_BLOB_ID_SIZE], [u8; EROFS_BLOB_ID_SIZE]) {
        let data = [0x5au8; EROFS_BLOCK_SIZE as usize];
        let data_digest = sha256_bytes(&data);
        let blob_meta = BlobMeta::from_parts(
            [0u8; EROFS_BLOB_ID_SIZE],
            BLOB_META_DEFAULT_CHUNK_BLOCK_COUNT,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let mut blob_meta_bytes = Vec::new();
        blob_meta.write_to(&mut blob_meta_bytes).unwrap();
        assert_eq!(blob_meta_bytes.len(), EROFS_BLOCK_SIZE as usize);

        let footer = BlobFooter::new(
            0,
            data.len() as u64,
            data.len() as u64,
            0,
            data.len() as u64,
            1,
        )
        .unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(&data);
        blob.extend_from_slice(&blob_meta_bytes);
        footer.write_to(&mut blob).unwrap();
        fs::write(path, &blob).unwrap();

        (sha256_bytes(&blob), data_digest)
    }
}
