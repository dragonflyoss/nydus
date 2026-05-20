use anyhow::{bail, Context, Result};
use clap::Args;
use lepton::build::inode::mode_to_file_type;
use lepton::fs::{DeviceInfo, ErofsReader};
use lepton::metadata::*;
use memmap2::Mmap;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct CheckArgs {
    /// File path to an lepton blob.
    #[arg(long)]
    pub blob: Option<PathBuf>,

    /// File path to an lepton bootstrap.
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,

    /// Optional directory containing external blob files referenced by bootstrap.
    #[arg(long)]
    pub blob_dir: Option<PathBuf>,
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
    total_logical_bytes: u64,
    chunk_sizes: BTreeSet<u64>,
}

struct BlobSummary {
    device_id: u16,
    slot_sha256: [u8; EROFS_BLOB_ID_SIZE],
    slot_sha256_kind: SlotSha256Kind,
    declared_data_size: u64,
    resolved_path: Option<PathBuf>,
    blob_size: Option<u64>,
    blob_sha256: Option<[u8; EROFS_BLOB_ID_SIZE]>,
    data_sha256: Option<[u8; EROFS_BLOB_ID_SIZE]>,
    data_size: Option<u64>,
    verified: bool,
    chunk_refs: u64,
    unique_blkaddrs: HashSet<u64>,
    logical_bytes: u64,
    chunk_sizes: BTreeSet<u64>,
}

impl BlobSummary {
    fn new(device: &DeviceInfo) -> Self {
        Self {
            device_id: device.device_id,
            slot_sha256: device.blob_id,
            slot_sha256_kind: SlotSha256Kind::Unknown,
            declared_data_size: device.blocks * EROFS_BLOCK_SIZE as u64,
            resolved_path: None,
            blob_size: None,
            blob_sha256: None,
            data_sha256: None,
            data_size: None,
            verified: false,
            chunk_refs: 0,
            unique_blkaddrs: HashSet::new(),
            logical_bytes: 0,
            chunk_sizes: BTreeSet::new(),
        }
    }

    fn blob_size_for_display(&self) -> Option<u64> {
        self.blob_size
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
    slot_sha256_kind: SlotSha256Kind,
    verified: bool,
}

struct BlobInspection {
    data_sha256: [u8; EROFS_BLOB_ID_SIZE],
    data_size: u64,
    blob_sha256: [u8; EROFS_BLOB_ID_SIZE],
    blob_size: u64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SlotSha256Kind {
    Blob,
    Data,
    Unknown,
}

pub fn run_check(args: CheckArgs) -> Result<()> {
    let (kind, path) = match (&args.blob, &args.bootstrap, &args.blob_dir) {
        (Some(blob), None, None) => (ImageKind::Blob, blob.as_path()),
        (None, Some(bootstrap), None) => (ImageKind::Bootstrap, bootstrap.as_path()),
        (None, Some(bootstrap), Some(blob_dir)) if blob_dir.is_dir() => {
            (ImageKind::Bootstrap, bootstrap.as_path())
        }
        (None, Some(_), Some(blob_dir)) => {
            bail!("blob-dir {} is not a directory", blob_dir.display())
        }
        _ => {
            bail!("check expects either --blob <path> or --bootstrap <path> [--blob-dir <dir>]")
        }
    };

    let reader = ErofsReader::open_layer(path)
        .with_context(|| format!("failed to open image for inspection: {}", path.display()))?;
    let sb = reader.sb();
    let image_file_bytes = fs::metadata(path)
        .with_context(|| format!("failed to stat image: {}", path.display()))?
        .len();
    let primary_image_bytes = sb.blocks() * EROFS_BLOCK_SIZE as u64;
    let device_infos = reader
        .device_infos()
        .context("failed to read device slots")?;
    let resolved_blobs = resolve_blobs(
        kind,
        path,
        args.blob_dir.as_deref(),
        primary_image_bytes,
        &device_infos,
    )?;
    let mut blobs = device_infos
        .iter()
        .map(|device| {
            let mut summary = BlobSummary::new(device);
            if let Some(resolved) = resolved_blobs.get(&device.device_id) {
                summary.resolved_path = Some(resolved.path.clone());
                summary.blob_size = Some(resolved.blob_size);
                summary.blob_sha256 = Some(resolved.blob_sha256);
                summary.data_sha256 = Some(resolved.data_sha256);
                summary.data_size = Some(resolved.data_size);
                summary.slot_sha256_kind = resolved.slot_sha256_kind;
                summary.verified = resolved.verified;
            }
            (device.device_id, summary)
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
    let file_type = mode_to_file_type(inode.mode());

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
                        let blob = blobs.entry(chunk.device_id).or_insert_with(|| BlobSummary {
                            device_id: chunk.device_id,
                            slot_sha256: [0u8; EROFS_BLOB_ID_SIZE],
                            slot_sha256_kind: SlotSha256Kind::Unknown,
                            declared_data_size: 0,
                            resolved_path: None,
                            blob_size: None,
                            blob_sha256: None,
                            data_sha256: None,
                            data_size: None,
                            verified: false,
                            chunk_refs: 0,
                            unique_blkaddrs: HashSet::new(),
                            logical_bytes: 0,
                            chunk_sizes: BTreeSet::new(),
                        });
                        blob.chunk_refs += 1;
                        blob.logical_bytes += logical_bytes;
                        blob.chunk_sizes.insert(chunk_size);
                        if chunk.blkaddr != EROFS_NULL_ADDR {
                            blob.unique_blkaddrs.insert(chunk.blkaddr);
                        }
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
    primary_image_bytes: u64,
    device_infos: &[DeviceInfo],
) -> Result<HashMap<u16, ResolvedBlob>> {
    let mut resolved = HashMap::new();

    if kind == ImageKind::Blob && device_infos.len() == 1 {
        let data_size = fs::metadata(image_path)
            .with_context(|| format!("failed to stat blob: {}", image_path.display()))?
            .len()
            .saturating_sub(primary_image_bytes);
        let verified = verify_blob_tail(image_path, primary_image_bytes, &device_infos[0].blob_id)
            .with_context(|| format!("failed to verify blob: {}", image_path.display()))?;
        let blob_sha256 = sha256_file(image_path)
            .with_context(|| format!("failed to hash blob: {}", image_path.display()))?;
        resolved.insert(
            device_infos[0].device_id,
            ResolvedBlob {
                path: image_path.to_path_buf(),
                blob_size: fs::metadata(image_path)
                    .with_context(|| format!("failed to stat blob: {}", image_path.display()))?
                    .len(),
                blob_sha256,
                data_sha256: sha256_file_region(image_path, primary_image_bytes).with_context(
                    || format!("failed to hash blob data: {}", image_path.display()),
                )?,
                data_size,
                slot_sha256_kind: SlotSha256Kind::Data,
                verified,
            },
        );
    }

    let Some(blob_dir) = blob_dir else {
        return Ok(resolved);
    };

    let mut blob_sha_matches = HashMap::new();
    let mut data_sha_matches = HashMap::new();

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
                slot_sha256_kind: SlotSha256Kind::Blob,
                verified: true,
            });
        data_sha_matches
            .entry(inspection.data_sha256)
            .or_insert(ResolvedBlob {
                path,
                blob_size: inspection.blob_size,
                blob_sha256: inspection.blob_sha256,
                data_sha256: inspection.data_sha256,
                data_size: inspection.data_size,
                slot_sha256_kind: SlotSha256Kind::Data,
                verified: true,
            });
    }

    for device in device_infos {
        if let Some(match_by_blob) = blob_sha_matches.get(&device.blob_id) {
            resolved
                .entry(device.device_id)
                .or_insert_with(|| match_by_blob.clone());
            continue;
        }
        if let Some(match_by_data) = data_sha_matches.get(&device.blob_id) {
            resolved
                .entry(device.device_id)
                .or_insert_with(|| match_by_data.clone());
        }
    }

    Ok(resolved)
}

fn inspect_blob(path: &Path) -> Result<Option<BlobInspection>> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open blob candidate: {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }
        .with_context(|| format!("failed to map blob candidate: {}", path.display()))?;
    if mmap.len() < EROFS_SUPER_OFFSET as usize + EROFS_SB_BASE_SIZE {
        return Ok(None);
    }

    let sb = cast_ref::<ErofsSuperblock>(&mmap[EROFS_SUPER_OFFSET as usize..]);
    if sb.magic() != EROFS_SUPER_MAGIC_V1 {
        return Ok(None);
    }

    let primary_image_bytes = sb.blocks() * EROFS_BLOCK_SIZE as u64;
    if primary_image_bytes as usize > mmap.len() {
        return Ok(None);
    }

    let data_digest = sha256_bytes(&mmap[primary_image_bytes as usize..]);
    let blob_sha256 = sha256_bytes(&mmap);
    Ok(Some(BlobInspection {
        data_sha256: data_digest,
        data_size: mmap.len().saturating_sub(primary_image_bytes as usize) as u64,
        blob_sha256,
        blob_size: mmap.len() as u64,
    }))
}

fn verify_blob_tail(
    path: &Path,
    primary_image_bytes: u64,
    expected: &[u8; EROFS_BLOB_ID_SIZE],
) -> Result<bool> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open blob for verification: {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }
        .with_context(|| format!("failed to map blob for verification: {}", path.display()))?;
    if primary_image_bytes as usize > mmap.len() {
        return Ok(false);
    }
    Ok(&sha256_bytes(&mmap[primary_image_bytes as usize..]) == expected)
}

fn chunkbits(reader: &ErofsReader, inode: &ErofsInode<'_>) -> u32 {
    reader.sb().blkszbits as u32 + (inode.chunk_format() as u32 & 0x1F)
}

fn sha256_bytes(data: &[u8]) -> [u8; EROFS_BLOB_ID_SIZE] {
    let mut digest = [0u8; EROFS_BLOB_ID_SIZE];
    digest.copy_from_slice(&Sha256::digest(data));
    digest
}

fn sha256_file(path: &Path) -> Result<[u8; EROFS_BLOB_ID_SIZE]> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open file for hashing: {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }
        .with_context(|| format!("failed to map file for hashing: {}", path.display()))?;
    Ok(sha256_bytes(&mmap))
}

fn sha256_file_region(path: &Path, offset: u64) -> Result<[u8; EROFS_BLOB_ID_SIZE]> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open file for hashing: {}", path.display()))?;
    let mmap = unsafe { Mmap::map(&file) }
        .with_context(|| format!("failed to map file for hashing: {}", path.display()))?;
    if offset as usize > mmap.len() {
        bail!("hash region offset exceeds file size: {}", path.display());
    }
    Ok(sha256_bytes(&mmap[offset as usize..]))
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
    println!("  file_size: {}", image_file_bytes);
    println!("  primary_image_size: {}", primary_image_bytes);
    if kind == ImageKind::Blob && blobs.len() == 1 {
        let blob = blobs.values().next().expect("single blob summary");
        println!(
            "  appended_blob_data_size: {}",
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
    println!("  unique_chunks: {}", total_unique_chunks);
    println!("  total_logical_bytes: {}", stats.total_logical_bytes);
    println!("  chunk_sizes: {}", format_u64_set(&stats.chunk_sizes));
    println!();
}

fn print_blobs(blobs: &BTreeMap<u16, BlobSummary>) {
    println!("Blobs");
    if blobs.is_empty() {
        println!("  (no external blobs recorded in device table)");
        println!();
        println!("Notes");
        println!("  current lepton writer does not emit compressed chunk payload; compressor is reported as none when blob devices exist.");
        return;
    }

    for blob in blobs.values() {
        let slot_sha256 = if blob.slot_sha256.iter().all(|byte| *byte == 0) {
            "<unknown>".to_string()
        } else {
            hex_string(&blob.slot_sha256)
        };
        let blob_sha256 = blob
            .blob_sha256
            .map(|sha256| hex_string(&sha256))
            .unwrap_or_else(|| "<unresolved>".to_string());
        let data_sha256 = blob
            .data_sha256
            .map(|sha256| hex_string(&sha256))
            .unwrap_or_else(|| "<unresolved>".to_string());
        let source = blob
            .resolved_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<metadata-only>".to_string());
        println!(
            "  device={} slot_sha256={} slot_sha256_kind={} blob_sha256={} blob_size={} data_sha256={} data_size={} chunk_refs={} unique_chunks={} compressor=none chunk_sizes={} logical_bytes={} declared_data_size={} verified={} source={}",
            blob.device_id,
            slot_sha256,
            match blob.slot_sha256_kind {
                SlotSha256Kind::Blob => "blob_sha256",
                SlotSha256Kind::Data => "data_sha256",
                SlotSha256Kind::Unknown => "unknown",
            },
            blob_sha256,
            blob.blob_size_for_display()
                .map(|size| size.to_string())
                .unwrap_or_else(|| "<metadata-only>".to_string()),
            data_sha256,
            blob.data_size_for_display(),
            blob.chunk_refs,
            blob.unique_blkaddrs.len(),
            format_u64_set(&blob.chunk_sizes),
            blob.logical_bytes,
            blob.declared_data_size,
            blob.verified,
            source,
        );
    }
    println!();
    println!("Notes");
    println!("  slot_sha256 is the raw SHA256 recorded in ErofsDeviceSlot.tag.");
    println!(
        "  slot_sha256_kind reports whether ErofsDeviceSlot.tag matched the full blob SHA256 or the appended data-region SHA256 when resolving from --blob-dir."
    );
    println!(
        "  blob_sha256 is the SHA256 of the full blob artifact file when the blob can be resolved."
    );
    println!("  data_sha256 is the SHA256 of the appended blob data region when the blob can be resolved.");
    println!("  current lepton writer does not emit compressed chunk payload; compressor is reported as none.");
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

fn hex_string(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut text, "{byte:02x}");
    }
    text
}
