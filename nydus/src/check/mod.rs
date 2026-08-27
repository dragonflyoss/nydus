//! Offline nydus image inspection: walk an image's inode tree, gather
//! per-image and per-blob statistics, resolve and verify the referenced
//! blobs, and report format violations such as inline data crossing a
//! metadata block.

use memmap2::Mmap;
use nydus_core::reader::RawBlobInfo;
use nydus_core::ErofsReader;
use nydus_error::{Context, Error, Result};
use nydus_format::blob::{BlobFooter, BlobMetadata, BlobMetadataCompressor};
use nydus_format::erofs::{
    mode_to_erofs_file_type, ErofsInode, ErofsSuperblock, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE,
    EROFS_FT_BLKDEV, EROFS_FT_CHRDEV, EROFS_FT_DIR, EROFS_FT_FIFO, EROFS_FT_REG_FILE,
    EROFS_FT_SOCK, EROFS_FT_SYMLINK, EROFS_INODE_CHUNK_BASED, EROFS_INODE_FLAT_INLINE,
    EROFS_INODE_FLAT_PLAIN, EROFS_NULL_ADDR, EROFS_SLOTSIZE,
};
use nydus_format::utils::sha256_bytes;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// What kind of image file is being inspected.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ImageKind {
    /// A nydus full blob (data + bootstrap + blob meta + footer).
    Blob,
    /// A standalone bootstrap referencing external blobs.
    Bootstrap,
}

/// The full inspection result for one image.
pub struct CheckReport {
    /// Size of the image file on disk.
    pub image_file_bytes: u64,
    /// Size declared by the superblock (`blocks * block_size`).
    pub primary_image_bytes: u64,
    /// Copy of the image's EROFS superblock.
    pub superblock: ErofsSuperblock,
    /// Aggregate statistics from walking the inode tree.
    pub stats: ImageStats,
    /// Per-blob summaries keyed by blob index.
    pub blobs: BTreeMap<u16, BlobSummary>,
}

#[derive(Default)]
pub struct ImageStats {
    pub visited_inodes: u64,
    pub max_depth: u32,
    pub directory_entries: u64,
    pub regular_files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub char_devices: u64,
    pub block_devices: u64,
    pub fifos: u64,
    pub sockets: u64,
    pub chunked_files: u64,
    pub flat_plain_files: u64,
    pub flat_inline_files: u64,
    pub other_layout_files: u64,
    pub xattr_entries: u64,
    pub hardlink_inodes: u64,
    pub hardlink_paths: u64,
    pub total_chunks: u64,
    pub hole_chunks: u64,
    pub total_logical_bytes: u64,
    pub chunk_sizes: BTreeSet<u64>,
    pub inline_overflows: Vec<InlineOverflow>,
}

/// An inode whose tail-packed inline data crosses its metadata block, which
/// the kernel rejects with `-EFSCORRUPTED` when the inode is read.
pub struct InlineOverflow {
    pub nid: u64,
    pub offset_in_block: u64,
    pub header_size: u64,
    pub xattr_size: u64,
    pub inline_size: u64,
}

#[derive(Default)]
pub struct BlobSummary {
    pub slot_sha256: [u8; EROFS_BLOB_ID_SIZE],
    pub slot_sha256_kind: SlotSha256Kind,
    pub declared_blocks: u64,
    pub mapped_blkaddr: u64,
    pub mapped_offset: u64,
    pub declared_data_size: u64,
    pub resolved_path: Option<PathBuf>,
    pub blob_size: Option<u64>,
    pub blob_sha256: Option<[u8; EROFS_BLOB_ID_SIZE]>,
    pub data_sha256: Option<[u8; EROFS_BLOB_ID_SIZE]>,
    pub data_size: Option<u64>,
    pub blob_metadata: Option<BlobMetadataSummary>,
    pub verified: bool,
    pub chunk_refs: u64,
    pub unique_blkaddrs: HashSet<u64>,
    pub logical_bytes: u64,
    pub chunk_sizes: BTreeSet<u64>,
}

impl BlobSummary {
    fn new(blob: &RawBlobInfo) -> Self {
        Self {
            slot_sha256: blob.blob_id,
            declared_blocks: blob.blocks,
            mapped_blkaddr: blob.mapped_blkaddr,
            mapped_offset: blob.mapped_blkaddr * EROFS_BLOCK_SIZE as u64,
            declared_data_size: blob.blocks * EROFS_BLOCK_SIZE as u64,
            ..Self::default()
        }
    }

    pub fn data_size_for_display(&self) -> u64 {
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
    blob_metadata: Option<BlobMetadataSummary>,
    slot_sha256_kind: SlotSha256Kind,
    verified: bool,
}

struct BlobInspection {
    data_sha256: [u8; EROFS_BLOB_ID_SIZE],
    data_size: u64,
    blob_sha256: [u8; EROFS_BLOB_ID_SIZE],
    blob_size: u64,
    blob_metadata: Option<BlobMetadataSummary>,
}

#[derive(Clone)]
pub struct BlobMetadataSummary {
    pub block_group_count: usize,
    pub chunk_size: u32,
    pub compressor: BlobMetadataCompressor,
    pub total_uncompressed_size: u64,
    pub total_compressed_size: u64,
}

/// Which digest the device slot's blob ID turned out to be.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum SlotSha256Kind {
    Blob,
    Data,
    #[default]
    Unknown,
}

impl SlotSha256Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Blob => "full_blob",
            Self::Data => "data_blob",
            Self::Unknown => "unknown",
        }
    }
}

/// Inspect the image at `path`, resolving and verifying referenced blobs from
/// `blob_dir` when provided.
pub fn check_image(kind: ImageKind, path: &Path, blob_dir: Option<&Path>) -> Result<CheckReport> {
    let reader = ErofsReader::open_metadata_only(path)
        .with_context(|| format!("failed to open image for inspection: {}", path.display()))?;
    let sb = reader.superblock();
    let image_file_bytes = fs::metadata(path)
        .with_context(|| format!("failed to stat image: {}", path.display()))?
        .len();
    let primary_image_bytes = sb.blocks() * EROFS_BLOCK_SIZE as u64;
    let blob_infos = reader.blob_infos().context("failed to read device slots")?;
    let resolved_blobs = resolve_blobs(kind, path, blob_dir, blob_infos)?;
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
                summary.blob_metadata = resolved.blob_metadata.clone();
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

    Ok(CheckReport {
        image_file_bytes,
        primary_image_bytes,
        superblock: *sb,
        stats,
        blobs,
    })
}

/// Report an inode whose tail-packed inline data would cross its metadata
/// block. EROFS requires that tail to stay inside the inode's own block; the
/// kernel fails `erofs_map_blocks()` with `-EFSCORRUPTED` otherwise, making the
/// inode unreadable.
fn inline_overflow(nid: u64, inode: &ErofsInode<'_>) -> Option<InlineOverflow> {
    if inode.data_layout() != EROFS_INODE_FLAT_INLINE {
        return None;
    }
    check_inline_fit(
        nid,
        inode.header_size() as u64,
        inode.xattr_size() as u64,
        inode.size(),
    )
}

fn check_inline_fit(
    nid: u64,
    header_size: u64,
    xattr_size: u64,
    file_size: u64,
) -> Option<InlineOverflow> {
    let block = EROFS_BLOCK_SIZE as u64;
    let offset_in_block = (nid * EROFS_SLOTSIZE as u64) % block;
    // Full blocks live in the data area; only the remainder is packed inline.
    let inline_size = file_size % block;
    if offset_in_block + header_size + xattr_size + inline_size > block {
        Some(InlineOverflow {
            nid,
            offset_in_block,
            header_size,
            xattr_size,
            inline_size,
        })
    } else {
        None
    }
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
        .with_context(|| format!("failed to read inode: {nid}"))?;
    let file_type = mode_to_erofs_file_type(inode.mode());

    stats.visited_inodes += 1;
    stats.max_depth = stats.max_depth.max(depth);
    stats.xattr_entries += reader.read_xattrs(nid, &inode)?.len() as u64;
    if file_type != EROFS_FT_DIR && inode.nlink() > 1 {
        stats.hardlink_inodes += 1;
        stats.hardlink_paths += inode.nlink() as u64;
    }
    if let Some(overflow) = inline_overflow(nid, &inode) {
        stats.inline_overflows.push(overflow);
    }

    match file_type {
        EROFS_FT_DIR => {
            stats.directories += 1;
            for entry in reader.read_dir(nid, &inode)? {
                if entry.name == b"." || entry.name == b".." {
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
                    let chunk_size = reader.chunk_size(&inode);
                    stats.chunk_sizes.insert(chunk_size);
                    let chunk_index_entries = reader.read_chunk_index_entries(nid, &inode)?;
                    stats.total_chunks += chunk_index_entries.len() as u64;
                    stats.total_logical_bytes += inode.size();

                    for (index, chunk) in chunk_index_entries.iter().enumerate() {
                        let remaining = inode.size().saturating_sub(index as u64 * chunk_size);
                        let logical_bytes = remaining.min(chunk_size);
                        // Hole chunks reference no blob at all (their on-disk
                        // device_id bits are part of the null sentinel), so
                        // they must not fabricate a blob summary entry.
                        if chunk.blkaddr == EROFS_NULL_ADDR {
                            stats.hole_chunks += 1;
                            continue;
                        }
                        let blob = blobs.entry(chunk.device_id).or_default();
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
    blob_infos: &[RawBlobInfo],
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
                    blob_metadata: inspection.blob_metadata,
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
        let entry = entry
            .with_context(|| format!("failed to read blob-dir entry: {}", blob_dir.display()))?;
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
                blob_metadata: inspection.blob_metadata.clone(),
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
    let Some(footer) = BlobFooter::from_blob_bytes(&mmap)? else {
        return Ok(None);
    };
    let data_start = usize::try_from(footer.compressed_data_offset())
        .map_err(|err| Error::Overflow(format!("compressed data offset too large: {err}")))?;
    let data_size = usize::try_from(footer.compressed_data_size())
        .map_err(|err| Error::Overflow(format!("compressed data size too large: {err}")))?;
    let data_end = data_start
        .checked_add(data_size)
        .ok_or_else(|| Error::Overflow("data range overflow".to_string()))?;
    let meta_start = usize::try_from(footer.blob_metadata_offset())
        .map_err(|err| Error::Overflow(format!("blob meta offset too large: {err}")))?;
    let meta_end = meta_start
        .checked_add(footer.blob_metadata_size() as usize)
        .ok_or_else(|| Error::Overflow("blob meta range overflow".to_string()))?;

    let data_digest = sha256_bytes(&mmap[data_start..data_end]);
    let blob_sha256 = sha256_bytes(&mmap);
    Ok(Some(BlobInspection {
        data_sha256: data_digest,
        data_size: footer.compressed_data_size(),
        blob_sha256,
        blob_size: mmap.len() as u64,
        blob_metadata: Some(blob_metadata_summary_from_bytes(
            &mmap[meta_start..meta_end],
        )?),
    }))
}

fn blob_metadata_summary_from_bytes(data: &[u8]) -> Result<BlobMetadataSummary> {
    let blob_metadata = BlobMetadata::from_bytes(data, false)?;
    Ok(BlobMetadataSummary {
        block_group_count: blob_metadata.block_group_count(),
        chunk_size: blob_metadata.chunk_size(),
        compressor: blob_metadata.compressor(),
        total_uncompressed_size: blob_metadata.uncompressed_size(),
        total_compressed_size: blob_metadata.compressed_end(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_format::blob::DEFAULT_NYDUS_BLOB_METADATA_CHUNK_BLOCK_COUNT;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn inline_fit_flags_only_block_crossing_inodes() {
        // nid 2557 sits 4000 bytes into its block; a 65-byte symlink target
        // behind a 32-byte header ends one byte past the block.
        let overflow = check_inline_fit(2557, 32, 0, 65).expect("should overflow");
        assert_eq!(overflow.offset_in_block, 4000);
        assert_eq!(overflow.inline_size, 65);

        // 64 bytes exactly fills the block tail.
        assert!(check_inline_fit(2557, 32, 0, 64).is_none());
        // An inode at the start of a block has room to spare.
        assert!(check_inline_fit(128, 32, 0, 4000).is_none());
    }

    #[test]
    fn inline_fit_accounts_for_xattrs_and_full_blocks() {
        // xattrs push the tail past the block end.
        assert!(check_inline_fit(2557, 32, 0, 60).is_none());
        assert!(check_inline_fit(2557, 32, 12, 60).is_some());

        // Only the remainder is inline: a whole-block file packs nothing.
        assert!(check_inline_fit(2557, 32, 0, EROFS_BLOCK_SIZE as u64).is_none());
    }

    #[test]
    fn resolve_bootstrap_blob_dir_by_full_blob_digest_only() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob");
        let (full_blob_digest, data_blob_digest) = write_minimal_blob(&blob_path);

        let full_blob_info = RawBlobInfo {
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

        let data_blob_info = RawBlobInfo {
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
        let blob_metadata = BlobMetadata::new(
            BlobMetadataCompressor::None,
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_BLOCK_COUNT,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let mut blob_metadata_bytes = Vec::new();
        blob_metadata.write_to(&mut blob_metadata_bytes).unwrap();
        assert_eq!(blob_metadata_bytes.len(), EROFS_BLOCK_SIZE as usize);

        let footer = BlobFooter::new(
            0,
            data.len() as u64,
            data.len() as u64,
            0,
            data.len() as u64,
            1,
            None,
        )
        .unwrap();
        let mut blob = Vec::new();
        blob.extend_from_slice(&data);
        blob.extend_from_slice(&blob_metadata_bytes);
        footer.write_to(&mut blob).unwrap();
        fs::write(path, &blob).unwrap();

        (sha256_bytes(&blob), data_digest)
    }
}
