use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use crate::build::bootstrap::{
    fit_z_devices_past_bootstrap, place_z_device_slots, render_flattened_bootstrap,
    render_flattened_bootstrap_to, render_z_device_bootstrap, ZRelocation,
    FLATTENED_BLOB_ALIGNMENT,
};
use crate::build::inode::{
    choose_epoch, flatten_tree, packed_inode, set_root_prefetch_blobs_xattr, InodeData,
    NamedChildren, NodeAttrs, TreeNode,
};
use nydus_core::reader::RawDirEntry;
use nydus_core::ErofsReader;
use nydus_error::{Context, Error, Result};
use nydus_format::blob::BlobFooter;
use nydus_format::erofs::{
    erofs_xattr_name_split, mode_to_erofs_file_type, ErofsChunkAddr, ErofsDeviceSlot, XattrEntry,
    EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE, EROFS_FT_BLKDEV, EROFS_FT_CHRDEV, EROFS_FT_DIR,
    EROFS_FT_FIFO, EROFS_FT_REG_FILE, EROFS_FT_SOCK, EROFS_FT_SYMLINK, EROFS_INODE_CHUNK_BASED,
    EROFS_INODE_COMPRESSED_FULL, EROFS_NULL_ADDR, Z_EROFS_MAP_HEADER_SIZE,
};
use nydus_format::utils::parse_sha256_hex;

const OCI_WHITEOUT_PREFIX: &[u8] = b".wh.";
const OCI_OPAQUE_MARKER: &[u8] = b".wh..wh..opq";

/// Return freed glibc heap pages to the OS. The consumed merge tree leaves
/// ~100 MiB of freed small allocations that glibc keeps in its arenas; the
/// buffers allocated afterwards (inode table growth, render buffer) are
/// large mmap'd blocks that cannot reuse them, so without trimming the peak
/// RSS stacks both.
fn release_freed_heap() {
    // malloc_trim is glibc-only; musl has no equivalent (and no arena bloat).
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        libc::malloc_trim(0);
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WhiteoutSpec {
    Oci,
}

/// Identifies a hardlink group across layers: the inode's home layer and nid.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MergeLinkId {
    layer_id: u32,
    nid: u64,
}

/// One source layer participating in the k-way merge: its metadata reader
/// and the mapping from its local blob indexes to the merged device table.
struct MergeLayer {
    layer_id: u32,
    reader: ErofsReader,
    epoch: u64,
    fixed_nsec: u32,
    local_to_global: HashMap<u16, u16>,
    /// Set for z_erofs layers: how their compressed data moves.
    z: Option<ZRelocation>,
}

/// The (layer, nid) variants of one merged path, in lower..upper order.
/// Directories keep every stacked directory variant so their children merge;
/// for any other kind only the topmost variant exists (upper shadows lower).
struct KWayVariants {
    /// Indexes into the layer slice paired with the nid in that layer.
    variants: Vec<(usize, u64)>,
    is_dir: bool,
}

/// A lazily expanded node of the merged tree: children are produced by
/// k-way merging the variant directories' entries on demand, so no merged
/// tree is ever materialised — peak memory is one directory's entry list
/// plus the DFS path.
struct KWayNode<'a> {
    layers: &'a [MergeLayer],
    whiteout_spec: WhiteoutSpec,
    variants: KWayVariants,
}

impl KWayVariants {
    fn top(&self) -> (usize, u64) {
        *self
            .variants
            .last()
            .expect("a merged path always has at least one variant")
    }
}

impl<'a> KWayNode<'a> {
    fn top_layer_and_inode(&self) -> Result<(&'a MergeLayer, u64)> {
        let (layer_index, nid) = self.variants.top();
        Ok((&self.layers[layer_index], nid))
    }
}

impl TreeNode<()> for KWayNode<'_> {
    type LinkKey = MergeLinkId;

    fn attrs(&mut self) -> Result<NodeAttrs> {
        let (layer, nid) = self.top_layer_and_inode()?;
        let inode = layer
            .reader
            .inode(nid)
            .with_context(|| format!("failed to read inode: {nid}"))?;
        let mut xattrs: Vec<XattrEntry> = layer
            .reader
            .read_xattrs(nid, &inode)?
            .into_iter()
            .filter_map(|(name, value)| {
                erofs_xattr_name_split(&name).map(|(index, suffix)| XattrEntry {
                    name_index: index,
                    suffix: suffix.to_vec(),
                    value,
                })
            })
            .collect();
        xattrs.sort_by(|a, b| (a.name_index, &a.suffix).cmp(&(b.name_index, &b.suffix)));
        Ok(NodeAttrs {
            mode: inode.mode(),
            uid: inode.uid(),
            gid: inode.gid(),
            size: inode.size(),
            mtime: inode.mtime(layer.epoch),
            mtime_nsec: inode.effective_mtime_nsec(layer.fixed_nsec),
            nlink: inode.nlink(),
            xattrs,
        })
    }

    fn link_key(&mut self) -> Result<Option<MergeLinkId>> {
        if self.variants.is_dir {
            return Ok(None);
        }
        let (layer, nid) = self.top_layer_and_inode()?;
        let inode = layer
            .reader
            .inode(nid)
            .with_context(|| format!("failed to read inode: {nid}"))?;
        // Any non-directory can be hardlinked (fifos, sockets, devices and
        // symlinks included); keying on the source (layer, nid) keeps every
        // link of a group mapped to a single merged inode.
        Ok((inode.nlink() > 1).then_some(MergeLinkId {
            layer_id: layer.layer_id,
            nid,
        }))
    }

    fn children(&mut self, _ctx: &mut ()) -> Result<Option<NamedChildren<Self>>> {
        if !self.variants.is_dir {
            return Ok(None);
        }
        let mut merged: BTreeMap<Vec<u8>, KWayVariants> = BTreeMap::new();
        for &(layer_index, nid) in &self.variants.variants {
            let layer = &self.layers[layer_index];
            let inode = layer
                .reader
                .inode(nid)
                .with_context(|| format!("failed to read inode: {nid}"))?;
            let entries = layer.reader.read_dir(nid, &inode)?;
            merge_layer_entries(&mut merged, entries, layer_index, self.whiteout_spec);
        }
        Ok(Some(
            merged
                .into_iter()
                .map(|(name, variants)| {
                    (
                        name,
                        KWayNode {
                            layers: self.layers,
                            whiteout_spec: self.whiteout_spec,
                            variants,
                        },
                    )
                })
                .collect(),
        ))
    }

    fn leaf_data(&mut self, _ctx: &mut ()) -> Result<InodeData> {
        let (layer, nid) = self.top_layer_and_inode()?;
        let inode = layer
            .reader
            .inode(nid)
            .with_context(|| format!("failed to read inode: {nid}"))?;
        Ok(match mode_to_erofs_file_type(inode.mode()) {
            EROFS_FT_REG_FILE if inode.data_layout() == EROFS_INODE_COMPRESSED_FULL => {
                let z = layer.z.as_ref().ok_or_else(|| {
                    Error::InvalidImage(
                        "compressed inode in a layer without a z_erofs device".to_string(),
                    )
                })?;
                let tail = layer.reader.read_z_inode_tail(nid, &inode)?;
                InodeData::ZFile {
                    tail: z.relocate_tail(tail, inode.size())?,
                    compressed_blocks: inode.i_u(),
                }
            }
            EROFS_FT_REG_FILE => {
                if inode.data_layout() != EROFS_INODE_CHUNK_BASED {
                    return Err(Error::Unsupported(
                        "merge currently only supports chunk-based regular files".to_string(),
                    ));
                }
                let chunk_size_bits = layer.reader.chunk_bits(&inode);
                let chunk_index_entries = layer
                    .reader
                    .read_chunk_index_entries(nid, &inode)?
                    .into_iter()
                    .map(|index| {
                        // A hole chunk carries no blob reference at all (its
                        // on-disk device_id bits are part of the null sentinel),
                        // so it passes through unchanged instead of being device
                        // remapped.
                        if index.blkaddr == EROFS_NULL_ADDR || index.device_id == 0 {
                            Ok(index)
                        } else {
                            let mapped = layer
                                .local_to_global
                                .get(&index.device_id)
                                .copied()
                                .ok_or_else(|| {
                                    Error::InvalidImage(format!(
                                        "missing global blob index mapping for source blob {}",
                                        index.device_id
                                    ))
                                })?;
                            Ok(ErofsChunkAddr {
                                blkaddr: index.blkaddr,
                                device_id: mapped,
                            })
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                InodeData::RegularFile {
                    chunk_index_entries,
                    chunk_size_bits,
                }
            }
            EROFS_FT_SYMLINK => InodeData::Symlink {
                target: layer.reader.read_symlink(nid, &inode)?,
                startblk: 0,
            },
            EROFS_FT_CHRDEV | EROFS_FT_BLKDEV => InodeData::Device { rdev: inode.rdev() },
            EROFS_FT_FIFO | EROFS_FT_SOCK => InodeData::FifoOrSocket,
            other => {
                return Err(Error::Unsupported(format!(
                    "unsupported inode file type {other} while loading layer"
                )))
            }
        })
    }
}

/// Merge one layer's directory entries (upper) into the accumulated view,
/// applying whiteout semantics: an opaque marker discards everything below,
/// `.wh.<name>` removes `<name>` from below, upper non-directories shadow
/// whatever is below, and stacked directories merge. Whiteout entries
/// themselves never appear in the result.
fn merge_layer_entries(
    merged: &mut BTreeMap<Vec<u8>, KWayVariants>,
    entries: Vec<RawDirEntry>,
    layer_index: usize,
    whiteout_spec: WhiteoutSpec,
) {
    if entries
        .iter()
        .any(|entry| is_opaque_marker(&entry.name, whiteout_spec))
    {
        merged.clear();
    }
    for entry in &entries {
        if let Some(target) = whiteout_target(&entry.name, whiteout_spec) {
            merged.remove(target);
        }
    }
    for entry in entries {
        if entry.name == b"."
            || entry.name == b".."
            || is_opaque_marker(&entry.name, whiteout_spec)
            || whiteout_target(&entry.name, whiteout_spec).is_some()
        {
            continue;
        }
        let is_dir = entry.file_type == EROFS_FT_DIR;
        match merged.get_mut(&entry.name) {
            Some(existing) if is_dir && existing.is_dir => {
                existing.variants.push((layer_index, entry.nid));
            }
            _ => {
                merged.insert(
                    entry.name,
                    KWayVariants {
                        variants: vec![(layer_index, entry.nid)],
                        is_dir,
                    },
                );
            }
        }
    }
}

pub fn merge_sources_to_bootstrap_bytes(
    sources: &[PathBuf],
    whiteout_spec: WhiteoutSpec,
) -> Result<Vec<u8>> {
    let mut bootstrap = Vec::new();
    merge_sources_to_bootstrap_writer(sources, whiteout_spec, &mut bootstrap)?;
    Ok(bootstrap)
}

/// Merge the sources and stream the flattened bootstrap into `writer`. The
/// merged tree is never materialised (children are k-way merged on demand
/// during flattening) and the bootstrap is stream-rendered, so peak memory
/// is the flat inode table plus one directory's entries.
pub fn merge_sources_to_bootstrap_writer(
    sources: &[PathBuf],
    whiteout_spec: WhiteoutSpec,
    writer: &mut impl std::io::Write,
) -> Result<()> {
    if sources.is_empty() {
        return Err(Error::InvalidParameter(
            "merge requires at least one source".to_string(),
        ));
    }
    let first = ErofsReader::open_metadata_only(&sources[0])
        .with_context(|| format!("failed to load layer: {}", sources[0].display()))?;
    if first.z_lz4_max_pclusterblks()?.is_some() {
        return merge_z_sources_to_bootstrap_writer(sources, whiteout_spec, writer);
    }

    let mut device_slots = Vec::new();
    let mut blob_indexes = HashMap::new();
    let mut layers = Vec::with_capacity(sources.len());

    for (layer_id, source) in sources.iter().enumerate() {
        let source_blob_id = parse_source_blob_id(source)
            .with_context(|| format!("invalid merge source: {}", source.display()))?;
        let reader = ErofsReader::open_metadata_only(source)
            .with_context(|| format!("failed to load layer: {}", source.display()))?;
        validate_single_layer_blob_source(source, &reader)?;
        let local_to_global = register_blobs(
            &reader,
            source_blob_id,
            &mut device_slots,
            &mut blob_indexes,
        )?;
        layers.push(MergeLayer {
            layer_id: layer_id as u32,
            epoch: reader.superblock().epoch(),
            fixed_nsec: reader.superblock().fixed_nsec(),
            local_to_global,
            reader,
            z: None,
        });
    }

    let root = KWayNode {
        layers: &layers,
        whiteout_spec,
        variants: KWayVariants {
            variants: layers
                .iter()
                .enumerate()
                .map(|(index, layer)| (index, layer.reader.superblock().root_nid()))
                .collect(),
            is_dir: true,
        },
    };

    // `flatten_tree` always yields at least the root inode; children are
    // k-way merged on demand while flattening.
    let mut inodes = flatten_tree(root, &mut ())?;
    drop(layers);
    release_freed_heap();

    let epoch = choose_epoch(&inodes);
    let uuid = [0u8; 16];
    let blob_count = u16::try_from(device_slots.len())
        .map_err(|err| Error::Overflow(format!("device slot count exceeds u16: {err}")))?;
    let prefetch_blob_indexes = (1..=blob_count).collect::<Vec<_>>();
    set_root_prefetch_blobs_xattr(&mut inodes[0], &prefetch_blob_indexes)?;

    render_flattened_bootstrap_to(writer, &mut inodes, epoch, &device_slots, &uuid)?;
    Ok(())
}

/// Merge z_erofs layer bootstraps (see `build_erofs_layer_from_tar`)
/// into one multi-device bootstrap: layer `i`'s data file becomes device
/// `i + 1`, placed back to back in the mapped block space, and the layers'
/// packed inodes are concatenated into one so fragments keep working. The
/// data files are untouched; they are passed to the kernel at mount time as
/// `device=` options in device table order.
fn merge_z_sources_to_bootstrap_writer(
    sources: &[PathBuf],
    whiteout_spec: WhiteoutSpec,
    writer: &mut impl std::io::Write,
) -> Result<()> {
    let mut readers = Vec::with_capacity(sources.len());
    let mut device_slots = Vec::with_capacity(sources.len());
    let mut z_max_pclusterblks = 0u16;
    for source in sources {
        let reader = ErofsReader::open_metadata_only(source)
            .with_context(|| format!("failed to load layer: {}", source.display()))?;
        let pclusterblks = reader.z_lz4_max_pclusterblks()?.ok_or_else(|| {
            Error::InvalidImage(format!(
                "merge source is not a z_erofs layer: {}",
                source.display()
            ))
        })?;
        z_max_pclusterblks = z_max_pclusterblks.max(pclusterblks);
        let infos = reader.blob_infos()?;
        let [info] = infos else {
            return Err(Error::InvalidImage(format!(
                "z_erofs merge source must reference exactly one device: {}",
                source.display()
            )));
        };
        device_slots.push(ErofsDeviceSlot::with_blob_id(info.blocks, &info.blob_id)?);
        readers.push(reader);
    }
    // Provisional placement right after the alignment boundary; the devices
    // are moved past the bootstrap once its size is known.
    place_z_device_slots(&mut device_slots, FLATTENED_BLOB_ALIGNMENT)?;

    // Packed inodes concatenate on the lcluster grid: every layer's packed
    // stream is block padded by the builder, so its lcluster indexes can be
    // appended verbatim (after address relocation) and its fragments shift
    // by the layers packed before it.
    let mut packed_tail: Vec<u8> = Vec::new();
    let mut packed_size = 0u64;
    let mut packed_blocks = 0u64;
    let mut layers = Vec::with_capacity(sources.len());
    for ((layer_id, reader), slot) in readers.into_iter().enumerate().zip(&device_slots) {
        let info = &reader.blob_infos()?[0];
        let z = ZRelocation {
            old_mapped_blkaddr: info.mapped_blkaddr,
            new_mapped_blkaddr: slot.mapped_blkaddr(),
            packed_base: packed_size,
        };
        if let Some(packed_nid) = reader.superblock().packed_nid() {
            let packed = reader
                .inode(packed_nid)
                .with_context(|| format!("failed to read packed inode {packed_nid}"))?;
            if packed.size() % EROFS_BLOCK_SIZE as u64 != 0 {
                return Err(Error::InvalidImage(format!(
                    "packed inode of {} is not block padded; rebuild the layer",
                    sources[layer_id].display()
                )));
            }
            let tail = z.relocate_tail(
                reader.read_z_inode_tail(packed_nid, &packed)?,
                packed.size(),
            )?;
            if packed_tail.is_empty() {
                packed_tail.extend_from_slice(&tail);
            } else {
                packed_tail.extend_from_slice(&tail[Z_EROFS_MAP_HEADER_SIZE + 8..]);
            }
            packed_size += packed.size();
            packed_blocks += packed.i_u() as u64;
        }
        layers.push(MergeLayer {
            layer_id: layer_id as u32,
            epoch: reader.superblock().epoch(),
            fixed_nsec: reader.superblock().fixed_nsec(),
            local_to_global: HashMap::new(),
            reader,
            z: Some(z),
        });
    }

    let root = KWayNode {
        layers: &layers,
        whiteout_spec,
        variants: KWayVariants {
            variants: layers
                .iter()
                .enumerate()
                .map(|(index, layer)| (index, layer.reader.superblock().root_nid()))
                .collect(),
            is_dir: true,
        },
    };
    let mut inodes = flatten_tree(root, &mut ())?;
    drop(layers);
    release_freed_heap();

    let packed_index = if packed_size > 0 {
        let packed_blocks = u32::try_from(packed_blocks).map_err(|_| {
            Error::Overflow("merged packed inode block count exceeds u32".to_string())
        })?;
        inodes.push(packed_inode(
            &inodes,
            packed_tail,
            packed_blocks,
            packed_size,
        ));
        Some(inodes.len() - 1)
    } else {
        None
    };

    // See merge_sources_to_bootstrap_writer: the root mtime is always 0.
    let epoch = 0;
    let uuid = [0u8; 16];
    fit_z_devices_past_bootstrap(&mut inodes, epoch, &mut device_slots)?;
    let bootstrap = render_z_device_bootstrap(
        &mut inodes,
        epoch,
        &uuid,
        z_max_pclusterblks,
        &device_slots,
        packed_index,
    )?;
    writer
        .write_all(&bootstrap)
        .context("failed to write merged bootstrap")?;
    Ok(())
}

/// Rewrite an existing merged bootstrap for the `optimize` flow: append an
/// "ondemand" device slot for the redirect blob and put its blob index first
/// in the root prefetch xattr so it is warmed before everything else. The
/// parent bootstrap is read-only; the rewritten bootstrap bytes are returned.
pub(crate) fn rewrite_bootstrap_with_ondemand_blob(
    parent_bootstrap: &Path,
    ondemand_blob_id: &[u8; EROFS_BLOB_ID_SIZE],
    ondemand_blocks: u64,
) -> Result<Vec<u8>> {
    let reader = ErofsReader::open_metadata_only(parent_bootstrap)
        .with_context(|| format!("failed to open bootstrap: {}", parent_bootstrap.display()))?;
    let blob_infos = reader.blob_infos()?.to_vec();
    if blob_infos.is_empty() {
        return Err(Error::InvalidImage(
            "parent bootstrap contains no blobs".to_string(),
        ));
    }
    if blob_infos
        .iter()
        .any(|info| info.blob_id == *ondemand_blob_id)
    {
        return Err(Error::InvalidImage(
            "parent bootstrap already contains the ondemand blob".to_string(),
        ));
    }

    // Blobs keep their indexes, so chunk indexes round-trip unchanged.
    let identity: HashMap<u16, u16> = blob_infos
        .iter()
        .map(|info| (info.blob_index, info.blob_index))
        .collect();
    let layers = [MergeLayer {
        layer_id: 0,
        epoch: reader.superblock().epoch(),
        fixed_nsec: reader.superblock().fixed_nsec(),
        local_to_global: identity,
        reader,
        z: None,
    }];
    let root = KWayNode {
        layers: &layers,
        // A merged bootstrap carries no whiteout entries; the spec is inert.
        whiteout_spec: WhiteoutSpec::Oci,
        variants: KWayVariants {
            variants: vec![(0, layers[0].reader.superblock().root_nid())],
            is_dir: true,
        },
    };

    // `flatten_tree` always yields at least the root inode; children are
    // expanded lazily from the bootstrap.
    let mut inodes = flatten_tree(root, &mut ()).with_context(|| {
        format!(
            "failed to load bootstrap inode tree: {}",
            parent_bootstrap.display()
        )
    })?;
    let [MergeLayer { reader, .. }] = layers;
    release_freed_heap();

    let mut device_slots: Vec<ErofsDeviceSlot> = blob_infos
        .iter()
        .map(|info| ErofsDeviceSlot::with_blob_id(info.blocks, &info.blob_id))
        .collect::<nydus_format::error::Result<_>>()?;
    let ondemand_blob_index = u16::try_from(device_slots.len() + 1).map_err(|err| {
        Error::Overflow(format!(
            "ondemand blob index exceeds u16 device table range: {err}"
        ))
    })?;
    device_slots.push(ErofsDeviceSlot::with_blob_id(
        ondemand_blocks,
        ondemand_blob_id,
    )?);

    // Ondemand blob first, then the existing prefetch order (defaulting to all
    // blobs ascending when the parent has no prefetch xattr).
    let mut prefetch_indexes = vec![ondemand_blob_index];
    let existing = reader.read_prefetch_order();
    if existing.is_empty() {
        prefetch_indexes.extend(blob_infos.iter().map(|info| info.blob_index));
    } else {
        prefetch_indexes.extend(existing);
    }
    set_root_prefetch_blobs_xattr(&mut inodes[0], &prefetch_indexes)?;

    let epoch = choose_epoch(&inodes);
    let uuid = [0u8; 16];
    render_flattened_bootstrap(&mut inodes, epoch, &device_slots, &uuid)
}

fn register_blobs(
    reader: &ErofsReader,
    source_blob_id: [u8; EROFS_BLOB_ID_SIZE],
    device_slots: &mut Vec<ErofsDeviceSlot>,
    blob_indexes: &mut HashMap<[u8; EROFS_BLOB_ID_SIZE], u16>,
) -> Result<HashMap<u16, u16>> {
    let mut local_to_global = HashMap::new();
    let infos = reader.blob_infos()?;
    let info = infos.first().ok_or_else(|| {
        Error::InvalidImage("merge source does not contain an external blob".to_string())
    })?;
    // The device slot stores the full-blob digest (the merge source file name),
    // not the per-layer data digest embedded in the source bootstrap, so a
    // registry backend can address the blob by the same digest.
    let global_blob_index = if let Some(existing) = blob_indexes.get(&source_blob_id) {
        *existing
    } else {
        let next = u16::try_from(device_slots.len())
            .ok()
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| Error::Overflow("merge device count exceeds u16".to_string()))?;
        device_slots.push(ErofsDeviceSlot::with_blob_id(info.blocks, &source_blob_id)?);
        blob_indexes.insert(source_blob_id, next);
        next
    };
    local_to_global.insert(info.blob_index, global_blob_index);

    if infos.len() > 1 {
        return Err(Error::Unsupported(
            "merge source currently supports exactly one external blob".to_string(),
        ));
    }
    Ok(local_to_global)
}

fn parse_source_blob_id(path: &Path) -> Result<[u8; EROFS_BLOB_ID_SIZE]> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            Error::InvalidParameter(
                "merge source file name must be valid UTF-8 sha256 hex".to_string(),
            )
        })?;
    parse_sha256_hex(file_name).context("merge source file name must be a sha256 hex string")
}

fn validate_single_layer_blob_source(path: &Path, reader: &ErofsReader) -> Result<()> {
    BlobFooter::from_blob_path(path)
        .with_context(|| format!("merge source must be a full blob file: {}", path.display()))?;
    let blob_infos = reader.blob_infos()?;
    if blob_infos.len() != 1 {
        return Err(Error::InvalidImage(
            "merge source must contain exactly one external blob".to_string(),
        ));
    }
    Ok(())
}

fn is_opaque_marker(name: &[u8], whiteout_spec: WhiteoutSpec) -> bool {
    match whiteout_spec {
        WhiteoutSpec::Oci => name == OCI_OPAQUE_MARKER,
    }
}

fn whiteout_target(name: &[u8], whiteout_spec: WhiteoutSpec) -> Option<&[u8]> {
    match whiteout_spec {
        WhiteoutSpec::Oci => {
            if name == OCI_OPAQUE_MARKER {
                None
            } else {
                name.strip_prefix(OCI_WHITEOUT_PREFIX)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use nydus_format::erofs::{
        needs_erofs_extended_inode, ErofsSuperblock, EROFS_BLOCK_SIZE, EROFS_SUPER_OFFSET,
        EROFS_XATTR_INDEX_TRUSTED, NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS,
    };

    const OPAQUE: &str = ".wh..wh..opq";

    fn entries(items: &[(&str, u8)]) -> Vec<RawDirEntry> {
        items
            .iter()
            .enumerate()
            .map(|(i, (name, file_type))| RawDirEntry {
                nid: i as u64 + 1,
                file_type: *file_type,
                name: name.as_bytes().to_vec(),
            })
            .collect()
    }

    fn merged_names(merged: &BTreeMap<Vec<u8>, KWayVariants>) -> Vec<String> {
        merged
            .keys()
            .map(|k| String::from_utf8_lossy(k).into_owned())
            .collect()
    }

    #[test]
    fn build_merge_and_optimize_choose_epoch_from_visible_compact_candidates() {
        use crate::build::{build_image, BuildImageOptions};
        use nydus_format::blob::BlobMetadataCompressor;
        use nydus_format::erofs::EROFS_INODE_COMPACT_SIZE;
        use nydus_format::utils::hex_string;
        use std::collections::HashSet;
        use std::os::unix::fs::MetadataExt;

        let directory = tempfile::tempdir().unwrap();
        let lower = directory.path().join("lower");
        let upper = directory.path().join("upper");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&upper).unwrap();
        let lower_times = [
            ("a", 100, 0, 1),
            ("b", 100, 0, 1),
            ("c", 100, 0, 1),
            ("d", 200, 0, 1),
            ("e", 200, 0, 1),
            ("outlier", 0, 0, 1),
            ("precise", 100, 123_456_789, 1),
            ("linked", 1000, 0, 2),
            ("survivor", 300, 0, 1),
        ];
        let upper_times = [("a", 300, 0, 1), ("b", 300, 0, 1), ("c", 300, 0, 1)];
        let verify = |path: &Path, expected: &BTreeMap<&str, (u64, u32, u32, u32, u32)>| {
            let mut counts = BTreeMap::<u64, usize>::new();
            for &(seconds, nanoseconds, nlink, uid, gid) in expected.values() {
                if nanoseconds == 0 && !needs_erofs_extended_inode(8, uid, gid, nlink as u64) {
                    *counts.entry(seconds).or_default() += 1;
                }
            }
            let epoch = counts
                .into_iter()
                .min_by_key(|&(seconds, count)| (std::cmp::Reverse(count), seconds))
                .map_or(0, |(seconds, _)| seconds);
            let reader = ErofsReader::open_metadata_only(path).unwrap();
            assert_eq!(reader.superblock().epoch(), epoch, "{}", path.display());
            let root_nid = reader.superblock().root_nid();
            let root = reader.inode(root_nid).unwrap();
            assert_eq!(root.mtime(epoch), 0);
            assert_eq!(
                root.effective_mtime_nsec(reader.superblock().fixed_nsec()),
                0
            );
            let mut actual = BTreeMap::new();
            for entry in reader.read_dir(root_nid, &root).unwrap() {
                if entry.name == b"." || entry.name == b".." {
                    continue;
                }
                let inode = reader.inode(entry.nid).unwrap();
                let name = String::from_utf8(entry.name).unwrap();
                let &(seconds, nanoseconds, nlink, uid, gid) = expected.get(name.as_str()).unwrap();
                assert_eq!(inode.mtime(epoch), seconds);
                assert_eq!(
                    inode.effective_mtime_nsec(reader.superblock().fixed_nsec()),
                    nanoseconds
                );
                assert_eq!(inode.nlink(), nlink);
                assert_eq!(inode.uid(), uid);
                assert_eq!(inode.gid(), gid);
                assert_eq!(
                    inode.header_size() == EROFS_INODE_COMPACT_SIZE,
                    seconds == epoch
                        && nanoseconds == 0
                        && !needs_erofs_extended_inode(8, uid, gid, nlink as u64),
                    "{name}"
                );
                actual.insert(name, (seconds, nanoseconds, nlink));
            }
            assert_eq!(actual.len(), expected.len());
        };
        let mut expected = BTreeMap::new();
        let mut sources = Vec::new();
        for (index, (source, times)) in [
            (&lower, lower_times.as_slice()),
            (&upper, upper_times.as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let mut layer_expected = BTreeMap::new();
            for &(name, seconds, nanoseconds, nlink) in times {
                let path = source.join(name);
                fs::write(&path, b"contents").unwrap();
                set_mtime(&path, seconds, nanoseconds);
                let metadata = fs::metadata(&path).unwrap();
                layer_expected.insert(
                    name,
                    (
                        seconds as u64,
                        nanoseconds as u32,
                        nlink,
                        metadata.uid(),
                        metadata.gid(),
                    ),
                );
            }
            if index == 0 {
                fs::hard_link(source.join("linked"), source.join("linked-alias")).unwrap();
                layer_expected.insert("linked-alias", layer_expected["linked"]);
            }
            let blob = directory.path().join(format!("layer-{index}"));
            let image = build_image(
                &BuildImageOptions::new(
                    source.to_path_buf(),
                    EROFS_BLOCK_SIZE,
                    1 << 20,
                    BlobMetadataCompressor::None,
                    HashSet::new(),
                    true,
                )
                .unwrap(),
                fs::File::create(&blob).unwrap(),
            )
            .unwrap();
            let standalone = directory.path().join(format!("standalone-{index}"));
            fs::write(&standalone, image.standalone_bootstrap.unwrap()).unwrap();
            verify(&blob, &layer_expected);
            verify(&standalone, &layer_expected);
            let source_blob = directory.path().join(hex_string(&image.full_blob_digest));
            fs::rename(blob, &source_blob).unwrap();
            sources.push(source_blob);
            expected.extend(layer_expected);
        }
        let merged = directory.path().join("merged");
        fs::write(
            &merged,
            merge_sources_to_bootstrap_bytes(&sources, WhiteoutSpec::Oci).unwrap(),
        )
        .unwrap();
        verify(&merged, &expected);
        let optimized = directory.path().join("optimized");
        fs::write(
            &optimized,
            rewrite_bootstrap_with_ondemand_blob(&merged, &[0x55; 32], 1).unwrap(),
        )
        .unwrap();
        verify(&optimized, &expected);
    }

    #[test]
    fn merge_and_optimize_reselect_epoch_and_reencode_parent_inodes() {
        use crate::build::blob_chunk::BlobWriter;
        use crate::build::bootstrap::render_bootstrap;
        use crate::build::inode::{ChildRef, InodeInfo};
        use nydus_format::blob::{finish_full_blob, BlobMetadataCompressor};
        use nydus_format::erofs::{
            EROFS_INODE_COMPACT_SIZE, EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN,
        };
        use nydus_format::utils::{hex_string, sha256_bytes};

        for (uid, gid) in [(0, 0), (u16::MAX as u32 + 1, 0), (0, u16::MAX as u32 + 1)] {
            let directory = tempfile::tempdir().unwrap();
            let target = vec![b'a'; 4040];
            let mut inodes = vec![InodeInfo {
                mode: 0o040755,
                uid,
                gid,
                size: 0,
                mtime: 0,
                mtime_nsec: 0,
                nlink: 2,
                ino: 1,
                nid: 0,
                meta_offset: 0,
                is_extended: true,
                data: InodeData::Directory {
                    children: Vec::new(),
                    startblk: 0,
                    data_size: 0,
                    parent_nid: 0,
                },
                xattrs: Vec::new(),
            }];
            let mut children = Vec::new();
            for (name, seconds) in [
                ("early", 100),
                ("file-a", 300),
                ("file-b", 300),
                ("link", 300),
            ] {
                let is_symlink = name == "link";
                let size = if is_symlink { target.len() as u64 } else { 0 };
                let index = inodes.len();
                children.push(ChildRef {
                    name: name.as_bytes().to_vec(),
                    file_type: if is_symlink {
                        EROFS_FT_SYMLINK
                    } else {
                        EROFS_FT_REG_FILE
                    },
                    inode_index: index,
                });
                inodes.push(InodeInfo {
                    mode: if is_symlink { 0o120777 } else { 0o100644 },
                    uid,
                    gid,
                    size,
                    mtime: seconds,
                    mtime_nsec: 0,
                    nlink: 1,
                    ino: index as u32 + 1,
                    nid: 0,
                    meta_offset: 0,
                    is_extended: needs_erofs_extended_inode(size, uid, gid, 1),
                    data: if is_symlink {
                        InodeData::Symlink {
                            target: target.clone(),
                            startblk: 0,
                        }
                    } else {
                        InodeData::RegularFile {
                            chunk_index_entries: Vec::new(),
                            chunk_size_bits: 12,
                        }
                    },
                    xattrs: Vec::new(),
                });
            }
            if let InodeData::Directory {
                children: root_children,
                ..
            } = &mut inodes[0].data
            {
                *root_children = children;
            }
            let slots = [ErofsDeviceSlot::with_blob_id(0, &[0x11; 32]).unwrap()];
            let parent = directory.path().join("parent");
            let parent_bytes = render_bootstrap(&mut inodes, 100, &slots, &[0; 16]).unwrap();
            fs::write(&parent, &parent_bytes).unwrap();
            let blob_writer = BlobWriter::from_writer(
                Vec::new(),
                EROFS_BLOCK_SIZE,
                1 << 20,
                BlobMetadataCompressor::None,
            )
            .unwrap();
            let mut full_blob = Vec::new();
            finish_full_blob(
                &mut full_blob,
                0,
                &parent_bytes,
                &blob_writer.blob_metadata(0).unwrap(),
            )
            .unwrap();
            let source = directory.path().join(hex_string(&sha256_bytes(&full_blob)));
            fs::write(&source, full_blob).unwrap();
            let merged = directory.path().join("merged");
            fs::write(
                &merged,
                merge_sources_to_bootstrap_bytes(&[source], WhiteoutSpec::Oci).unwrap(),
            )
            .unwrap();
            let optimized = directory.path().join("optimized");
            fs::write(
                &optimized,
                rewrite_bootstrap_with_ondemand_blob(&parent, &[0x55; 32], 1).unwrap(),
            )
            .unwrap();

            let eligible = !needs_erofs_extended_inode(target.len() as u64, uid, gid, 1);
            let chosen_epoch = if eligible { 300 } else { 0 };
            for (path, epoch) in [
                (&parent, 100),
                (&merged, chosen_epoch),
                (&optimized, chosen_epoch),
            ] {
                let reader = ErofsReader::open_metadata_only(path).unwrap();
                assert_eq!(reader.superblock().epoch(), epoch);
                let root_nid = reader.superblock().root_nid();
                let root = reader.inode(root_nid).unwrap();
                assert_eq!(root.mtime(epoch), 0);
                let entries = reader.read_dir(root_nid, &root).unwrap();
                let entries: Vec<_> = entries
                    .iter()
                    .filter(|entry| entry.name != b"." && entry.name != b"..")
                    .collect();
                assert_eq!(entries.len(), 4);
                for entry in entries {
                    let inode = reader.inode(entry.nid).unwrap();
                    let seconds = if entry.name == b"early" { 100 } else { 300 };
                    let compact = eligible && seconds == epoch;
                    assert_eq!(inode.header_size() == EROFS_INODE_COMPACT_SIZE, compact);
                    assert_eq!(inode.mtime(epoch), seconds);
                    assert_eq!(
                        inode.effective_mtime_nsec(reader.superblock().fixed_nsec()),
                        0
                    );
                    assert_eq!((inode.uid(), inode.gid(), inode.nlink()), (uid, gid, 1));
                    if entry.name == b"link" {
                        assert_eq!(
                            inode.data_layout(),
                            if compact {
                                EROFS_INODE_FLAT_INLINE
                            } else {
                                EROFS_INODE_FLAT_PLAIN
                            }
                        );
                        assert_eq!(reader.read_symlink(entry.nid, &inode).unwrap(), target);
                    }
                }
            }
        }
    }

    #[test]
    fn merge_accepts_full_blob_when_file_size_matches_primary_image() {
        use crate::build::image::write_erofs_superblock_checksum;
        use crate::build::{build_image, BuildImageOptions};
        use nydus_format::blob::BlobMetadataCompressor;
        use std::collections::HashSet;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("data"), vec![b'x'; 5000]).unwrap();

        let path = dir.path().join("blob");
        let image = build_image(
            &BuildImageOptions::new(
                source,
                EROFS_BLOCK_SIZE,
                1 << 20,
                BlobMetadataCompressor::None,
                HashSet::new(),
                false,
            )
            .unwrap(),
            fs::File::create(&path).unwrap(),
        )
        .unwrap();

        let original_blob = fs::read(&path).unwrap();
        let data_size = usize::try_from(image.blob_footer.compressed_data_size()).unwrap();
        let bootstrap_offset = usize::try_from(image.blob_footer.bootstrap_offset()).unwrap();
        let compressed_bootstrap_size =
            usize::try_from(image.blob_footer.bootstrap_compressed_size().unwrap()).unwrap();
        let mut bootstrap = zstd::stream::decode_all(
            &original_blob[bootstrap_offset..bootstrap_offset + compressed_bootstrap_size],
        )
        .unwrap();
        let blocks_lo_offset =
            EROFS_SUPER_OFFSET as usize + std::mem::offset_of!(ErofsSuperblock, blocks_lo);
        let mut file_blocks =
            u32::try_from(original_blob.len() / EROFS_BLOCK_SIZE as usize).unwrap();
        let blob = loop {
            bootstrap[blocks_lo_offset..blocks_lo_offset + 4]
                .copy_from_slice(&file_blocks.to_le_bytes());
            write_erofs_superblock_checksum(&mut bootstrap).unwrap();

            let mut rebuilt = original_blob[..data_size].to_vec();
            nydus_format::blob::finish_full_blob(
                &mut rebuilt,
                data_size as u64,
                &bootstrap,
                &image.blob_metadata,
            )
            .unwrap();
            assert_eq!(rebuilt.len() % EROFS_BLOCK_SIZE as usize, 0);
            let rebuilt_blocks = u32::try_from(rebuilt.len() / EROFS_BLOCK_SIZE as usize).unwrap();
            if rebuilt_blocks == file_blocks {
                break rebuilt;
            }
            file_blocks = rebuilt_blocks;
        };
        fs::write(&path, blob).unwrap();

        let reader = ErofsReader::open_metadata_only(&path).unwrap();
        assert_eq!(reader.superblock().blocks(), u64::from(file_blocks));
        assert!(reader.blob_infos().unwrap()[0].blocks > 0);
        validate_single_layer_blob_source(&path, &reader).unwrap();
    }

    #[test]
    fn no_xattr_marker_is_recomputed_after_merge_and_optimize() {
        use crate::build::{build_image, BuildImageOptions};
        use nydus_format::blob::BlobMetadataCompressor;
        use nydus_format::erofs::is_nydus_xattr;
        use nydus_format::utils::hex_string;
        use std::collections::HashSet;

        for (operation, source_has_xattrs, expected_no_xattr) in [
            ("keep", true, false),
            ("without-xattrs", false, true),
            ("whiteout", true, true),
            ("replace", true, true),
            ("opaque", true, true),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let lower = directory.path().join("lower");
            let upper = directory.path().join("upper");
            fs::create_dir_all(lower.join("nested")).unwrap();
            fs::create_dir_all(upper.join("nested")).unwrap();
            fs::write(lower.join("nested/entry"), vec![b'x'; 8193]).unwrap();
            if source_has_xattrs {
                xattr::set(lower.join("nested/entry"), "user.test", b"preserved value").unwrap();
                xattr::set(lower.join("nested/entry"), "user.empty", b"").unwrap();
            }
            let upper_entry = match operation {
                "whiteout" => "nested/.wh.entry",
                "replace" => "nested/entry",
                "opaque" => "nested/.wh..wh..opq",
                _ => "unrelated",
            };
            fs::write(upper.join(upper_entry), b"").unwrap();
            let mut sources = Vec::new();
            for (index, source) in [lower, upper].into_iter().enumerate() {
                let blob = directory.path().join(format!("layer-{index}"));
                let image = build_image(
                    &BuildImageOptions::new(
                        source,
                        EROFS_BLOCK_SIZE,
                        1 << 20,
                        BlobMetadataCompressor::None,
                        HashSet::new(),
                        true,
                    )
                    .unwrap(),
                    fs::File::create(&blob).unwrap(),
                )
                .unwrap();
                let standalone = directory.path().join(format!("bootstrap-{index}"));
                fs::write(&standalone, image.standalone_bootstrap.unwrap()).unwrap();
                for path in [&blob, &standalone] {
                    let reader = ErofsReader::open_metadata_only(path).unwrap();
                    let root_nid = reader.superblock().root_nid();
                    let root = reader.inode(root_nid).unwrap();
                    assert_eq!(
                        reader
                            .read_xattrs(root_nid, &root)
                            .unwrap()
                            .iter()
                            .any(|(name, value)| {
                                name == b"trusted.nydus.no_xattr" && value == b"1"
                            }),
                        index == 1 || !source_has_xattrs
                    );
                }
                let source = directory.path().join(hex_string(&image.full_blob_digest));
                fs::rename(blob, &source).unwrap();
                sources.push(source);
            }
            let merged = directory.path().join("merged");
            fs::write(
                &merged,
                merge_sources_to_bootstrap_bytes(&sources, WhiteoutSpec::Oci).unwrap(),
            )
            .unwrap();
            let optimized = directory.path().join("optimized");
            fs::write(
                &optimized,
                rewrite_bootstrap_with_ondemand_blob(&merged, &[0x55; 32], 1).unwrap(),
            )
            .unwrap();
            for path in [&merged, &optimized] {
                let reader = ErofsReader::open_metadata_only(path).unwrap();
                let root_nid = reader.superblock().root_nid();
                let root = reader.inode(root_nid).unwrap();
                assert_eq!(
                    reader
                        .read_xattrs(root_nid, &root)
                        .unwrap()
                        .iter()
                        .any(|(name, value)| {
                            name == b"trusted.nydus.no_xattr" && value == b"1"
                        }),
                    expected_no_xattr,
                    "{operation}: {}",
                    path.display()
                );

                let mut visible_xattrs = BTreeMap::new();
                let mut pending = vec![(Vec::new(), root_nid)];
                while let Some((relative_path, nid)) = pending.pop() {
                    let inode = reader.inode(nid).unwrap();
                    let mut xattrs = reader.read_xattrs(nid, &inode).unwrap();
                    if nid == root_nid {
                        xattrs.retain(|(name, _)| !is_nydus_xattr(name));
                    }
                    if !xattrs.is_empty() {
                        xattrs.sort();
                        visible_xattrs.insert(relative_path.clone(), xattrs);
                    }
                    if mode_to_erofs_file_type(inode.mode()) == EROFS_FT_DIR {
                        for entry in reader.read_dir(nid, &inode).unwrap() {
                            if entry.name == b"." || entry.name == b".." {
                                continue;
                            }
                            let mut child_path = relative_path.clone();
                            if !child_path.is_empty() {
                                child_path.push(b'/');
                            }
                            child_path.extend_from_slice(&entry.name);
                            pending.push((child_path, entry.nid));
                        }
                    }
                }
                let expected_xattrs = if expected_no_xattr {
                    BTreeMap::new()
                } else {
                    BTreeMap::from([(
                        b"nested/entry".to_vec(),
                        vec![
                            (b"user.empty".to_vec(), Vec::new()),
                            (b"user.test".to_vec(), b"preserved value".to_vec()),
                        ],
                    )])
                };
                assert_eq!(
                    visible_xattrs,
                    expected_xattrs,
                    "{operation}: {}",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn whiteout_semantics_follow_the_oci_rules() {
        type Layers = &'static [&'static [(&'static str, u8)]];
        let cases: [(&str, Layers, &[&str]); 4] = [
            (
                "opaque marker clears lower entries and is dropped",
                &[
                    &[("old.txt", EROFS_FT_REG_FILE), ("subdir", EROFS_FT_DIR)],
                    &[(OPAQUE, EROFS_FT_REG_FILE), ("new.txt", EROFS_FT_REG_FILE)],
                ],
                &["new.txt"],
            ),
            (
                "plain whiteout removes the lower entry and the marker",
                &[
                    &[("kept", EROFS_FT_REG_FILE), ("removed", EROFS_FT_REG_FILE)],
                    &[(".wh.removed", EROFS_FT_REG_FILE)],
                ],
                &["kept"],
            ),
            (
                "bottom layer whiteout markers are never emitted",
                &[&[
                    (".wh.lower-only", EROFS_FT_REG_FILE),
                    (OPAQUE, EROFS_FT_REG_FILE),
                    ("fresh", EROFS_FT_REG_FILE),
                ]],
                &["fresh"],
            ),
            (
                "lower whiteout marker does not delete a later upper entry",
                &[
                    &[(".wh.recreated", EROFS_FT_REG_FILE)],
                    &[("recreated", EROFS_FT_REG_FILE)],
                ],
                &["recreated"],
            ),
        ];

        for (case, layers, expected) in cases {
            let mut merged = BTreeMap::new();
            for (layer_index, layer) in layers.iter().enumerate() {
                merge_layer_entries(&mut merged, entries(layer), layer_index, WhiteoutSpec::Oci);
            }
            assert_eq!(merged_names(&merged), expected, "{case}");
        }
    }

    #[test]
    fn upper_whiteout_does_not_delete_same_layer_dotfile() {
        let mut merged = BTreeMap::new();
        merge_layer_entries(
            &mut merged,
            entries(&[(".dotfile", EROFS_FT_REG_FILE)]),
            0,
            WhiteoutSpec::Oci,
        );
        merge_layer_entries(
            &mut merged,
            entries(&[
                (".dotfile", EROFS_FT_REG_FILE),
                (".wh..dotfile", EROFS_FT_REG_FILE),
            ]),
            1,
            WhiteoutSpec::Oci,
        );
        assert_eq!(merged_names(&merged), vec![".dotfile"]);
        assert_eq!(merged[b".dotfile".as_slice()].top(), (1, 1));
    }

    #[test]
    fn directories_stack_variants_and_files_shadow() {
        let mut merged = BTreeMap::new();
        merge_layer_entries(
            &mut merged,
            entries(&[("dir", EROFS_FT_DIR), ("file", EROFS_FT_REG_FILE)]),
            0,
            WhiteoutSpec::Oci,
        );
        merge_layer_entries(
            &mut merged,
            entries(&[("dir", EROFS_FT_DIR), ("file", EROFS_FT_REG_FILE)]),
            1,
            WhiteoutSpec::Oci,
        );
        let dir = &merged[b"dir".as_slice()];
        assert!(dir.is_dir);
        assert_eq!(dir.variants, vec![(0, 1), (1, 1)]);
        let file = &merged[b"file".as_slice()];
        assert_eq!(file.variants, vec![(1, 2)]);
    }

    #[test]
    fn upper_file_replaces_lower_directory() {
        let mut merged = BTreeMap::new();
        merge_layer_entries(
            &mut merged,
            entries(&[("path", EROFS_FT_DIR)]),
            0,
            WhiteoutSpec::Oci,
        );
        merge_layer_entries(
            &mut merged,
            entries(&[("path", EROFS_FT_REG_FILE)]),
            1,
            WhiteoutSpec::Oci,
        );
        let node = &merged[b"path".as_slice()];
        assert!(!node.is_dir);
        assert_eq!(node.variants, vec![(1, 1)]);
    }

    fn set_mtime(path: &Path, secs: i64, nanoseconds: i64) {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: secs,
                tv_nsec: nanoseconds,
            },
        ];
        let rc = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                c_path.as_ptr(),
                times.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        assert_eq!(rc, 0, "utimensat failed for {}", path.display());
    }

    /// Guards against the build and merge flatteners drifting apart: building
    /// a directory tree directly and merging a single layer built from that
    /// same tree must emit identical inode sequences (the merged root's
    /// prefetch xattr aside, which is stamped on after flattening).
    #[test]
    fn build_and_single_layer_merge_produce_identical_inodes() {
        use crate::build::blob_chunk::BlobWriter;
        use crate::build::inode::build_tree;
        use crate::build::{build_image, BuildImageOptions};
        use nydus_format::blob::BlobMetadataCompressor;
        use nydus_format::utils::hex_string;
        use std::collections::HashSet;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        fs::create_dir_all(source.join("dir1").join("subdir")).unwrap();
        fs::write(source.join("dir1").join("file_a"), b"hardlinked contents").unwrap();
        fs::write(source.join("file_b"), vec![b'x'; 5000]).unwrap();
        fs::write(source.join("empty"), b"").unwrap();
        fs::hard_link(source.join("dir1").join("file_a"), source.join("link_a")).unwrap();
        std::os::unix::fs::symlink("file_b", source.join("sym")).unwrap();
        let fifo = std::ffi::CString::new(source.join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        // Hardlinks to non-regular files must also survive the merge round
        // trip as shared inodes (on Linux link(2) does not follow symlinks,
        // so `link_sym` shares the symlink's inode).
        fs::hard_link(source.join("fifo"), source.join("link_fifo")).unwrap();
        fs::hard_link(source.join("sym"), source.join("link_sym")).unwrap();
        // `link_a` shares its inode with `dir1/file_a`, so its mtime is set
        // through that path.
        for (i, rel) in [
            "dir1/subdir",
            "dir1/file_a",
            "dir1",
            "file_b",
            "empty",
            "sym",
            "fifo",
        ]
        .iter()
        .enumerate()
        {
            set_mtime(
                &source.join(rel),
                1_700_000_000 + i as i64,
                i as i64 * 123_456_789,
            );
        }

        // Path A: build the tree straight from the host directory.
        let excludes = HashSet::new();
        let scratch_blob = dir.path().join("scratch.blob");
        let mut blob_writer = BlobWriter::new(&scratch_blob, EROFS_BLOCK_SIZE).unwrap();
        let built = build_tree(&source, &mut blob_writer, EROFS_BLOCK_SIZE, &excludes).unwrap();

        // Path B: build the same tree into a full blob, then load it back as
        // a single merge layer and flatten it.
        let blob_path = dir.path().join("layer.blob");
        let image = build_image(
            &BuildImageOptions::new(
                source.clone(),
                EROFS_BLOCK_SIZE,
                1 << 20,
                BlobMetadataCompressor::None,
                excludes.clone(),
                false,
            )
            .unwrap(),
            fs::File::create(&blob_path).unwrap(),
        )
        .unwrap();
        let merge_source = dir.path().join(hex_string(&image.full_blob_digest));
        fs::rename(&blob_path, &merge_source).unwrap();

        let source_blob_id = parse_source_blob_id(&merge_source).unwrap();
        let mut device_slots = Vec::new();
        let mut blob_indexes = HashMap::new();
        let reader = ErofsReader::open_metadata_only(&merge_source).unwrap();
        validate_single_layer_blob_source(&merge_source, &reader).unwrap();
        let local_to_global = register_blobs(
            &reader,
            source_blob_id,
            &mut device_slots,
            &mut blob_indexes,
        )
        .unwrap();
        let epoch = reader.superblock().epoch();
        let fixed_nsec = reader.superblock().fixed_nsec();
        let layers = [MergeLayer {
            layer_id: 0,
            epoch,
            fixed_nsec,
            local_to_global,
            reader,
            z: None,
        }];
        let root = KWayNode {
            layers: &layers,
            whiteout_spec: WhiteoutSpec::Oci,
            variants: KWayVariants {
                variants: vec![(0, layers[0].reader.superblock().root_nid())],
                is_dir: true,
            },
        };
        let mut merged = flatten_tree(root, &mut ()).unwrap();

        // The layer bootstrap carries the prefetch xattr the build stamps on
        // its root after flattening; drop it so the roots compare equal.
        merged[0].xattrs.retain(|entry| {
            !(entry.name_index == EROFS_XATTR_INDEX_TRUSTED
                && entry.suffix.as_slice() == NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS)
        });

        assert_eq!(built.len(), merged.len(), "inode count differs");
        for (i, (a, b)) in built.iter().zip(merged.iter()).enumerate() {
            assert_eq!(a.mode, b.mode, "mode differs at inode {i}");
            assert_eq!(a.uid, b.uid, "uid differs at inode {i}");
            assert_eq!(a.gid, b.gid, "gid differs at inode {i}");
            assert_eq!(a.size, b.size, "size differs at inode {i}");
            assert_eq!(a.mtime, b.mtime, "mtime differs at inode {i}");
            assert_eq!(
                a.mtime_nsec, b.mtime_nsec,
                "mtime_nsec differs at inode {i}"
            );
            assert_eq!(a.nlink, b.nlink, "nlink differs at inode {i}");
            assert_eq!(a.ino, b.ino, "ino differs at inode {i}");
            assert_eq!(
                a.is_extended, b.is_extended,
                "is_extended differs at inode {i}"
            );
            assert_eq!(a.xattrs, b.xattrs, "xattrs differ at inode {i}");
            match (&a.data, &b.data) {
                (
                    InodeData::RegularFile {
                        chunk_index_entries: chunks_a,
                        chunk_size_bits: bits_a,
                    },
                    InodeData::RegularFile {
                        chunk_index_entries: chunks_b,
                        chunk_size_bits: bits_b,
                    },
                ) => {
                    assert_eq!(bits_a, bits_b, "chunk_size_bits differ at inode {i}");
                    assert_eq!(
                        chunks_a.len(),
                        chunks_b.len(),
                        "chunk count differs at inode {i}"
                    );
                    for (ca, cb) in chunks_a.iter().zip(chunks_b.iter()) {
                        assert_eq!(ca.blkaddr, cb.blkaddr, "chunk blkaddr differs at inode {i}");
                        assert_eq!(
                            ca.device_id, cb.device_id,
                            "chunk device differs at inode {i}"
                        );
                    }
                }
                (
                    InodeData::Directory {
                        children: children_a,
                        ..
                    },
                    InodeData::Directory {
                        children: children_b,
                        ..
                    },
                ) => {
                    assert_eq!(
                        children_a.len(),
                        children_b.len(),
                        "child count differs at inode {i}"
                    );
                    for (ca, cb) in children_a.iter().zip(children_b.iter()) {
                        assert_eq!(ca.name, cb.name, "child name differs at inode {i}");
                        assert_eq!(
                            ca.file_type, cb.file_type,
                            "child type differs at inode {i}"
                        );
                        assert_eq!(
                            ca.inode_index, cb.inode_index,
                            "child index differs at inode {i}"
                        );
                    }
                }
                (
                    InodeData::Symlink {
                        target: target_a,
                        startblk: startblk_a,
                    },
                    InodeData::Symlink {
                        target: target_b,
                        startblk: startblk_b,
                    },
                ) => {
                    assert_eq!(target_a, target_b, "symlink target differs at inode {i}");
                    assert_eq!(
                        startblk_a, startblk_b,
                        "symlink startblk differs at inode {i}"
                    );
                }
                (InodeData::Device { rdev: rdev_a }, InodeData::Device { rdev: rdev_b }) => {
                    assert_eq!(rdev_a, rdev_b, "rdev differs at inode {i}");
                }
                (InodeData::FifoOrSocket, InodeData::FifoOrSocket) => {}
                _ => panic!("inode {i} kind differs between build and merge"),
            }
        }

        // Pin the directory policy host-independently: nlink counts `.`, the
        // parent's entry, and one `..` per subdirectory, and the format
        // decision uses the computed values — whatever the host filesystem
        // reports for directories.
        let mut directories = 0;
        for (i, inode) in built.iter().enumerate() {
            if let InodeData::Directory { children, .. } = &inode.data {
                directories += 1;
                let subdirs = children
                    .iter()
                    .filter(|child| child.file_type == EROFS_FT_DIR)
                    .count() as u32;
                assert_eq!(
                    inode.nlink,
                    2 + subdirs,
                    "directory nlink policy at inode {i}"
                );
                assert_eq!(
                    inode.is_extended,
                    needs_erofs_extended_inode(0, inode.uid, inode.gid, inode.nlink as u64),
                    "directory format policy at inode {i}"
                );
            }
        }
        assert_eq!(directories, 3);

        let merged_bytes =
            render_flattened_bootstrap(&mut merged, 0, &device_slots, &[0; 16]).unwrap();
        let merged_path = dir.path().join("merged.bootstrap");
        fs::write(&merged_path, merged_bytes).unwrap();
        let reader = ErofsReader::open_metadata_only(&merged_path).unwrap();
        for (expected, rendered) in built.iter().zip(&merged) {
            let inode = reader.inode(rendered.nid).unwrap();
            assert_eq!(inode.mtime(reader.superblock().epoch()), expected.mtime);
            assert_eq!(
                inode.effective_mtime_nsec(reader.superblock().fixed_nsec()),
                expected.mtime_nsec
            );
        }
        let optimized_path = dir.path().join("optimized.bootstrap");
        fs::write(
            &optimized_path,
            rewrite_bootstrap_with_ondemand_blob(&merged_path, &[0xab; EROFS_BLOB_ID_SIZE], 1)
                .unwrap(),
        )
        .unwrap();
        let optimized = ErofsReader::open_metadata_only(&optimized_path).unwrap();
        let optimized_layer = [MergeLayer {
            layer_id: 0,
            epoch: optimized.superblock().epoch(),
            fixed_nsec: optimized.superblock().fixed_nsec(),
            local_to_global: [(1, 1), (2, 2)].into_iter().collect(),
            reader: optimized,
            z: None,
        }];
        let optimized_root = KWayNode {
            layers: &optimized_layer,
            whiteout_spec: WhiteoutSpec::Oci,
            variants: KWayVariants {
                variants: vec![(0, optimized_layer[0].reader.superblock().root_nid())],
                is_dir: true,
            },
        };
        let optimized_inodes = flatten_tree(optimized_root, &mut ()).unwrap();
        assert_eq!(built.len(), optimized_inodes.len());
        for (expected, actual) in built.iter().zip(optimized_inodes) {
            assert_eq!(actual.mtime, expected.mtime);
            assert_eq!(actual.mtime_nsec, expected.mtime_nsec);
        }
    }

    /// Hardlink groups must survive a multi-layer merge: links within one
    /// layer keep sharing a single merged inode (special files included),
    /// and an upper layer shadowing one name splits only that name out of
    /// its group.
    #[test]
    fn merge_preserves_hardlink_groups_across_layers() {
        use crate::build::{build_image, BuildImageOptions};
        use nydus_format::blob::BlobMetadataCompressor;
        use nydus_format::utils::hex_string;
        use std::collections::HashSet;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let build_layer = |source: &Path, scratch: &str| -> PathBuf {
            let blob_path = dir.path().join(scratch);
            let image = build_image(
                &BuildImageOptions::new(
                    source.to_path_buf(),
                    EROFS_BLOCK_SIZE,
                    1 << 20,
                    BlobMetadataCompressor::None,
                    HashSet::new(),
                    false,
                )
                .unwrap(),
                fs::File::create(&blob_path).unwrap(),
            )
            .unwrap();
            // Merge sources are named by their full blob digest.
            let merge_source = dir.path().join(hex_string(&image.full_blob_digest));
            fs::rename(&blob_path, &merge_source).unwrap();
            merge_source
        };

        // Lower layer: a hardlinked fifo pair and a hardlinked regular pair.
        let lower = dir.path().join("lower");
        fs::create_dir_all(&lower).unwrap();
        let fifo = std::ffi::CString::new(lower.join("fifo").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        fs::hard_link(lower.join("fifo"), lower.join("fifo_link")).unwrap();
        fs::write(lower.join("shared_a"), b"lower contents").unwrap();
        fs::hard_link(lower.join("shared_a"), lower.join("shared_b")).unwrap();

        // Upper layer: shadows one name of the regular pair and carries its
        // own hardlinked symlink pair.
        let upper = dir.path().join("upper");
        fs::create_dir_all(&upper).unwrap();
        fs::write(upper.join("shared_b"), b"upper replacement").unwrap();
        std::os::unix::fs::symlink("shared_a", upper.join("sym")).unwrap();
        fs::hard_link(upper.join("sym"), upper.join("sym_link")).unwrap();

        let sources = [
            build_layer(&lower, "lower.blob"),
            build_layer(&upper, "upper.blob"),
        ];

        let mut device_slots = Vec::new();
        let mut blob_indexes = HashMap::new();
        let mut layers = Vec::new();
        for (layer_id, source) in sources.iter().enumerate() {
            let source_blob_id = parse_source_blob_id(source).unwrap();
            let reader = ErofsReader::open_metadata_only(source).unwrap();
            let local_to_global = register_blobs(
                &reader,
                source_blob_id,
                &mut device_slots,
                &mut blob_indexes,
            )
            .unwrap();
            layers.push(MergeLayer {
                layer_id: layer_id as u32,
                epoch: reader.superblock().epoch(),
                fixed_nsec: reader.superblock().fixed_nsec(),
                local_to_global,
                reader,
                z: None,
            });
        }
        let root = KWayNode {
            layers: &layers,
            whiteout_spec: WhiteoutSpec::Oci,
            variants: KWayVariants {
                variants: layers
                    .iter()
                    .enumerate()
                    .map(|(index, layer)| (index, layer.reader.superblock().root_nid()))
                    .collect(),
                is_dir: true,
            },
        };
        let inodes = flatten_tree(root, &mut ()).unwrap();

        let InodeData::Directory { children, .. } = &inodes[0].data else {
            panic!("root should be a directory")
        };
        let index_of = |name: &str| {
            children
                .iter()
                .find(|child| child.name == name.as_bytes())
                .unwrap_or_else(|| panic!("missing root entry {name}"))
                .inode_index
        };

        assert_eq!(
            index_of("fifo"),
            index_of("fifo_link"),
            "hardlinked fifo pair split by merge"
        );
        assert_eq!(
            index_of("sym"),
            index_of("sym_link"),
            "hardlinked symlink pair split by merge"
        );
        assert_ne!(
            index_of("shared_a"),
            index_of("shared_b"),
            "shadowed name must not share the lower group's inode"
        );
        assert_eq!(
            inodes[index_of("shared_b")].size,
            b"upper replacement".len() as u64,
            "shared_b must come from the upper layer"
        );
    }

    /// Writes an OCI layer tarball with the given regular files (`.wh.` names
    /// are whiteouts) and returns its path.
    fn write_tar_layer(dir: &Path, name: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let path = dir.join(name);
        let mut builder = tar::Builder::new(fs::File::create(&path).unwrap());
        for (rel, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(1_700_000_000);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, rel, *data).unwrap();
        }
        builder.finish().unwrap();
        path
    }

    /// Lcluster indexes of a COMPRESSED_FULL tail as (type, blkaddr) pairs;
    /// NONHEAD entries report `None`.
    fn lcluster_addrs(tail: &[u8]) -> Vec<Option<u32>> {
        tail[Z_EROFS_MAP_HEADER_SIZE + 8..]
            .chunks_exact(8)
            .map(|index| {
                let advise = u16::from_le_bytes([index[0], index[1]]);
                (advise & 0x3 != 2).then(|| u32::from_le_bytes(index[4..8].try_into().unwrap()))
            })
            .collect()
    }

    #[test]
    fn z_layers_merge_into_one_device_table_with_relocated_addresses() {
        use crate::build::{build_erofs_layer_from_tar, BuildImageOptions};
        use nydus_format::blob::BlobMetadataCompressor;
        use nydus_format::erofs::{EROFS_FT_REG_FILE, Z_EROFS_FRAGMENT_INODE_FLAG};
        use std::collections::HashSet;

        let dir = tempfile::tempdir().unwrap();
        // Incompressible data so the big files keep one PLAIN/HEAD lcluster per
        // block and stay above the 64KiB fragment threshold.
        let noise: Vec<u8> = (0..200_000u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let lower = write_tar_layer(
            dir.path(),
            "lower.tar",
            &[
                ("big_lower", &noise[..100_000]),
                ("small_lower", b"lower small file"),
                ("gone", b"to be whited out"),
            ],
        );
        let upper = write_tar_layer(
            dir.path(),
            "upper.tar",
            &[
                ("big_upper", &noise[100_000..]),
                ("small_upper", b"upper small file, a bit longer"),
                ("empty_upper", b""),
                (".wh.gone", b""),
            ],
        );

        let options = BuildImageOptions::new(
            PathBuf::from("/unused"),
            EROFS_BLOCK_SIZE,
            1 << 20,
            BlobMetadataCompressor::None,
            HashSet::new(),
            false,
        )
        .unwrap()
        .with_erofs_lz4(true, 0);

        let mut metas = Vec::new();
        let mut layer_packed_sizes = Vec::new();
        for (index, layer) in [lower, upper].iter().enumerate() {
            let blob_path = dir.path().join(format!("blob{index}"));
            let layer =
                build_erofs_layer_from_tar(&options, layer, fs::File::create(&blob_path).unwrap())
                    .unwrap();
            assert_eq!(
                fs::metadata(&blob_path).unwrap().len(),
                layer.blob_blocks * EROFS_BLOCK_SIZE as u64
            );
            let meta_path = dir.path().join(format!("layer{index}.meta"));
            fs::write(&meta_path, &layer.bootstrap).unwrap();

            let reader = ErofsReader::open_metadata_only(&meta_path).unwrap();
            let [info] = reader.blob_infos().unwrap() else {
                panic!("one device per layer");
            };
            assert_eq!(info.blob_id, layer.blob_digest);
            assert!(
                info.mapped_blkaddr * EROFS_BLOCK_SIZE as u64 >= layer.bootstrap.len() as u64,
                "layer device must start past its bootstrap"
            );
            let packed_nid = reader.superblock().packed_nid().expect("fragments enabled");
            let packed = reader.inode(packed_nid).unwrap();
            assert_eq!(
                packed.size() % EROFS_BLOCK_SIZE as u64,
                0,
                "packed inode is block padded"
            );
            layer_packed_sizes.push(packed.size());
            metas.push(meta_path);
        }

        let merged = merge_sources_to_bootstrap_bytes(&metas, WhiteoutSpec::Oci).unwrap();
        let merged_path = dir.path().join("merged.img");
        fs::write(&merged_path, &merged).unwrap();
        let reader = ErofsReader::open_metadata_only(&merged_path).unwrap();
        let infos = reader.blob_infos().unwrap();
        assert_eq!(infos.len(), 2);
        assert!(infos[0].mapped_blkaddr * EROFS_BLOCK_SIZE as u64 >= merged.len() as u64);
        assert_eq!(
            infos[1].mapped_blkaddr,
            (infos[0].mapped_blkaddr + infos[0].blocks)
                .next_multiple_of(FLATTENED_BLOB_ALIGNMENT / EROFS_BLOCK_SIZE as u64)
        );

        let root_nid = reader.superblock().root_nid();
        let root = reader.inode(root_nid).unwrap();
        let mut names: Vec<Vec<u8>> = reader
            .read_dir(root_nid, &root)
            .unwrap()
            .into_iter()
            .filter(|entry| entry.name != b"." && entry.name != b"..")
            .map(|entry| entry.name)
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                b"big_lower".to_vec(),
                b"big_upper".to_vec(),
                b"empty_upper".to_vec(),
                b"small_lower".to_vec(),
                b"small_upper".to_vec(),
            ],
            "whiteout applied, marker dropped"
        );

        let lookup = |name: &[u8]| {
            let nid = reader
                .lookup_dir_entry(root_nid, &root, name)
                .unwrap()
                .unwrap();
            let inode = reader.inode(nid).unwrap();
            assert_eq!(mode_to_erofs_file_type(inode.mode()), EROFS_FT_REG_FILE);
            assert_eq!(inode.data_layout(), EROFS_INODE_COMPRESSED_FULL);
            let tail = reader.read_z_inode_tail(nid, &inode).unwrap().to_vec();
            (inode.size(), tail)
        };
        // Big files: every lcluster address lies inside its layer's device.
        for (name, info) in [
            (&b"big_lower"[..], &infos[0]),
            (&b"big_upper"[..], &infos[1]),
        ] {
            let (size, tail) = lookup(name);
            assert_eq!(size, 100_000);
            let addrs = lcluster_addrs(&tail);
            assert_eq!(addrs.len(), 25);
            for addr in addrs.into_iter().flatten() {
                let addr = addr as u64;
                assert!(
                    addr >= info.mapped_blkaddr && addr < info.mapped_blkaddr + info.blocks,
                    "{} lcluster {addr} outside device [{}, {})",
                    String::from_utf8_lossy(name),
                    info.mapped_blkaddr,
                    info.mapped_blkaddr + info.blocks
                );
            }
        }
        // Small files: fragments whose offsets are shifted by the packed
        // streams merged before their layer.
        let fragment_offset = |name: &[u8]| {
            let (_, tail) = lookup(name);
            assert_eq!(tail.len(), Z_EROFS_MAP_HEADER_SIZE);
            let head = u64::from_le_bytes(tail.try_into().unwrap());
            assert_ne!(head & Z_EROFS_FRAGMENT_INODE_FLAG, 0);
            head ^ Z_EROFS_FRAGMENT_INODE_FLAG
        };
        assert_eq!(fragment_offset(b"small_lower"), 0);
        assert_eq!(fragment_offset(b"small_upper"), layer_packed_sizes[0]);
        // Empty files are z inodes too, with no lclusters and no fragment.
        let (size, tail) = lookup(b"empty_upper");
        assert_eq!(size, 0);
        assert_eq!(tail.len(), Z_EROFS_MAP_HEADER_SIZE + 8);

        let packed_nid = reader.superblock().packed_nid().unwrap();
        let packed = reader.inode(packed_nid).unwrap();
        assert_eq!(packed.size(), layer_packed_sizes.iter().sum::<u64>());
        let packed_tail = reader.read_z_inode_tail(packed_nid, &packed).unwrap();
        let packed_addrs = lcluster_addrs(packed_tail);
        assert_eq!(
            packed_addrs.len(),
            (packed.size() / EROFS_BLOCK_SIZE as u64) as usize
        );
        let head_addrs: Vec<u64> = packed_addrs.into_iter().flatten().map(u64::from).collect();
        assert!(head_addrs.iter().any(
            |a| *a >= infos[0].mapped_blkaddr && *a < infos[0].mapped_blkaddr + infos[0].blocks
        ));
        assert!(head_addrs.iter().any(
            |a| *a >= infos[1].mapped_blkaddr && *a < infos[1].mapped_blkaddr + infos[1].blocks
        ));
    }
}
