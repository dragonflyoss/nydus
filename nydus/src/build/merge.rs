use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::build::bootstrap::{render_flattened_bootstrap, render_flattened_bootstrap_to};
use crate::build::inode::{
    flatten_tree, set_root_prefetch_blobs_xattr, InodeData, NamedChildren, NodeAttrs, TreeNode,
};
use nydus_core::reader::RawDirEntry;
use nydus_core::ErofsReader;
use nydus_error::{Context, Error, Result};
use nydus_format::erofs::{
    erofs_xattr_name_split, mode_to_erofs_file_type, ErofsChunkAddr, ErofsDeviceSlot, XattrEntry,
    EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE, EROFS_FT_BLKDEV, EROFS_FT_CHRDEV, EROFS_FT_DIR,
    EROFS_FT_FIFO, EROFS_FT_REG_FILE, EROFS_FT_SOCK, EROFS_FT_SYMLINK, EROFS_INODE_CHUNK_BASED,
    EROFS_NULL_ADDR,
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
        Ok(
            (mode_to_erofs_file_type(inode.mode()) == EROFS_FT_REG_FILE && inode.nlink() > 1)
                .then_some(MergeLinkId {
                    layer_id: layer.layer_id,
                    nid,
                }),
        )
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

    // `build_tree` zeroes the root mtime for reproducibility, so the minimum
    // inode mtime read back from any layer is always 0.
    let epoch = 0;
    let uuid = [0u8; 16];
    let blob_count = u16::try_from(device_slots.len())
        .map_err(|err| Error::Overflow(format!("device slot count exceeds u16: {err}")))?;
    let prefetch_blob_indexes = (1..=blob_count).collect::<Vec<_>>();
    set_root_prefetch_blobs_xattr(&mut inodes[0], &prefetch_blob_indexes)?;

    render_flattened_bootstrap_to(writer, &mut inodes, epoch, &device_slots, &uuid)?;
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
        .collect();
    let ondemand_blob_index = u16::try_from(device_slots.len() + 1).map_err(|err| {
        Error::Overflow(format!(
            "ondemand blob index exceeds u16 device table range: {err}"
        ))
    })?;
    device_slots.push(ErofsDeviceSlot::with_blob_id(
        ondemand_blocks,
        ondemand_blob_id,
    ));

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

    // See merge_sources_to_bootstrap_bytes: the root mtime is always 0.
    let epoch = 0;
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
        let next = device_slots.len() as u16 + 1;
        device_slots.push(ErofsDeviceSlot::with_blob_id(info.blocks, &source_blob_id));
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
    let file_size = fs::metadata(path)
        .with_context(|| format!("failed to stat merge source: {}", path.display()))?
        .len();
    let primary_image_size = reader.superblock().blocks() * EROFS_BLOCK_SIZE as u64;
    let blob_infos = reader.blob_infos()?;
    if blob_infos.len() != 1 {
        return Err(Error::InvalidImage(
            "merge source must contain exactly one external blob".to_string(),
        ));
    }
    if blob_infos[0].blocks > 0 && file_size == primary_image_size {
        return Err(Error::InvalidImage(
            "merge source must be a full blob file, not a metadata-only bootstrap".to_string(),
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
    use nydus_format::erofs::{
        needs_erofs_extended_inode, EROFS_XATTR_INDEX_TRUSTED, NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS,
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

    /// Set a path's mtime to whole seconds (no nanoseconds), without
    /// following symlinks. Compact EROFS inodes store no mtime nanoseconds,
    /// so a layer read back cannot reproduce them; pinning fixture mtimes to
    /// whole seconds keeps the build and merge paths exactly comparable.
    fn set_mtime_seconds(path: &Path, secs: i64) {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: secs,
                tv_nsec: 0,
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
            set_mtime_seconds(&source.join(rel), 1_700_000_000 + i as i64);
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
    }
}
