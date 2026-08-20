use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::build::bootstrap::render_flattened_bootstrap;
use crate::build::inode::{
    flatten_tree, set_root_prefetch_blobs_xattr, InodeData, NamedChildren, NodeAttrs, TreeNode,
};
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WhiteoutSpec {
    Oci,
}

#[derive(Clone)]
struct MergeNode {
    link_id: Option<MergeLinkId>,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    mtime: u64,
    mtime_nsec: u32,
    nlink: u32,
    xattrs: Vec<XattrEntry>,
    data: MergeNodeData,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MergeLinkId {
    layer_id: u32,
    nid: u64,
}

#[derive(Clone)]
enum MergeNodeData {
    RegularFile {
        chunk_index_entries: Vec<ErofsChunkAddr>,
        chunk_size_bits: u32,
    },
    Directory {
        children: BTreeMap<Vec<u8>, MergeNode>,
    },
    Symlink {
        target: Vec<u8>,
    },
    SpecialDev {
        rdev: u32,
    },
    SpecialNoData,
}

pub fn merge_sources_to_bootstrap_bytes(
    sources: &[PathBuf],
    whiteout_spec: WhiteoutSpec,
) -> Result<Vec<u8>> {
    if sources.is_empty() {
        return Err(Error::InvalidParameter(
            "merge requires at least one source".to_string(),
        ));
    }

    let mut merged_root: Option<MergeNode> = None;
    let mut device_slots = Vec::new();
    let mut blob_indexes = HashMap::new();

    for (layer_id, source) in sources.iter().enumerate() {
        let source_blob_id = parse_source_blob_id(source)
            .with_context(|| format!("invalid merge source: {}", source.display()))?;
        let layer = load_layer(
            layer_id as u32,
            source,
            source_blob_id,
            &mut device_slots,
            &mut blob_indexes,
        )
        .with_context(|| format!("failed to load layer: {}", source.display()))?;
        merged_root = Some(match merged_root {
            Some(existing) => overlay_nodes(existing, layer, whiteout_spec)?,
            None => layer,
        });
    }

    let mut merged_root = merged_root
        .ok_or_else(|| Error::InvalidImage("merge produced no root node".to_string()))?;
    strip_whiteout_entries(&mut merged_root, whiteout_spec);

    // `flatten_tree` always yields at least the root inode.
    let mut inodes = flatten_tree(&merged_root, &mut ())?;

    // `build_tree` zeroes the root mtime for reproducibility, so the minimum
    // inode mtime read back from any layer is always 0.
    let epoch = 0;
    let uuid = [0u8; 16];
    let blob_count = u16::try_from(device_slots.len())
        .map_err(|err| Error::Overflow(format!("device slot count exceeds u16: {err}")))?;
    let prefetch_blob_indexes = (1..=blob_count).collect::<Vec<_>>();
    set_root_prefetch_blobs_xattr(&mut inodes[0], &prefetch_blob_indexes)?;

    render_flattened_bootstrap(&mut inodes, epoch, &device_slots, &uuid)
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
    let blob_infos = reader.blob_infos()?;
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
    let root = load_node(
        &reader,
        0,
        reader.superblock().root_nid(),
        reader.superblock().epoch(),
        &identity,
    )
    .with_context(|| {
        format!(
            "failed to load bootstrap inode tree: {}",
            parent_bootstrap.display()
        )
    })?;

    // `flatten_tree` always yields at least the root inode.
    let mut inodes = flatten_tree(&root, &mut ())?;

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

fn load_layer(
    layer_id: u32,
    source: &Path,
    source_blob_id: [u8; EROFS_BLOB_ID_SIZE],
    device_slots: &mut Vec<ErofsDeviceSlot>,
    blob_indexes: &mut HashMap<[u8; EROFS_BLOB_ID_SIZE], u16>,
) -> Result<MergeNode> {
    let reader = ErofsReader::open_metadata_only(source)?;
    validate_single_layer_blob_source(source, &reader)?;
    let layer_epoch = reader.superblock().epoch();
    let local_to_global = register_blobs(&reader, source_blob_id, device_slots, blob_indexes)?;
    load_node(
        &reader,
        layer_id,
        reader.superblock().root_nid(),
        layer_epoch,
        &local_to_global,
    )
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

fn load_node(
    reader: &ErofsReader,
    layer_id: u32,
    nid: u64,
    epoch: u64,
    local_to_global: &HashMap<u16, u16>,
) -> Result<MergeNode> {
    let inode = reader
        .inode(nid)
        .with_context(|| format!("failed to read inode: {nid}"))?;
    let mode = inode.mode();
    let mut xattrs: Vec<XattrEntry> = reader
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

    let data =
        match mode_to_erofs_file_type(mode) {
            EROFS_FT_DIR => {
                let mut children = BTreeMap::new();
                for entry in reader.read_dir(nid, &inode)? {
                    if entry.name == b"." || entry.name == b".." {
                        continue;
                    }
                    children.insert(
                        entry.name.clone(),
                        load_node(reader, layer_id, entry.nid, epoch, local_to_global)
                            .with_context(|| {
                                format!(
                                    "failed to load child: {}",
                                    String::from_utf8_lossy(&entry.name)
                                )
                            })?,
                    );
                }
                MergeNodeData::Directory { children }
            }
            EROFS_FT_REG_FILE => {
                if inode.data_layout() != EROFS_INODE_CHUNK_BASED {
                    return Err(Error::Unsupported(
                        "merge currently only supports chunk-based regular files".to_string(),
                    ));
                }
                let chunk_size_bits = reader.chunk_bits(&inode);
                let chunk_index_entries = reader
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
                            let mapped = local_to_global
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
                MergeNodeData::RegularFile {
                    chunk_index_entries,
                    chunk_size_bits,
                }
            }
            EROFS_FT_SYMLINK => MergeNodeData::Symlink {
                target: reader.read_symlink(nid, &inode)?,
            },
            EROFS_FT_CHRDEV | EROFS_FT_BLKDEV => MergeNodeData::SpecialDev { rdev: inode.rdev() },
            EROFS_FT_FIFO | EROFS_FT_SOCK => MergeNodeData::SpecialNoData,
            other => {
                return Err(Error::Unsupported(format!(
                    "unsupported inode file type {other} while loading layer"
                )))
            }
        };

    Ok(MergeNode {
        link_id: if mode_to_erofs_file_type(mode) == EROFS_FT_REG_FILE && inode.nlink() > 1 {
            Some(MergeLinkId { layer_id, nid })
        } else {
            None
        },
        mode,
        uid: inode.uid(),
        gid: inode.gid(),
        size: inode.size(),
        mtime: inode.mtime(epoch),
        mtime_nsec: inode.effective_mtime_nsec(reader.superblock().fixed_nsec()),
        nlink: inode.nlink(),
        xattrs,
        data,
    })
}

fn overlay_nodes(
    lower: MergeNode,
    upper: MergeNode,
    whiteout_spec: WhiteoutSpec,
) -> Result<MergeNode> {
    if let (
        MergeNodeData::Directory {
            children: lower_children,
        },
        MergeNodeData::Directory {
            children: upper_children,
        },
    ) = (&lower.data, &upper.data)
    {
        let lower_children = lower_children.clone();
        let upper_children = upper_children.clone();
        return overlay_directories(lower_children, upper, upper_children, whiteout_spec);
    }

    Ok(upper)
}

fn overlay_directories(
    lower_children: BTreeMap<Vec<u8>, MergeNode>,
    upper_meta: MergeNode,
    upper_children: BTreeMap<Vec<u8>, MergeNode>,
    whiteout_spec: WhiteoutSpec,
) -> Result<MergeNode> {
    let mut merged_children = lower_children;
    let opaque = upper_children
        .keys()
        .any(|name| is_opaque_marker(name, whiteout_spec));
    if opaque {
        merged_children.clear();
    }

    for name in upper_children.keys() {
        if let Some(target) = whiteout_target(name, whiteout_spec) {
            merged_children.remove(target);
        }
    }

    for (name, child) in upper_children {
        if is_opaque_marker(&name, whiteout_spec) || whiteout_target(&name, whiteout_spec).is_some()
        {
            continue;
        }

        match merged_children.remove(&name) {
            Some(existing) => {
                merged_children.insert(name, overlay_nodes(existing, child, whiteout_spec)?);
            }
            None => {
                merged_children.insert(name, child);
            }
        }
    }

    Ok(MergeNode {
        data: MergeNodeData::Directory {
            children: merged_children,
        },
        ..upper_meta
    })
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

fn strip_whiteout_entries(node: &mut MergeNode, whiteout_spec: WhiteoutSpec) {
    let MergeNodeData::Directory { children } = &mut node.data else {
        return;
    };

    children.retain(|name, _| {
        !is_opaque_marker(name, whiteout_spec) && whiteout_target(name, whiteout_spec).is_none()
    });
    for child in children.values_mut() {
        strip_whiteout_entries(child, whiteout_spec);
    }
}

/// [`TreeNode`] over the in-memory merge tree, so [`flatten_tree`] produces
/// exactly the same inodes for a merged layer as for a directory build.
impl<'a> TreeNode<()> for &'a MergeNode {
    type LinkKey = MergeLinkId;

    fn attrs(&self) -> NodeAttrs {
        NodeAttrs {
            mode: self.mode,
            uid: self.uid,
            gid: self.gid,
            size: self.size,
            mtime: self.mtime,
            mtime_nsec: self.mtime_nsec,
            nlink: self.nlink,
            xattrs: self.xattrs.clone(),
        }
    }

    fn link_key(&self) -> Option<MergeLinkId> {
        self.link_id
    }

    fn children(&self, _ctx: &mut ()) -> Result<Option<NamedChildren<Self>>> {
        let node: &'a MergeNode = self;
        match &node.data {
            MergeNodeData::Directory { children } => Ok(Some(
                children
                    .iter()
                    .map(|(name, child)| (name.clone(), child))
                    .collect(),
            )),
            _ => Ok(None),
        }
    }

    fn leaf_data(&self, _ctx: &mut ()) -> Result<InodeData> {
        Ok(match &self.data {
            MergeNodeData::RegularFile {
                chunk_index_entries,
                chunk_size_bits,
            } => InodeData::RegularFile {
                chunk_index_entries: chunk_index_entries.clone(),
                chunk_size_bits: *chunk_size_bits,
            },
            MergeNodeData::Symlink { target } => InodeData::Symlink {
                target: target.clone(),
                startblk: 0,
            },
            MergeNodeData::SpecialDev { rdev } => InodeData::Device { rdev: *rdev },
            MergeNodeData::SpecialNoData => InodeData::FifoOrSocket,
            MergeNodeData::Directory { .. } => {
                unreachable!("leaf_data is only called for non-directories")
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_format::erofs::{
        needs_erofs_extended_inode, EROFS_BLKSZBITS, EROFS_XATTR_INDEX_TRUSTED,
        NYDUS_XATTR_SUFFIX_PREFETCH_BLOBS,
    };

    const OPAQUE: &str = ".wh..wh..opq";

    fn directory(entries: Vec<(&str, MergeNode)>) -> MergeNode {
        let children = entries
            .into_iter()
            .map(|(name, node)| (name.as_bytes().to_vec(), node))
            .collect();
        merge_node(MergeNodeData::Directory { children })
    }

    fn regular_file() -> MergeNode {
        merge_node(MergeNodeData::RegularFile {
            chunk_index_entries: Vec::new(),
            chunk_size_bits: EROFS_BLKSZBITS as u32,
        })
    }

    fn merge_node(data: MergeNodeData) -> MergeNode {
        let mode = match data {
            MergeNodeData::Directory { .. } => libc::S_IFDIR as u16 | 0o755,
            MergeNodeData::RegularFile { .. } => libc::S_IFREG as u16 | 0o644,
            _ => libc::S_IFREG as u16 | 0o644,
        };
        MergeNode {
            link_id: None,
            mode,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: 0,
            mtime_nsec: 0,
            nlink: 1,
            xattrs: Vec::new(),
            data,
        }
    }

    fn child_names(node: &MergeNode) -> Vec<String> {
        let MergeNodeData::Directory { children } = &node.data else {
            panic!("not a directory")
        };
        children
            .keys()
            .map(|k| String::from_utf8_lossy(k).into_owned())
            .collect()
    }

    #[test]
    fn strip_whiteout_entries_removes_opaque_marker_from_inserted_directory() {
        let mut root = directory(vec![(
            "opt",
            directory(vec![(
                "yarn-v1.22.19",
                directory(vec![(OPAQUE, regular_file())]),
            )]),
        )]);

        strip_whiteout_entries(&mut root, WhiteoutSpec::Oci);

        let MergeNodeData::Directory { children } = &root.data else {
            panic!("root should be a directory")
        };
        let opt = children.get(b"opt".as_slice()).unwrap();
        let MergeNodeData::Directory { children } = &opt.data else {
            panic!("opt should be a directory")
        };
        let yarn = children.get(b"yarn-v1.22.19".as_slice()).unwrap();
        assert!(child_names(yarn).is_empty());
    }

    #[test]
    fn strip_whiteout_entries_removes_plain_whiteout_marker() {
        let mut root = directory(vec![
            (".wh.removed", regular_file()),
            ("kept", regular_file()),
        ]);

        strip_whiteout_entries(&mut root, WhiteoutSpec::Oci);

        assert_eq!(child_names(&root), vec!["kept"]);
    }

    #[test]
    fn overlay_opaque_directory_keeps_upper_entries_and_drops_marker() {
        let lower = directory(vec![(
            "opq",
            directory(vec![
                ("old.txt", regular_file()),
                ("subdir", directory(Vec::new())),
            ]),
        )]);
        let upper = directory(vec![(
            "opq",
            directory(vec![(OPAQUE, regular_file()), ("new.txt", regular_file())]),
        )]);

        let mut merged = overlay_nodes(lower, upper, WhiteoutSpec::Oci).unwrap();
        strip_whiteout_entries(&mut merged, WhiteoutSpec::Oci);

        let MergeNodeData::Directory { children } = &merged.data else {
            panic!("root should be a directory")
        };
        assert_eq!(
            child_names(children.get(b"opq".as_slice()).unwrap()),
            vec!["new.txt"]
        );
    }

    #[test]
    fn overlay_plain_whiteout_removes_lower_entry_and_marker() {
        let lower = directory(vec![("kept", regular_file()), ("removed", regular_file())]);
        let upper = directory(vec![(".wh.removed", regular_file())]);

        let mut merged = overlay_nodes(lower, upper, WhiteoutSpec::Oci).unwrap();
        strip_whiteout_entries(&mut merged, WhiteoutSpec::Oci);

        assert_eq!(child_names(&merged), vec!["kept"]);
    }

    #[test]
    fn strip_whiteout_entries_removes_marker_inside_inserted_directory() {
        let mut root = directory(vec![(
            "newdir",
            directory(vec![
                (".wh.lower-only", regular_file()),
                ("fresh", regular_file()),
            ]),
        )]);

        strip_whiteout_entries(&mut root, WhiteoutSpec::Oci);

        let MergeNodeData::Directory { children } = &root.data else {
            panic!("root should be a directory")
        };
        assert_eq!(
            child_names(children.get(b"newdir".as_slice()).unwrap()),
            vec!["fresh"]
        );
    }

    #[test]
    fn lower_whiteout_marker_does_not_delete_later_upper_entry() {
        let lower = directory(vec![(".wh.recreated", regular_file())]);
        let upper = directory(vec![("recreated", regular_file())]);

        let mut merged = overlay_nodes(lower, upper, WhiteoutSpec::Oci).unwrap();
        strip_whiteout_entries(&mut merged, WhiteoutSpec::Oci);

        assert_eq!(child_names(&merged), vec!["recreated"]);
    }

    #[test]
    fn upper_whiteout_does_not_delete_same_layer_dotfile() {
        let lower = directory(vec![(".dotfile", regular_file())]);
        let upper = directory(vec![
            (".dotfile", regular_file()),
            (".wh..dotfile", regular_file()),
        ]);

        let mut merged = overlay_nodes(lower, upper, WhiteoutSpec::Oci).unwrap();
        strip_whiteout_entries(&mut merged, WhiteoutSpec::Oci);

        assert_eq!(child_names(&merged), vec![".dotfile"]);
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
        let root = load_layer(
            0,
            &merge_source,
            source_blob_id,
            &mut device_slots,
            &mut blob_indexes,
        )
        .unwrap();
        let mut merged = flatten_tree(&root, &mut ()).unwrap();

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
