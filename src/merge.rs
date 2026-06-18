use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context, Result};

use crate::build::blob_chunk::ChunkIndex;
use crate::build::bootstrap::render_flattened_bootstrap;
use crate::build::inode::{
    mode_to_erofs_file_type, set_root_prefetch_blobs_xattr, DirEntry, InodeData, InodeInfo,
};
use crate::fs::ErofsReader;
use crate::metadata::*;
use crate::utils::parse_sha256_hex;

const OCI_WHITEOUT_PREFIX: &str = ".wh.";
const OCI_OPAQUE_MARKER: &str = ".wh..wh..opq";

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
    xattrs: Vec<(u8, Vec<u8>, Vec<u8>)>,
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
        chunk_indexes: Vec<ChunkIndex>,
        chunkbits: u32,
    },
    Directory {
        children: BTreeMap<String, MergeNode>,
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
        bail!("merge requires at least one source");
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

    let mut merged_root = merged_root.ok_or_else(|| anyhow!("merge produced no root node"))?;
    strip_whiteout_entries(&mut merged_root, whiteout_spec);

    let mut inodes = Vec::new();
    let mut ino_counter = 0u32;
    let mut hardlink_indexes = HashMap::new();
    flatten_node(
        &merged_root,
        &mut inodes,
        &mut ino_counter,
        &mut hardlink_indexes,
    );

    let build_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_secs();
    let epoch = inodes
        .iter()
        .map(|inode| inode.mtime)
        .min()
        .unwrap_or(build_time);
    let uuid = [0u8; 16];
    let blob_count = u16::try_from(device_slots.len()).context("device slot count exceeds u16")?;
    let prefetch_blob_indexes = (1..=blob_count).collect::<Vec<_>>();
    set_root_prefetch_blobs_xattr(&mut inodes[0], &prefetch_blob_indexes)?;

    render_flattened_bootstrap(
        &mut inodes,
        epoch,
        EROFS_BLKSZBITS as u32,
        &device_slots,
        &uuid,
    )
}

/// Rewrite an existing merged bootstrap for the `optimize` flow: append an
/// "ondemand" device slot for the redirect blob and put its blob index first
/// in the root prefetch xattr so it is warmed before everything else. The
/// parent bootstrap is read-only; the rewritten bootstrap bytes are returned.
pub fn rewrite_bootstrap_with_ondemand_blob(
    parent_bootstrap: &Path,
    ondemand_blob_id: &[u8; EROFS_BLOB_ID_SIZE],
    ondemand_blocks: u64,
) -> Result<Vec<u8>> {
    let reader = ErofsReader::open_layer(parent_bootstrap)
        .with_context(|| format!("failed to open bootstrap: {}", parent_bootstrap.display()))?;
    let blob_infos = reader.blob_infos()?;
    if blob_infos.is_empty() {
        bail!("parent bootstrap contains no blobs");
    }
    if blob_infos
        .iter()
        .any(|info| info.blob_id == *ondemand_blob_id)
    {
        bail!("parent bootstrap already contains the ondemand blob");
    }

    // Blobs keep their indexes, so chunk indexes round-trip unchanged.
    let identity: HashMap<u16, u16> = blob_infos
        .iter()
        .map(|info| (info.blob_index, info.blob_index))
        .collect();
    let root = load_node(
        &reader,
        0,
        reader.sb().root_nid(),
        reader.sb().epoch(),
        &identity,
    )
    .context("failed to load bootstrap inode tree")?;

    let mut inodes = Vec::new();
    let mut ino_counter = 0u32;
    let mut hardlink_indexes = HashMap::new();
    flatten_node(&root, &mut inodes, &mut ino_counter, &mut hardlink_indexes);
    if inodes.is_empty() {
        bail!("bootstrap produced no inodes");
    }

    let mut device_slots: Vec<ErofsDeviceSlot> = blob_infos
        .iter()
        .map(|info| ErofsDeviceSlot::with_blob_id(info.blocks, &info.blob_id))
        .collect();
    let ondemand_blob_index = u16::try_from(device_slots.len() + 1)
        .context("ondemand blob index exceeds u16 device table range")?;
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

    let epoch = inodes
        .iter()
        .map(|inode| inode.mtime)
        .min()
        .unwrap_or_else(|| reader.sb().epoch());
    let uuid = [0u8; 16];
    render_flattened_bootstrap(
        &mut inodes,
        epoch,
        EROFS_BLKSZBITS as u32,
        &device_slots,
        &uuid,
    )
}

fn load_layer(
    layer_id: u32,
    source: &Path,
    source_blob_id: [u8; EROFS_BLOB_ID_SIZE],
    device_slots: &mut Vec<ErofsDeviceSlot>,
    blob_indexes: &mut HashMap<[u8; EROFS_BLOB_ID_SIZE], u16>,
) -> Result<MergeNode> {
    let reader = ErofsReader::open_layer(source)?;
    validate_single_layer_blob_source(source, &reader)?;
    let layer_epoch = reader.sb().epoch();
    let local_to_global = register_blobs(&reader, source_blob_id, device_slots, blob_indexes)?;
    load_node(
        &reader,
        layer_id,
        reader.sb().root_nid(),
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
    let info = infos
        .first()
        .ok_or_else(|| anyhow!("merge source does not contain an external blob"))?;
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
        bail!("merge source currently supports exactly one external blob")
    }
    Ok(local_to_global)
}

fn parse_source_blob_id(path: &Path) -> Result<[u8; EROFS_BLOB_ID_SIZE]> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("merge source file name must be valid UTF-8 sha256 hex"))?;
    parse_sha256_hex(file_name).context("merge source file name must be a sha256 hex string")
}

fn validate_single_layer_blob_source(path: &Path, reader: &ErofsReader) -> Result<()> {
    let file_size = fs::metadata(path)
        .with_context(|| format!("failed to stat merge source: {}", path.display()))?
        .len();
    let primary_image_size = reader.sb().blocks() * EROFS_BLOCK_SIZE as u64;
    let blob_infos = reader.blob_infos()?;
    if blob_infos.len() != 1 {
        bail!("merge source must contain exactly one external blob");
    }
    if blob_infos[0].blocks > 0 && file_size == primary_image_size {
        bail!("merge source must be a full blob file, not a metadata-only bootstrap");
    }
    Ok(())
}

fn load_node(
    reader: &ErofsReader,
    layer_id: u32,
    nid: u64,
    epoch: u64,
    blob_indexes: &HashMap<u16, u16>,
) -> Result<MergeNode> {
    let inode = reader
        .inode(nid)
        .with_context(|| format!("failed to read inode {nid}"))?;
    let mode = inode.mode();
    let xattrs = reader
        .read_xattrs(nid, &inode)?
        .into_iter()
        .filter_map(|(name, value)| {
            erofs_xattr_name_split(&name).map(|(index, suffix)| (index, suffix.to_vec(), value))
        })
        .collect();

    let data = match mode_to_erofs_file_type(mode) {
        EROFS_FT_DIR => {
            let mut children = BTreeMap::new();
            for entry in reader.read_dir(nid, &inode)? {
                if entry.name == "." || entry.name == ".." {
                    continue;
                }
                children.insert(
                    entry.name.clone(),
                    load_node(reader, layer_id, entry.nid, epoch, blob_indexes)
                        .with_context(|| format!("failed to load child {}", entry.name))?,
                );
            }
            MergeNodeData::Directory { children }
        }
        EROFS_FT_REG_FILE => {
            if inode.data_layout() != EROFS_INODE_CHUNK_BASED {
                bail!("merge currently only supports chunk-based regular files")
            }
            let chunkbits = reader.sb().blkszbits as u32 + (inode.chunk_format() as u32 & 0x1F);
            let chunk_indexes = reader
                .read_chunk_indexes(nid, &inode)?
                .into_iter()
                .map(|index| {
                    if index.device_id == 0 {
                        Ok(index)
                    } else {
                        let mapped =
                            blob_indexes.get(&index.device_id).copied().ok_or_else(|| {
                                anyhow!(
                                    "missing global blob index mapping for source blob {}",
                                    index.device_id
                                )
                            })?;
                        Ok(ChunkIndex {
                            blkaddr: index.blkaddr,
                            device_id: mapped,
                        })
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            MergeNodeData::RegularFile {
                chunk_indexes,
                chunkbits,
            }
        }
        EROFS_FT_SYMLINK => MergeNodeData::Symlink {
            target: reader.read_symlink(nid, &inode)?,
        },
        EROFS_FT_CHRDEV | EROFS_FT_BLKDEV => MergeNodeData::SpecialDev { rdev: inode.rdev() },
        EROFS_FT_FIFO | EROFS_FT_SOCK => MergeNodeData::SpecialNoData,
        other => bail!("unsupported inode file type {other} while loading layer"),
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
        mtime_nsec: inode.effective_mtime_nsec(reader.sb().fixed_nsec()),
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
    lower_children: BTreeMap<String, MergeNode>,
    upper_meta: MergeNode,
    upper_children: BTreeMap<String, MergeNode>,
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

fn is_opaque_marker(name: &str, whiteout_spec: WhiteoutSpec) -> bool {
    match whiteout_spec {
        WhiteoutSpec::Oci => name == OCI_OPAQUE_MARKER,
    }
}

fn whiteout_target(name: &str, whiteout_spec: WhiteoutSpec) -> Option<&str> {
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

fn flatten_node(
    node: &MergeNode,
    inodes: &mut Vec<InodeInfo>,
    ino_counter: &mut u32,
    hardlink_indexes: &mut HashMap<MergeLinkId, usize>,
) -> usize {
    if let Some(link_id) = node.link_id {
        if let Some(inode_index) = hardlink_indexes.get(&link_id) {
            return *inode_index;
        }
    }

    *ino_counter += 1;
    let ino = *ino_counter;
    let inode_index = inodes.len();

    match &node.data {
        MergeNodeData::Directory { children } => {
            inodes.push(InodeInfo {
                mode: node.mode,
                uid: node.uid,
                gid: node.gid,
                size: 0,
                mtime: node.mtime,
                mtime_nsec: node.mtime_nsec,
                nlink: 0,
                ino,
                nid: 0,
                meta_offset: 0,
                is_extended: needs_extended(0, node.uid, node.gid, 0),
                data: InodeData::Directory {
                    children: Vec::new(),
                    startblk: 0,
                    data_size: 0,
                    parent_nid: 0,
                },
                xattrs: node.xattrs.clone(),
            });

            let mut child_entries = Vec::new();
            let mut subdir_count = 0u32;
            for (name, child) in children {
                let child_index = flatten_node(child, inodes, ino_counter, hardlink_indexes);
                let file_type = mode_to_erofs_file_type(child.mode);
                if file_type == EROFS_FT_DIR {
                    subdir_count += 1;
                }
                child_entries.push(DirEntry {
                    name: name.clone(),
                    file_type,
                    inode_index: child_index,
                });
            }

            let nlink = 2 + subdir_count;
            let is_extended = needs_extended(0, node.uid, node.gid, nlink);
            inodes[inode_index].nlink = nlink;
            inodes[inode_index].is_extended = is_extended;
            if let InodeData::Directory {
                children: ref mut dir_children,
                ..
            } = inodes[inode_index].data
            {
                *dir_children = child_entries;
            }
        }
        MergeNodeData::RegularFile {
            chunk_indexes,
            chunkbits,
        } => {
            let nlink = node.nlink.max(1);
            inodes.push(InodeInfo {
                mode: node.mode,
                uid: node.uid,
                gid: node.gid,
                size: node.size,
                mtime: node.mtime,
                mtime_nsec: node.mtime_nsec,
                nlink,
                ino,
                nid: 0,
                meta_offset: 0,
                is_extended: needs_extended(node.size, node.uid, node.gid, nlink),
                data: InodeData::RegularFile {
                    chunk_indexes: chunk_indexes.clone(),
                    chunk_size_bits: *chunkbits,
                },
                xattrs: node.xattrs.clone(),
            });
            if let Some(link_id) = node.link_id {
                hardlink_indexes.insert(link_id, inode_index);
            }
        }
        MergeNodeData::Symlink { target } => {
            let size = target.len() as u64;
            let nlink = node.nlink.max(1);
            inodes.push(InodeInfo {
                mode: node.mode,
                uid: node.uid,
                gid: node.gid,
                size,
                mtime: node.mtime,
                mtime_nsec: node.mtime_nsec,
                nlink,
                ino,
                nid: 0,
                meta_offset: 0,
                is_extended: needs_extended(size, node.uid, node.gid, nlink),
                data: InodeData::Symlink {
                    target: target.clone(),
                },
                xattrs: node.xattrs.clone(),
            });
        }
        MergeNodeData::SpecialDev { rdev } => {
            let nlink = node.nlink.max(1);
            inodes.push(InodeInfo {
                mode: node.mode,
                uid: node.uid,
                gid: node.gid,
                size: 0,
                mtime: node.mtime,
                mtime_nsec: node.mtime_nsec,
                nlink,
                ino,
                nid: 0,
                meta_offset: 0,
                is_extended: needs_extended(0, node.uid, node.gid, nlink),
                data: InodeData::Device { rdev: *rdev },
                xattrs: node.xattrs.clone(),
            });
        }
        MergeNodeData::SpecialNoData => {
            let nlink = node.nlink.max(1);
            inodes.push(InodeInfo {
                mode: node.mode,
                uid: node.uid,
                gid: node.gid,
                size: 0,
                mtime: node.mtime,
                mtime_nsec: node.mtime_nsec,
                nlink,
                ino,
                nid: 0,
                meta_offset: 0,
                is_extended: needs_extended(0, node.uid, node.gid, nlink),
                data: InodeData::FifoOrSocket,
                xattrs: node.xattrs.clone(),
            });
        }
    }

    inode_index
}

fn needs_extended(size: u64, uid: u32, gid: u32, nlink: u32) -> bool {
    size > u32::MAX as u64 || uid > u16::MAX as u32 || gid > u16::MAX as u32 || nlink > 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(entries: Vec<(&str, MergeNode)>) -> MergeNode {
        let children = entries
            .into_iter()
            .map(|(name, node)| (name.to_string(), node))
            .collect();
        merge_node(MergeNodeData::Directory { children })
    }

    fn regular_file() -> MergeNode {
        merge_node(MergeNodeData::RegularFile {
            chunk_indexes: Vec::new(),
            chunkbits: EROFS_BLKSZBITS as u32,
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
        children.keys().cloned().collect()
    }

    #[test]
    fn strip_whiteout_entries_removes_opaque_marker_from_inserted_directory() {
        let mut root = directory(vec![(
            "opt",
            directory(vec![(
                "yarn-v1.22.19",
                directory(vec![(OCI_OPAQUE_MARKER, regular_file())]),
            )]),
        )]);

        strip_whiteout_entries(&mut root, WhiteoutSpec::Oci);

        let MergeNodeData::Directory { children } = &root.data else {
            panic!("root should be a directory")
        };
        let opt = children.get("opt").unwrap();
        let MergeNodeData::Directory { children } = &opt.data else {
            panic!("opt should be a directory")
        };
        let yarn = children.get("yarn-v1.22.19").unwrap();
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
            directory(vec![
                (OCI_OPAQUE_MARKER, regular_file()),
                ("new.txt", regular_file()),
            ]),
        )]);

        let mut merged = overlay_nodes(lower, upper, WhiteoutSpec::Oci).unwrap();
        strip_whiteout_entries(&mut merged, WhiteoutSpec::Oci);

        let MergeNodeData::Directory { children } = &merged.data else {
            panic!("root should be a directory")
        };
        assert_eq!(child_names(children.get("opq").unwrap()), vec!["new.txt"]);
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
        assert_eq!(child_names(children.get("newdir").unwrap()), vec!["fresh"]);
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
}
