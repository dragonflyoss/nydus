use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context, Result};

use crate::build::blobchunk::ChunkIndex;
use crate::build::bootstrap::render_bootstrap;
use crate::build::inode::{mode_to_file_type, DirEntry, InodeData, InodeInfo};
use crate::fs::ErofsReader;
use crate::metadata::*;
use crate::utils::{hex_string, parse_sha256_hex, sha256_file};

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
    let mut device_ids = HashMap::new();

    for (layer_id, source) in sources.iter().enumerate() {
        let _source_blob_sha256 = validate_source_blob_path(source)
            .with_context(|| format!("invalid merge source: {}", source.display()))?;
        let layer = load_layer(layer_id as u32, source, &mut device_slots, &mut device_ids)
            .with_context(|| format!("failed to load layer: {}", source.display()))?;
        merged_root = Some(match merged_root {
            Some(existing) => overlay_nodes(existing, layer, whiteout_spec)?,
            None => layer,
        });
    }

    let mut inodes = Vec::new();
    let mut ino_counter = 0u32;
    let mut hardlink_indexes = HashMap::new();
    flatten_node(
        merged_root
            .as_ref()
            .ok_or_else(|| anyhow!("merge produced no root node"))?,
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

    render_bootstrap(
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
    device_slots: &mut Vec<ErofsDeviceSlot>,
    device_ids: &mut HashMap<[u8; EROFS_BLOB_ID_SIZE], u16>,
) -> Result<MergeNode> {
    let reader = ErofsReader::open_layer(source)?;
    validate_single_layer_blob_source(source, &reader)?;
    let layer_epoch = reader.sb().epoch();
    let local_to_global = register_devices(&reader, device_slots, device_ids)?;
    load_node(
        &reader,
        layer_id,
        reader.sb().root_nid(),
        layer_epoch,
        &local_to_global,
    )
}

fn register_devices(
    reader: &ErofsReader,
    device_slots: &mut Vec<ErofsDeviceSlot>,
    device_ids: &mut HashMap<[u8; EROFS_BLOB_ID_SIZE], u16>,
) -> Result<HashMap<u16, u16>> {
    let mut local_to_global = HashMap::new();
    let infos = reader.device_infos()?;
    let info = infos
        .first()
        .ok_or_else(|| anyhow!("merge source does not contain an external blob device"))?;
    let global_device_id = if let Some(existing) = device_ids.get(&info.blob_id) {
        *existing
    } else {
        let next = device_slots.len() as u16 + 1;
        device_slots.push(ErofsDeviceSlot::with_blob_id(info.blocks, &info.blob_id));
        device_ids.insert(info.blob_id, next);
        next
    };
    local_to_global.insert(info.device_id, global_device_id);

    if infos.len() > 1 {
        bail!("merge source currently supports exactly one external blob device")
    }
    Ok(local_to_global)
}

fn validate_source_blob_path(path: &Path) -> Result<[u8; EROFS_BLOB_ID_SIZE]> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("merge source file name must be valid UTF-8 sha256 hex"))?;
    let expected = parse_sha256_hex(file_name)
        .context("merge source file name must be a sha256 hex string")?;
    let actual = sha256_file(path)?;
    if actual != expected {
        bail!(
            "merge source file name sha256 does not match file content: expected {}, got {}",
            hex_string(&expected),
            hex_string(&actual)
        );
    }
    Ok(expected)
}

fn validate_single_layer_blob_source(path: &Path, reader: &ErofsReader) -> Result<()> {
    let file_size = fs::metadata(path)
        .with_context(|| format!("failed to stat merge source: {}", path.display()))?
        .len();
    let primary_image_size = reader.sb().blocks() * EROFS_BLOCK_SIZE as u64;
    let device_infos = reader.device_infos()?;
    if device_infos.len() != 1 {
        bail!("merge source must contain exactly one external blob device");
    }
    if device_infos[0].blocks > 0 && file_size == primary_image_size {
        bail!("merge source must be a full blob file, not a metadata-only bootstrap");
    }
    Ok(())
}

fn load_node(
    reader: &ErofsReader,
    layer_id: u32,
    nid: u64,
    epoch: u64,
    device_ids: &HashMap<u16, u16>,
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

    let data = match mode_to_file_type(mode) {
        EROFS_FT_DIR => {
            let mut children = BTreeMap::new();
            for entry in reader.read_dir(nid, &inode)? {
                if entry.name == "." || entry.name == ".." {
                    continue;
                }
                children.insert(
                    entry.name.clone(),
                    load_node(reader, layer_id, entry.nid, epoch, device_ids)
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
                            device_ids.get(&index.device_id).copied().ok_or_else(|| {
                                anyhow!(
                                    "missing global device mapping for source device {}",
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
        link_id: if mode_to_file_type(mode) == EROFS_FT_REG_FILE && inode.nlink() > 1 {
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

    for (name, child) in upper_children {
        if is_opaque_marker(&name, whiteout_spec) {
            continue;
        }
        if let Some(target) = whiteout_target(&name, whiteout_spec) {
            merged_children.remove(target);
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

fn flatten_node(
    node: &MergeNode,
    inodes: &mut Vec<InodeInfo>,
    ino_counter: &mut u32,
    hardlink_indexes: &mut HashMap<MergeLinkId, usize>,
) -> usize {
    if let Some(link_id) = node.link_id {
        if let Some(inode_idx) = hardlink_indexes.get(&link_id) {
            return *inode_idx;
        }
    }

    *ino_counter += 1;
    let ino = *ino_counter;
    let inode_idx = inodes.len();

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
                    dir_data_size: 0,
                    parent_nid: 0,
                },
                xattrs: node.xattrs.clone(),
            });

            let mut child_entries = Vec::new();
            let mut subdir_count = 0u32;
            for (name, child) in children {
                let child_idx = flatten_node(child, inodes, ino_counter, hardlink_indexes);
                let file_type = mode_to_file_type(child.mode);
                if file_type == EROFS_FT_DIR {
                    subdir_count += 1;
                }
                child_entries.push(DirEntry {
                    name: name.clone(),
                    file_type,
                    inode_idx: child_idx,
                });
            }

            let nlink = 2 + subdir_count;
            let is_extended = needs_extended(0, node.uid, node.gid, nlink);
            inodes[inode_idx].nlink = nlink;
            inodes[inode_idx].is_extended = is_extended;
            if let InodeData::Directory {
                children: ref mut dir_children,
                ..
            } = inodes[inode_idx].data
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
                    chunkbits: *chunkbits,
                },
                xattrs: node.xattrs.clone(),
            });
            if let Some(link_id) = node.link_id {
                hardlink_indexes.insert(link_id, inode_idx);
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
                data: InodeData::SpecialDev { rdev: *rdev },
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
                data: InodeData::SpecialNoData,
                xattrs: node.xattrs.clone(),
            });
        }
    }

    inode_idx
}

fn needs_extended(size: u64, uid: u32, gid: u32, nlink: u32) -> bool {
    size > u32::MAX as u64 || uid > u16::MAX as u32 || gid > u16::MAX as u32 || nlink > 1
}
