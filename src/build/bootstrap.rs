use anyhow::{bail, Result};

use crate::build::dir::{serialize_directory, DirChild};
use crate::build::image::{device_table_meta_blkaddr, write_image};
use crate::build::inode::{inode_meta_size, serialize_inode, InodeData, InodeInfo};
use crate::metadata::layout::MetadataLayout;
use crate::metadata::*;

pub fn render_bootstrap(
    inodes: &mut [InodeInfo],
    epoch: u64,
    chunkbits: u32,
    device_slots: &[ErofsDeviceSlot],
    uuid: &[u8; 16],
) -> Result<Vec<u8>> {
    if inodes.is_empty() {
        bail!("cannot render bootstrap for empty inode set");
    }

    let mut layout = MetadataLayout::new();
    // The device table is laid out right after the superblock and may push the
    // metadata region past block 0 when there are many external blobs, so the
    // layout must use the same metadata block address as the image writer for
    // directory data block addresses to be correct.
    layout.meta_blkaddr = device_table_meta_blkaddr(device_slots.len())?;
    let blkszbits = EROFS_BLKSZBITS as u32;

    for inode in inodes.iter_mut() {
        let meta_size = inode_meta_size(inode, chunkbits, blkszbits);
        let (offset, nid) = layout.alloc_inode(meta_size);
        inode.meta_offset = offset;
        inode.nid = nid;
    }

    set_parent_nids(inodes);
    layout.pad_to_block();

    let dir_infos: Vec<(usize, Vec<DirChild>, u64, u64)> = inodes
        .iter()
        .enumerate()
        .filter_map(|(idx, inode)| {
            if let InodeData::Directory {
                ref children,
                parent_nid,
                ..
            } = inode.data
            {
                let self_nid = inode.nid;
                let dir_children: Vec<DirChild> = children
                    .iter()
                    .map(|de| DirChild {
                        name: de.name.clone(),
                        nid: inodes[de.inode_idx].nid,
                        file_type: de.file_type,
                    })
                    .collect();
                Some((idx, dir_children, self_nid, parent_nid))
            } else {
                None
            }
        })
        .collect();

    for (idx, dir_children, self_nid, parent_nid) in dir_infos {
        let dir_data = serialize_directory(&dir_children, self_nid, parent_nid);
        let dir_data_len = dir_data.len();
        let (data_offset, startblk) = layout.alloc_dir_data(dir_data_len);
        layout.write_at(data_offset, &dir_data);

        if let InodeData::Directory {
            startblk: ref mut sb,
            data_size: ref mut dds,
            ..
        } = inodes[idx].data
        {
            *sb = startblk;
            *dds = dir_data_len;
        }
        inodes[idx].size = dir_data_len as u64;
    }

    for inode in inodes.iter() {
        let inode_bytes = serialize_inode(inode, epoch);
        let offset = inode.meta_offset;
        layout.write_at(offset, &inode_bytes);
    }

    let root_nid = inodes[0].nid;
    if root_nid > u16::MAX as u64 {
        bail!("root NID exceeds 16-bit range");
    }

    let mut bootstrap = Vec::new();
    write_image(
        &mut bootstrap,
        &layout.buf,
        root_nid as u16,
        inodes.len() as u64,
        epoch,
        device_slots,
        uuid,
    )?;

    Ok(bootstrap)
}

pub fn set_parent_nids(inodes: &mut [InodeInfo]) {
    let root_nid = inodes[0].nid;
    if let InodeData::Directory {
        ref mut parent_nid, ..
    } = inodes[0].data
    {
        *parent_nid = root_nid;
    }

    let dir_infos: Vec<(u64, Vec<usize>)> = inodes
        .iter()
        .filter_map(|inode| {
            if let InodeData::Directory { ref children, .. } = inode.data {
                let child_dir_idxs: Vec<usize> = children
                    .iter()
                    .filter(|de| de.file_type == EROFS_FT_DIR)
                    .map(|de| de.inode_idx)
                    .collect();
                if child_dir_idxs.is_empty() {
                    None
                } else {
                    Some((inode.nid, child_dir_idxs))
                }
            } else {
                None
            }
        })
        .collect();

    for (parent_nid_val, child_idxs) in dir_infos {
        for child_idx in child_idxs {
            if let InodeData::Directory {
                ref mut parent_nid, ..
            } = inodes[child_idx].data
            {
                *parent_nid = parent_nid_val;
            }
        }
    }
}
