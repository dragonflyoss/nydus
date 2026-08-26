use super::layout::MetadataLayout;
use crate::build::dir::{serialize_directory, DirChild};
use crate::build::image::{
    device_table_meta_blkaddr, fill_image_head, write_erofs_superblock_checksum,
};
use crate::build::inode::{
    erofs_inode_size, serialize_inode, symlink_is_inline, InodeData, InodeInfo,
};
use nydus_error::{Context, Error, Result};
use nydus_format::erofs::{
    ErofsDeviceSlot, EROFS_BLOCK_SIZE, EROFS_DEVICESLOT_SIZE, EROFS_FT_DIR, EROFS_SB_BASE_SIZE,
    EROFS_SUPER_OFFSET, EROFS_XATTR_INDEX_TRUSTED,
};
use nydus_format::utils::align_up_usize;
use std::io::Write;

pub const FLATTENED_BLOB_ALIGNMENT: u64 = 0x8_0000;

pub fn render_bootstrap(
    inodes: &mut [InodeInfo],
    epoch: u64,
    device_slots: &[ErofsDeviceSlot],
    uuid: &[u8; 16],
) -> Result<Vec<u8>> {
    let bootstrap = render_bootstrap_inner(inodes, epoch, device_slots, uuid)?;
    debug_assert_eq!(bootstrap.len() % EROFS_BLOCK_SIZE as usize, 0);
    Ok(bootstrap)
}

pub fn render_flattened_bootstrap(
    inodes: &mut [InodeInfo],
    epoch: u64,
    device_slots: &[ErofsDeviceSlot],
    uuid: &[u8; 16],
) -> Result<Vec<u8>> {
    let mut bootstrap = Vec::new();
    render_flattened_bootstrap_to(&mut bootstrap, inodes, epoch, device_slots, uuid)?;
    Ok(bootstrap)
}

/// Stream-render a flattened bootstrap into `writer`: a sizing pass assigns
/// every offset without materialising a buffer, then the head, the inode
/// region and the directory/symlink data are written strictly in offset
/// order. Peak memory is O(1) in the bootstrap size (directory data is
/// serialized twice: once for its size, once for the write). Returns the
/// bootstrap size in bytes.
pub fn render_flattened_bootstrap_to(
    writer: &mut impl Write,
    inodes: &mut [InodeInfo],
    epoch: u64,
    device_slots: &[ErofsDeviceSlot],
    uuid: &[u8; 16],
) -> Result<u64> {
    if inodes.is_empty() {
        return Err(Error::InvalidParameter(
            "cannot render bootstrap for empty inode set".to_string(),
        ));
    }

    let meta_blkaddr = device_table_meta_blkaddr(device_slots.len())?;
    let head_size = meta_blkaddr as usize * EROFS_BLOCK_SIZE as usize;
    let mut layout = MetadataLayout::size_only(meta_blkaddr);

    // --- Sizing pass: identical allocation order to the buffered renderer ---
    for inode in inodes.iter_mut() {
        if !symlink_is_inline(inode) && matches!(inode.data, InodeData::Symlink { .. }) {
            inode.is_extended = true;
        }
        if inode.mtime.wrapping_sub(epoch) > u32::MAX as u64 {
            inode.is_extended = true;
        }
        let inode_size = erofs_inode_size(inode);
        let has_inline = symlink_is_inline(inode);
        let (offset, nid) = layout.alloc_inode(inode_size, has_inline);
        inode.meta_offset = offset;
        inode.nid = nid;
    }

    set_parent_nids(inodes);
    layout.pad_to_block();

    // Data-region entries in allocation (= write) order: directory data and
    // long symlink targets, identified by inode index.
    let mut data_entries: Vec<(usize, usize)> = Vec::new(); // (inode index, offset)
    for index in 0..inodes.len() {
        match inodes[index].data {
            InodeData::Directory { .. } => {
                let dir_data = serialize_dir_of(inodes, index);
                let (data_offset, startblk) = layout.alloc_dir_data(dir_data.len());
                let dir_data_len = dir_data.len();
                if let InodeData::Directory {
                    startblk: ref mut sb,
                    data_size: ref mut dds,
                    ..
                } = inodes[index].data
                {
                    *sb = startblk;
                    *dds = dir_data_len;
                }
                inodes[index].size = dir_data_len as u64;
                data_entries.push((index, data_offset));
            }
            InodeData::Symlink { .. } if !symlink_is_inline(&inodes[index]) => {
                let target_len = match &inodes[index].data {
                    InodeData::Symlink { target, .. } => target.len(),
                    _ => unreachable!(),
                };
                let (data_offset, startblk) = layout.alloc_dir_data(target_len);
                if let InodeData::Symlink {
                    startblk: ref mut sb,
                    ..
                } = inodes[index].data
                {
                    *sb = startblk;
                }
                data_entries.push((index, data_offset));
            }
            _ => {}
        }
    }

    let metadata_len = layout.pad_to_block();
    let bootstrap_size = (head_size + metadata_len) as u64;

    // The head can be written up front: the flattened device addresses only
    // need the total size, and the superblock checksum covers block 0 alone.
    let mut flattened_slots = device_slots.to_vec();
    set_flattened_mapped_blkaddrs(
        &mut flattened_slots,
        bootstrap_size,
        FLATTENED_BLOB_ALIGNMENT,
    )?;

    let root_nid = inodes[0].nid;
    if root_nid > u16::MAX as u64 {
        return Err(Error::Overflow("root nid exceeds 16-bit range".to_string()));
    }
    let has_xattrs = inodes.iter().any(|inode| {
        inode.xattrs.iter().any(|entry| {
            !(entry.name_index == EROFS_XATTR_INDEX_TRUSTED && entry.suffix.starts_with(b"nydus."))
        })
    });
    let mut head = vec![0u8; head_size];
    fill_image_head(
        &mut head,
        metadata_len,
        root_nid as u16,
        inodes.len() as u64,
        epoch,
        &flattened_slots,
        uuid,
        has_xattrs,
    )?;
    writer
        .write_all(&head)
        .context("failed to write bootstrap head")?;

    // --- Write pass: inode region, then data region, in offset order ---
    let mut cursor = 0usize;
    for inode in inodes.iter() {
        debug_assert!(inode.meta_offset >= cursor);
        write_zeros(writer, inode.meta_offset - cursor)?;
        let bytes = serialize_inode(inode, epoch);
        writer
            .write_all(&bytes)
            .context("failed to write bootstrap inode")?;
        cursor = inode.meta_offset + bytes.len();
    }

    for (index, data_offset) in data_entries {
        debug_assert!(data_offset >= cursor);
        write_zeros(writer, data_offset - cursor)?;
        match &inodes[index].data {
            InodeData::Directory { .. } => {
                let dir_data = serialize_dir_of(inodes, index);
                writer
                    .write_all(&dir_data)
                    .context("failed to write bootstrap directory data")?;
                cursor = data_offset + dir_data.len();
            }
            InodeData::Symlink { target, .. } => {
                writer
                    .write_all(target)
                    .context("failed to write bootstrap symlink target")?;
                cursor = data_offset + target.len();
            }
            _ => unreachable!("data_entries only holds directories and long symlinks"),
        }
    }

    debug_assert!(metadata_len >= cursor);
    write_zeros(writer, metadata_len - cursor)?;
    Ok(bootstrap_size)
}

/// Serialize the directory data of `inodes[index]` from its child refs;
/// children resolve their nids through the shared inode table.
fn serialize_dir_of(inodes: &[InodeInfo], index: usize) -> Vec<u8> {
    let InodeData::Directory {
        ref children,
        parent_nid,
        ..
    } = inodes[index].data
    else {
        unreachable!("serialize_dir_of is only called for directories");
    };
    let dir_children: Vec<DirChild> = children
        .iter()
        .map(|de| DirChild {
            name: de.name.clone(),
            nid: inodes[de.inode_index].nid,
            file_type: de.file_type,
        })
        .collect();
    serialize_directory(&dir_children, inodes[index].nid, parent_nid)
}

fn write_zeros(writer: &mut impl Write, mut n: usize) -> Result<()> {
    const ZEROS: [u8; 4096] = [0u8; 4096];
    while n > 0 {
        let take = n.min(ZEROS.len());
        writer
            .write_all(&ZEROS[..take])
            .context("failed to write bootstrap padding")?;
        n -= take;
    }
    Ok(())
}

/// Rewrite a rendered bootstrap's device table with flattened mapped block
/// addresses for the given slots and refresh the superblock checksum. The
/// metadata region is device-slot independent, so a bootstrap rendered for
/// one slot set can be retargeted in place instead of re-rendered.
pub(crate) fn flatten_bootstrap_in_place(
    bootstrap: &mut [u8],
    device_slots: &[ErofsDeviceSlot],
) -> Result<()> {
    let mut device_slots = device_slots.to_vec();
    set_flattened_mapped_blkaddrs(
        &mut device_slots,
        bootstrap.len() as u64,
        FLATTENED_BLOB_ALIGNMENT,
    )?;
    patch_device_slots(bootstrap, &device_slots)?;
    debug_assert_eq!(bootstrap.len() % EROFS_BLOCK_SIZE as usize, 0);
    Ok(())
}

fn set_flattened_mapped_blkaddrs(
    device_slots: &mut [ErofsDeviceSlot],
    bootstrap_size: u64,
    alignment: u64,
) -> Result<()> {
    let block_size = EROFS_BLOCK_SIZE as u64;
    let mut next_offset = bootstrap_size;
    for slot in device_slots {
        let next_offset_usize = usize::try_from(next_offset).map_err(|err| {
            Error::Overflow(format!(
                "flattened blob offset exceeds addressable size: {err}"
            ))
        })?;
        let alignment_usize = usize::try_from(alignment).map_err(|err| {
            Error::Overflow(format!(
                "flattened blob alignment exceeds addressable size: {err}"
            ))
        })?;
        let mapped_offset = align_up_usize(next_offset_usize, alignment_usize)
            .expect("alignment overflowed") as u64;
        if mapped_offset % block_size != 0 {
            return Err(Error::InvalidImage(
                "flattened blob offset must be block aligned".to_string(),
            ));
        }
        slot.set_mapped_blkaddr(mapped_offset / block_size);
        next_offset = mapped_offset
            .checked_add(
                slot.blocks()
                    .checked_mul(block_size)
                    .ok_or_else(|| Error::Overflow("flattened blob size overflow".to_string()))?,
            )
            .ok_or_else(|| Error::Overflow("flattened blob offset overflow".to_string()))?;
    }
    Ok(())
}

fn patch_device_slots(bootstrap: &mut [u8], device_slots: &[ErofsDeviceSlot]) -> Result<()> {
    let devslot_offset = EROFS_SUPER_OFFSET as usize + EROFS_SB_BASE_SIZE;
    let device_table_size = device_slots
        .len()
        .checked_mul(EROFS_DEVICESLOT_SIZE)
        .ok_or_else(|| Error::Overflow("device table size overflow".to_string()))?;
    let device_table_end = devslot_offset
        .checked_add(device_table_size)
        .ok_or_else(|| Error::Overflow("device table offset overflow".to_string()))?;
    if device_table_end > bootstrap.len() {
        return Err(Error::InvalidImage(
            "device table out of bounds".to_string(),
        ));
    }

    for (index, devslot) in device_slots.iter().enumerate() {
        let start = devslot_offset + index * EROFS_DEVICESLOT_SIZE;
        let end = start + EROFS_DEVICESLOT_SIZE;
        bootstrap[start..end].copy_from_slice(devslot.as_bytes());
    }
    write_erofs_superblock_checksum(bootstrap)
}

fn render_bootstrap_inner(
    inodes: &mut [InodeInfo],
    epoch: u64,
    device_slots: &[ErofsDeviceSlot],
    uuid: &[u8; 16],
) -> Result<Vec<u8>> {
    if inodes.is_empty() {
        return Err(Error::InvalidParameter(
            "cannot render bootstrap for empty inode set".to_string(),
        ));
    }

    // The device table is laid out right after the superblock and may push the
    // metadata region past block 0 when there are many external blobs, so the
    // layout must use the same metadata block address as the image writer for
    // directory data block addresses to be correct.
    let mut layout =
        MetadataLayout::with_meta_blkaddr(device_table_meta_blkaddr(device_slots.len())?);

    for inode in inodes.iter_mut() {
        if !symlink_is_inline(inode) && matches!(inode.data, InodeData::Symlink { .. }) {
            inode.is_extended = true;
        }
        // A compact inode stores mtime as a 32-bit delta from the epoch, so a
        // timestamp further out than that has to move to the extended layout
        // rather than wrap.
        if inode.mtime.wrapping_sub(epoch) > u32::MAX as u64 {
            inode.is_extended = true;
        }
        let inode_size = erofs_inode_size(inode);
        let has_inline = symlink_is_inline(inode);
        let (offset, nid) = layout.alloc_inode(inode_size, has_inline);
        inode.meta_offset = offset;
        inode.nid = nid;
    }

    set_parent_nids(inodes);
    layout.pad_to_block();
    // The directory-data region that follows is in the same order of
    // magnitude as the inode region; one generous reservation avoids every
    // doubling realloc (each one transiently duplicates the buffer in RSS).
    layout.reserve(layout.buf().len() * 2);

    let dir_indexes: Vec<usize> = inodes
        .iter()
        .enumerate()
        .filter_map(|(index, inode)| {
            matches!(inode.data, InodeData::Directory { .. }).then_some(index)
        })
        .collect();

    // Directories are processed one at a time: cloning every directory's
    // child names up front would keep a second copy of all file names
    // resident at once.
    for index in dir_indexes {
        let InodeData::Directory {
            ref children,
            parent_nid,
            ..
        } = inodes[index].data
        else {
            unreachable!("dir_indexes only collects directory inodes");
        };
        let self_nid = inodes[index].nid;
        let dir_children: Vec<DirChild> = children
            .iter()
            .map(|de| DirChild {
                name: de.name.clone(),
                nid: inodes[de.inode_index].nid,
                file_type: de.file_type,
            })
            .collect();
        let dir_data = serialize_directory(&dir_children, self_nid, parent_nid);
        drop(dir_children);
        let dir_data_len = dir_data.len();
        let (data_offset, startblk) = layout.alloc_dir_data(dir_data_len);
        layout.write_at(data_offset, &dir_data);

        if let InodeData::Directory {
            startblk: ref mut sb,
            data_size: ref mut dds,
            ..
        } = inodes[index].data
        {
            *sb = startblk;
            *dds = dir_data_len;
        }
        inodes[index].size = dir_data_len as u64;
    }

    // Symlinks whose target is too long to ride behind the inode header get a
    // data block of their own, in the same region as directory data.
    let long_symlinks: Vec<usize> = inodes
        .iter()
        .enumerate()
        .filter_map(|(index, inode)| match inode.data {
            InodeData::Symlink { .. } if !symlink_is_inline(inode) => Some(index),
            _ => None,
        })
        .collect();

    for index in long_symlinks {
        let target = match &inodes[index].data {
            InodeData::Symlink { target, .. } => target.clone(),
            _ => unreachable!("long_symlinks only collects symlink inodes"),
        };
        let (data_offset, startblk) = layout.alloc_dir_data(target.len());
        layout.write_at(data_offset, &target);
        if let InodeData::Symlink {
            startblk: ref mut sb,
            ..
        } = inodes[index].data
        {
            *sb = startblk;
        }
    }

    for inode in inodes.iter() {
        let inode_bytes = serialize_inode(inode, epoch);
        let offset = inode.meta_offset;
        layout.write_at(offset, &inode_bytes);
    }

    let root_nid = inodes[0].nid;
    if root_nid > u16::MAX as u64 {
        return Err(Error::Overflow("root nid exceeds 16-bit range".to_string()));
    }

    // Nydus-internal xattrs (trusted.nydus.*) are hidden from readers, so
    // only user-visible xattrs disqualify the image-wide no-xattr shortcut.
    let has_xattrs = inodes.iter().any(|inode| {
        inode.xattrs.iter().any(|entry| {
            !(entry.name_index == EROFS_XATTR_INDEX_TRUSTED && entry.suffix.starts_with(b"nydus."))
        })
    });
    // The layout buffer already holds the head region followed by the padded
    // metadata area; fill the head in place so the buffer IS the bootstrap
    // and the tens-of-MiB metadata copy of the old write_image path is gone.
    let head_size =
        device_table_meta_blkaddr(device_slots.len())? as usize * EROFS_BLOCK_SIZE as usize;
    let mut bootstrap = layout.into_image_buf();
    let metadata_len = bootstrap.len() - head_size;
    fill_image_head(
        &mut bootstrap,
        metadata_len,
        root_nid as u16,
        inodes.len() as u64,
        epoch,
        device_slots,
        uuid,
        has_xattrs,
    )?;

    Ok(bootstrap)
}

pub(crate) fn set_parent_nids(inodes: &mut [InodeInfo]) {
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
                let child_dir_indexes: Vec<usize> = children
                    .iter()
                    .filter(|de| de.file_type == EROFS_FT_DIR)
                    .map(|de| de.inode_index)
                    .collect();
                if child_dir_indexes.is_empty() {
                    None
                } else {
                    Some((inode.nid, child_dir_indexes))
                }
            } else {
                None
            }
        })
        .collect();

    for (parent_nid_val, child_indexes) in dir_infos {
        for child_index in child_indexes {
            if let InodeData::Directory {
                ref mut parent_nid, ..
            } = inodes[child_index].data
            {
                *parent_nid = parent_nid_val;
            }
        }
    }
}
