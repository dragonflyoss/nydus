use super::layout::MetadataLayout;
use crate::build::dir::{serialize_directory, DirChild};
use crate::build::image::{
    device_table_meta_blkaddr, fill_image_head, head_layout, write_erofs_superblock_checksum,
};
use crate::build::inode::{
    directory_inline_len, erofs_inode_size, has_inline_data, serialize_inode, symlink_is_inline,
    InodeData, InodeInfo,
};
use nydus_error::{Context, Error, Result};
use nydus_format::erofs::{
    cast_ref, ErofsDeviceSlot, ErofsSuperblock, EROFS_BLOCK_SIZE, EROFS_DEVICESLOT_SIZE,
    EROFS_FT_DIR, EROFS_SB_BASE_SIZE, EROFS_SUPER_OFFSET, Z_EROFS_FRAGMENT_INODE_FLAG,
    Z_EROFS_LCLUSTER_INDEX_SIZE, Z_EROFS_LCLUSTER_TYPE_NONHEAD, Z_EROFS_LI_LCLUSTER_TYPE_MASK,
    Z_EROFS_MAP_HEADER_SIZE,
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
    render_flattened_bootstrap_to_inner(writer, inodes, epoch, device_slots, uuid, 0, 0, None)
}

/// z_erofs multi-device variant: the compressed data lives in external
/// device files described by `device_slots`, whose `mapped_blkaddr`s the
/// caller has already placed past the bootstrap (see
/// [`fit_z_devices_past_bootstrap`]); the pcluster addresses in the inode
/// tails are absolute in that mapped space. The metadata region directly
/// follows the head, so the result is a plain bootstrap file to write at
/// offset 0.
pub fn render_z_device_bootstrap(
    inodes: &mut [InodeInfo],
    epoch: u64,
    uuid: &[u8; 16],
    z_max_pclusterblks: u16,
    device_slots: &[ErofsDeviceSlot],
    packed_index: Option<usize>,
) -> Result<Vec<u8>> {
    let min_total_blocks = device_slots
        .iter()
        .map(|slot| slot.mapped_blkaddr() + slot.blocks())
        .max()
        .unwrap_or(0);
    let mut bootstrap = Vec::new();
    render_flattened_bootstrap_to_inner(
        &mut bootstrap,
        inodes,
        epoch,
        device_slots,
        uuid,
        z_max_pclusterblks,
        min_total_blocks,
        packed_index,
    )?;
    Ok(bootstrap)
}

/// Places z device slots back to back in the mapped block space, each on a
/// [`FLATTENED_BLOB_ALIGNMENT`] boundary, the first one at `base` bytes
/// (itself aligned up). Directory and symlink data blocks are addressed like
/// file data, through the device table, so `base` must lie past the
/// bootstrap; see [`fit_z_devices_past_bootstrap`].
pub fn place_z_device_slots(device_slots: &mut [ErofsDeviceSlot], base: u64) -> Result<()> {
    set_flattened_mapped_blkaddrs(device_slots, base, FLATTENED_BLOB_ALIGNMENT)
}

/// Sizes the bootstrap of `inodes` and, when the first z device would start
/// inside it, moves every device and every pcluster address in the inode
/// tails up so the devices begin at the first alignment boundary past the
/// bootstrap. Returns the shift in blocks (0 when nothing moved).
pub fn fit_z_devices_past_bootstrap(
    inodes: &mut [InodeInfo],
    epoch: u64,
    device_slots: &mut [ErofsDeviceSlot],
) -> Result<u64> {
    let Some(first) = device_slots.first() else {
        return Ok(0);
    };
    let sizing = size_bootstrap(inodes, epoch, device_slots.len(), true)?;
    let bootstrap_size = (sizing.head_size + sizing.metadata_len) as u64;
    let needed =
        bootstrap_size.next_multiple_of(FLATTENED_BLOB_ALIGNMENT) / EROFS_BLOCK_SIZE as u64;
    let delta = needed.saturating_sub(first.mapped_blkaddr());
    if delta == 0 {
        return Ok(0);
    }
    let shift = ZRelocation {
        old_mapped_blkaddr: 0,
        new_mapped_blkaddr: delta,
        packed_base: 0,
    };
    for inode in inodes.iter_mut() {
        if let InodeData::ZFile { ref mut tail, .. } = inode.data {
            *tail = shift.relocate_tail(tail, inode.size)?;
        }
    }
    for slot in device_slots.iter_mut() {
        slot.set_mapped_blkaddr(slot.mapped_blkaddr() + delta)?;
    }
    Ok(delta)
}

/// How a z_erofs layer's data is relocated into another image: its device
/// moves from `old_mapped_blkaddr` to `new_mapped_blkaddr` (every pcluster
/// address shifts by the difference) and its packed inode becomes the slice
/// of the merged packed inode starting at `packed_base`.
pub struct ZRelocation {
    pub old_mapped_blkaddr: u64,
    pub new_mapped_blkaddr: u64,
    pub packed_base: u64,
}

impl ZRelocation {
    /// Rewrites a COMPRESSED_FULL inode tail (see
    /// `ErofsReader::read_z_inode_tail`): the fragment offset of a whole-file
    /// fragment, else the block address of every HEAD/PLAIN lcluster index.
    pub fn relocate_tail(&self, tail: &[u8], size: u64) -> Result<Vec<u8>> {
        let mut tail = tail.to_vec();
        if size > 0 && tail.len() == Z_EROFS_MAP_HEADER_SIZE {
            let head = u64::from_le_bytes(tail[..8].try_into().expect("8-byte header"));
            let offset = (head ^ Z_EROFS_FRAGMENT_INODE_FLAG) + self.packed_base;
            if offset & Z_EROFS_FRAGMENT_INODE_FLAG != 0 {
                return Err(Error::Overflow(
                    "merged fragment offset exceeds 63 bits".to_string(),
                ));
            }
            tail.copy_from_slice(&(offset | Z_EROFS_FRAGMENT_INODE_FLAG).to_le_bytes());
            return Ok(tail);
        }
        if tail.len() < Z_EROFS_MAP_HEADER_SIZE + 8 {
            return Ok(tail);
        }
        let indexes = &mut tail[Z_EROFS_MAP_HEADER_SIZE + 8..];
        for index in indexes.chunks_exact_mut(Z_EROFS_LCLUSTER_INDEX_SIZE) {
            let advise = u16::from_le_bytes([index[0], index[1]]);
            if advise & Z_EROFS_LI_LCLUSTER_TYPE_MASK == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                continue;
            }
            let blkaddr = u32::from_le_bytes(index[4..8].try_into().expect("4-byte blkaddr"));
            let relocated = (blkaddr as u64)
                .checked_sub(self.old_mapped_blkaddr)
                .ok_or_else(|| {
                    Error::InvalidImage(format!(
                        "pcluster address {blkaddr} precedes the layer device mapping {}",
                        self.old_mapped_blkaddr
                    ))
                })?
                + self.new_mapped_blkaddr;
            let relocated = u32::try_from(relocated)
                .map_err(|_| Error::Overflow("merged pcluster address exceeds u32".to_string()))?;
            index[4..8].copy_from_slice(&relocated.to_le_bytes());
        }
        Ok(tail)
    }
}

/// Result of the bootstrap sizing pass: every inode has its nid and
/// metadata offset assigned and directories/long symlinks their data blocks.
struct Sizing {
    /// Bytes of the head (superblock + device table), block padded.
    head_size: usize,
    /// Bytes of the metadata region (inodes + directory/symlink data), block
    /// padded.
    metadata_len: usize,
    /// Data-region entries in allocation (= write) order, as (inode index,
    /// byte offset in the metadata region).
    data_entries: Vec<(usize, usize)>,
}

/// Lays out the bootstrap without writing it: identical allocation order to
/// the write pass, so rendering afterwards reproduces the same offsets.
fn size_bootstrap(
    inodes: &mut [InodeInfo],
    epoch: u64,
    device_count: usize,
    z_lz4: bool,
) -> Result<Sizing> {
    if inodes.is_empty() {
        return Err(Error::InvalidParameter(
            "cannot render bootstrap for empty inode set".to_string(),
        ));
    }

    // The head (superblock + device table) occupies the leading blocks; the
    // metadata region follows it.
    let meta_blkaddr = head_layout(device_count, z_lz4)?.1;
    let head_size = meta_blkaddr as usize * EROFS_BLOCK_SIZE as usize;
    let mut layout = MetadataLayout::size_only(meta_blkaddr);

    // --- Sizing pass: identical allocation order to the buffered renderer ---
    alloc_inodes(&mut layout, inodes, epoch);
    set_parent_nids(inodes);
    layout.pad_to_block();

    // Data-region entries in allocation (= write) order, identified by inode
    // index: every directory's block-backed data, then every long symlink's
    // target.
    let mut data_entries: Vec<(usize, usize)> = Vec::new();
    for index in 0..inodes.len() {
        if !matches!(inodes[index].data, InodeData::Directory { .. }) {
            continue;
        }
        if let Some(data_offset) = place_dir_data(&mut layout, inodes, index) {
            data_entries.push((index, data_offset));
        }
    }
    for (index, inode) in inodes.iter_mut().enumerate() {
        if symlink_is_inline(inode) {
            continue;
        }
        let InodeData::Symlink { ref target, .. } = inode.data else {
            continue;
        };
        let (data_offset, data_startblk) = layout.alloc_dir_data(target.len());
        if let InodeData::Symlink {
            ref mut startblk, ..
        } = inode.data
        {
            *startblk = data_startblk;
        }
        data_entries.push((index, data_offset));
    }

    let metadata_len = layout.pad_to_block();
    Ok(Sizing {
        head_size,
        metadata_len,
        data_entries,
    })
}

#[allow(clippy::too_many_arguments)]
fn render_flattened_bootstrap_to_inner(
    writer: &mut impl Write,
    inodes: &mut [InodeInfo],
    epoch: u64,
    device_slots: &[ErofsDeviceSlot],
    uuid: &[u8; 16],
    z_max_pclusterblks: u16,
    min_total_blocks: u64,
    packed_index: Option<usize>,
) -> Result<u64> {
    let z_lz4 = z_max_pclusterblks != 0;
    let Sizing {
        head_size,
        metadata_len,
        data_entries,
    } = size_bootstrap(inodes, epoch, device_slots.len(), z_lz4)?;
    let bootstrap_size = (head_size + metadata_len) as u64;

    // The head can be written up front: the flattened device addresses only
    // need the total size, and the superblock checksum covers block 0 alone.
    // z device slots arrive pre-placed (their addresses are baked into the
    // inode tails), so they are written as given.
    let mut flattened_slots = device_slots.to_vec();
    if !z_lz4 {
        set_flattened_mapped_blkaddrs(
            &mut flattened_slots,
            bootstrap_size,
            FLATTENED_BLOB_ALIGNMENT,
        )?;
    }

    let root_nid = inodes[0].nid;
    if root_nid > u16::MAX as u64 {
        return Err(Error::Overflow("root nid exceeds 16-bit range".to_string()));
    }
    let packed_nid = packed_index.map(|index| inodes[index].nid);
    let mut head = vec![0u8; head_size];
    fill_image_head(
        &mut head,
        metadata_len,
        root_nid as u16,
        inodes.len() as u64,
        epoch,
        &flattened_slots,
        uuid,
        z_max_pclusterblks,
        min_total_blocks,
        packed_nid,
    )?;
    writer
        .write_all(&head)
        .context("failed to write bootstrap head")?;

    // --- Write pass: inode region, then data region, in offset order ---
    let mut cursor = 0usize;
    let mut inode_order: Vec<usize> = (0..inodes.len()).collect();
    inode_order.sort_unstable_by_key(|&index| inodes[index].meta_offset);
    for index in inode_order {
        let inode = &inodes[index];
        debug_assert!(inode.meta_offset >= cursor);
        write_zeros(writer, inode.meta_offset - cursor)?;
        let bytes = serialize_inode(inode, epoch)?;
        writer
            .write_all(&bytes)
            .context("failed to write bootstrap inode")?;
        cursor = inode.meta_offset + bytes.len();
    }

    for (index, data_offset) in data_entries {
        debug_assert!(data_offset >= cursor);
        write_zeros(writer, data_offset - cursor)?;
        match &inodes[index].data {
            InodeData::Directory { data_size, .. } => {
                let dir_data = serialize_dir_data(inodes, index);
                let block_part = &dir_data[..dir_data.len().min(*data_size)];
                writer
                    .write_all(block_part)
                    .context("failed to write bootstrap directory data")?;
                cursor = data_offset + block_part.len();
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

/// Serialize the directory data of `inodes[index]` from its child refs,
/// resolving child nids through the shared inode table.
fn serialize_dir_data(inodes: &[InodeInfo], index: usize) -> Vec<u8> {
    let InodeData::Directory {
        ref children,
        parent_nid,
        ..
    } = inodes[index].data
    else {
        unreachable!("serialize_dir_data is only called for directories");
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

/// Lays out one directory's data: the full blocks (if any) get a data-region
/// allocation whose offset is returned, the partial last block is kept as the
/// inode's inline tail when [`directory_inline_len`] allows it, else the data
/// is block padded in the data region. Sets the inode's startblk, data_size,
/// inline tail and size.
fn place_dir_data(
    layout: &mut MetadataLayout,
    inodes: &mut [InodeInfo],
    index: usize,
) -> Option<usize> {
    let data = serialize_dir_data(inodes, index);
    let InodeData::Directory { inline_len, .. } = inodes[index].data else {
        unreachable!("place_dir_data is only called for directories");
    };
    let (block_len, size) = if inline_len > 0 {
        debug_assert_eq!(data.len() % EROFS_BLOCK_SIZE as usize, inline_len);
        (data.len() - inline_len, data.len())
    } else {
        let padded =
            align_up_usize(data.len(), EROFS_BLOCK_SIZE as usize).expect("alignment overflowed");
        (padded, padded)
    };
    let placed = (block_len > 0).then(|| layout.alloc_dir_data(block_len));
    if let InodeData::Directory {
        ref mut startblk,
        ref mut data_size,
        ref mut inline_tail,
        ..
    } = inodes[index].data
    {
        *startblk = placed.map_or(0, |(_, startblk)| startblk);
        *data_size = block_len;
        *inline_tail = data[data.len() - inline_len..].to_vec();
    }
    inodes[index].size = size as u64;
    placed.map(|(offset, _)| offset)
}

fn write_zeros(writer: &mut impl Write, n: usize) -> Result<()> {
    nydus_format::utils::write_zeros(writer, n as u64).context("failed to write bootstrap padding")
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
            .ok_or_else(|| Error::Overflow("flattened blob alignment overflow".to_string()))?
            as u64;
        if mapped_offset % block_size != 0 {
            return Err(Error::InvalidImage(
                "flattened blob offset must be block aligned".to_string(),
            ));
        }
        slot.set_mapped_blkaddr(mapped_offset / block_size)?;
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
    let sb_offset = EROFS_SUPER_OFFSET as usize;
    if bootstrap.len() < sb_offset + EROFS_SB_BASE_SIZE {
        return Err(Error::InvalidImage(
            "bootstrap too small for a superblock".to_string(),
        ));
    }
    let devslot_offset = cast_ref::<ErofsSuperblock>(&bootstrap[sb_offset..]).devt_slotoff()
        as usize
        * EROFS_DEVICESLOT_SIZE;
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

    alloc_inodes(&mut layout, inodes, epoch);
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

    // Directories are processed one at a time: serializing every directory
    // up front would keep a second copy of all file names resident at once.
    for index in dir_indexes {
        if let Some(data_offset) = place_dir_data(&mut layout, inodes, index) {
            let dir_data = serialize_dir_data(inodes, index);
            let InodeData::Directory { data_size, .. } = inodes[index].data else {
                unreachable!("dir_indexes only collects directory inodes");
            };
            layout.write_at(data_offset, &dir_data[..dir_data.len().min(data_size)]);
        }
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
            startblk: ref mut slot_startblk,
            ..
        } = inodes[index].data
        {
            *slot_startblk = startblk;
        }
    }

    for inode in inodes.iter() {
        let inode_bytes = serialize_inode(inode, epoch)?;
        let offset = inode.meta_offset;
        layout.write_at(offset, &inode_bytes);
    }

    let root_nid = inodes[0].nid;
    if root_nid > u16::MAX as u64 {
        return Err(Error::Overflow("root nid exceeds 16-bit range".to_string()));
    }

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
        0,
        0,
        None,
    )?;

    Ok(bootstrap)
}

/// Assign every inode's on-disk slot in table order: promote inodes that
/// cannot stay compact to the extended layout, then allocate and stamp each
/// one's metadata offset and nid.
fn alloc_inodes(layout: &mut MetadataLayout, inodes: &mut [InodeInfo], epoch: u64) {
    for inode in inodes.iter_mut() {
        if inode.mtime != epoch || inode.mtime_nsec != 0 {
            inode.is_extended = true;
        }
        let inline_len = directory_inline_len(inode);
        if let InodeData::Directory {
            inline_len: ref mut slot,
            ..
        } = inode.data
        {
            *slot = inline_len;
        }
    }
    for index in allocation_order(inodes) {
        let inode = &mut inodes[index];
        let inode_size = erofs_inode_size(inode);
        let (offset, nid) = layout.alloc_inode(inode_size, has_inline_data(inode));
        inode.meta_offset = offset;
        inode.nid = nid;
    }
}

/// Inode allocation order: the root, then for each directory (in that same
/// order) all of its children back to back, as mkfs.erofs lays them out. A
/// directory's inline dirents and its children's inodes thus share a few
/// consecutive blocks, so listing or looking up siblings touches one or two
/// metadata blocks instead of one per child. Inodes outside the tree (the
/// z_erofs packed inode) come last.
fn allocation_order(inodes: &[InodeInfo]) -> Vec<usize> {
    let mut order = Vec::with_capacity(inodes.len());
    let mut placed = vec![false; inodes.len()];
    if inodes.is_empty() {
        return order;
    }
    order.push(0);
    placed[0] = true;
    let mut next_dir = 0;
    while next_dir < order.len() {
        let dir = order[next_dir];
        next_dir += 1;
        if let InodeData::Directory { ref children, .. } = inodes[dir].data {
            for child in children {
                // Hardlinked inodes are listed under several parents.
                if !placed[child.inode_index] {
                    placed[child.inode_index] = true;
                    order.push(child.inode_index);
                }
            }
        }
    }
    order.extend((0..inodes.len()).filter(|&index| !placed[index]));
    order
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::blob_chunk::BlobWriter;
    use crate::build::inode::{build_tree, choose_epoch, ChildRef};
    use nydus_core::ErofsReader;
    use nydus_format::erofs::{
        erofs_xattr_ibody_size, ErofsInode, XattrEntry, EROFS_FT_SYMLINK, EROFS_INODE_COMPACT_SIZE,
        EROFS_INODE_EXTENDED_SIZE, EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN,
        EROFS_XATTR_INDEX_USER,
    };
    use std::collections::HashSet;
    use std::fs;

    fn symlink_tree(
        target_len: usize,
        is_extended: bool,
        mtime: u64,
        xattrs: Vec<XattrEntry>,
    ) -> Vec<InodeInfo> {
        vec![
            InodeInfo {
                mode: 0o040755,
                uid: 0,
                gid: 0,
                size: 0,
                mtime: 0,
                mtime_nsec: 0,
                nlink: 2,
                ino: 1,
                nid: 0,
                meta_offset: 0,
                is_extended: true,
                data: InodeData::Directory {
                    children: vec![ChildRef {
                        name: b"link".to_vec(),
                        file_type: EROFS_FT_SYMLINK,
                        inode_index: 1,
                    }],
                    startblk: 0,
                    data_size: 0,
                    inline_len: 0,
                    inline_tail: Vec::new(),
                    parent_nid: 0,
                },
                xattrs: Vec::new(),
            },
            InodeInfo {
                mode: 0o120777,
                uid: if is_extended { u16::MAX as u32 + 1 } else { 0 },
                gid: 0,
                size: target_len as u64,
                mtime,
                mtime_nsec: 0,
                nlink: 1,
                ino: 2,
                nid: 0,
                meta_offset: 0,
                is_extended,
                data: InodeData::Symlink {
                    target: vec![b'a'; target_len],
                    startblk: 0,
                },
                xattrs,
            },
        ]
    }

    fn check_symlink_rendering(
        make_inodes: impl Fn() -> Vec<InodeInfo>,
        expected_layout: u16,
        expected_extended: bool,
    ) {
        let mut inodes = make_inodes();
        let mut streamed_inodes = make_inodes();
        let image = render_bootstrap(&mut inodes, 0, &[], &[0; 16]).unwrap();
        let mut streamed = Vec::new();
        render_flattened_bootstrap_to(&mut streamed, &mut streamed_inodes, 0, &[], &[0; 16])
            .unwrap();
        assert_eq!(image, streamed);
        for (buffered_inode, streamed_inode) in inodes.iter().zip(&streamed_inodes) {
            assert_eq!(buffered_inode.nid, streamed_inode.nid);
            assert_eq!(buffered_inode.meta_offset, streamed_inode.meta_offset);
            assert_eq!(buffered_inode.is_extended, streamed_inode.is_extended);
        }

        let block_size = EROFS_BLOCK_SIZE as usize;
        let inode_offset = block_size + inodes[1].meta_offset;
        let inode = ErofsInode::parse(&image[inode_offset..]).unwrap();
        assert_eq!(inode.data_layout(), expected_layout);
        assert_eq!(inodes[1].is_extended, expected_extended);
        assert_eq!(
            inode.header_size(),
            if expected_extended {
                EROFS_INODE_EXTENDED_SIZE
            } else {
                EROFS_INODE_COMPACT_SIZE
            }
        );
        assert_eq!(inode.uid(), inodes[1].uid);
        assert_eq!(inode.gid(), inodes[1].gid);
        assert_eq!(inode.nlink(), inodes[1].nlink);
        assert_eq!(inode.mtime(0), inodes[1].mtime);
        assert_eq!(inode.effective_mtime_nsec(0), inodes[1].mtime_nsec);
        let InodeData::Symlink { target, .. } = &inodes[1].data else {
            unreachable!();
        };
        let data_offset = if expected_layout == EROFS_INODE_FLAT_INLINE {
            let offset = inode_offset + inode.header_size() + inode.xattr_size();
            assert!(offset % block_size + target.len() <= block_size);
            offset
        } else {
            assert_ne!(inode.startblk(), 0);
            inode.startblk() as usize * block_size
        };
        assert_eq!(&image[data_offset..data_offset + target.len()], target);

        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&image).unwrap();
        let reader = ErofsReader::open_metadata_only(file.path()).unwrap();
        let parsed = reader.inode(inodes[1].nid).unwrap();
        assert_eq!(
            reader.read_symlink(inodes[1].nid, &parsed).unwrap(),
            *target
        );
    }

    #[test]
    fn common_epoch_reduces_bootstrap_size_without_changing_timestamps() {
        use crate::build::inode::choose_epoch;
        use nydus_format::erofs::EROFS_FT_REG_FILE;

        let make_tree = || {
            let mut inodes = symlink_tree(0, false, 0, Vec::new());
            inodes.pop();
            let mut children = Vec::new();
            for index in 0..1024 {
                children.push(ChildRef {
                    name: format!("file-{index:04}").into_bytes(),
                    file_type: EROFS_FT_REG_FILE,
                    inode_index: index + 1,
                });
                inodes.push(InodeInfo {
                    mode: 0o100644,
                    uid: 0,
                    gid: 0,
                    size: 0,
                    mtime: if index == 0 { 0 } else { 1_700_000_000 },
                    mtime_nsec: 0,
                    nlink: 1,
                    ino: index as u32 + 2,
                    nid: 0,
                    meta_offset: 0,
                    is_extended: false,
                    data: InodeData::RegularFile {
                        chunk_index_entries: Vec::new(),
                        chunk_size_bits: 12,
                    },
                    xattrs: Vec::new(),
                });
            }
            let InodeData::Directory {
                children: root_children,
                ..
            } = &mut inodes[0].data
            else {
                unreachable!()
            };
            *root_children = children;
            inodes
        };
        let mut before = make_tree();
        let old = render_bootstrap(&mut before, 0, &[], &[0; 16]).unwrap();
        let mut after = make_tree();
        let epoch = choose_epoch(&after);
        assert_eq!(epoch, 1_700_000_000);
        let new = render_bootstrap(&mut after, epoch, &[], &[0; 16]).unwrap();
        let old_compact = before.iter().filter(|inode| !inode.is_extended).count();
        let new_compact = after.iter().filter(|inode| !inode.is_extended).count();
        assert_eq!((old_compact, new_compact), (1, 1023));
        assert!(new.len() < old.len());
        for (old_inode, new_inode) in before.iter().zip(&after) {
            let old_parsed =
                ErofsInode::parse(&old[EROFS_BLOCK_SIZE as usize + old_inode.meta_offset..])
                    .unwrap();
            let new_parsed =
                ErofsInode::parse(&new[EROFS_BLOCK_SIZE as usize + new_inode.meta_offset..])
                    .unwrap();
            assert_eq!(old_parsed.mtime(0), new_parsed.mtime(epoch));
            assert_eq!(
                old_parsed.effective_mtime_nsec(0),
                new_parsed.effective_mtime_nsec(0)
            );
        }
        println!("1024 empty files + root: bootstrap {} -> {} bytes; compact {old_compact} -> {new_compact}; extended {} -> {}",
            old.len(), new.len(), before.len() - old_compact, after.len() - new_compact);
    }

    #[test]
    fn timestamps_round_trip_across_epoch_and_nanosecond_boundaries() {
        for epoch in [0u64, 1_700_000_000] {
            for (seconds, nanoseconds) in [
                (epoch, 0),
                (epoch, 123_456_789),
                (epoch.saturating_sub(1), 0),
                (epoch + 1, 0),
                (epoch + u32::MAX as u64 + 1, 999_999_999),
            ] {
                let make_inodes = || {
                    let mut inodes = symlink_tree(4040, false, seconds, Vec::new());
                    inodes[1].mtime_nsec = nanoseconds;
                    inodes
                };
                let mut inodes = make_inodes();
                let mut streamed_inodes = make_inodes();
                let image = render_bootstrap(&mut inodes, epoch, &[], &[0; 16]).unwrap();
                let mut streamed = Vec::new();
                render_flattened_bootstrap_to(
                    &mut streamed,
                    &mut streamed_inodes,
                    epoch,
                    &[],
                    &[0; 16],
                )
                .unwrap();
                assert_eq!(image, streamed);
                let mut file = tempfile::NamedTempFile::new().unwrap();
                file.write_all(&image).unwrap();
                let reader = ErofsReader::open_metadata_only(file.path()).unwrap();
                let parsed = reader.inode(inodes[1].nid).unwrap();
                let compact = seconds == epoch && nanoseconds == 0;
                assert_eq!(
                    parsed.header_size(),
                    if compact {
                        EROFS_INODE_COMPACT_SIZE
                    } else {
                        EROFS_INODE_EXTENDED_SIZE
                    }
                );
                assert_eq!(parsed.mtime(reader.superblock().epoch()), seconds);
                assert_eq!(
                    parsed.effective_mtime_nsec(reader.superblock().fixed_nsec()),
                    nanoseconds
                );
                assert_eq!(
                    reader.read_symlink(inodes[1].nid, &parsed).unwrap(),
                    vec![b'a'; 4040]
                );
                if compact {
                    let offset = EROFS_BLOCK_SIZE as usize + inodes[1].meta_offset;
                    assert_eq!(&image[offset + 12..offset + 16], &[0; 4]);
                }
            }
        }
    }

    #[test]
    fn flattened_device_starts_are_checked_after_alignment() {
        let block_size = EROFS_BLOCK_SIZE as u64;
        let mut slots = [ErofsDeviceSlot::new(u32::MAX as u64).unwrap()];
        set_flattened_mapped_blkaddrs(&mut slots, u32::MAX as u64 * block_size, block_size)
            .unwrap();
        assert_eq!(slots[0].mapped_blkaddr(), u32::MAX as u64);
        assert!(slots[0].mapped_blkaddr() + slots[0].blocks() > u32::MAX as u64);
        assert!(set_flattened_mapped_blkaddrs(
            &mut slots,
            u32::MAX as u64 * block_size,
            FLATTENED_BLOB_ALIGNMENT,
        )
        .is_err());
        assert!(
            set_flattened_mapped_blkaddrs(&mut slots, u64::MAX, FLATTENED_BLOB_ALIGNMENT).is_err()
        );
        let mut slots = [
            ErofsDeviceSlot::new(u32::MAX as u64).unwrap(),
            ErofsDeviceSlot::new(1).unwrap(),
        ];
        assert!(set_flattened_mapped_blkaddrs(&mut slots, block_size, block_size).is_err());
    }

    #[test]
    fn symlink_inline_boundaries_use_actual_header_and_xattrs() {
        for is_extended in [false, true] {
            for has_xattrs in [false, true] {
                let xattrs = if has_xattrs {
                    vec![XattrEntry {
                        name_index: EROFS_XATTR_INDEX_USER,
                        suffix: b"key".to_vec(),
                        value: b"value".to_vec(),
                    }]
                } else {
                    Vec::new()
                };
                let header_size = if is_extended {
                    EROFS_INODE_EXTENDED_SIZE
                } else {
                    EROFS_INODE_COMPACT_SIZE
                };
                let limit =
                    EROFS_BLOCK_SIZE as usize - header_size - erofs_xattr_ibody_size(&xattrs);
                for (target_len, expected_layout) in [
                    (limit, EROFS_INODE_FLAT_INLINE),
                    (limit + 1, EROFS_INODE_FLAT_PLAIN),
                ] {
                    check_symlink_rendering(
                        || symlink_tree(target_len, is_extended, 0, xattrs.clone()),
                        expected_layout,
                        is_extended,
                    );
                }
            }
        }
    }

    #[test]
    fn symlink_inline_rechecks_fit_after_timestamp_promotion() {
        check_symlink_rendering(
            || symlink_tree(4040, false, u32::MAX as u64 + 1, Vec::new()),
            EROFS_INODE_FLAT_PLAIN,
            true,
        );
    }

    #[test]
    fn non_inline_symlinks_preserve_header_constraints_and_metadata() {
        use nydus_format::erofs::needs_erofs_extended_inode;

        for (uid, gid, nlink, seconds, nanoseconds, expected_extended) in [
            (0, 0, 1, 0, 0, false),
            (u16::MAX as u32 + 1, 0, 1, 0, 0, true),
            (0, u16::MAX as u32 + 1, 1, 0, 0, true),
            (0, 0, 2, 0, 0, true),
            (0, 0, 1, 1, 0, true),
            (0, 0, 1, 0, 1, true),
        ] {
            check_symlink_rendering(
                || {
                    let mut inodes = symlink_tree(4070, false, seconds, Vec::new());
                    let inode = &mut inodes[1];
                    inode.uid = uid;
                    inode.gid = gid;
                    inode.nlink = nlink;
                    inode.mtime_nsec = nanoseconds;
                    inode.is_extended =
                        needs_erofs_extended_inode(inode.size, uid, gid, nlink as u64);
                    inodes
                },
                EROFS_INODE_FLAT_PLAIN,
                expected_extended,
            );
        }
    }

    /// Directories pack their last dirent block behind the inode and a
    /// directory's children get consecutive nids; both must read back through
    /// the metadata reader exactly.
    #[test]
    fn directories_inline_their_tail_and_children_are_contiguous() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        fs::create_dir_all(source.join("small")).unwrap();
        fs::create_dir_all(source.join("big")).unwrap();
        for i in 0..8 {
            fs::write(source.join("small").join(format!("f{i}")), b"x").unwrap();
        }
        // Long names so the dirents span several blocks (> 4KiB) and end in a
        // partial block that still fits behind a compact inode.
        let big_names: Vec<String> = (0..120)
            .map(|i| format!("{i:04}-{}", "n".repeat(60)))
            .collect();
        for name in &big_names {
            fs::write(source.join("big").join(name), b"y").unwrap();
        }

        let scratch = dir.path().join("scratch.blob");
        let mut blob_writer = BlobWriter::new(&scratch, EROFS_BLOCK_SIZE).unwrap();
        let mut inodes =
            build_tree(&source, &mut blob_writer, EROFS_BLOCK_SIZE, &HashSet::new()).unwrap();
        // Fresh files carry sub-second mtimes, which force the extended inode
        // layout; put every inode on the epoch so the children stay compact.
        for inode in inodes.iter_mut() {
            inode.mtime = 1_700_000_000;
            inode.mtime_nsec = 0;
        }
        let epoch = choose_epoch(&inodes);
        let bootstrap = render_flattened_bootstrap(&mut inodes, epoch, &[], &[0u8; 16]).unwrap();
        let path = dir.path().join("bootstrap");
        fs::write(&path, &bootstrap).unwrap();
        let reader = ErofsReader::open_metadata_only(&path).unwrap();

        let root_nid = reader.superblock().root_nid();
        let root = reader.inode(root_nid).unwrap();
        let lookup = |parent: u64, name: &str| {
            let parent_inode = reader.inode(parent).unwrap();
            reader
                .lookup_dir_entry(parent, &parent_inode, name.as_bytes())
                .unwrap()
                .unwrap_or_else(|| panic!("{name} missing"))
        };

        // Small directory: everything inline, size is the used length.
        let small_nid = lookup(root_nid, "small");
        let small = reader.inode(small_nid).unwrap();
        assert_eq!(small.data_layout(), EROFS_INODE_FLAT_INLINE);
        assert!(small.size() > 0 && small.size() < EROFS_BLOCK_SIZE as u64);
        let mut names: Vec<Vec<u8>> = reader
            .read_dir(small_nid, &small)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect();
        names.sort();
        let mut expected: Vec<Vec<u8>> = (0..8).map(|i| format!("f{i}").into_bytes()).collect();
        expected.extend([b".".to_vec(), b"..".to_vec()]);
        expected.sort();
        assert_eq!(names, expected);
        // Children allocated back to back, in dirent order (each one-chunk
        // file is 40 bytes, i.e. two 32-byte slots).
        let child_nids: Vec<u64> = (0..8)
            .map(|i| lookup(small_nid, &format!("f{i}")))
            .collect();
        for pair in child_nids.windows(2) {
            assert_eq!(
                pair[1],
                pair[0] + 2,
                "siblings must be allocated back to back"
            );
        }

        // Big directory: full blocks in the data region plus an inline tail.
        let big_nid = lookup(root_nid, "big");
        let big = reader.inode(big_nid).unwrap();
        assert_eq!(big.data_layout(), EROFS_INODE_FLAT_INLINE);
        assert!(big.size() > EROFS_BLOCK_SIZE as u64);
        assert_ne!(big.size() % EROFS_BLOCK_SIZE as u64, 0);
        assert_ne!(big.startblk(), 0);
        let entries = reader.read_dir(big_nid, &big).unwrap();
        assert_eq!(entries.len(), big_names.len() + 2);
        for name in &big_names {
            let nid = lookup(big_nid, name);
            assert_eq!(reader.inode(nid).unwrap().size(), 1);
        }
        assert_eq!(root.data_layout(), EROFS_INODE_FLAT_INLINE);
    }
}
