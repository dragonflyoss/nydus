use super::*;
use std::mem;

/// EROFS superblock — 128 bytes, `#[repr(C, packed)]`.
#[repr(C, packed)]
pub struct ErofsSuperblock {
    pub magic: [u8; 4],
    pub checksum: [u8; 4],
    pub feature_compat: [u8; 4],
    pub blkszbits: u8,
    pub sb_extslots: u8,
    pub rootnid_2b: [u8; 2],
    pub inos: [u8; 8],
    pub epoch: [u8; 8],
    pub fixed_nsec: [u8; 4],
    pub blocks_lo: [u8; 4],
    pub meta_blkaddr: [u8; 4],
    pub xattr_blkaddr: [u8; 4],
    pub uuid: [u8; 16],
    pub volume_name: [u8; 16],
    pub feature_incompat: [u8; 4],
    pub compr_or_distance: [u8; 2],
    pub extra_devices: [u8; 2],
    pub devt_slotoff: [u8; 2],
    pub dirblkbits: u8,
    pub xattr_prefix_count: u8,
    pub xattr_prefix_start: [u8; 4],
    pub packed_nid: [u8; 8],
    pub xattr_filter_reserved: u8,
    pub _reserved2: [u8; 3],
    pub build_time: [u8; 8],
    pub rootnid_8b: [u8; 8],
    pub _reserved3: [u8; 4],
}

const _: () = assert!(mem::size_of::<ErofsSuperblock>() == EROFS_SB_BASE_SIZE);

impl ErofsSuperblock {
    pub fn magic(&self) -> u32 {
        get_u32(&self.magic)
    }

    pub fn feature_compat(&self) -> u32 {
        get_u32(&self.feature_compat)
    }

    pub fn feature_incompat(&self) -> u32 {
        get_u32(&self.feature_incompat)
    }

    pub fn root_nid(&self) -> u64 {
        get_u16(&self.rootnid_2b) as u64
    }

    pub fn inos(&self) -> u64 {
        get_u64(&self.inos)
    }

    pub fn epoch(&self) -> u64 {
        get_u64(&self.epoch)
    }

    pub fn fixed_nsec(&self) -> u32 {
        get_u32(&self.fixed_nsec)
    }

    pub fn blocks(&self) -> u64 {
        get_u32(&self.blocks_lo) as u64
    }

    pub fn meta_blkaddr(&self) -> u32 {
        get_u32(&self.meta_blkaddr)
    }

    pub fn extra_devices(&self) -> u16 {
        get_u16(&self.extra_devices)
    }

    pub fn devt_slotoff(&self) -> u16 {
        get_u16(&self.devt_slotoff)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        feature_compat: u32,
        feature_incompat: u32,
        root_nid: u16,
        inos: u64,
        epoch: u64,
        blocks: u64,
        meta_blkaddr: u32,
        extra_devices: u16,
        devt_slotoff: u16,
        uuid: &[u8; 16],
    ) -> Self {
        let mut sb: Self = unsafe { mem::zeroed() };
        set_u32(&mut sb.magic, EROFS_SUPER_MAGIC_V1);
        set_u32(
            &mut sb.feature_compat,
            feature_compat & !EROFS_FEATURE_COMPAT_SB_CHKSUM,
        );
        sb.blkszbits = EROFS_BLKSZBITS;
        set_u16(&mut sb.rootnid_2b, root_nid);
        set_u64(&mut sb.inos, inos);
        set_u64(&mut sb.epoch, epoch);
        set_u32(&mut sb.blocks_lo, blocks as u32);
        set_u32(&mut sb.meta_blkaddr, meta_blkaddr);
        sb.uuid = *uuid;
        set_u32(&mut sb.feature_incompat, feature_incompat);
        set_u16(&mut sb.extra_devices, extra_devices);
        set_u16(&mut sb.devt_slotoff, devt_slotoff);
        sb
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, EROFS_SB_BASE_SIZE) }
    }
}
