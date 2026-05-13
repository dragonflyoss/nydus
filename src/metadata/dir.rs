use std::mem;

use super::*;

// =====================================================================
// ErofsDirent — 12 bytes
// =====================================================================

#[repr(C, packed)]
pub struct ErofsDirent {
    pub nid: [u8; 8],
    pub nameoff: [u8; 2],
    pub file_type: u8,
    pub reserved: u8,
}

const _: () = assert!(mem::size_of::<ErofsDirent>() == EROFS_DIRENT_SIZE);

impl ErofsDirent {
    pub fn nid(&self) -> u64 {
        get_u64(&self.nid)
    }
    pub fn nameoff(&self) -> u16 {
        get_u16(&self.nameoff)
    }
    pub fn file_type(&self) -> u8 {
        self.file_type
    }

    pub fn new(nid: u64, nameoff: u16, file_type: u8) -> Self {
        let mut v: Self = unsafe { mem::zeroed() };
        set_u64(&mut v.nid, nid);
        set_u16(&mut v.nameoff, nameoff);
        v.file_type = file_type;
        v
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, EROFS_DIRENT_SIZE) }
    }
}
