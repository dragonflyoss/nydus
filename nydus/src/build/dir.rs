use crate::metadata::{ErofsDirent, EROFS_BLOCK_SIZE, EROFS_DIRENT_SIZE, EROFS_FT_DIR};

/// A directory child entry with name, NID, and file type.
pub struct DirChild {
    pub name: String,
    pub nid: u64,
    pub file_type: u8,
}

/// Serialize directory entries into block-aligned data.
///
/// Entries are sorted alphabetically.  "." and ".." are prepended.
/// Each block is independently formatted: dirent array followed by names.
///
/// Returns the serialized directory data (multiple of EROFS_BLOCK_SIZE).
pub fn serialize_directory(children: &[DirChild], self_nid: u64, parent_nid: u64) -> Vec<u8> {
    let block_size = EROFS_BLOCK_SIZE as usize;

    let mut entries: Vec<(&str, u64, u8)> = Vec::with_capacity(children.len() + 2);
    entries.push((".", self_nid, EROFS_FT_DIR));
    entries.push(("..", parent_nid, EROFS_FT_DIR));
    for c in children {
        entries.push((&c.name, c.nid, c.file_type));
    }

    let mut result = Vec::new();
    let mut index = 0;

    while index < entries.len() {
        let block_start = index;
        let mut dirent_area = 0usize;
        let mut name_area = 0usize;

        while index < entries.len() {
            let new_dirent_area = (index - block_start + 1) * EROFS_DIRENT_SIZE;
            let new_name_area = name_area + entries[index].0.len();
            if new_dirent_area + new_name_area > block_size {
                break;
            }
            dirent_area = new_dirent_area;
            name_area = new_name_area;
            index += 1;
        }

        let count = index - block_start;
        assert!(count > 0, "directory entry too large for a single block");

        let mut block = vec![0u8; block_size];
        let names_start = count * EROFS_DIRENT_SIZE;
        let mut name_offset = names_start;

        for i in 0..count {
            let (name, nid, ft) = entries[block_start + i];
            let de = ErofsDirent::new(nid, name_offset as u16, ft);
            let de_offset = i * EROFS_DIRENT_SIZE;
            block[de_offset..de_offset + EROFS_DIRENT_SIZE].copy_from_slice(de.as_bytes());
            let name_bytes = name.as_bytes();
            block[name_offset..name_offset + name_bytes.len()].copy_from_slice(name_bytes);
            name_offset += name_bytes.len();
        }
        let _ = dirent_area;
        result.extend_from_slice(&block);
    }

    result
}
