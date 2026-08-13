use nydus_format::erofs::{ErofsDirent, EROFS_BLOCK_SIZE, EROFS_DIRENT_SIZE, EROFS_FT_DIR};

/// A directory child entry with name, NID, and file type.
///
/// Names are raw bytes: a Linux filename is any byte sequence other than `/`
/// and NUL, so converting through `String` would rewrite the invalid sequences
/// and can make two distinct names collide.
pub(crate) struct DirChild {
    pub name: Vec<u8>,
    pub nid: u64,
    pub file_type: u8,
}

/// Serialize directory entries into block-aligned data.
///
/// Entries are sorted by name in byte order, including "." and "..".  The
/// kernel binary-searches dirents, so a name that sorts before "." -- anything
/// starting below 0x2e, such as a space or "-" -- must come first rather than
/// after the two conventional entries.
/// Each block is independently formatted: dirent array followed by names.
///
/// Returns the serialized directory data (multiple of EROFS_BLOCK_SIZE).
pub(crate) fn serialize_directory(
    children: &[DirChild],
    self_nid: u64,
    parent_nid: u64,
) -> Vec<u8> {
    let block_size = EROFS_BLOCK_SIZE as usize;

    let mut entries: Vec<(&[u8], u64, u8)> = Vec::with_capacity(children.len() + 2);
    entries.push((b".", self_nid, EROFS_FT_DIR));
    entries.push((b"..", parent_nid, EROFS_FT_DIR));
    for c in children {
        entries.push((&c.name, c.nid, c.file_type));
    }
    entries.sort_unstable_by(|a, b| a.0.cmp(b.0));

    let mut result = Vec::new();
    let mut index = 0;

    while index < entries.len() {
        let block_start = index;
        let mut name_area = 0usize;

        while index < entries.len() {
            let new_dirent_area = (index - block_start + 1) * EROFS_DIRENT_SIZE;
            let new_name_area = name_area + entries[index].0.len();
            if new_dirent_area + new_name_area > block_size {
                break;
            }
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
            block[name_offset..name_offset + name.len()].copy_from_slice(name);
            name_offset += name.len();
        }
        result.extend_from_slice(&block);
    }

    result
}
