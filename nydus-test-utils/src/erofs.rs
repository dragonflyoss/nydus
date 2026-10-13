//! Minimal EROFS images: just enough bytes to pass the superblock checks,
//! for tests that never read a file out of them.

use nydus_format::erofs::{
    ErofsInodeCompact, ErofsSuperblock, EROFS_BLOCK_SIZE, EROFS_INODE_FLAT_PLAIN,
    EROFS_SUPER_OFFSET,
};

/// An image of `blocks` blocks holding nothing but a valid superblock, the
/// bootstrap a full blob fixture embeds when no test reads it.
pub fn superblock_image(blocks: u32) -> Vec<u8> {
    let mut image = vec![0u8; blocks as usize * EROFS_BLOCK_SIZE as usize];
    write_superblock(&mut image, 0, blocks);
    image
}

/// An image whose root directory (nid 0, a compact inode at block 1) is
/// `data`, stored flat from block 2. `data` is taken verbatim, so a test
/// lays out the directory entries itself, malformed ones included.
pub fn directory_image(data: &[u8]) -> Vec<u8> {
    let block_size = EROFS_BLOCK_SIZE as usize;
    let mut image = vec![0u8; 2 * block_size + data.len()];
    let blocks = image.len().div_ceil(block_size) as u32;
    write_superblock(&mut image, 1, blocks);

    let root = ErofsInodeCompact::new(
        EROFS_INODE_FLAT_PLAIN,
        0o040755,
        2,
        data.len() as u32,
        0,
        2,
        0,
        0,
        0,
    );
    image[block_size..block_size + root.as_bytes().len()].copy_from_slice(root.as_bytes());
    image[2 * block_size..].copy_from_slice(data);
    image
}

/// Writes a superblock for `blocks` blocks and `inos` inodes, the inode
/// slots counted from block 1.
fn write_superblock(image: &mut [u8], inos: u64, blocks: u32) {
    let superblock =
        ErofsSuperblock::new(0, 0, 0, inos, 0, u64::from(blocks), 1, 0, 0, &[0u8; 16]).unwrap();
    let offset = EROFS_SUPER_OFFSET as usize;
    image[offset..offset + superblock.as_bytes().len()].copy_from_slice(superblock.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_format::erofs::{ErofsInode, EROFS_INODE_FLAT_PLAIN};

    #[test]
    fn superblock_image_holds_a_valid_superblock_and_nothing_else() {
        let test_cases = vec![1u32, 2, 7];

        for blocks in test_cases {
            let image = superblock_image(blocks);
            let superblock =
                ErofsSuperblock::from_bytes(&image[EROFS_SUPER_OFFSET as usize..]).unwrap();
            assert_eq!(image.len(), blocks as usize * EROFS_BLOCK_SIZE as usize);
            superblock.validate().unwrap();
            assert_eq!(superblock.blocks(), u64::from(blocks));
            assert!(image[..EROFS_SUPER_OFFSET as usize]
                .iter()
                .all(|byte| *byte == 0));
        }
    }

    #[test]
    fn directory_image_places_the_root_inode_and_data() {
        let data = b"not a real directory block".to_vec();
        let image = directory_image(&data);
        let block_size = EROFS_BLOCK_SIZE as usize;
        let superblock =
            ErofsSuperblock::from_bytes(&image[EROFS_SUPER_OFFSET as usize..]).unwrap();
        let root = ErofsInode::from_bytes(&image[block_size..]).unwrap();

        superblock.validate().unwrap();
        assert_eq!(superblock.inos(), 1);
        assert_eq!(superblock.blocks(), 3);
        assert_eq!(root.data_layout(), EROFS_INODE_FLAT_PLAIN);
        assert_eq!(root.mode(), 0o040755);
        assert_eq!(root.nlink(), 2);
        assert_eq!(root.size(), data.len() as u64);
        assert_eq!(root.startblk(), 2);
        assert_eq!(&image[2 * block_size..], &data[..]);
    }
}
