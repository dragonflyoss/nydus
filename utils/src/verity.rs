// Copyright (C) 2020-2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Utilities to generate Merkle trees for data integrity verification.

use std::fs::File;
use std::io::Result;
use std::mem::size_of;
use std::sync::Mutex;

use crate::digest::{Algorithm, DigestData, RafsDigest};
use crate::div_round_up;
use crate::filemap::FileMapState;

const NON_EXIST_ENTRY_DIGEST: RafsDigest = RafsDigest {
    data: [
        173, 127, 172, 178, 88, 111, 198, 233, 102, 192, 4, 215, 209, 209, 107, 2, 79, 88, 5, 255,
        124, 180, 124, 122, 133, 218, 189, 139, 72, 137, 44, 167,
    ],
};

/// Struct to maintain and compute Merkle Tree topology and layout.
pub struct MerkleTree {
    digest_algo: Algorithm,
    digest_per_page: u32,
    digest_size: usize,
    data_pages: u32,
    page_size: u32,
    max_levels: u32,
}

impl MerkleTree {
    /// Create a new instance of `MerkleTree`.
    pub fn new(page_size: u32, data_pages: u32, digest_algo: Algorithm) -> Self {
        assert_eq!(page_size, 4096);
        assert_eq!(digest_algo, Algorithm::Sha256);
        let digest_size = 32;
        let digest_shift = u32::trailing_zeros(page_size / digest_size);
        let digest_per_page = 1u32 << digest_shift;

        let mut max_levels = 0;
        let mut tmp_pages = data_pages as u64;
        while tmp_pages > 1 {
            tmp_pages = div_round_up(tmp_pages, digest_per_page as u64);
            max_levels += 1;
        }

        MerkleTree {
            digest_algo,
            digest_per_page: 1 << digest_shift,
            digest_size: digest_size as usize,
            page_size,
            data_pages,
            max_levels,
        }
    }

    /// Get digest algorithm used to generate the Merkle tree.
    pub fn digest_algorithm(&self) -> Algorithm {
        self.digest_algo
    }

    /// Get height of the Merkle tree, 0 means there is only a root digest for one data page.
    pub fn max_levels(&self) -> u32 {
        self.max_levels
    }

    /// Get number of pages to store digest at specified Merkle tree level.
    pub fn level_pages(&self, mut level: u32) -> u32 {
        if level > self.max_levels {
            0
        } else {
            let mut pages = self.data_pages as u64;
            while level > 0 && pages > 0 {
                pages = div_round_up(pages, self.digest_per_page as u64);
                level -= 1;
            }
            pages as u32
        }
    }

    /// Get number of digest entries at specified Merkle tree level.
    pub fn level_entries(&self, level: u32) -> u32 {
        if self.data_pages == 0 || level > self.max_levels {
            0
        } else {
            self.level_index(level, self.data_pages - 1) + 1
        }
    }

    /// Get entry index at the specified level covering the data page with index `page_index`.
    pub fn level_index(&self, mut level: u32, mut page_index: u32) -> u32 {
        if level <= 1 {
            page_index
        } else {
            level -= 1;
            while level > 0 {
                page_index /= self.digest_per_page;
                level -= 1;
            }
            page_index
        }
    }

    /// Get base position of digest array for the specified Merkle tree level.
    pub fn level_base(&self, level: u32) -> u64 {
        if level >= self.max_levels {
            0
        } else {
            let mut offset = 0;
            let mut curr = self.max_levels;
            while curr > level {
                let pages = self.level_pages(curr);
                offset += pages as u64 * self.page_size as u64;
                curr -= 1;
            }
            offset
        }
    }

    /// Get total pages needed to store the Merkle Tree.
    pub fn total_pages(&self) -> u32 {
        let mut pages = 0;
        for idx in 1..=self.max_levels {
            pages += self.level_pages(idx);
        }
        pages
    }
}

/// Merkle tree generator for data integrity verification.
pub struct VerityGenerator {
    mkl_tree: MerkleTree,
    file_map: Mutex<FileMapState>,
    root_digest: RafsDigest,
}

impl VerityGenerator {
    /// Create a new instance [VerityGenerator].
    pub fn new(file: File, offset: u64, data_pages: u32) -> Result<Self> {
        let mkl_tree = MerkleTree::new(4096, data_pages, Algorithm::Sha256);
        let total_size = mkl_tree.total_pages() as usize * 4096;
        let file_map = if data_pages > 1 {
            if offset.checked_add(total_size as u64).is_none() {
                return Err(einval!(format!(
                    "verity data offset 0x{:x} and size 0x{:x} is too big",
                    offset, total_size
                )));
            }

            let md = file.metadata()?;
            if md.len() < total_size as u64 + offset {
                file.set_len(total_size as u64 + offset)?;
            }
            FileMapState::new(file, offset as libc::off_t, total_size, true)?
        } else {
            FileMapState::default()
        };

        Ok(VerityGenerator {
            mkl_tree,
            file_map: Mutex::new(file_map),
            root_digest: NON_EXIST_ENTRY_DIGEST,
        })
    }

    /// Initialize all digest values.
    pub fn initialize(&mut self) -> Result<()> {
        let total_size = self.mkl_tree.total_pages() as usize * 4096;
        let mut offset = 0;
        let mut map = self.file_map.lock().unwrap();

        while offset < total_size {
            let digest = map.get_mut::<DigestData>(offset)?;
            digest.copy_from_slice(&NON_EXIST_ENTRY_DIGEST.data);
            offset += size_of::<DigestData>();
        }

        Ok(())
    }

    /// Set digest value for Merkle entry at `level` with `index`.
    ///
    /// Digests for data pages must be set by calling this method. It can also be used to set
    /// digest values for intermediate digest pages.
    pub fn set_digest(&mut self, level: u32, index: u32, digest: &[u8]) -> Result<()> {
        let digest_size = self.mkl_tree.digest_size;
        if digest.len() != digest_size {
            return Err(einval!(format!(
                "size of digest data is not {}",
                digest_size
            )));
        }

        // Handle special case of zero-level Merkle tree.
        if self.mkl_tree.data_pages == 1 && level == 1 && index == 0 {
            self.root_digest.data.copy_from_slice(digest);
            return Ok(());
        }

        if level > self.mkl_tree.max_levels() || level == 0 {
            return Err(einval!(format!(
                "level {} is out of range, max {}",
                level,
                self.mkl_tree.max_levels()
            )));
        } else if index >= self.mkl_tree.level_entries(level) {
            return Err(einval!(format!(
                "index {} is out of range, max {}",
                index,
                self.mkl_tree.level_entries(level) - 1
            )));
        }

        let base = self.mkl_tree.level_base(level) as usize;
        let offset = base + index as usize * digest_size;
        let mut guard = self.file_map.lock().unwrap();
        let buf = guard.get_mut::<DigestData>(offset)?;
        buf.copy_from_slice(digest);

        Ok(())
    }

    /// Generate digest values from lower level digest pages.
    pub fn generate_level_digests(&mut self, level: u32) -> Result<()> {
        assert!(level > 1 && level <= self.mkl_tree.max_levels);
        let page_size = self.mkl_tree.page_size as usize;
        let count = self.mkl_tree.level_entries(level) as usize;
        let mut digest_base = self.mkl_tree.level_base(level) as usize;
        let mut data_base = self.mkl_tree.level_base(level - 1) as usize;
        let mut guard = self.file_map.lock().unwrap();

        for _ in 0..count {
            let data = guard.get_slice::<u8>(data_base, page_size)?;
            let digest = RafsDigest::from_buf(data, self.mkl_tree.digest_algo);
            let buf = guard.get_mut::<DigestData>(digest_base)?;
            buf.copy_from_slice(digest.as_ref());
            data_base += page_size;
            digest_base += self.mkl_tree.digest_size;
        }

        Ok(())
    }

    /// Generate Merkle root digest.
    ///
    /// The returned Merkle tree root digest will be:
    /// - `NON_EXIST_ENTRY_DIGEST` if there's no data page
    /// - digest of the data page if there's only one data page
    /// - digest of the intermediate digest page if there's more than one data pages
    pub fn generate_root_digest(&mut self) -> Result<RafsDigest> {
        if self.mkl_tree.max_levels == 0 {
            Ok(self.root_digest)
        } else {
            let guard = self.file_map.lock().unwrap();
            let data = guard.get_slice::<u8>(0, self.mkl_tree.page_size as usize)?;
            Ok(RafsDigest::from_buf(data, self.mkl_tree.digest_algo))
        }
    }

    /// Generate all intermediate and root digests for the Merkle tree.
    ///
    /// Digests for data pages at level 1 must be set up by calling [set_digest()] before this
    /// function to generate intermediate and root digests.
    pub fn generate_all_digests(&mut self) -> Result<RafsDigest> {
        for level in 2..=self.mkl_tree.max_levels {
            self.generate_level_digests(level)?;
        }
        self.generate_root_digest()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_max_levels() {
        let mkl = MerkleTree::new(4096, 1, Algorithm::Sha256);
        assert_eq!(mkl.max_levels(), 0);
        assert_eq!(mkl.level_pages(0), 1);
        assert_eq!(mkl.level_pages(1), 0);
        assert_eq!(mkl.level_base(0), 0);
        assert_eq!(mkl.level_base(1), 0);
        assert_eq!(mkl.level_entries(0), 1);
        assert_eq!(mkl.level_entries(1), 0);
        assert_eq!(mkl.total_pages(), 0);

        let mkl = MerkleTree::new(4096, 2, Algorithm::Sha256);
        assert_eq!(mkl.max_levels(), 1);
        assert_eq!(mkl.level_pages(0), 2);
        assert_eq!(mkl.level_pages(1), 1);
        assert_eq!(mkl.level_pages(2), 0);
        assert_eq!(mkl.level_entries(0), 2);
        assert_eq!(mkl.level_entries(1), 2);
        assert_eq!(mkl.level_entries(2), 0);
        assert_eq!(mkl.level_base(0), 4096);
        assert_eq!(mkl.level_base(1), 0);
        assert_eq!(mkl.level_base(2), 0);
        assert_eq!(mkl.total_pages(), 1);

        let mkl = MerkleTree::new(4096, 128, Algorithm::Sha256);
        assert_eq!(mkl.max_levels(), 1);
        assert_eq!(mkl.level_pages(0), 128);
        assert_eq!(mkl.level_pages(1), 1);
        assert_eq!(mkl.level_pages(2), 0);
        assert_eq!(mkl.level_entries(0), 128);
        assert_eq!(mkl.level_entries(1), 128);
        assert_eq!(mkl.level_entries(2), 0);
        assert_eq!(mkl.level_base(0), 4096);
        assert_eq!(mkl.level_base(1), 0);
        assert_eq!(mkl.level_base(2), 0);
        assert_eq!(mkl.total_pages(), 1);

        let mkl = MerkleTree::new(4096, 129, Algorithm::Sha256);
        assert_eq!(mkl.max_levels(), 2);
        assert_eq!(mkl.level_pages(0), 129);
        assert_eq!(mkl.level_pages(1), 2);
        assert_eq!(mkl.level_pages(2), 1);
        assert_eq!(mkl.level_pages(3), 0);
        assert_eq!(mkl.level_entries(0), 129);
        assert_eq!(mkl.level_entries(1), 129);
        assert_eq!(mkl.level_entries(2), 2);
        assert_eq!(mkl.level_entries(3), 0);
        assert_eq!(mkl.level_base(0), 4096 * 3);
        assert_eq!(mkl.level_base(1), 4096);
        assert_eq!(mkl.level_base(2), 0);
        assert_eq!(mkl.level_base(3), 0);
        assert_eq!(mkl.total_pages(), 3);

        let mkl = MerkleTree::new(4096, 128 * 128, Algorithm::Sha256);
        assert_eq!(mkl.max_levels(), 2);
        assert_eq!(mkl.level_pages(0), 128 * 128);
        assert_eq!(mkl.level_pages(1), 128);
        assert_eq!(mkl.level_pages(2), 1);
        assert_eq!(mkl.level_pages(3), 0);
        assert_eq!(mkl.level_base(0), 4096 * 129);
        assert_eq!(mkl.level_base(1), 4096);
        assert_eq!(mkl.level_base(2), 0);
        assert_eq!(mkl.level_base(3), 0);
        assert_eq!(mkl.total_pages(), 129);

        let mkl = MerkleTree::new(4096, 128 * 128 + 1, Algorithm::Sha256);
        assert_eq!(mkl.max_levels(), 3);
        assert_eq!(mkl.level_pages(0), 128 * 128 + 1);
        assert_eq!(mkl.level_pages(1), 129);
        assert_eq!(mkl.level_pages(2), 2);
        assert_eq!(mkl.level_pages(3), 1);
        assert_eq!(mkl.level_pages(4), 0);
        assert_eq!(mkl.level_entries(0), 128 * 128 + 1);
        assert_eq!(mkl.level_entries(1), 128 * 128 + 1);
        assert_eq!(mkl.level_entries(2), 129);
        assert_eq!(mkl.level_entries(3), 2);
        assert_eq!(mkl.level_entries(4), 0);
        assert_eq!(mkl.level_base(0), 4096 * 132);
        assert_eq!(mkl.level_base(1), 4096 * 3);
        assert_eq!(mkl.level_base(2), 4096);
        assert_eq!(mkl.level_base(3), 0);
        assert_eq!(mkl.level_base(4), 0);
        assert_eq!(mkl.total_pages(), 132);

        let mkl = MerkleTree::new(4096, u32::MAX, Algorithm::Sha256);
        assert_eq!(mkl.max_levels(), 5);
    }

    #[test]
    fn test_generate_mkl_tree_zero_entry() {
        let digest = RafsDigest::from_buf(&[0u8; 4096], Algorithm::Sha256);
        assert_eq!(digest, NON_EXIST_ENTRY_DIGEST);

        let file = TempFile::new().unwrap();
        let mut generator = VerityGenerator::new(file.into_file(), 0, 0).unwrap();

        assert!(generator
            .set_digest(0, 0, &NON_EXIST_ENTRY_DIGEST.data)
            .is_err());
        assert!(generator
            .set_digest(1, 0, &NON_EXIST_ENTRY_DIGEST.data)
            .is_err());

        let root_digest = generator.generate_all_digests().unwrap();
        assert_eq!(root_digest, NON_EXIST_ENTRY_DIGEST);
    }

    #[test]
    fn test_generate_mkl_tree_one_entry() {
        let file = TempFile::new().unwrap();
        let mut generator = VerityGenerator::new(file.into_file(), 0, 1).unwrap();

        let digest = RafsDigest::from_buf(&[1u8; 4096], Algorithm::Sha256);
        assert!(generator.set_digest(0, 0, &digest.data).is_err());
        assert!(generator.set_digest(2, 0, &digest.data).is_err());
        assert!(generator.set_digest(1, 1, &digest.data).is_err());
        generator.set_digest(1, 0, &digest.data).unwrap();

        let root_digest = generator.generate_all_digests().unwrap();
        assert_eq!(root_digest, digest);
    }

    #[test]
    fn test_generate_mkl_tree_two_entries() {
        let file = TempFile::new().unwrap();
        let mut generator = VerityGenerator::new(file.into_file(), 0, 2).unwrap();

        let digest = RafsDigest::from_buf(&[1u8; 4096], Algorithm::Sha256);
        assert!(generator.set_digest(0, 0, &digest.data).is_err());
        assert!(generator.set_digest(2, 0, &digest.data).is_err());
        assert!(generator.set_digest(1, 2, &digest.data).is_err());
        generator.set_digest(1, 0, &digest.data).unwrap();
        generator.set_digest(1, 1, &digest.data).unwrap();

        let root_digest = generator.generate_all_digests().unwrap();
        assert_ne!(root_digest, digest);
    }

    #[test]
    fn test_generate_mkl_tree_4097_entries() {
        let file = TempFile::new().unwrap();
        let mut generator = VerityGenerator::new(file.into_file(), 0, 4097).unwrap();

        let digest = RafsDigest::from_buf(&[1u8; 4096], Algorithm::Sha256);
        assert!(generator.set_digest(0, 0, &digest.data).is_err());
        generator.set_digest(2, 0, &digest.data).unwrap();
        for idx in 0..4097 {
            generator.set_digest(1, idx, &digest.data).unwrap();
        }

        let root_digest = generator.generate_all_digests().unwrap();
        assert_ne!(root_digest, digest);
        assert_eq!(generator.mkl_tree.max_levels, 2);
    }
}
