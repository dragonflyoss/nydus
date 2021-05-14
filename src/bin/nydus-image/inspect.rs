// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::mem::size_of;
use std::path::Path;

use rafs::metadata::layout::{OndiskBlobTable, OndiskInode, OndiskSuperBlock};
use rafs::{RafsIoRead, RafsIoReader};

pub(crate) struct RafsInspector<'a> {
    bootstrap: RafsIoReader,
    layout_profile: RafsLayoutV5,
    rafs_meta: RafsMeta,
    cur_dir_index: u32,
    parent_indexes: Vec<u32>,
    inode_table: MappedRafsInodeTable<'a>,
}

/// | Superblock | inode table | prefetch table |inode + name +symlink pointer + xattr pairs + chunk info
#[allow(dead_code)]
pub(crate) struct RafsLayoutV5 {
    super_block_offset: u32,
    super_block_size: u32,
    inode_size: u32,
    chunk_info_size: u32,
}

pub(crate) struct RafsMeta {
    inode_table_offset: u64,
    inode_table_size: u32,
    prefetch_table_offset: u64,
    blob_table_offset: u64,
    blob_table_size: u32,
}

impl From<&OndiskSuperBlock> for RafsMeta {
    fn from(sb: &OndiskSuperBlock) -> Self {
        Self {
            inode_table_offset: sb.inode_table_offset(),
            inode_table_size: sb.inode_table_entries() * size_of::<u32>() as u32,
            prefetch_table_offset: sb.prefetch_table_offset(),
            blob_table_offset: sb.blob_table_offset(),
            blob_table_size: sb.blob_table_size(),
        }
    }
}

impl RafsLayoutV5 {
    pub fn new() -> Self {
        RafsLayoutV5 {
            super_block_offset: 0,
            super_block_size: 8192,
            inode_size: 128,
            chunk_info_size: 80,
        }
    }
}

struct MappedRafsInodeTable<'a> {
    pub data: &'a [u32],
}

impl MappedRafsInodeTable<'_> {
    fn load(fd: i32, size: usize, offset: i64) -> Result<Self> {
        // Mmap the bootstrap file into current process for direct access
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ,
                libc::MAP_NORESERVE | libc::MAP_SHARED,
                fd,
                offset,
            )
        } as *const u32;

        if base as *mut core::ffi::c_void == libc::MAP_FAILED {
            return Err(anyhow!("failed to mmap inode table, {:?}", last_error!()));
        }
        if base.is_null() {
            return Err(anyhow!("failed to mmap inode table"));
        }

        // Safe because mmapped underlying memory won't be truncated and we won't
        // free memory through slice
        let slice = unsafe { std::slice::from_raw_parts(base, size) };

        Ok(Self { data: slice })
    }
}

pub enum Action {
    Break,
    Continue,
}

impl RafsInspector<'_> {
    pub fn new(b: &Path) -> Result<Self> {
        let layout_profile = RafsLayoutV5::new();
        let mut f = RafsIoRead::from_file(b)
            .map_err(|e| anyhow!("Can't find bootstrap, path={:?}, {:?}", b, e))?;
        let sb = Self::super_block(&mut f, &layout_profile).unwrap();
        let rafs_meta: RafsMeta = (&sb).into();
        let inode_table = MappedRafsInodeTable::load(
            f.as_raw_fd(),
            rafs_meta.inode_table_size as usize,
            rafs_meta.inode_table_offset as i64,
        )
        .unwrap();

        Ok(RafsInspector {
            bootstrap: f,
            layout_profile,
            rafs_meta,
            // Root inode has index of 0
            cur_dir_index: 0,
            parent_indexes: Vec::new(),
            inode_table,
        })
    }

    fn super_block(
        b: &mut RafsIoReader,
        layout_profile: &RafsLayoutV5,
    ) -> Result<OndiskSuperBlock> {
        let mut sb = OndiskSuperBlock::new();

        // Rafs super block always start from the very beginning of bootstrap.
        b.seek_to_offset(layout_profile.super_block_offset as u64)
            .unwrap();
        sb.load(b)
            .map_err(|e| anyhow!("Failed in loading super block, {:?}", e))?;

        Ok(sb)
    }

    /// Index is u32, by which the inode can be found.
    fn stat_inode(&mut self, index: usize) -> Result<(OndiskInode, OsString)> {
        // Safe to truncate `inode_table_offset` now.
        let inode_offset = self.inode_table.data[index] << 3;
        let mut ondisk_inode = OndiskInode::new();

        self.bootstrap.seek_to_offset(inode_offset as u64).unwrap();
        ondisk_inode.load(&mut self.bootstrap).map_err(|e| {
            anyhow!(
                "failed to jump to inode index={}, inode={}, {:?}",
                index,
                inode_offset,
                e
            )
        })?;

        // No need to move offset forward
        let file_name = ondisk_inode.file_name(&mut self.bootstrap).unwrap();
        Ok((ondisk_inode, file_name))
    }

    pub fn iter_dir(&mut self, mut op: impl FnMut(&OsStr, &OndiskInode, u32) -> Action) {
        let (dir_inode, _) = self.stat_inode(self.cur_dir_index as usize).unwrap();

        let children_count = dir_inode.i_child_count;
        let first_index = dir_inode.i_child_index;
        let last_index = first_index + children_count;

        for idx in first_index..=last_index {
            let (child_inode, name) = self.stat_inode(idx as usize).unwrap();
            trace!("inode: {:?}; name: {:?}", child_inode, name);
            match op(name.as_os_str(), &child_inode, idx) {
                Action::Break => break,
                Action::Continue => continue,
            }
        }
    }

    pub fn list_dir(&mut self) {
        self.iter_dir(|f, inode, _idx| {
            info!("inode {:?}, name: {:?}", inode, f);
            Action::Continue
        })
    }

    pub fn change_dir(&mut self, name: &str) {
        if name == "." {
            return;
        }

        if name == ".." {
            if let Some(p) = self.parent_indexes.pop() {
                self.cur_dir_index = p
            }
            return;
        }

        let mut new_dir_index = None;

        self.iter_dir(|f, _inode, idx| {
            if f == name {
                new_dir_index = Some(idx);
                return Action::Break;
            }
            Action::Continue
        });

        if let Some(n) = new_dir_index {
            self.parent_indexes.push(self.cur_dir_index);
            self.cur_dir_index = n;
        } else {
            println!("File does not exist");
        }
    }

    pub fn stats(&mut self) {
        let sb = Self::super_block(&mut self.bootstrap, &self.layout_profile).unwrap();
    }

    pub fn list_blobs(&mut self) {
        self.bootstrap
            .seek_to_offset(self.rafs_meta.blob_table_offset)
            .unwrap();

        let mut blobs = OndiskBlobTable::new();
        blobs
            .load(&mut self.bootstrap, self.rafs_meta.blob_table_size)
            .unwrap();
    }
}

pub(crate) struct Prompt {}

impl Prompt {
    pub(crate) fn run(mut inspector: RafsInspector) {
        loop {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();

            let mut raw = input.strip_suffix("\n").unwrap().split(' ');
            let cmd = raw.next().unwrap();
            let args = raw.next();

            info!("execute {:?} {:?}", cmd, args);

            if cmd == "exit" {
                break;
            }

            if cmd == "stats" {
                inspector.stats()
            }

            if cmd == "ls" {
                inspector.list_dir();
            }

            if cmd == "cd" {
                inspector.change_dir(args.unwrap())
            }
        }
    }
}
