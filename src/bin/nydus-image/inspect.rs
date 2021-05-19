// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};

use rafs::metadata::layout::{
    OndiskBlobTable, OndiskInode, OndiskInodeTable, OndiskSuperBlock, PrefetchTable,
};
use rafs::{RafsIoRead, RafsIoReader};

pub(crate) struct RafsInspector {
    bootstrap: RafsIoReader,
    layout_profile: RafsLayoutV5,
    rafs_meta: RafsMeta,
    cur_dir_index: u32,
    parent_indexes: Vec<u32>,
    inodes_table: OndiskInodeTable,
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
    inode_table_entries: u32,
    prefetch_table_offset: u64,
    prefetch_table_entries: u32,
    blob_table_offset: u64,
    blob_table_size: u32,
}

impl From<&OndiskSuperBlock> for RafsMeta {
    fn from(sb: &OndiskSuperBlock) -> Self {
        Self {
            inode_table_offset: sb.inode_table_offset(),
            inode_table_entries: sb.inode_table_entries(),
            prefetch_table_offset: sb.prefetch_table_offset(),
            blob_table_offset: sb.blob_table_offset(),
            blob_table_size: sb.blob_table_size(),
            prefetch_table_entries: sb.prefetch_table_entries(),
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

pub enum Action {
    Break,
    Continue,
}

impl RafsInspector {
    pub fn new(b: &Path) -> Result<Self> {
        let layout_profile = RafsLayoutV5::new();
        let mut f = RafsIoRead::from_file(b)
            .map_err(|e| anyhow!("Can't find bootstrap, path={:?}, {:?}", b, e))?;
        let sb = Self::super_block(&mut f, &layout_profile).unwrap();
        let rafs_meta: RafsMeta = (&sb).into();

        let mut inodes_table = OndiskInodeTable::new(rafs_meta.inode_table_entries as usize);
        f.seek_to_offset(rafs_meta.inode_table_offset).unwrap();
        inodes_table.load(&mut f).unwrap();

        Ok(RafsInspector {
            bootstrap: f,
            layout_profile,
            rafs_meta,
            // Root inode has index of 0
            cur_dir_index: 0,
            parent_indexes: Vec::new(),
            inodes_table,
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

    fn info_prefetch(&mut self) {
        let mut pt = PrefetchTable::new();
        pt.load_prefetch_table_from(
            &mut self.bootstrap,
            self.rafs_meta.prefetch_table_offset,
            self.rafs_meta.prefetch_table_entries as usize,
        )
        .unwrap();
        println!(
            "Prefetched Files: {}",
            self.rafs_meta.prefetch_table_entries
        );

        for ino in pt.inodes {
            let path = self.path_from_ino(ino as u64).unwrap();
            println!(
                r#"Inode Number:{inode_number:10}   |   Path: {path:?} "#,
                path = path,
                inode_number = ino,
            );
        }
    }

    fn load_ondisk_inode(&mut self, offset: u32) -> Result<(OndiskInode, OsString)> {
        let mut ondisk_inode = OndiskInode::new();
        self.bootstrap.seek_to_offset(offset as u64).unwrap();
        ondisk_inode
            .load(&mut self.bootstrap)
            .map_err(|e| anyhow!("failed to jump to inode offset={}, {:?}", offset, e))?;

        // No need to move offset forward
        let file_name = ondisk_inode.file_name(&mut self.bootstrap).unwrap();

        Ok((ondisk_inode, file_name))
    }

    fn path_from_ino(&mut self, mut ino: u64) -> Result<PathBuf> {
        let mut path = PathBuf::new();
        let mut entries = Vec::<PathBuf>::new();

        loop {
            let offset = self.inodes_table.get(ino).unwrap();
            let (inode, file_name) = self.load_ondisk_inode(offset).unwrap();
            entries.push(file_name.into());
            if inode.i_parent == 0 {
                break;
            }
            ino = inode.i_parent;
        }
        entries.reverse();
        for e in entries {
            path.push(e);
        }

        Ok(path)
    }

    /// Index is u32, by which the inode can be found.
    fn stat_inode(&mut self, index: usize) -> Result<(OndiskInode, OsString)> {
        // Safe to truncate `inode_table_offset` now.
        let inode_offset = self.inodes_table.data[index] << 3;

        self.load_ondisk_inode(inode_offset)
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

    pub fn stat_by_name(&mut self, name: &str) {
        self.iter_dir(|f, inode, idx| {
            if f == name {
                println!(
                    r#"
    Inode Number:       {inode_number}
    Index:              {index}
    Name:               {name:?}
    Size:               {size}
    Mode:               {mode}
    Nlink:              {nlink}
    UID:                {uid}
    GID:                {gid}
    Blocks:             {blocks}"#,
                    inode_number = inode.i_ino,
                    name = f,
                    index = idx,
                    size = inode.i_size,
                    mode = inode.i_mode,
                    nlink = inode.i_nlink,
                    uid = inode.i_uid,
                    gid = inode.i_gid,
                    blocks = inode.i_blocks,
                );
                return Action::Break;
            }
            Action::Continue
        });
    }

    pub fn list_dir(&mut self) {
        self.iter_dir(|f, inode, _idx| {
            trace!("inode {:?}, name: {:?}", inode, f);

            println!(
                r#"     {inode_number}            {name:?}"#,
                name = f,
                inode_number = inode.i_ino,
            );

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
        println!(
            r#"
    Version:            {version}
    Inodes Count:       {inodes_count}
    Flags:              {flags}"#,
            version = sb.version(),
            inodes_count = sb.inodes_count(),
            flags = sb.flags()
        )
    }

    pub fn list_blobs(&mut self) {
        self.bootstrap
            .seek_to_offset(self.rafs_meta.blob_table_offset)
            .unwrap();

        let mut blobs = OndiskBlobTable::new();
        blobs
            .load(&mut self.bootstrap, self.rafs_meta.blob_table_size)
            .unwrap();

        for b in blobs.entries {
            println!(
                r#"
    Blob ID:            {blob_id}
    Readahead Offset:   {readahead_offset}
    Readahead Size:     {readahead_size}"#,
                blob_id = b.blob_id,
                readahead_offset = b.readahead_offset,
                readahead_size = b.readahead_size,
            )
        }
    }
}

pub(crate) struct Prompt {}

impl Prompt {
    pub(crate) fn run(mut inspector: RafsInspector) {
        loop {
            print!("Inspecting Rafs :> ");
            std::io::stdout().flush().unwrap();

            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();

            let mut raw = input.strip_suffix("\n").unwrap().split(' ');
            let cmd = raw.next().unwrap();
            let args = raw.next();

            debug!("execute {:?} {:?}", cmd, args);

            if cmd == "exit" || cmd == "quit" || cmd == "q" {
                break;
            }

            match cmd {
                "help" => Self::usage(),
                "stats" => inspector.stats(),
                "ls" => inspector.list_dir(),
                "cd" => inspector.change_dir(args.unwrap()),
                "stat" => inspector.stat_by_name(args.unwrap()),
                "blobs" => inspector.list_blobs(),
                "prefetch" => inspector.info_prefetch(),
                _ => {
                    println!("Unsupported command");
                    Self::usage()
                }
            }
        }
    }

    pub(crate) fn usage() {}
}
