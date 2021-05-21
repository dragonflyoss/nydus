// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::Value;

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
        let sb = Self::super_block(&mut f, &layout_profile)?;
        let rafs_meta: RafsMeta = (&sb).into();

        let mut inodes_table = OndiskInodeTable::new(rafs_meta.inode_table_entries as usize);
        f.seek_to_offset(rafs_meta.inode_table_offset)?;
        inodes_table.load(&mut f)?;

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

        b.seek_to_offset(layout_profile.super_block_offset as u64)?;
        sb.load(b)
            .map_err(|e| anyhow!("Failed in loading super block, {:?}", e))?;

        Ok(sb)
    }

    fn load_ondisk_inode(&mut self, offset: u32) -> Result<(OndiskInode, OsString)> {
        let mut ondisk_inode = OndiskInode::new();
        self.bootstrap.seek_to_offset(offset as u64)?;
        ondisk_inode
            .load(&mut self.bootstrap)
            .map_err(|e| anyhow!("failed to jump to inode offset={}, {:?}", offset, e))?;

        // No need to move offset forward
        let file_name = ondisk_inode.file_name(&mut self.bootstrap)?;

        Ok((ondisk_inode, file_name))
    }

    /// Index is u32, by which the inode can be found.
    fn load_inode_by_index(&mut self, index: usize) -> Result<(OndiskInode, OsString)> {
        // Safe to truncate `inode_table_offset` now.
        let inode_offset = self.inodes_table.data[index] << 3;
        self.load_ondisk_inode(inode_offset)
    }

    pub fn cmd_list_dir(&mut self) -> Result<Option<Value>> {
        self.iter_dir(|f, inode, _idx| {
            trace!("inode {:?}, name: {:?}", inode, f);

            println!(
                r#"     {inode_number}            {name:?}"#,
                name = f,
                inode_number = inode.i_ino,
            );

            Action::Continue
        })?;

        Ok(None)
    }

    pub fn iter_dir(
        &mut self,
        mut op: impl FnMut(&OsStr, &OndiskInode, u32) -> Action,
    ) -> Result<()> {
        let (dir_inode, _) = self.load_inode_by_index(self.cur_dir_index as usize)?;

        let children_count = dir_inode.i_child_count;
        let first_index = dir_inode.i_child_index;
        let last_index = first_index + children_count;

        for idx in first_index..=last_index {
            let (child_inode, name) = self.load_inode_by_index(idx as usize)?;
            trace!("inode: {:?}; name: {:?}", child_inode, name);
            match op(name.as_os_str(), &child_inode, idx) {
                Action::Break => break,
                Action::Continue => continue,
            }
        }

        Ok(())
    }

    fn path_from_ino(&mut self, mut ino: u64) -> Result<PathBuf> {
        let mut path = PathBuf::new();
        let mut entries = Vec::<PathBuf>::new();

        loop {
            let offset = self.inodes_table.get(ino)?;
            let (inode, file_name) = self.load_ondisk_inode(offset)?;
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

    fn cmd_list_prefetch(&mut self) -> Result<Option<Value>> {
        let mut pt = PrefetchTable::new();
        pt.load_prefetch_table_from(
            &mut self.bootstrap,
            self.rafs_meta.prefetch_table_offset,
            self.rafs_meta.prefetch_table_entries as usize,
        )?;
        println!(
            "Prefetched Files: {}",
            self.rafs_meta.prefetch_table_entries
        );

        for ino in pt.inodes {
            let path = self.path_from_ino(ino as u64)?;
            println!(
                r#"Inode Number:{inode_number:10}   |   Path: {path:?} "#,
                path = path,
                inode_number = ino,
            );
        }

        Ok(None)
    }

    pub fn cmd_stat_file(&mut self, name: &str) -> Result<Option<Value>> {
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
        })?;

        Ok(None)
    }

    pub fn cmd_change_dir(&mut self, name: &str) -> Result<Option<Value>> {
        if name == "." {
            return Ok(None);
        }

        if name == ".." {
            if let Some(p) = self.parent_indexes.pop() {
                self.cur_dir_index = p
            }
            return Ok(None);
        }

        let mut new_dir_index = None;

        self.iter_dir(|f, _inode, idx| {
            if f == name {
                new_dir_index = Some(idx);
                return Action::Break;
            }
            Action::Continue
        })?;

        if let Some(n) = new_dir_index {
            self.parent_indexes.push(self.cur_dir_index);
            self.cur_dir_index = n;
        } else {
            println!("File does not exist");
        }

        Ok(None)
    }

    pub fn cmd_stats(&mut self) -> Result<Option<Value>> {
        let sb = Self::super_block(&mut self.bootstrap, &self.layout_profile)?;

        println!(
            r#"
    Version:            {version}
    Inodes Count:       {inodes_count}
    Flags:              {flags}"#,
            version = sb.version(),
            inodes_count = sb.inodes_count(),
            flags = sb.flags()
        );

        Ok(None)
    }

    pub fn cmd_list_blobs(&mut self) -> Result<Option<Value>> {
        self.bootstrap
            .seek_to_offset(self.rafs_meta.blob_table_offset)?;

        let mut blobs = OndiskBlobTable::new();
        blobs.load(&mut self.bootstrap, self.rafs_meta.blob_table_size)?;

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

        Ok(None)
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

            let output = match (cmd, args) {
                ("help", None) => Self::usage(),
                ("stats", None) => inspector.cmd_stats(),
                ("ls", None) => inspector.cmd_list_dir(),
                ("cd", Some(dir)) => inspector.cmd_change_dir(dir),
                ("stat", Some(file_name)) => inspector.cmd_stat_file(file_name),
                ("blobs", None) => inspector.cmd_list_blobs(),
                ("prefetch", None) => inspector.cmd_list_prefetch(),
                _ => {
                    println!("Unsupported command or argument is needed!");
                    Self::usage()
                }
            };

            if let Ok(Some(o)) = output {
                serde_json::to_writer(std::io::stdout(), &o)
                    .unwrap_or_else(|e| error!("Failed to serialize, {:?}", e));
            } else if let Err(e) = output {
                println!("Failed in executing command, {:?}", e);
            } else {
            }
        }
    }

    pub(crate) fn usage() -> Result<Option<Value>> {
        Ok(None)
    }
}
