// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    ffi::OsString,
    fs::Permissions,
    io::{Error, ErrorKind, Write},
    ops::DerefMut,
    os::unix::prelude::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use nydus_rafs::{
    metadata::{PostWalkAction, RafsInode, RafsSuper},
    RafsIoRead, RafsIoReader,
};
use serde_json::Value;
use storage::device::BlobChunkInfo;

pub(crate) struct RafsInspector {
    request_mode: bool,
    // Rafs Meta Data
    rafs_meta: RafsSuper,
    // Bootstrap
    bootstrap: Arc<Mutex<RafsIoReader>>,
    // The inode number of current directory
    cur_dir_ino: u64,
    // Inode numbers of parent directories
    parent_inoes: Vec<u64>,
}

impl RafsInspector {
    // create the RafsInspector
    pub fn new(bootstrap_path: &Path, request_mode: bool) -> Result<Self, anyhow::Error> {
        // Load Bootstrap
        let mut f = <dyn RafsIoRead>::from_file(bootstrap_path)
            .map_err(|e| anyhow!("Can't find bootstrap, path={:?}, {:?}", bootstrap_path, e))?;

        // Load rafs_meta(RafsSuper) from bootstrap
        let mut rafs_meta = RafsSuper::default();
        rafs_meta
            .load(&mut f)
            .map_err(|e| anyhow!("Can't load bootstrap, error {:?}", e))?;

        // Get ino of root directory.
        let root_ino = rafs_meta.superblock.root_ino();

        Ok(RafsInspector {
            request_mode,
            rafs_meta,
            bootstrap: Arc::new(Mutex::new(f)),
            cur_dir_ino: root_ino,
            parent_inoes: Vec::new(),
        })
    }

    // Implement command "stats""
    // Print information of "RafsSuperMeta"
    fn cmd_stats(&mut self) -> Result<Option<Value>, anyhow::Error> {
        let o = if self.request_mode {
            Some(json!({"inodes_count": self.rafs_meta.meta.inodes_count}))
        } else {
            println!(
                r#"
    Version:            {version}
    Inodes Count:       {inodes_count}
    Chunk Size:         {chunk_size}KB
    Root Inode:         {root_inode}
    Flags:              {flags}"#,
                version = self.rafs_meta.meta.version >> 8,
                inodes_count = self.rafs_meta.meta.inodes_count,
                chunk_size = self.rafs_meta.meta.chunk_size / 1024,
                flags = self.rafs_meta.meta.flags,
                root_inode = self.rafs_meta.superblock.root_ino(),
            );
            None
        };
        Ok(o)
    }

    // Implement command "ls"
    // Walk_children_inodes with handler defined
    fn cmd_list_dir(&mut self) -> Result<Option<Value>, anyhow::Error> {
        let dir_inode = self.rafs_meta.get_inode(self.cur_dir_ino, false)?;

        // Entry_offset: 0, and skip 0
        dir_inode.walk_children_inodes(0, &mut |_inode, f, ino, _offset| {
            trace!("inode {:?}, name: {:?}", ino, f);

            if f == "." || f == ".." {
                return Ok(PostWalkAction::Continue);
            }

            let child_inode = self.rafs_meta.get_inode(ino, false)?;
            let sign = if child_inode.is_reg() {
                "-"
            } else if child_inode.is_dir() {
                "d"
            } else if child_inode.is_symlink() {
                "l"
            } else {
                " "
            };

            println!(
                r#"{}    {inode_number:<8} {name:?}"#,
                sign,
                name = f,
                inode_number = ino,
            );

            Ok(PostWalkAction::Continue)
        })?;

        Ok(None)
    }

    // Implement command "cd"
    // Change_dir to address relative to current directory
    fn cmd_change_dir(&mut self, dir_name: &str) -> Result<Option<Value>, anyhow::Error> {
        // Special path
        if dir_name == "." {
            return Ok(None);
        }
        if dir_name == ".." {
            // Parent_inodes is empty only when current directory is root,
            // so we do not have to handle the error case
            if let Some(parent_ino) = self.parent_inoes.pop() {
                self.cur_dir_ino = parent_ino;
            }
            return Ok(None);
        }

        // Walk through children inodes of current directory
        let mut new_dir_ino = None;
        let mut err = "";
        let dir_inodes = self.rafs_meta.get_inode(self.cur_dir_ino, false)?;
        dir_inodes.walk_children_inodes(0, &mut |_inode, child_name, child_ino, _offset| {
            let child_inode = self.rafs_meta.get_inode(child_ino, false)?;
            if child_name != dir_name {
                Ok(PostWalkAction::Continue)
            } else {
                if child_inode.is_dir() {
                    new_dir_ino = Some(child_ino);
                } else {
                    err = "not a directory";
                }
                Ok(PostWalkAction::Break)
            }
        })?;

        if let Some(n) = new_dir_ino {
            self.parent_inoes.push(self.cur_dir_ino);
            self.cur_dir_ino = n;
        } else {
            println!("{} is {}", dir_name, err);
        }

        Ok(None)
    }

    // Implement command "stat"
    fn cmd_stat_file(&self, file_name: &str) -> Result<Option<Value>, anyhow::Error> {
        // Stat current directory
        if file_name == "." {
            let inode = self.rafs_meta.get_inode(self.cur_dir_ino, false)?;
            return self.stat_single_file(Some(inode.parent()), self.cur_dir_ino);
        }

        // Walk through children inodes to find the file
        // Print its basic information and all chunk infomation
        let dir_inode = self.rafs_meta.get_inode(self.cur_dir_ino, false)?;
        dir_inode.walk_children_inodes(0, &mut |_inode, child_name, child_ino, _offset| {
            if child_name == file_name {
                // Print file information
                if let Err(e) = self.stat_single_file(Some(dir_inode.ino()), child_ino) {
                    return Err(Error::new(ErrorKind::Other, e));
                }

                let mut chunks = Vec::<Arc<dyn BlobChunkInfo>>::new();
                let child_inode = self.rafs_meta.get_inode(child_ino, false)?;

                // only reg_file can get and print chunk info
                if !child_inode.is_reg() {
                    return Ok(PostWalkAction::Break);
                }

                let chunk_count = child_inode.get_chunk_count();
                for idx in 0..chunk_count {
                    let cur_chunk = child_inode.get_chunk_info(idx)?;
                    chunks.push(cur_chunk);
                }

                println!("  Chunk list:");
                for (i, c) in chunks.iter().enumerate() {
                    let blob_id = if let Ok(id) = self.get_blob_id_by_index(c.blob_index()) {
                        id.to_owned()
                    } else {
                        error!(
                            "Blob index is {}. But no blob entry associate with it",
                            c.blob_index()
                        );
                        return Ok(PostWalkAction::Break);
                    };

                    // file_offset = chunk_index * chunk_size
                    let file_offset = c.id() * self.rafs_meta.meta.chunk_size;

                    println!(
                        r#"        {} ->
        file offset: {file_offset}, chunk index: {chunk_index}
        compressed size: {compressed_size}, decompressed size: {decompressed_size}
        compressed offset: {compressed_offset}, decompressed offset: {decompressed_offset}
        blob id: {blob_id} 
        chunk id: {chunk_id}
    "#,
                        i,
                        chunk_index = c.id(),
                        file_offset = file_offset,
                        compressed_size = c.compressed_size(),
                        decompressed_size = c.uncompressed_size(),
                        decompressed_offset = c.uncompressed_offset(),
                        compressed_offset = c.compressed_offset(),
                        blob_id = blob_id,
                        chunk_id = c.chunk_id()
                    );
                }

                Ok(PostWalkAction::Break)
            } else {
                Ok(PostWalkAction::Continue)
            }
        })?;

        Ok(None)
    }

    // Implement command "blobs"
    fn cmd_list_blobs(&self) -> Result<Option<Value>, anyhow::Error> {
        let blob_infos = self.rafs_meta.superblock.get_blob_infos();

        let mut value = json!([]);
        for (_i, blob_info) in blob_infos.iter().enumerate() {
            if self.request_mode {
                let v = json!({"blob_id": blob_info.blob_id(), 
                                    "readahead_offset": blob_info.readahead_offset(),
                                    "readahead_size": blob_info.readahead_size(),
                                    "decompressed_size": blob_info.uncompressed_size(),
                                    "compressed_size": blob_info.compressed_size(),});
                value.as_array_mut().unwrap().push(v);
            } else {
                print!(
                    r#"
Blob ID:            {blob_id}
Readahead Offset:   {readahead_offset}
Readahead Size:     {readahead_size}
Cache Size:         {cache_size}
Compressed Size:    {compressed_size}
"#,
                    blob_id = blob_info.blob_id(),
                    readahead_offset = blob_info.readahead_offset(),
                    readahead_size = blob_info.readahead_size(),
                    cache_size = blob_info.uncompressed_size(),
                    compressed_size = blob_info.compressed_size(),
                );
            }
        }

        if self.request_mode {
            return Ok(Some(value));
        }

        Ok(None)
    }

    // Convert an inode number to a file path, the rafs v6 file is handled separately.
    fn path_from_ino(&self, ino: u64) -> Result<PathBuf, anyhow::Error> {
        let inode = self.rafs_meta.superblock.get_inode(ino, false)?;
        if ino == self.rafs_meta.superblock.root_ino() {
            return Ok(self
                .rafs_meta
                .superblock
                .get_inode(ino, false)?
                .name()
                .into());
        }

        let mut file_path = PathBuf::from("");
        if self.rafs_meta.meta.is_v6() && !inode.is_dir() {
            self.rafs_meta.walk_dir(
                self.rafs_meta.superblock.root_ino(),
                None,
                &mut |inode, path| {
                    if inode.ino() == ino {
                        file_path = PathBuf::from(path);
                    }
                    Ok(())
                },
            )?;
        } else {
            file_path = self.rafs_meta.path_from_ino(ino as u64)?;
        };
        Ok(file_path)
    }

    // Implement command "prefetch"
    fn cmd_list_prefetch(&self) -> Result<Option<Value>, anyhow::Error> {
        let mut guard = self.bootstrap.lock().unwrap();
        let bootstrap = guard.deref_mut();
        let prefetch_inos = self.rafs_meta.get_prefetched_inos(bootstrap)?;
        drop(guard);

        let o = if self.request_mode {
            let mut value = json!([]);
            for ino in prefetch_inos {
                let path = self.path_from_ino(ino as u64)?;
                let v = json!({"inode": ino, "path": path});
                value.as_array_mut().unwrap().push(v);
            }
            Some(value)
        } else {
            println!(
                "Total Prefetching Files: {}",
                self.rafs_meta.meta.prefetch_table_entries
            );
            for ino in prefetch_inos {
                let path = self.path_from_ino(ino as u64)?;
                println!(
                    r#"Inode Number:{inode_number:10} | Path: {path:?} "#,
                    path = path,
                    inode_number = ino,
                );
            }
            None
        };

        Ok(o)
    }

    // Implement command "chunk"
    fn cmd_show_chunk(&self, offset_in_blob: u64) -> Result<Option<Value>, anyhow::Error> {
        self.rafs_meta.walk_dir(
            self.rafs_meta.superblock.root_ino(),
            None,
            &mut |inode: &dyn RafsInode, _path: &Path| -> anyhow::Result<()> {
                // only regular file has data chunks
                if !inode.is_reg() {
                    return Ok(());
                }

                // walk through chunks of current file
                let chunk_count = inode.get_chunk_count();
                for idx in 0..chunk_count {
                    let cur_chunk = inode.get_chunk_info(idx)?;
                    if cur_chunk.compressed_offset() == offset_in_blob {
                        let path = self.rafs_meta.path_from_ino(inode.parent()).unwrap();
                        let block_id = if let Ok(blob_id) =
                            self.get_blob_id_by_index(cur_chunk.blob_index())
                        {
                            blob_id.to_owned()
                        } else {
                            return Err(anyhow!(
                                "Can't find blob by its index, index={:?}",
                                cur_chunk.blob_index()
                            ));
                        };

                        println!(
                            r#"
File: {:width$} Parent Path: {:width$}
Compressed Offset: {}, Compressed Size: {}
Decompressed Offset: {}, Decompressed Size: {}
Chunk ID: {:50}, 
Blob ID: {}
"#,
                            inode.name().to_string_lossy(),
                            path.to_string_lossy(),
                            cur_chunk.compressed_offset(),
                            cur_chunk.compressed_size(),
                            cur_chunk.uncompressed_offset(),
                            cur_chunk.uncompressed_size(),
                            cur_chunk.chunk_id(),
                            block_id,
                            width = 32
                        );
                    }
                }
                Ok(())
            },
        )?;

        Ok(None)
    }

    /// Walkthrough the file tree rooted at ino, calling cb for each file or directory
    /// in the tree by DFS order, including ino, please ensure ino is a directory.
    fn walk_dir(
        &self,
        ino: u64,
        parent: Option<&PathBuf>,
        parent_ino: Option<u64>,
        cb: &mut dyn FnMut(Option<u64>, &dyn RafsInode, &Path) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let inode = self.rafs_meta.superblock.get_inode(ino, false)?;
        if !inode.is_dir() {
            bail!("inode {} is not a directory", ino);
        }
        self.walk_dir_inner(inode.as_ref(), parent, parent_ino, cb)
    }

    fn walk_dir_inner(
        &self,
        inode: &dyn RafsInode,
        parent: Option<&PathBuf>,
        parent_ino: Option<u64>,
        cb: &mut dyn FnMut(Option<u64>, &dyn RafsInode, &Path) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let path = if let Some(parent) = parent {
            parent.join(inode.name())
        } else {
            PathBuf::from("/")
        };
        cb(parent_ino, inode, &path)?;
        if !inode.is_dir() {
            return Ok(());
        }
        let child_count = inode.get_child_count();
        for idx in 0..child_count {
            let child = inode.get_child_by_index(idx)?;
            self.walk_dir_inner(child.as_ref(), Some(&path), Some(inode.ino()), cb)?;
        }
        Ok(())
    }

    // Implement command "icheck"
    fn cmd_check_inode(&self, ino: u64) -> Result<Option<Value>, anyhow::Error> {
        self.walk_dir(
            self.rafs_meta.superblock.root_ino(),
            None,
            None,
            &mut |parent, inode, path| {
                if inode.ino() == ino {
                    println!(r#"{}"#, path.to_string_lossy(),);
                    self.stat_single_file(parent, ino)?;
                }
                Ok(())
            },
        )?;
        Ok(None)
    }
}

impl RafsInspector {
    /// Get file name of the inode, the rafs v6 file is handled separately.
    fn get_file_name(&self, parent_inode: &dyn RafsInode, inode: &dyn RafsInode) -> OsString {
        let mut filename = OsString::from("");
        if self.rafs_meta.meta.is_v6() && !inode.is_dir() {
            parent_inode
                .walk_children_inodes(
                    0,
                    &mut |_inode: Option<Arc<dyn RafsInode>>, name: OsString, cur_ino, _offset| {
                        if cur_ino == inode.ino() {
                            filename = name;
                        }
                        Ok(PostWalkAction::Continue)
                    },
                )
                .unwrap();
        } else {
            filename = inode.name();
        }
        filename
    }

    // print information of single file
    fn stat_single_file(
        &self,
        parent_ino: Option<u64>,
        ino: u64,
    ) -> Result<Option<Value>, anyhow::Error> {
        // get RafsInode of current ino
        let inode = self.rafs_meta.get_inode(ino, false)?;
        let inode_attr = inode.get_attr();

        if let Some(parent_ino) = parent_ino {
            let parent = self.rafs_meta.superblock.get_inode(parent_ino, false)?;
            println!(
                r#"
Inode Number:       {inode_number}
Name:               {name:?}
Size:               {size}
Parent:             {parent}
Mode:               0x{mode:X}
Permissions:        {permissions:o}
Nlink:              {nlink}
UID:                {uid}
GID:                {gid}
Mtime:              {mtime}
MtimeNsec:          {mtime_nsec}
Blocks:             {blocks}"#,
                inode_number = inode.ino(),
                name = self.get_file_name(parent.as_ref(), inode.as_ref()),
                size = inode.size(),
                parent = parent.ino(),
                mode = inode_attr.mode,
                permissions = Permissions::from_mode(inode_attr.mode).mode(),
                nlink = inode_attr.nlink,
                uid = inode_attr.uid,
                gid = inode_attr.gid,
                mtime = inode_attr.mtime,
                mtime_nsec = inode_attr.mtimensec,
                blocks = inode_attr.blocks,
            );
        }

        Ok(None)
    }

    // Match blobinfo by using blob index
    fn get_blob_id_by_index(&self, blob_index: u32) -> Result<String, anyhow::Error> {
        let blob_infos = self.rafs_meta.superblock.get_blob_infos();
        for (_i, b) in blob_infos.iter().enumerate() {
            if b.blob_index() == blob_index {
                return Ok(b.blob_id().to_owned());
            }
        }
        Err(anyhow!("can not find blob info by index: {}", blob_index))
    }
}

#[derive(Debug)]
pub(crate) enum ExecuteError {
    HelpCommand,
    IllegalCommand,
    ArgumentParse,
    Exit,
    ExecError(anyhow::Error),
}

pub(crate) struct Executor {}

impl Executor {
    pub fn execute(
        inspector: &mut RafsInspector,
        input: String,
    ) -> std::result::Result<Option<Value>, ExecuteError> {
        let mut raw = input
            .strip_suffix('\n')
            .unwrap_or(&input)
            .split_ascii_whitespace();
        let cmd = match raw.next() {
            Some(c) => c,
            None => return Ok(None),
        };
        let args = raw.next().map(|a| a.trim());

        debug!("execute {:?} {:?}", cmd, args);

        let output = match (cmd, args) {
            ("help", _) => {
                Self::usage();
                return Err(ExecuteError::HelpCommand);
            }
            ("exit", _) | ("q", _) => return Err(ExecuteError::Exit),
            ("stats", None) => inspector.cmd_stats(),
            ("ls", None) => inspector.cmd_list_dir(),
            ("cd", Some(dir)) => inspector.cmd_change_dir(dir),
            ("stat", Some(file_name)) => inspector.cmd_stat_file(file_name),
            ("blobs", None) => inspector.cmd_list_blobs(),
            ("prefetch", None) => inspector.cmd_list_prefetch(),
            ("chunk", Some(argument)) => {
                let offset: u64 = argument.parse().unwrap();
                inspector.cmd_show_chunk(offset)
            }
            ("icheck", Some(argument)) => {
                let ino: u64 = argument.parse().map_err(|_| {
                    println!("Wrong INODE is specified. Is it a inode number?");
                    ExecuteError::ArgumentParse
                })?;
                inspector.cmd_check_inode(ino)
            }
            _ => {
                println!("Unsupported command!");
                {
                    Self::usage();
                    return Err(ExecuteError::IllegalCommand);
                };
            }
        }
        .map_err(ExecuteError::ExecError)?;

        Ok(output)
    }

    pub(crate) fn usage() {
        println!(
            r#"
    stats:              Display global rafs metadata
    ls:                 Show files in current directory
    cd DIR:             Change current directory
    stat FILE_NAME:     Show particular information of rafs inode
    blobs:              Show blobs table
    prefetch:           Show prefetch table
    chunk OFFSET:       List basic info of a single chunk together with a list of files that share it
    icheck INODE:       Show path of the inode and basic information
        "#
        );
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

            match Executor::execute(&mut inspector, input) {
                Err(ExecuteError::Exit) => break,
                Err(ExecuteError::IllegalCommand) => continue,
                Err(ExecuteError::HelpCommand) => continue,
                Err(ExecuteError::ExecError(e)) => {
                    println!("Failed in executing command, {:?}", e);
                    continue;
                }
                Ok(Some(o)) => {
                    serde_json::to_writer(std::io::stdout(), &o)
                        .unwrap_or_else(|e| error!("Failed to serialize, {:?}", e));
                }
                _ => continue,
            }
        }
    }
}
