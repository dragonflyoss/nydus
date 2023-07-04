// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::Permissions,
    io::{Error, ErrorKind, Write},
    ops::DerefMut,
    os::unix::prelude::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use nydus_api::ConfigV2;
use nydus_rafs::metadata::{RafsInode, RafsInodeExt, RafsInodeWalkAction, RafsSuper};
use nydus_rafs::RafsIoReader;
use nydus_storage::device::BlobChunkInfo;
use serde_json::Value;

pub(crate) struct RafsInspector {
    request_mode: bool,
    // Rafs Meta Data
    rafs_meta: RafsSuper,
    // Bootstrap
    bootstrap: Arc<Mutex<RafsIoReader>>,
    // The inode number of current directory
    cur_dir_ino: u64,
    // Inode numbers of parent directories
    parent_inodes: Vec<u64>,
    // Inode of parent directory for rafs v6 files
    file_parents: BTreeMap<u64, Vec<u64>>,
}

impl RafsInspector {
    // create the RafsInspector
    pub fn new(
        bootstrap_path: &Path,
        request_mode: bool,
        config: Arc<ConfigV2>,
    ) -> Result<Self, anyhow::Error> {
        let (rafs_meta, f) = RafsSuper::load_from_file(bootstrap_path, config, false)?;
        let root_ino = rafs_meta.superblock.root_ino();

        Ok(RafsInspector {
            request_mode,
            rafs_meta,
            bootstrap: Arc::new(Mutex::new(f)),
            cur_dir_ino: root_ino,
            parent_inodes: Vec::new(),
            file_parents: BTreeMap::new(),
        })
    }

    // Generate the files parent inode BTreeMap for rafs v6
    fn generate_file_parents(&mut self) -> anyhow::Result<()> {
        let mut file_parents = BTreeMap::new();
        self.walk_dir(
            self.rafs_meta.superblock.root_ino(),
            None,
            None,
            &mut |parent, inode, _| {
                if !inode.is_dir() {
                    if let Some(parent) = parent {
                        file_parents
                            .entry(inode.ino())
                            .or_insert_with(Vec::new)
                            .push(parent.ino());
                    }
                }
                Ok(())
            },
        )?;
        self.file_parents = file_parents;
        Ok(())
    }

    // Implement command "stats""
    // Print information of "RafsSuperMeta"
    fn cmd_stats(&mut self) -> Result<Option<Value>, anyhow::Error> {
        let o = if self.request_mode {
            Some(json!({"inodes_count": self.rafs_meta.meta.inodes_count}))
        } else {
            println!(
                r#"
    Version:                {version}
    Inodes Count:           {inodes_count}
    Chunk Size:             {chunk_size}KB
    Root Inode:             {root_inode}
    Flags:                  {flags}
    Blob table offset:      0x{blob_tbl_offset:x}
    Blob table size:        0x{blob_tbl_size:x}
    Prefetch table offset:  0x{prefetch_tbl_offset:x}
    Prefetch table entries: 0x{prefetch_tbl_entries:x}
    Chunk table offset:     0x{chunk_tbl_offset:x}
    Chunk table size:       0x{chunk_tbl_size:x}
    "#,
                version = self.rafs_meta.meta.version >> 8,
                inodes_count = self.rafs_meta.meta.inodes_count,
                chunk_size = self.rafs_meta.meta.chunk_size / 1024,
                flags = self.rafs_meta.meta.flags,
                root_inode = self.rafs_meta.superblock.root_ino(),
                blob_tbl_offset = self.rafs_meta.meta.blob_table_offset,
                blob_tbl_size = self.rafs_meta.meta.blob_table_size,
                prefetch_tbl_offset = self.rafs_meta.meta.prefetch_table_offset,
                prefetch_tbl_entries = self.rafs_meta.meta.prefetch_table_entries,
                chunk_tbl_offset = self.rafs_meta.meta.chunk_table_offset,
                chunk_tbl_size = self.rafs_meta.meta.chunk_table_size,
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
                return Ok(RafsInodeWalkAction::Continue);
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

            Ok(RafsInodeWalkAction::Continue)
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
            if let Some(parent_ino) = self.parent_inodes.pop() {
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
                Ok(RafsInodeWalkAction::Continue)
            } else {
                if child_inode.is_dir() {
                    new_dir_ino = Some(child_ino);
                } else {
                    err = "not a directory";
                }
                Ok(RafsInodeWalkAction::Break)
            }
        })?;

        if let Some(n) = new_dir_ino {
            self.parent_inodes.push(self.cur_dir_ino);
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
            let inode = self.rafs_meta.get_extended_inode(self.cur_dir_ino, false)?;
            let inode_parent = self.rafs_meta.get_extended_inode(inode.parent(), false)?;
            return self.stat_single_file(Some(inode_parent.as_ref()), inode.as_inode());
        }

        // Walk through children inodes to find the file
        // Print its basic information and all chunk infomation
        let dir_inode = self.rafs_meta.get_extended_inode(self.cur_dir_ino, false)?;
        dir_inode.walk_children_inodes(0, &mut |_inode, child_name, child_ino, _offset| {
            if child_name == file_name {
                // Print file information
                let child_inode = self.rafs_meta.get_inode(child_ino, false)?;
                if let Err(e) =
                    self.stat_single_file(Some(dir_inode.as_ref()), child_inode.as_ref())
                {
                    return Err(Error::new(ErrorKind::Other, e));
                }

                let child_inode = dir_inode.get_child_by_name(&child_name)?;
                // only reg_file can get and print chunk info
                if !child_inode.is_reg() {
                    return Ok(RafsInodeWalkAction::Break);
                }

                let mut chunks = Vec::<Arc<dyn BlobChunkInfo>>::new();
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
                        return Ok(RafsInodeWalkAction::Break);
                    };

                    // file_offset = chunk_index * chunk_size
                    let file_offset = i * self.rafs_meta.meta.chunk_size as usize;

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
                Ok(RafsInodeWalkAction::Break)
            } else {
                Ok(RafsInodeWalkAction::Continue)
            }
        })?;

        Ok(None)
    }

    // Implement command "blobs"
    fn cmd_list_blobs(&self) -> Result<Option<Value>, anyhow::Error> {
        let blob_infos = self.rafs_meta.superblock.get_blob_infos();
        let extra_infos = self
            .rafs_meta
            .superblock
            .get_blob_extra_infos()
            .unwrap_or_default();

        let mut value = json!([]);
        for blob_info in blob_infos.iter() {
            if self.request_mode {
                let v = json!({"blob_id": blob_info.blob_id(),
                                    "readahead_offset": blob_info.prefetch_offset(),
                                    "readahead_size": blob_info.prefetch_size(),
                                    "decompressed_size": blob_info.uncompressed_size(),
                                    "compressed_size": blob_info.compressed_size(),});
                value.as_array_mut().unwrap().push(v);
            } else {
                let mapped_blkaddr = extra_infos
                    .get(&blob_info.blob_id())
                    .map(|v| v.mapped_blkaddr)
                    .unwrap_or_default();
                print!(
                    r#"
Blob Index:             {blob_index}
Blob ID:                {blob_id}
Raw Blob ID:            {raw_blob_id}
Blob Size:              {blob_size}
Compressed Data Size:   {compressed_size}
Uncompressed Data Size: {uncompressed_size}
Mapped Block Address:   {mapped_blkaddr}
Features:               {features:?}
Compressor:             {compressor}
Digester:               {digester}
Cipher:                 {cipher}
Chunk Size:             0x{chunk_size:x}
Chunk Count:            {chunk_count}
Prefetch Table Offset:  {prefetch_tbl_offset}
Prefetch Table Size:    {prefetch_tbl_size}
Meta Compressor:        {meta_compressor}
Meta Offset:            {meta_offset}
Meta Compressed Size:   {meta_comp_size}
Meta Uncompressed Size: {meta_uncomp_size}
ToC Digest:             {toc_digest}
ToC Size:               {toc_size}
RAFS Blob Digest:       {rafs_digest}
RAFS Blob Size:         {rafs_size}
"#,
                    blob_index = blob_info.blob_index(),
                    blob_id = blob_info.blob_id(),
                    raw_blob_id = blob_info.raw_blob_id(),
                    features = blob_info.features(),
                    uncompressed_size = blob_info.uncompressed_size(),
                    blob_size = blob_info.compressed_size(),
                    compressed_size = blob_info.compressed_data_size(),
                    chunk_size = blob_info.chunk_size(),
                    chunk_count = blob_info.chunk_count(),
                    compressor = blob_info.compressor(),
                    digester = blob_info.digester(),
                    cipher = blob_info.cipher(),
                    prefetch_tbl_offset = blob_info.prefetch_offset(),
                    prefetch_tbl_size = blob_info.prefetch_size(),
                    meta_compressor = blob_info.meta_ci_compressor(),
                    meta_offset = blob_info.meta_ci_offset(),
                    meta_comp_size = blob_info.meta_ci_compressed_size(),
                    meta_uncomp_size = blob_info.meta_ci_uncompressed_size(),
                    toc_digest = hex::encode(blob_info.blob_toc_digest()),
                    toc_size = blob_info.blob_toc_size(),
                    rafs_digest = hex::encode(blob_info.blob_meta_digest()),
                    rafs_size = blob_info.blob_meta_size(),
                );
            }
        }

        if self.request_mode {
            return Ok(Some(value));
        }

        Ok(None)
    }

    // Convert an inode number to a file path.
    // For rafs v6, it will return all paths of the hard link file.
    fn path_from_ino(&mut self, ino: u64) -> Result<Vec<PathBuf>, anyhow::Error> {
        let inode = self.rafs_meta.superblock.get_inode(ino, false)?;
        let mut file_paths = Vec::new();
        if ino == self.rafs_meta.superblock.root_ino() {
            file_paths.push(PathBuf::from(
                self.rafs_meta
                    .superblock
                    .get_extended_inode(ino, false)?
                    .name(),
            ));
            return Ok(file_paths);
        }

        if self.rafs_meta.meta.is_v6() && !inode.is_dir() {
            if self.file_parents.is_empty() {
                self.generate_file_parents()?;
            }

            if let Some(parents) = self.file_parents.get(&ino) {
                for parent in parents {
                    let parent_inode = self
                        .rafs_meta
                        .superblock
                        .get_extended_inode(*parent, false)?;
                    let parent_path = self.rafs_meta.path_from_ino(*parent)?;
                    let child_count = parent_inode.get_child_count();
                    for idx in 0..child_count {
                        let child = parent_inode.get_child_by_index(idx)?;
                        if child.ino() == ino {
                            file_paths.push(parent_path.join(child.name()));
                            break;
                        }
                    }
                }
            }
        } else {
            let file_path = self.rafs_meta.path_from_ino(ino as u64)?;
            file_paths.push(file_path);
        };
        Ok(file_paths)
    }

    // Implement command "prefetch"
    fn cmd_list_prefetch(&mut self) -> Result<Option<Value>, anyhow::Error> {
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
                let path_string: Vec<String> = self
                    .path_from_ino(ino as u64)?
                    .iter()
                    .map(|x| String::from(x.to_string_lossy()))
                    .collect();

                println!(
                    r#"Inode Number:{inode_number:10} | Path: {path:?} "#,
                    path = path_string.join(" "),
                    inode_number = ino,
                );
            }
            None
        };

        Ok(o)
    }

    // Implement command "chunk"
    fn cmd_show_chunk(&self, offset_in_blob: u64) -> Result<Option<Value>, anyhow::Error> {
        self.rafs_meta.walk_directory::<PathBuf>(
            self.rafs_meta.superblock.root_ino(),
            None,
            &mut |inode: Arc<dyn RafsInodeExt>, _path: &Path| -> anyhow::Result<()> {
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

    #[allow(clippy::type_complexity)]
    /// Walkthrough the file tree rooted at ino, calling cb for each file or directory
    /// in the tree by DFS order, including ino, please ensure ino is a directory.
    fn walk_dir(
        &self,
        ino: u64,
        parent: Option<&PathBuf>,
        parent_inode_ext: Option<&dyn RafsInodeExt>,
        cb: &mut dyn FnMut(Option<&dyn RafsInodeExt>, &dyn RafsInode, &Path) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let inode = self.rafs_meta.superblock.get_extended_inode(ino, false)?;
        if !inode.is_dir() {
            bail!("inode {} is not a directory", ino);
        }
        self.walk_dir_inner(inode.as_ref(), parent, parent_inode_ext, cb)
    }

    #[allow(clippy::only_used_in_recursion, clippy::type_complexity)]
    fn walk_dir_inner(
        &self,
        inode: &dyn RafsInodeExt,
        parent: Option<&PathBuf>,
        parent_inode_ext: Option<&dyn RafsInodeExt>,
        cb: &mut dyn FnMut(Option<&dyn RafsInodeExt>, &dyn RafsInode, &Path) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let path = if let Some(parent) = parent {
            parent.join(inode.name())
        } else {
            PathBuf::from("/")
        };
        cb(parent_inode_ext, inode.as_inode(), &path)?;
        if !inode.is_dir() {
            return Ok(());
        }
        let child_count = inode.get_child_count();
        for idx in 0..child_count {
            let child = inode.get_child_by_index(idx)?;
            self.walk_dir_inner(child.as_ref(), Some(&path), Some(inode), cb)?;
        }
        Ok(())
    }

    // Implement command "icheck"
    fn cmd_check_inode(&mut self, ino: u64) -> Result<Option<Value>, anyhow::Error> {
        let current_inode = self.rafs_meta.superblock.get_inode(ino, false)?;
        if self.rafs_meta.meta.is_v6() && !current_inode.is_dir() {
            if self.file_parents.is_empty() {
                self.generate_file_parents()?;
            }

            if let Some(parents) = self.file_parents.get(&ino) {
                for parent in parents {
                    let parent_inode = self
                        .rafs_meta
                        .superblock
                        .get_extended_inode(*parent, false)?;
                    let parent_path = self.rafs_meta.path_from_ino(*parent)?;
                    let child_count = parent_inode.get_child_count();
                    for idx in 0..child_count {
                        let child = parent_inode.get_child_by_index(idx)?;
                        if child.ino() == ino {
                            let path = parent_path.join(child.name());
                            println!(r#"{}"#, path.to_string_lossy(),);
                            self.stat_single_file(
                                Some(parent_inode.as_ref()),
                                current_inode.as_ref(),
                            )?;
                            break;
                        }
                    }
                }
            }
        } else {
            self.walk_dir(
                self.rafs_meta.superblock.root_ino(),
                None,
                None,
                &mut |parent, inode, path| {
                    if inode.ino() == ino {
                        println!(r#"{}"#, path.to_string_lossy(),);
                        self.stat_single_file(parent, inode)?;
                    }
                    Ok(())
                },
            )?;
        }

        Ok(None)
    }
}

impl RafsInspector {
    /// Get file name of the inode, the rafs v6 file is handled separately.
    fn get_file_name(&self, parent_inode: &dyn RafsInodeExt, inode: &dyn RafsInode) -> OsString {
        let mut filename = OsString::from("");
        if self.rafs_meta.meta.is_v6() && !inode.is_dir() {
            parent_inode
                .walk_children_inodes(
                    0,
                    &mut |_inode: Option<Arc<dyn RafsInode>>, name: OsString, cur_ino, _offset| {
                        if cur_ino == inode.ino() {
                            filename = name;
                            Ok(RafsInodeWalkAction::Break)
                        } else {
                            Ok(RafsInodeWalkAction::Continue)
                        }
                    },
                )
                .unwrap();
        } else if let Ok(inode) = self
            .rafs_meta
            .superblock
            .get_extended_inode(inode.ino(), false)
        {
            filename = inode.name();
        }
        filename
    }

    // print information of single file
    fn stat_single_file(
        &self,
        parent_inode: Option<&dyn RafsInodeExt>,
        inode: &dyn RafsInode,
    ) -> Result<Option<Value>, anyhow::Error> {
        let inode_attr = inode.get_attr();

        if let Some(parent) = parent_inode {
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
                name = self.get_file_name(parent, inode),
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
        for b in blob_infos.iter() {
            if b.blob_index() == blob_index {
                return Ok(b.blob_id());
            }
        }
        Err(anyhow!("can not find blob by index: {}", blob_index))
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
    ) -> Result<Option<Value>, ExecuteError> {
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
            (cmd, _) => {
                println!("Unsupported command: {}", cmd);
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
    stats:              Display RAFS filesystesm metadata
    ls:                 Show files in current directory
    cd DIR:             Change current directory
    stat FILE_NAME:     Show particular information of RAFS file
    blobs:              Show blob table
    prefetch:           Show prefetch table
    chunk OFFSET:       List basic info of a single chunk together with a list of files that share it
    icheck INODE:       Show path of the inode and basic information
    exit:               Exit
        "#
        );
    }
}

pub(crate) struct Prompt {}

impl Prompt {
    pub(crate) fn run(mut inspector: RafsInspector) {
        loop {
            print!("Inspecting RAFS :> ");
            std::io::stdout().flush().unwrap();

            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();

            match Executor::execute(&mut inspector, input) {
                Err(ExecuteError::Exit) => break,
                Err(ExecuteError::IllegalCommand) => continue,
                Err(ExecuteError::HelpCommand) => continue,
                Err(ExecuteError::ExecError(e)) => {
                    println!("Failed to execute command, {:?}", e);
                    continue;
                }
                Ok(Some(o)) => {
                    serde_json::to_writer(std::io::stdout(), &o)
                        .unwrap_or_else(|e| error!("Failed to serialize message, {:?}", e));
                }
                _ => continue,
            }
        }
    }
}
