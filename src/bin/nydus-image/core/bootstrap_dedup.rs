// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::io::SeekFrom;
use std::mem::size_of;
use std::path::{Path, PathBuf};

use anyhow::Result;

use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::layout::v5::{RafsV5ChunkInfo, RafsV5InodeTable, RafsV5XAttrsTable};
use nydus_rafs::metadata::layout::v6::{
    align_offset, RafsV6InodeChunkAddr, EROFS_BLOCK_SIZE, EROFS_INODE_SLOT_SIZE,
};
use nydus_rafs::metadata::{RafsMode, RafsSuper, RafsVersion};
use nydus_rafs::{RafsIoReader, RafsIoWrite};
use nydus_storage::device::BlobInfo;
use nydus_utils::cas::CasMgr;
use nydus_utils::digest::RafsDigest;

use crate::anyhow::Context;
use crate::core::bootstrap::Bootstrap;
use crate::core::context::{
    ArtifactFileWriter, ArtifactWriter, BlobContext, BlobManager, BuildContext, ConversionType,
};
use crate::core::feature::Features;
use crate::node::{ChunkSource, Node, WhiteoutSpec};
use crate::tree::Tree;
use crate::ArtifactStorage;

pub struct BootstrapDedup {
    cas_mgr: CasMgr,
    rs: RafsSuper,
    cache_chunks: HashMap<RafsDigest, ChunkWrapper>,
    insert_chunks: Vec<(String, String, String)>,
    insert_blobs: Vec<(String, String)>,
    reader: RafsIoReader,
    writer: Box<dyn RafsIoWrite>,
}

impl BootstrapDedup {
    pub fn new(
        bootstrap_path: PathBuf,
        output_path: PathBuf,
        work_dir: impl AsRef<Path>,
    ) -> Result<Self> {
        let rs = RafsSuper::load_from_metadata(&bootstrap_path, RafsMode::Direct, true)?;
        let cas_mgr = CasMgr::new(work_dir)?;
        let cache_chunks = HashMap::new();
        let insert_chunks = vec![];
        let insert_blobs = vec![];

        fs::copy(&bootstrap_path, &output_path)?;

        let reader = Box::new(
            fs::OpenOptions::new()
                .read(true)
                .write(false)
                .open(&bootstrap_path)?,
        ) as RafsIoReader;

        let writer = Box::new(ArtifactFileWriter(ArtifactWriter::new(
            ArtifactStorage::SingleFile(PathBuf::from(&output_path)),
            true,
        )?)) as Box<dyn RafsIoWrite>;

        Ok(BootstrapDedup {
            cas_mgr,
            rs,
            cache_chunks,
            insert_chunks,
            insert_blobs,
            reader,
            writer,
        })
    }

    fn get_chunk_ofs(&mut self, node: &Node) -> Result<(u64, u64)> {
        if self.rs.meta.is_v5() {
            let unit = size_of::<RafsV5ChunkInfo>() as u64;

            let mut inodes_table = RafsV5InodeTable::new(self.rs.meta.inode_table_entries as usize);
            self.reader
                .seek_to_offset(self.rs.meta.inode_table_offset)?;
            inodes_table.load(&mut self.reader)?;

            let chunk_idx_offset = inodes_table.get(node.src_ino)?;
            let mut chunk_ofs = (chunk_idx_offset + node.inode.inode_size() as u32) as u64;
            if node.inode.has_xattr() {
                chunk_ofs +=
                    (size_of::<RafsV5XAttrsTable>() + node.xattrs.aligned_size_v5()) as u64;
            }

            Ok((chunk_ofs, unit))
        } else if self.rs.meta.is_v6() {
            let unit = size_of::<RafsV6InodeChunkAddr>() as u64;

            let chunk_idx_offset = self.rs.meta.meta_blkaddr as u64 * EROFS_BLOCK_SIZE
                + node.src_ino * EROFS_INODE_SLOT_SIZE as u64;
            let chunk_ofs = align_offset(chunk_idx_offset + node.v6_size_with_xattr() as u64, unit);

            Ok((chunk_ofs, unit))
        } else {
            unimplemented!()
        }
    }

    fn do_chunk_dedup(
        &mut self,
        nodes: Vec<Node>,
        build_ctx: &BuildContext,
        blob_mgr: &mut BlobManager,
    ) -> Result<()> {
        for node in nodes {
            let (mut chunk_ofs, chunk_size) = self.get_chunk_ofs(&node)?;

            for chunk in &node.chunks {
                let chunk_id = chunk.inner.id();
                let blob_id = blob_mgr
                    .get_blob_id_by_idx(chunk.inner.blob_index() as usize)
                    .unwrap();
                self.writer
                    .seek(SeekFrom::Start(chunk_ofs))
                    .context("failed seek for chunk_ofs")
                    .unwrap();

                match self.cache_chunks.get(chunk_id) {
                    //dedup chunk between layers
                    Some(new_chunk) => node.dedup_bootstrap(new_chunk, self.writer.as_mut())?,
                    None => match self.cas_mgr.get_chunk(chunk_id, &blob_id)? {
                        Some((new_blob_id, chunk_info)) => {
                            let blob_idx = match blob_mgr.get_blob_idx_by_id(&new_blob_id) {
                                Some(blob_idx) => blob_idx,
                                None => {
                                    //Safe to use unwarp since we get blob_id from chunk table
                                    let blob_info = self.cas_mgr.get_blob(&new_blob_id)?.unwrap();
                                    let blob = serde_json::from_str::<BlobInfo>(&blob_info)?;
                                    let blob_idx = blob_mgr.alloc_index()?;
                                    blob_mgr.add(BlobContext::from(
                                        build_ctx,
                                        &blob,
                                        ChunkSource::Parent,
                                    ));
                                    blob_idx
                                }
                            };
                            let mut new_chunk = serde_json::from_str::<ChunkWrapper>(&chunk_info)?;
                            new_chunk.set_blob_index(blob_idx);
                            node.dedup_bootstrap(&new_chunk, self.writer.as_mut())?;
                            self.cache_chunks.insert(*chunk_id, new_chunk);
                        }
                        None => {
                            self.cache_chunks.insert(*chunk_id, chunk.inner.clone());
                            //insert db
                            let chunk_info = serde_json::to_string(&chunk.inner).unwrap();
                            self.insert_chunks
                                .push((String::from(*chunk_id), chunk_info, blob_id));
                        }
                    },
                }

                chunk_ofs += chunk_size;
            }
        }

        Ok(())
    }

    pub fn do_dedup(&mut self) -> Result<()> {
        let tree = Tree::from_bootstrap(&self.rs, &mut ())?;
        let mut nodes = Vec::new();
        tree.iterate(&mut |node| {
            if node.is_reg() {
                nodes.push(node.clone());
            }
            true
        })?;

        let mut build_ctx = BuildContext::new(
            "".to_string(),
            false,
            0,
            self.rs.meta.get_compressor(),
            self.rs.meta.get_digester(),
            self.rs.meta.explicit_uidgid(),
            WhiteoutSpec::Oci,
            ConversionType::DirectoryToRafs,
            PathBuf::from(""),
            Default::default(),
            None,
            false,
            Features::new(),
        );
        build_ctx.set_fs_version(RafsVersion::try_from(self.rs.meta.version).unwrap());
        let mut blob_mgr = BlobManager::new();
        blob_mgr.from_blob_table(&build_ctx, self.rs.superblock.get_blob_infos());
        self.do_chunk_dedup(nodes, &build_ctx, &mut blob_mgr)?;

        let blob_table = blob_mgr.to_blob_table(&build_ctx)?;
        let mut bootstrap = Bootstrap::new()?;
        bootstrap.dedup(
            &self.rs,
            &mut self.reader,
            self.writer.as_mut(),
            &blob_table,
            &self.cache_chunks,
        )?;

        let blobs = self.rs.superblock.get_blob_infos();
        for blob in blobs {
            self.insert_blobs
                .push((String::from(blob.blob_id()), serde_json::to_string(&blob)?))
        }
        self.cas_mgr.add_blobs(&self.insert_blobs)?;
        self.cas_mgr.add_chunks(&self.insert_chunks)?;

        Ok(())
    }
}
