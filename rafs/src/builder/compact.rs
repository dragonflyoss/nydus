// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::Write;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use nydus_storage::backend::BlobBackend;
use nydus_storage::utils::alloc_buf;
use nydus_utils::digest::RafsDigest;
use nydus_utils::{digest, try_round_up_4k};

use super::core::blob::Blob;
use super::core::bootstrap::Bootstrap;
use super::core::node::Node;
use crate::builder::{
    ArtifactStorage, ArtifactWriter, BlobContext, BlobManager, BootstrapManager, BuildContext,
    BuildOutput, ChunkDict, ConversionType, Features, HashChunkDict, Tree, WhiteoutSpec,
};
use crate::metadata::chunk::ChunkWrapper;
use crate::metadata::{RafsSuper, RafsVersion};

const DEFAULT_COMPACT_BLOB_SIZE: usize = 10 * 1024 * 1024;
const DEFAULT_MAX_COMPACT_SIZE: usize = 100 * 1024 * 1024;

const fn default_compact_blob_size() -> usize {
    DEFAULT_COMPACT_BLOB_SIZE
}

const fn default_max_compact_size() -> usize {
    DEFAULT_MAX_COMPACT_SIZE
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Config {
    /// rebuild blobs whose used_ratio < min_used_ratio
    /// used_ratio = (compress_size of all chunks which are referenced by bootstrap) / blob_compress_size
    /// available value: 0-99, 0 means disable
    /// hint: it's better to disable this option when there are some shared blobs
    /// for example: build-cache
    #[serde(default)]
    min_used_ratio: u8,
    /// we compact blobs whose size are less than compact_blob_size
    #[serde(default = "default_compact_blob_size")]
    compact_blob_size: usize,
    /// size of compacted blobs should not be large than max_compact_size
    #[serde(default = "default_max_compact_size")]
    max_compact_size: usize,
    /// if number of blobs >= layers_to_compact, do compact
    /// 0 means always try compact
    #[serde(default)]
    layers_to_compact: usize,
    /// local blobs dir, may haven't upload to backend yet
    /// what's more, new blobs will output to this dir
    /// name of blob file should be equal to blob_id
    blobs_dir: String,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
enum ChunkKey {
    // Chunk digest for RAFS v5, may be extended to support RAFS v6 in future.
    Digest(RafsDigest),
    // (blob_idx, compress_offset) for RAFS v6 only
    Offset(u32, u64),
}

impl ChunkKey {
    fn from(c: &ChunkWrapper) -> Self {
        match c {
            ChunkWrapper::V5(_) => Self::Digest(*c.id()),
            ChunkWrapper::V6(_) => Self::Offset(c.blob_index(), c.compressed_offset()),
            ChunkWrapper::Ref(_) => unimplemented!("unsupport ChunkWrapper::Ref(c)"),
        }
    }
}

#[derive(Clone, Debug)]
struct ChunkSet {
    chunks: HashMap<ChunkKey, ChunkWrapper>,
    #[allow(unused)]
    version: RafsVersion,
    total_size: usize,
}

impl ChunkSet {
    fn new(version: RafsVersion) -> Self {
        Self {
            chunks: Default::default(),
            version,
            total_size: 0,
        }
    }

    fn add_chunk(&mut self, chunk: &ChunkWrapper) {
        let key = ChunkKey::from(chunk);
        if let Entry::Vacant(e) = self.chunks.entry(key) {
            e.insert(chunk.clone());
            self.total_size += chunk.compressed_size() as usize;
        }
    }

    fn get_chunk(&self, key: &ChunkKey) -> Option<&ChunkWrapper> {
        self.chunks.get(key)
    }

    fn merge(&mut self, other: Self) {
        for (_, c) in other.chunks.iter() {
            self.add_chunk(c);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dump(
        &self,
        build_ctx: &BuildContext,
        blob_storage: ArtifactStorage,
        ori_blob_ids: &[String],
        new_blob_ctx: &mut BlobContext,
        new_blob_idx: u32,
        aligned_chunk: bool,
        backend: &Arc<dyn BlobBackend + Send + Sync>,
    ) -> Result<Vec<(ChunkWrapper, ChunkWrapper)>> {
        let mut blob_writer = ArtifactWriter::new(blob_storage)?;

        // sort chunks first, don't break order in original blobs
        let mut chunks = self.chunks.values().collect::<Vec<&ChunkWrapper>>();
        chunks.sort_by(|a, b| {
            if (*a).blob_index() == (*b).blob_index() {
                (*a).compressed_offset().cmp(&(*b).compressed_offset())
            } else {
                (*a).blob_index().cmp(&(*b).blob_index())
            }
        });
        let mut chunks_change = Vec::new();
        for chunk in chunks {
            let blob_idx = chunk.blob_index();
            // get data from backend
            // todo: merge download requests
            let reader = backend
                .get_reader(&ori_blob_ids[blob_idx as usize])
                .expect("get blob err");
            let mut buf = alloc_buf(chunk.compressed_size() as usize);
            reader
                .read(&mut buf, chunk.compressed_offset())
                .expect("read blob data err");
            blob_writer.write_all(&buf)?;

            let mut new_chunk = chunk.clone();
            // file offset field is useless
            new_chunk.set_index(new_blob_ctx.chunk_count);
            new_chunk.set_blob_index(new_blob_idx);
            new_chunk.set_compressed_offset(new_blob_ctx.current_compressed_offset);
            new_chunk.set_uncompressed_offset(new_blob_ctx.current_uncompressed_offset);
            new_blob_ctx.add_chunk_meta_info(&new_chunk, None)?;
            // insert change ops
            chunks_change.push((chunk.clone(), new_chunk));

            new_blob_ctx.blob_hash.update(&buf);
            new_blob_ctx.chunk_count += 1;
            new_blob_ctx.current_compressed_offset += chunk.compressed_size() as u64;
            new_blob_ctx.compressed_blob_size += chunk.compressed_size() as u64;

            let aligned_size = if aligned_chunk {
                try_round_up_4k(chunk.uncompressed_size()).unwrap()
            } else {
                chunk.uncompressed_size() as u64
            };
            new_blob_ctx.current_uncompressed_offset += aligned_size;
            new_blob_ctx.uncompressed_blob_size += aligned_size;
        }
        new_blob_ctx.blob_id = format!("{:x}", new_blob_ctx.blob_hash.clone().finalize());
        // dump blob meta for v6
        Blob::dump_meta_data(build_ctx, new_blob_ctx, &mut blob_writer)?;
        let blob_id = new_blob_ctx.blob_id();
        blob_writer.finalize(blob_id)?;
        Ok(chunks_change)
    }
}

#[derive(Clone, Debug)]
enum State {
    Original(ChunkSet),
    ChunkDict,
    /// delete this blob
    Delete,
    /// output chunks as a new blob file
    Rebuild(ChunkSet),
}

impl State {
    fn is_rebuild(&self) -> bool {
        matches!(self, Self::Rebuild(_))
    }

    fn merge_blob(&mut self, other: Self) -> Result<()> {
        let merge_cs = match other {
            State::Original(cs) => cs,
            State::Rebuild(cs) => cs,
            _ => bail!("invalid state"),
        };
        match self {
            State::Rebuild(cs) => {
                cs.merge(merge_cs);
            }
            _ => bail!("invalid state"),
        }
        Ok(())
    }

    fn chunk_total_size(&self) -> Result<usize> {
        Ok(match self {
            State::Original(cs) => cs.total_size,
            State::Rebuild(cs) => cs.total_size,
            _ => bail!("invalid state"),
        })
    }
}

#[inline]
fn apply_chunk_change(from: &ChunkWrapper, to: &mut ChunkWrapper) -> Result<()> {
    ensure!(
        to.uncompressed_size() == from.uncompressed_size(),
        "different uncompress size"
    );
    ensure!(
        to.compressed_size() == from.compressed_size(),
        "different compressed size"
    );

    to.set_blob_index(from.blob_index());
    to.set_index(from.index());
    to.set_uncompressed_offset(from.uncompressed_offset());
    to.set_compressed_offset(from.compressed_offset());
    Ok(())
}

pub struct BlobCompactor {
    /// v5 or v6
    version: RafsVersion,
    /// states
    states: Vec<Option<State>>,
    /// original blobs
    ori_blob_mgr: BlobManager,
    /// new blobs
    new_blob_mgr: BlobManager,
    /// inode list
    nodes: Vec<Node>,
    /// chunk --> list<node_idx, chunk_idx in node>
    c2nodes: HashMap<ChunkKey, Vec<(usize, usize)>>,
    /// original blob index --> list<node_idx, chunk_idx in node>
    b2nodes: HashMap<u32, Vec<(usize, usize)>>,
    /// blobs backend
    backend: Arc<dyn BlobBackend + Send + Sync>,
}

impl BlobCompactor {
    pub fn new(
        version: RafsVersion,
        ori_blob_mgr: BlobManager,
        nodes: Vec<Node>,
        backend: Arc<dyn BlobBackend + Send + Sync>,
        digester: digest::Algorithm,
    ) -> Result<Self> {
        let ori_blobs_number = ori_blob_mgr.len();
        let mut compactor = Self {
            version,
            states: vec![None; ori_blobs_number],
            ori_blob_mgr,
            new_blob_mgr: BlobManager::new(digester),
            nodes,
            c2nodes: HashMap::new(),
            b2nodes: HashMap::new(),
            backend,
        };
        compactor.load_chunk_dict_blobs();
        compactor.load_and_dedup_chunks()?;
        Ok(compactor)
    }

    pub fn is_v6(&self) -> bool {
        self.version.is_v6()
    }

    fn load_and_dedup_chunks(&mut self) -> Result<()> {
        let mut all_chunks = ChunkSet::new(self.version);
        let chunk_dict = self.get_chunk_dict();
        for node_idx in 0..self.nodes.len() {
            let node = &mut self.nodes[node_idx];
            for chunk_idx in 0..node.chunks.len() {
                let chunk = &mut node.chunks[chunk_idx];
                let chunk_key = ChunkKey::from(&chunk.inner);
                if let Some(State::ChunkDict) = self.states[chunk.inner.blob_index() as usize] {
                    // dedup by chunk dict
                    if let Some(c) =
                        chunk_dict.get_chunk(chunk.inner.id(), chunk.inner.uncompressed_size())
                    {
                        let mut chunk_inner = chunk.inner.deref().clone();
                        apply_chunk_change(c, &mut chunk_inner)?;
                        chunk.inner = Arc::new(chunk_inner);
                    } else if let Some(c) = all_chunks.get_chunk(&chunk_key) {
                        let mut chunk_inner = chunk.inner.deref().clone();
                        apply_chunk_change(c, &mut chunk_inner)?;
                        chunk.inner = Arc::new(chunk_inner);
                    } else {
                        all_chunks.add_chunk(&chunk.inner);
                        // add to per blob ChunkSet
                        let blob_index = chunk.inner.blob_index() as usize;
                        if self.states[blob_index].is_none() {
                            self.states[blob_index]
                                .replace(State::Original(ChunkSet::new(self.version)));
                        }
                        if let Some(State::Original(cs)) = &mut self.states[blob_index] {
                            cs.add_chunk(&chunk.inner);
                        }
                    }
                }

                // construct blobs/chunk --> nodes index map
                self.c2nodes
                    .entry(chunk_key)
                    .or_default()
                    .push((node_idx, chunk_idx));
                self.b2nodes
                    .entry(chunk.inner.blob_index())
                    .or_default()
                    .push((node_idx, chunk_idx));
            }
        }

        Ok(())
    }

    fn get_chunk_dict(&self) -> Arc<dyn ChunkDict> {
        self.ori_blob_mgr.get_chunk_dict()
    }

    fn load_chunk_dict_blobs(&mut self) {
        let chunk_dict = self.get_chunk_dict();
        let blobs = chunk_dict.get_blobs();
        for i in 0..blobs.len() {
            if let Some(real_blob_idx) = chunk_dict.get_real_blob_idx(i as u32) {
                self.states[real_blob_idx as usize].replace(State::ChunkDict);
            }
        }
    }

    fn apply_blob_move(&mut self, from: u32, to: u32) -> Result<()> {
        if let Some(idx_list) = self.b2nodes.get(&from) {
            for (node_idx, chunk_idx) in idx_list.iter() {
                ensure!(
                    self.nodes[*node_idx].chunks[*chunk_idx].inner.blob_index() == from,
                    "unexpected blob_index of chunk"
                );
                self.nodes[*node_idx].chunks[*chunk_idx].set_blob_index(to);
            }
        }
        Ok(())
    }

    fn apply_chunk_change(&mut self, c: &(ChunkWrapper, ChunkWrapper)) -> Result<()> {
        if let Some(idx_list) = self.c2nodes.get(&ChunkKey::from(&c.0)) {
            for (node_idx, chunk_idx) in idx_list.iter() {
                let chunk = &mut self.nodes[*node_idx].chunks[*chunk_idx];
                let mut chunk_inner = chunk.inner.deref().clone();
                apply_chunk_change(&c.1, &mut chunk_inner)?;
                chunk.inner = Arc::new(chunk_inner);
            }
        }
        Ok(())
    }

    fn delete_unused_blobs(&mut self) {
        for i in 0..self.states.len() {
            if self.states[i].is_none() {
                info!(
                    "delete unused blob {}",
                    self.ori_blob_mgr.get_blob(i).unwrap().blob_id
                );
                self.states[i].replace(State::Delete);
            }
        }
    }

    fn prepare_to_rebuild(&mut self, idx: usize) -> Result<()> {
        if self.states[idx].as_ref().unwrap().is_rebuild() {
            return Ok(());
        }
        if let Some(cs) = self.states[idx].take() {
            match cs {
                State::Original(cs) => {
                    self.states[idx].replace(State::Rebuild(cs));
                }
                _ => bail!("invalid state"),
            }
        }
        Ok(())
    }

    fn try_rebuild_blobs(&mut self, ratio: u8) {
        for idx in 0..self.ori_blob_mgr.len() {
            let blob_info = self.ori_blob_mgr.get_blob(idx).unwrap();
            // calculate ratio
            let used_ratio = match self.states[idx].as_ref().unwrap() {
                State::Original(cs) => {
                    let compressed_blob_size = if blob_info.compressed_blob_size == 0 {
                        // get blob compressed size of blob from backend
                        self.backend
                            .get_reader(&blob_info.blob_id)
                            .expect("get blob failed")
                            .blob_size()
                            .expect("get blob size failed")
                    } else {
                        blob_info.compressed_blob_size
                    };
                    (cs.total_size * 100 / compressed_blob_size as usize) as u8
                }
                _ => 100_u8,
            };
            info!("blob {} used ratio {}%", blob_info.blob_id, used_ratio);
            if used_ratio < ratio {
                self.prepare_to_rebuild(idx).unwrap();
            }
        }
    }

    fn merge_blob(&mut self, from: usize, to: usize) -> Result<()> {
        let s = self.states[from].replace(State::Delete).unwrap();
        self.states[to].as_mut().unwrap().merge_blob(s)
    }

    /// use greedy algorithm to merge small blobs(<low)
    fn try_merge_blobs(&mut self, low: usize, max: usize) -> Result<()> {
        let mut need_merge_blobs = Vec::new();
        for idx in 0..self.states.len() {
            let blob_info = self.ori_blob_mgr.get_blob(idx).unwrap();
            match self.states[idx].as_ref().unwrap() {
                State::Original(cs) => {
                    let blob_size = if blob_info.compressed_blob_size == 0 {
                        cs.total_size
                    } else {
                        blob_info.compressed_blob_size as usize
                    };
                    if blob_size < low {
                        info!("blob {} size {}, try merge", blob_info.blob_id, blob_size);
                        need_merge_blobs.push((idx, blob_size));
                    }
                }
                State::Rebuild(cs) => {
                    if cs.total_size < low {
                        info!(
                            "blob {} size {}, try merge",
                            blob_info.blob_id, cs.total_size
                        );
                        need_merge_blobs.push((idx, cs.total_size));
                    }
                }
                _ => {}
            }
        }
        // sort by size
        need_merge_blobs.sort_by(|(_, len1), (_, len2)| len1.cmp(len2));
        // try merge
        if need_merge_blobs.len() < 2 {
            return Ok(());
        }
        let mut merge_to = need_merge_blobs[0].0;
        for (blob_idx, _) in need_merge_blobs.iter().skip(1) {
            let before_size = self.states[merge_to].as_ref().unwrap().chunk_total_size()?;
            let append_size = self.states[*blob_idx]
                .as_ref()
                .unwrap()
                .chunk_total_size()?;
            if before_size + append_size <= max {
                self.prepare_to_rebuild(merge_to)?;
                self.merge_blob(*blob_idx, merge_to)?;
            } else {
                merge_to = *blob_idx;
            }
        }
        Ok(())
    }

    fn original_blob_ids(&self) -> Vec<String> {
        self.ori_blob_mgr
            .get_blobs()
            .into_iter()
            .map(|blob| blob.blob_id.clone())
            .collect()
    }

    pub fn dump_new_blobs(
        &mut self,
        build_ctx: &BuildContext,
        dir: &str,
        aligned_chunk: bool,
    ) -> Result<()> {
        let ori_blob_ids = self.original_blob_ids();
        ensure!(self.states.len() == self.ori_blob_mgr.len());
        for idx in 0..self.states.len() {
            match self.states[idx].as_ref().unwrap() {
                State::Original(_) | State::ChunkDict => {
                    info!("do nothing to blob {}", ori_blob_ids[idx]);
                    // already exists, no need to dump
                    let ctx = self.ori_blob_mgr.take_blob(idx);
                    let blob_idx = self.new_blob_mgr.alloc_index()?;
                    if blob_idx != idx as u32 {
                        self.apply_blob_move(idx as u32, blob_idx)?;
                    }
                    self.new_blob_mgr.add_blob(ctx);
                }
                State::Delete => {
                    info!("delete blob {}", ori_blob_ids[idx]);
                }
                State::Rebuild(cs) => {
                    let blob_storage = ArtifactStorage::FileDir(PathBuf::from(dir));
                    let mut blob_ctx = BlobContext::new(
                        String::from(""),
                        0,
                        build_ctx.blob_features,
                        build_ctx.compressor,
                        build_ctx.digester,
                    );
                    blob_ctx.set_meta_info_enabled(self.is_v6());
                    let blob_idx = self.new_blob_mgr.alloc_index()?;
                    let new_chunks = cs.dump(
                        build_ctx,
                        blob_storage,
                        &ori_blob_ids,
                        &mut blob_ctx,
                        blob_idx,
                        aligned_chunk,
                        &self.backend,
                    )?;
                    for change_chunk in new_chunks.iter() {
                        self.apply_chunk_change(change_chunk)?;
                    }
                    info!("rebuild blob {} successfully", blob_ctx.blob_id);
                    self.new_blob_mgr.add_blob(blob_ctx);
                }
            }
        }
        Ok(())
    }

    pub fn compact(&mut self, cfg: &Config) -> Result<()> {
        self.delete_unused_blobs();
        self.try_rebuild_blobs(cfg.min_used_ratio);
        self.try_merge_blobs(cfg.compact_blob_size, cfg.max_compact_size)?;
        Ok(())
    }

    pub fn do_compact(
        rs: RafsSuper,
        d_bootstrap: PathBuf,
        chunk_dict: Option<Arc<dyn ChunkDict>>,
        backend: Arc<dyn BlobBackend + Send + Sync>,
        cfg: &Config,
    ) -> Result<Option<BuildOutput>> {
        let mut build_ctx = BuildContext::new(
            "".to_string(),
            false,
            0,
            rs.meta.get_compressor(),
            rs.meta.get_digester(),
            rs.meta.explicit_uidgid(),
            // useless args
            WhiteoutSpec::Oci,
            ConversionType::DirectoryToRafs,
            PathBuf::from(""),
            Default::default(),
            None,
            false,
            Features::new(),
        );
        let mut bootstrap_mgr =
            BootstrapManager::new(Some(ArtifactStorage::SingleFile(d_bootstrap)), None);
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx()?;
        let mut ori_blob_mgr = BlobManager::new(rs.meta.get_digester());
        ori_blob_mgr.extend_from_blob_table(&build_ctx, rs.superblock.get_blob_infos())?;
        if let Some(dict) = chunk_dict {
            ori_blob_mgr.set_chunk_dict(dict);
            ori_blob_mgr.extend_from_chunk_dict(&build_ctx)?;
        }
        if ori_blob_mgr.len() < cfg.layers_to_compact {
            return Ok(None);
        }
        let mut _dict = HashChunkDict::new(build_ctx.digester);
        let tree = Tree::from_bootstrap(&rs, &mut _dict)?;
        let mut bootstrap = Bootstrap::new()?;
        bootstrap.build(&mut build_ctx, &mut bootstrap_ctx, tree)?;
        let mut nodes = Vec::new();
        // move out nodes
        std::mem::swap(&mut bootstrap_ctx.nodes, &mut nodes);
        let mut compactor = Self::new(
            build_ctx.fs_version,
            ori_blob_mgr,
            nodes,
            backend.clone(),
            rs.meta.get_digester(),
        )?;
        compactor.compact(cfg)?;
        compactor.dump_new_blobs(&build_ctx, &cfg.blobs_dir, build_ctx.aligned_chunk)?;
        if compactor.new_blob_mgr.is_empty() {
            info!("blobs of source bootstrap have already been optimized");
            return Ok(None);
        }
        info!("compact blob successfully");
        // give back nodes
        std::mem::swap(&mut bootstrap_ctx.nodes, &mut compactor.nodes);
        // blobs have already been dumped, dump bootstrap only
        let blob_table = compactor.new_blob_mgr.to_blob_table(&build_ctx)?;
        bootstrap.dump(
            &mut build_ctx,
            &mut bootstrap_mgr.bootstrap_storage,
            &mut bootstrap_ctx,
            &blob_table,
        )?;
        Ok(Some(BuildOutput::new(
            &compactor.new_blob_mgr,
            &bootstrap_mgr.bootstrap_storage,
        )?))
    }
}
