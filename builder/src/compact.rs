// Copyright 2020 Ant Group. All rights reserved.
// Copyright 2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::Write;
use std::mem;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, ensure, Result};
use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::{RafsSuper, RafsVersion};
use nydus_storage::backend::BlobBackend;
use nydus_storage::utils::alloc_buf;
use nydus_utils::digest::RafsDigest;
use nydus_utils::{digest, try_round_up_4k};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::core::context::Artifact;

use super::core::blob::Blob;
use super::core::bootstrap::Bootstrap;
use super::{
    ArtifactStorage, ArtifactWriter, BlobContext, BlobManager, BootstrapManager, BuildContext,
    BuildOutput, ChunkDict, ConversionType, Features, Tree, TreeNode, WhiteoutSpec,
};

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
    total_size: usize,
}

impl ChunkSet {
    fn new() -> Self {
        Self {
            chunks: Default::default(),
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
        let mut chunks = self.chunks.values().collect::<Vec<&ChunkWrapper>>();
        // sort chunks first, don't break order in original blobs
        chunks.sort_by(|a, b| {
            if (*a).blob_index() == (*b).blob_index() {
                (*a).compressed_offset().cmp(&(*b).compressed_offset())
            } else {
                (*a).blob_index().cmp(&(*b).blob_index())
            }
        });

        let mut changed_chunks = Vec::new();
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
            changed_chunks.push((chunk.clone(), new_chunk));

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

        Ok(changed_chunks)
    }
}

#[derive(Clone, Debug, Default)]
enum State {
    ChunkDict,
    /// delete this blob
    Delete,
    #[default]
    Invalid,
    Original(ChunkSet),
    /// output chunks as a new blob file
    Rebuild(ChunkSet),
}

impl State {
    fn is_rebuild(&self) -> bool {
        matches!(self, Self::Rebuild(_))
    }

    fn is_from_dict(&self) -> bool {
        matches!(self, Self::ChunkDict)
    }

    fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid)
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

/// RAFS blob compactor to compact multiple small blobs into one blob.
pub struct BlobCompactor {
    /// v5 or v6
    version: RafsVersion,
    /// states
    states: Vec<State>,
    /// original blobs
    ori_blob_mgr: BlobManager,
    /// new blobs
    new_blob_mgr: BlobManager,
    /// chunk --> list<tree_node, chunk_idx in node>
    c2nodes: HashMap<ChunkKey, Vec<(TreeNode, usize)>>,
    /// original blob index --> list<tree_node, chunk_idx in node>
    b2nodes: HashMap<u32, Vec<(TreeNode, usize)>>,
    /// blobs backend
    backend: Arc<dyn BlobBackend + Send + Sync>,
}

impl BlobCompactor {
    /// Create a new instance of [BlobCompactor].
    fn new(
        version: RafsVersion,
        ori_blob_mgr: BlobManager,
        backend: Arc<dyn BlobBackend + Send + Sync>,
        digester: digest::Algorithm,
        bootstrap: &Bootstrap,
    ) -> Result<Self> {
        let ori_blobs_number = ori_blob_mgr.len();
        let mut compactor = Self {
            version,
            states: vec![Default::default(); ori_blobs_number],
            ori_blob_mgr,
            new_blob_mgr: BlobManager::new(digester),
            c2nodes: HashMap::new(),
            b2nodes: HashMap::new(),
            backend,
        };
        compactor.load_chunk_dict_blobs();
        compactor.load_and_dedup_chunks(bootstrap)?;
        Ok(compactor)
    }

    fn is_v6(&self) -> bool {
        self.version.is_v6()
    }

    fn load_and_dedup_chunks(&mut self, bootstrap: &Bootstrap) -> Result<()> {
        let mut all_chunks = ChunkSet::new();
        let chunk_dict = self.get_chunk_dict();

        let cb = &mut |n: &Tree| -> Result<()> {
            let mut node = n.lock_node();
            for chunk_idx in 0..node.chunks.len() {
                let chunk = &mut node.chunks[chunk_idx];
                let chunk_key = ChunkKey::from(&chunk.inner);

                if self.states[chunk.inner.blob_index() as usize].is_from_dict() {
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
                        if self.states[blob_index].is_invalid() {
                            self.states[blob_index] = State::Original(ChunkSet::new());
                        }
                        if let State::Original(cs) = &mut self.states[blob_index] {
                            cs.add_chunk(&chunk.inner);
                        }
                    }
                }

                // construct blobs/chunk --> nodes index map
                self.c2nodes
                    .entry(chunk_key)
                    .or_default()
                    .push((n.node.clone(), chunk_idx));
                self.b2nodes
                    .entry(chunk.inner.blob_index())
                    .or_default()
                    .push((n.node.clone(), chunk_idx));
            }
            Ok(())
        };

        bootstrap.tree.walk_bfs(false, cb)
    }

    fn get_chunk_dict(&self) -> Arc<dyn ChunkDict> {
        self.ori_blob_mgr.get_chunk_dict()
    }

    fn load_chunk_dict_blobs(&mut self) {
        let chunk_dict = self.get_chunk_dict();
        let blobs = chunk_dict.get_blobs();
        for i in 0..blobs.len() {
            if let Some(real_blob_idx) = chunk_dict.get_real_blob_idx(i as u32) {
                self.states[real_blob_idx as usize] = State::ChunkDict;
            }
        }
    }

    fn apply_blob_move(&mut self, from: u32, to: u32) -> Result<()> {
        if let Some(idx_list) = self.b2nodes.get(&from) {
            for (n, chunk_idx) in idx_list.iter() {
                let mut node = n.lock().unwrap();
                ensure!(
                    node.chunks[*chunk_idx].inner.blob_index() == from,
                    "unexpected blob_index of chunk"
                );
                node.chunks[*chunk_idx].set_blob_index(to);
            }
        }
        Ok(())
    }

    fn apply_chunk_change(&mut self, c: &(ChunkWrapper, ChunkWrapper)) -> Result<()> {
        if let Some(chunks) = self.c2nodes.get(&ChunkKey::from(&c.0)) {
            for (n, chunk_idx) in chunks.iter() {
                let mut node = n.lock().unwrap();
                let chunk = &mut node.chunks[*chunk_idx];
                let mut chunk_inner = chunk.inner.deref().clone();
                apply_chunk_change(&c.1, &mut chunk_inner)?;
                chunk.inner = Arc::new(chunk_inner);
            }
        }
        Ok(())
    }

    fn delete_unused_blobs(&mut self) {
        for i in 0..self.states.len() {
            if self.states[i].is_invalid() {
                info!(
                    "compactor: delete unused blob {}",
                    self.ori_blob_mgr.get_blob(i).unwrap().blob_id
                );
                self.states[i] = State::Delete;
            }
        }
    }

    fn prepare_to_rebuild(&mut self, idx: usize) -> Result<()> {
        if !self.states[idx].is_rebuild() {
            return Ok(());
        }

        let mut old = State::Invalid;
        mem::swap(&mut self.states[idx], &mut old);
        if let State::Original(cs) = old {
            self.states[idx] = State::Rebuild(cs);
        } else {
            mem::swap(&mut self.states[idx], &mut old);
            bail!("invalid state");
        }

        Ok(())
    }

    fn try_rebuild_blobs(&mut self, ratio: u8) -> Result<()> {
        for idx in 0..self.ori_blob_mgr.len() {
            let blob_info = self.ori_blob_mgr.get_blob(idx).unwrap();
            let used_ratio = match &self.states[idx] {
                State::Original(cs) => {
                    let compressed_blob_size = if blob_info.compressed_blob_size == 0 {
                        let reader = match self.backend.get_reader(&blob_info.blob_id) {
                            Ok(r) => r,
                            Err(e) => bail!("compactor: failed to get blob reader, {}", e),
                        };
                        match reader.blob_size() {
                            Ok(sz) => sz,
                            Err(e) => bail!("compactor: failed to get blob size, {}", e),
                        }
                    } else {
                        blob_info.compressed_blob_size
                    };
                    (cs.total_size * 100 / compressed_blob_size as usize) as u8
                }
                _ => 100_u8,
            };

            info!(
                "compactor: original blob size {}, used data ratio {}%",
                blob_info.blob_id, used_ratio
            );
            if used_ratio < ratio {
                self.prepare_to_rebuild(idx)?;
            }
        }

        Ok(())
    }

    fn merge_blob(&mut self, from: usize, to: usize) -> Result<()> {
        let mut old = State::Delete;
        mem::swap(&mut self.states[from], &mut old);
        self.states[to].merge_blob(old)
    }

    /// use greedy algorithm to merge small blobs(<low)
    fn try_merge_blobs(&mut self, low: usize, max: usize) -> Result<()> {
        let mut need_merge_blobs = Vec::new();
        for idx in 0..self.states.len() {
            let blob_info = self.ori_blob_mgr.get_blob(idx).unwrap();
            match &self.states[idx] {
                State::Original(cs) => {
                    let blob_size = if blob_info.compressed_blob_size == 0 {
                        cs.total_size
                    } else {
                        blob_info.compressed_blob_size as usize
                    };
                    if blob_size < low {
                        info!(
                            "compactor: try to merge blob {} size {}",
                            blob_info.blob_id, blob_size
                        );
                        need_merge_blobs.push((idx, blob_size));
                    }
                }
                State::Rebuild(cs) => {
                    if cs.total_size < low {
                        info!(
                            "compactor: try to merge blob {} size {}",
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
            let before_size = self.states[merge_to].chunk_total_size()?;
            let append_size = self.states[*blob_idx].chunk_total_size()?;
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

    fn dump_new_blobs(
        &mut self,
        build_ctx: &BuildContext,
        dir: &str,
        aligned_chunk: bool,
    ) -> Result<()> {
        let ori_blob_ids = self.original_blob_ids();
        ensure!(self.states.len() == self.ori_blob_mgr.len());

        for idx in 0..self.states.len() {
            match &self.states[idx] {
                State::Original(_) | State::ChunkDict => {
                    info!("compactor: keep original data blob {}", ori_blob_ids[idx]);
                    // already exists, no need to dump
                    let ctx = self.ori_blob_mgr.take_blob(idx);
                    let blob_idx = self.new_blob_mgr.alloc_index()?;
                    if blob_idx != idx as u32 {
                        self.apply_blob_move(idx as u32, blob_idx)?;
                    }
                    self.new_blob_mgr.add_blob(ctx);
                }
                State::Delete => {
                    info!("compactor: delete compacted blob {}", ori_blob_ids[idx]);
                }
                State::Rebuild(cs) => {
                    let blob_storage = ArtifactStorage::FileDir(PathBuf::from(dir));
                    let mut blob_ctx = BlobContext::new(
                        String::from(""),
                        0,
                        build_ctx.blob_features,
                        build_ctx.compressor,
                        build_ctx.digester,
                        build_ctx.cipher,
                        Default::default(),
                        None,
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
                    info!("compactor: successfully rebuild blob {}", blob_ctx.blob_id);
                    self.new_blob_mgr.add_blob(blob_ctx);
                }
                State::Invalid => bail!("compactor: invalid state for blob {}", ori_blob_ids[idx]),
            }
        }

        Ok(())
    }

    fn do_compact(&mut self, cfg: &Config) -> Result<()> {
        self.delete_unused_blobs();
        self.try_rebuild_blobs(cfg.min_used_ratio)?;
        self.try_merge_blobs(cfg.compact_blob_size, cfg.max_compact_size)?;
        Ok(())
    }

    /// Compact multiple small data blobs into one to reduce number of blobs.
    pub fn compact(
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
            WhiteoutSpec::None,
            ConversionType::DirectoryToRafs,
            PathBuf::from(""),
            Default::default(),
            None,
            false,
            Features::new(),
            false,
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

        let tree = Tree::from_bootstrap(&rs, &mut ())?;
        let mut bootstrap = Bootstrap::new(tree)?;
        let mut compactor = Self::new(
            build_ctx.fs_version,
            ori_blob_mgr,
            backend.clone(),
            rs.meta.get_digester(),
            &bootstrap,
        )?;
        compactor.do_compact(cfg)?;
        compactor.dump_new_blobs(&build_ctx, &cfg.blobs_dir, build_ctx.aligned_chunk)?;
        if compactor.new_blob_mgr.is_empty() {
            info!("compactor: no chance to compact data blobs");
            return Ok(None);
        }

        info!("compatctor: successfully compacted blob");
        // blobs have already been dumped, dump bootstrap only
        let blob_table = compactor.new_blob_mgr.to_blob_table(&build_ctx)?;
        bootstrap.build(&mut build_ctx, &mut bootstrap_ctx)?;
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

#[cfg(test)]
mod tests {
    use crate::core::node::Node;
    use crate::HashChunkDict;
    use crate::{NodeChunk, Overlay};

    use super::*;
    use nydus_api::ConfigV2;
    use nydus_rafs::metadata::RafsSuperConfig;
    use nydus_storage::backend::{BackendResult, BlobReader};
    use nydus_storage::device::v5::BlobV5ChunkInfo;
    use nydus_storage::device::{BlobChunkFlags, BlobChunkInfo, BlobFeatures};
    use nydus_storage::RAFS_DEFAULT_CHUNK_SIZE;
    use nydus_utils::crypt::Algorithm;
    use nydus_utils::metrics::BackendMetrics;
    use nydus_utils::{compress, crypt};
    use std::any::Any;
    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    #[doc(hidden)]
    #[macro_export]
    macro_rules! impl_getter {
        ($G: ident, $F: ident, $U: ty) => {
            fn $G(&self) -> $U {
                self.$F
            }
        };
    }

    #[derive(Default, Clone)]
    struct MockChunkInfo {
        pub block_id: RafsDigest,
        pub blob_index: u32,
        pub flags: BlobChunkFlags,
        pub compress_size: u32,
        pub uncompress_size: u32,
        pub compress_offset: u64,
        pub uncompress_offset: u64,
        pub file_offset: u64,
        pub index: u32,
        #[allow(unused)]
        pub reserved: u32,
    }

    impl BlobChunkInfo for MockChunkInfo {
        fn chunk_id(&self) -> &RafsDigest {
            &self.block_id
        }
        fn id(&self) -> u32 {
            self.index
        }
        fn is_compressed(&self) -> bool {
            self.flags.contains(BlobChunkFlags::COMPRESSED)
        }

        fn is_encrypted(&self) -> bool {
            false
        }

        fn is_deduped(&self) -> bool {
            false
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        impl_getter!(blob_index, blob_index, u32);
        impl_getter!(compressed_offset, compress_offset, u64);
        impl_getter!(compressed_size, compress_size, u32);
        impl_getter!(uncompressed_offset, uncompress_offset, u64);
        impl_getter!(uncompressed_size, uncompress_size, u32);
    }

    impl BlobV5ChunkInfo for MockChunkInfo {
        fn as_base(&self) -> &dyn BlobChunkInfo {
            self
        }

        impl_getter!(index, index, u32);
        impl_getter!(file_offset, file_offset, u64);
        impl_getter!(flags, flags, BlobChunkFlags);
    }

    struct MockBackend {
        pub metrics: Arc<BackendMetrics>,
    }

    impl BlobReader for MockBackend {
        fn blob_size(&self) -> BackendResult<u64> {
            Ok(1)
        }

        fn try_read(&self, buf: &mut [u8], _offset: u64) -> BackendResult<usize> {
            let mut i = 0;
            while i < buf.len() {
                buf[i] = i as u8;
                i += 1;
            }
            Ok(i)
        }

        fn metrics(&self) -> &BackendMetrics {
            // Safe because nydusd must have backend attached with id, only image builder can no id
            // but use backend instance to upload blob.
            &self.metrics
        }
    }

    unsafe impl Send for MockBackend {}
    unsafe impl Sync for MockBackend {}

    impl BlobBackend for MockBackend {
        fn shutdown(&self) {}

        fn metrics(&self) -> &BackendMetrics {
            // Safe because nydusd must have backend attached with id, only image builder can no id
            // but use backend instance to upload blob.
            &self.metrics
        }

        fn get_reader(&self, _blob_id: &str) -> BackendResult<Arc<dyn BlobReader>> {
            Ok(Arc::new(MockBackend {
                metrics: self.metrics.clone(),
            }))
        }
    }

    #[test]
    #[should_panic = "not implemented: unsupport ChunkWrapper::Ref(c)"]
    fn test_chunk_key_from() {
        let cw = ChunkWrapper::new(RafsVersion::V5);
        matches!(ChunkKey::from(&cw), ChunkKey::Digest(_));

        let cw = ChunkWrapper::new(RafsVersion::V6);
        matches!(ChunkKey::from(&cw), ChunkKey::Offset(_, _));

        let chunk = Arc::new(MockChunkInfo {
            block_id: Default::default(),
            blob_index: 2,
            flags: BlobChunkFlags::empty(),
            compress_size: 0x800,
            uncompress_size: 0x1000,
            compress_offset: 0x800,
            uncompress_offset: 0x1000,
            file_offset: 0x1000,
            index: 1,
            reserved: 0,
        }) as Arc<dyn BlobChunkInfo>;
        let cw = ChunkWrapper::Ref(chunk);
        ChunkKey::from(&cw);
    }

    #[test]
    fn test_chunk_set() {
        let mut chunk_set1 = ChunkSet::new();

        let mut chunk_wrapper1 = ChunkWrapper::new(RafsVersion::V5);
        chunk_wrapper1.set_id(RafsDigest { data: [1u8; 32] });
        chunk_wrapper1.set_compressed_size(8);
        let mut chunk_wrapper2 = ChunkWrapper::new(RafsVersion::V6);
        chunk_wrapper2.set_compressed_size(16);

        chunk_set1.add_chunk(&chunk_wrapper1);
        chunk_set1.add_chunk(&chunk_wrapper2);
        assert_eq!(chunk_set1.total_size, 24);

        let chunk_key2 = ChunkKey::from(&chunk_wrapper2);
        assert_eq!(
            format!("{:?}", Some(chunk_wrapper2)),
            format!("{:?}", chunk_set1.get_chunk(&chunk_key2))
        );

        let mut chunk_wrapper3 = ChunkWrapper::new(RafsVersion::V5);
        chunk_wrapper3.set_id(RafsDigest { data: [3u8; 32] });
        chunk_wrapper3.set_compressed_size(32);

        let mut chunk_set2 = ChunkSet::new();
        chunk_set2.add_chunk(&chunk_wrapper3);
        chunk_set2.merge(chunk_set1);
        assert_eq!(chunk_set2.total_size, 56);
        assert_eq!(chunk_set2.chunks.len(), 3);

        let build_ctx = BuildContext::default();
        let tmp_file = TempFile::new().unwrap();
        let blob_storage = ArtifactStorage::SingleFile(PathBuf::from(tmp_file.as_path()));
        let cipher_object = Algorithm::Aes256Xts.new_cipher().unwrap();
        let mut new_blob_ctx = BlobContext::new(
            "blob_id".to_owned(),
            0,
            BlobFeatures::all(),
            compress::Algorithm::Lz4Block,
            digest::Algorithm::Sha256,
            crypt::Algorithm::Aes256Xts,
            Arc::new(cipher_object),
            None,
        );
        let ori_blob_ids = ["1".to_owned(), "2".to_owned()];
        let backend = Arc::new(MockBackend {
            metrics: BackendMetrics::new("id", "backend_type"),
        }) as Arc<dyn BlobBackend + Send + Sync>;

        let mut res = chunk_set2
            .dump(
                &build_ctx,
                blob_storage,
                &ori_blob_ids,
                &mut new_blob_ctx,
                0,
                true,
                &backend,
            )
            .unwrap();

        res.sort_by(|a, b| a.0.id().data.cmp(&b.0.id().data));

        assert_eq!(res.len(), 3);
        assert_eq!(
            format!("{:?}", res[0].1.id()),
            format!("{:?}", RafsDigest { data: [0u8; 32] })
        );
        assert_eq!(
            format!("{:?}", res[1].1.id()),
            format!("{:?}", RafsDigest { data: [1u8; 32] })
        );
        assert_eq!(
            format!("{:?}", res[2].1.id()),
            format!("{:?}", RafsDigest { data: [3u8; 32] })
        );
    }

    #[test]
    fn test_state() {
        let state = State::Rebuild(ChunkSet::new());
        assert!(state.is_rebuild());
        let state = State::ChunkDict;
        assert!(state.is_from_dict());
        let state = State::default();
        assert!(state.is_invalid());

        let mut chunk_set1 = ChunkSet::new();
        let mut chunk_wrapper1 = ChunkWrapper::new(RafsVersion::V5);
        chunk_wrapper1.set_id(RafsDigest { data: [1u8; 32] });
        chunk_wrapper1.set_compressed_size(8);
        chunk_set1.add_chunk(&chunk_wrapper1);
        let mut state1 = State::Original(chunk_set1);
        assert_eq!(state1.chunk_total_size().unwrap(), 8);

        let mut chunk_wrapper2 = ChunkWrapper::new(RafsVersion::V6);
        chunk_wrapper2.set_compressed_size(16);
        let mut chunk_set2 = ChunkSet::new();
        chunk_set2.add_chunk(&chunk_wrapper2);
        let mut state2 = State::Rebuild(chunk_set2);
        assert_eq!(state2.chunk_total_size().unwrap(), 16);

        assert!(state1.merge_blob(state2.clone()).is_err());
        assert!(state2.merge_blob(state1).is_ok());
        assert!(state2.merge_blob(State::Invalid).is_err());

        assert_eq!(state2.chunk_total_size().unwrap(), 24);
        assert!(State::Delete.chunk_total_size().is_err());
    }

    #[test]
    fn test_apply_chunk_change() {
        let mut chunk_wrapper1 = ChunkWrapper::new(RafsVersion::V5);
        chunk_wrapper1.set_id(RafsDigest { data: [1u8; 32] });
        chunk_wrapper1.set_uncompressed_size(8);
        chunk_wrapper1.set_compressed_size(8);

        let mut chunk_wrapper2 = ChunkWrapper::new(RafsVersion::V6);
        chunk_wrapper2.set_uncompressed_size(16);
        chunk_wrapper2.set_compressed_size(16);

        assert!(apply_chunk_change(&chunk_wrapper1, &mut chunk_wrapper2).is_err());
        chunk_wrapper2.set_uncompressed_size(8);
        assert!(apply_chunk_change(&chunk_wrapper1, &mut chunk_wrapper2).is_err());

        chunk_wrapper2.set_compressed_size(8);
        chunk_wrapper1.set_blob_index(0x10);
        chunk_wrapper1.set_index(0x20);
        chunk_wrapper1.set_uncompressed_offset(0x30);
        chunk_wrapper1.set_compressed_offset(0x40);
        assert!(apply_chunk_change(&chunk_wrapper1, &mut chunk_wrapper2).is_ok());
        assert_eq!(chunk_wrapper2.blob_index(), 0x10);
        assert_eq!(chunk_wrapper2.index(), 0x20);
        assert_eq!(chunk_wrapper2.uncompressed_offset(), 0x30);
        assert_eq!(chunk_wrapper2.compressed_offset(), 0x40);
    }

    fn create_blob_compactor() -> Result<BlobCompactor> {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v5.boot");
        let path = source_path.to_str().unwrap();
        let rafs_config = RafsSuperConfig {
            version: RafsVersion::V5,
            compressor: compress::Algorithm::Lz4Block,
            digester: digest::Algorithm::Blake3,
            chunk_size: 0x100000,
            batch_size: 0,
            explicit_uidgid: true,
            is_tarfs_mode: false,
        };
        let dict =
            HashChunkDict::from_commandline_arg(path, Arc::new(ConfigV2::default()), &rafs_config)
                .unwrap();

        let mut ori_blob_mgr = BlobManager::new(digest::Algorithm::Sha256);
        ori_blob_mgr.set_chunk_dict(dict);

        let backend = Arc::new(MockBackend {
            metrics: BackendMetrics::new("id", "backend_type"),
        });

        let tmpdir = TempDir::new()?;
        let tmpfile = TempFile::new_in(tmpdir.as_path())?;
        let node = Node::from_fs_object(
            RafsVersion::V6,
            tmpdir.as_path().to_path_buf(),
            tmpfile.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            true,
            false,
        )?;
        let tree = Tree::new(node);
        let bootstrap = Bootstrap::new(tree)?;

        BlobCompactor::new(
            RafsVersion::V6,
            ori_blob_mgr,
            backend,
            digest::Algorithm::Sha256,
            &bootstrap,
        )
    }

    #[test]
    fn test_blob_compactor_new() {
        let compactor = create_blob_compactor();
        assert!(compactor.is_ok());
        assert!(compactor.unwrap().is_v6());
    }

    #[test]
    fn test_blob_compactor_load_chunk_dict_blobs() {
        let mut compactor = create_blob_compactor().unwrap();
        let chunk_dict = compactor.get_chunk_dict();
        let n = chunk_dict.get_blobs().len();
        for i in 0..n {
            chunk_dict.set_real_blob_idx(i as u32, i as u32);
        }
        compactor.states = vec![State::default(); n + 1];
        compactor.load_chunk_dict_blobs();

        assert_eq!(compactor.states.len(), n + 1);
        assert!(compactor.states[0].is_from_dict());
        assert!(compactor.states[n >> 1].is_from_dict());
        assert!(compactor.states[n - 1].is_from_dict());
        assert!(!compactor.states[n].is_from_dict());
    }

    fn blob_compactor_load_and_dedup_chunks() -> Result<BlobCompactor> {
        let mut compactor = create_blob_compactor()?;

        let mut chunk1 = ChunkWrapper::new(RafsVersion::V5);
        chunk1.set_id(RafsDigest { data: [1u8; 32] });
        chunk1.set_uncompressed_size(0);
        chunk1.set_compressed_offset(0x11);
        chunk1.set_blob_index(1);
        let node_chunk1 = NodeChunk {
            source: crate::ChunkSource::Dict,
            inner: Arc::new(chunk1.clone()),
        };
        let mut chunk2 = ChunkWrapper::new(RafsVersion::V6);
        chunk2.set_id(RafsDigest { data: [2u8; 32] });
        chunk2.set_uncompressed_size(0x20);
        chunk2.set_compressed_offset(0x22);
        chunk2.set_blob_index(2);
        let node_chunk2 = NodeChunk {
            source: crate::ChunkSource::Dict,
            inner: Arc::new(chunk2.clone()),
        };
        let mut chunk3 = ChunkWrapper::new(RafsVersion::V6);
        chunk3.set_id(RafsDigest { data: [3u8; 32] });
        chunk3.set_uncompressed_size(0x20);
        chunk3.set_compressed_offset(0x22);
        chunk3.set_blob_index(2);
        let node_chunk3 = NodeChunk {
            source: crate::ChunkSource::Dict,
            inner: Arc::new(chunk3.clone()),
        };

        let mut chunk_dict = HashChunkDict::new(digest::Algorithm::Sha256);
        chunk_dict.add_chunk(
            Arc::new(ChunkWrapper::new(RafsVersion::V5)),
            digest::Algorithm::Sha256,
        );
        chunk_dict.add_chunk(Arc::new(chunk1.clone()), digest::Algorithm::Sha256);
        compactor.ori_blob_mgr.set_chunk_dict(Arc::new(chunk_dict));

        compactor.states = vec![State::ChunkDict; 5];

        let tmpdir = TempDir::new()?;
        let tmpfile = TempFile::new_in(tmpdir.as_path())?;
        let node = Node::from_fs_object(
            RafsVersion::V6,
            tmpdir.as_path().to_path_buf(),
            tmpfile.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            true,
            false,
        )?;
        let mut tree = Tree::new(node);
        let tmpfile2 = TempFile::new_in(tmpdir.as_path())?;
        let mut node = Node::from_fs_object(
            RafsVersion::V6,
            tmpdir.as_path().to_path_buf(),
            tmpfile2.as_path().to_path_buf(),
            Overlay::UpperAddition,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            true,
            false,
        )?;
        node.chunks.push(node_chunk1);
        node.chunks.push(node_chunk2);
        node.chunks.push(node_chunk3);
        let tree2 = Tree::new(node);
        tree.insert_child(tree2);

        let bootstrap = Bootstrap::new(tree)?;

        assert!(compactor.load_and_dedup_chunks(&bootstrap).is_ok());
        assert_eq!(compactor.c2nodes.len(), 2);
        assert_eq!(compactor.b2nodes.len(), 2);

        let chunk_key1 = ChunkKey::from(&chunk1);
        assert!(compactor.c2nodes.get(&chunk_key1).is_some());
        assert_eq!(compactor.c2nodes.get(&chunk_key1).unwrap().len(), 1);
        assert!(compactor.b2nodes.get(&chunk2.blob_index()).is_some());
        assert_eq!(
            compactor.b2nodes.get(&chunk2.blob_index()).unwrap().len(),
            2
        );

        Ok(compactor)
    }

    #[test]
    fn test_blob_compactor_load_and_dedup_chunks() {
        assert!(blob_compactor_load_and_dedup_chunks().is_ok());
    }

    #[test]
    fn test_blob_compactor_dump_new_blobs() {
        let tmp_dir = TempDir::new().unwrap();
        let build_ctx = BuildContext::new(
            "build_ctx".to_string(),
            false,
            0,
            compress::Algorithm::Lz4Block,
            digest::Algorithm::Sha256,
            true,
            WhiteoutSpec::None,
            ConversionType::DirectoryToRafs,
            PathBuf::from(tmp_dir.as_path()),
            Default::default(),
            None,
            false,
            Features::new(),
            false,
        );

        let mut compactor = blob_compactor_load_and_dedup_chunks().unwrap();

        let blob_ctx1 = BlobContext::new(
            "blob_id1".to_owned(),
            0,
            build_ctx.blob_features,
            build_ctx.compressor,
            build_ctx.digester,
            build_ctx.cipher,
            Default::default(),
            None,
        );
        let blob_ctx2 = BlobContext::new(
            "blob_id2".to_owned(),
            0,
            build_ctx.blob_features,
            build_ctx.compressor,
            build_ctx.digester,
            build_ctx.cipher,
            Default::default(),
            None,
        );
        let blob_ctx3 = BlobContext::new(
            "blob_id3".to_owned(),
            0,
            build_ctx.blob_features,
            build_ctx.compressor,
            build_ctx.digester,
            build_ctx.cipher,
            Default::default(),
            None,
        );
        let blob_ctx4 = BlobContext::new(
            "blob_id4".to_owned(),
            0,
            build_ctx.blob_features,
            build_ctx.compressor,
            build_ctx.digester,
            build_ctx.cipher,
            Default::default(),
            None,
        );
        let blob_ctx5 = BlobContext::new(
            "blob_id5".to_owned(),
            0,
            build_ctx.blob_features,
            build_ctx.compressor,
            build_ctx.digester,
            build_ctx.cipher,
            Default::default(),
            None,
        );
        compactor.ori_blob_mgr.add_blob(blob_ctx1);
        compactor.ori_blob_mgr.add_blob(blob_ctx2);
        compactor.ori_blob_mgr.add_blob(blob_ctx3);
        compactor.ori_blob_mgr.add_blob(blob_ctx4);
        compactor.ori_blob_mgr.add_blob(blob_ctx5);

        compactor.states[0] = State::Invalid;

        let tmp_dir = TempDir::new().unwrap();
        let dir = tmp_dir.as_path().to_str().unwrap();
        assert!(compactor.dump_new_blobs(&build_ctx, dir, true).is_err());

        compactor.states = vec![
            State::Delete,
            State::ChunkDict,
            State::Original(ChunkSet::new()),
            State::Rebuild(ChunkSet::new()),
            State::Delete,
        ];
        assert!(compactor.dump_new_blobs(&build_ctx, dir, true).is_ok());
        assert_eq!(compactor.ori_blob_mgr.len(), 3);
    }

    #[test]
    fn test_blob_compactor_do_compact() {
        let mut compactor = blob_compactor_load_and_dedup_chunks().unwrap();

        let tmp_dir = TempDir::new().unwrap();
        let build_ctx = BuildContext::new(
            "build_ctx".to_string(),
            false,
            0,
            compress::Algorithm::Lz4Block,
            digest::Algorithm::Sha256,
            true,
            WhiteoutSpec::None,
            ConversionType::DirectoryToRafs,
            PathBuf::from(tmp_dir.as_path()),
            Default::default(),
            None,
            false,
            Features::new(),
            false,
        );
        let mut blob_ctx1 = BlobContext::new(
            "blob_id1".to_owned(),
            0,
            build_ctx.blob_features,
            build_ctx.compressor,
            build_ctx.digester,
            build_ctx.cipher,
            Default::default(),
            None,
        );
        blob_ctx1.compressed_blob_size = 2;
        let mut blob_ctx2 = BlobContext::new(
            "blob_id2".to_owned(),
            0,
            build_ctx.blob_features,
            build_ctx.compressor,
            build_ctx.digester,
            build_ctx.cipher,
            Default::default(),
            None,
        );
        blob_ctx2.compressed_blob_size = 0;
        let blob_ctx3 = BlobContext::new(
            "blob_id3".to_owned(),
            0,
            build_ctx.blob_features,
            build_ctx.compressor,
            build_ctx.digester,
            build_ctx.cipher,
            Default::default(),
            None,
        );
        let blob_ctx4 = BlobContext::new(
            "blob_id4".to_owned(),
            0,
            build_ctx.blob_features,
            build_ctx.compressor,
            build_ctx.digester,
            build_ctx.cipher,
            Default::default(),
            None,
        );
        let blob_ctx5 = BlobContext::new(
            "blob_id5".to_owned(),
            0,
            build_ctx.blob_features,
            build_ctx.compressor,
            build_ctx.digester,
            build_ctx.cipher,
            Default::default(),
            None,
        );
        compactor.ori_blob_mgr.add_blob(blob_ctx1);
        compactor.ori_blob_mgr.add_blob(blob_ctx2);
        compactor.ori_blob_mgr.add_blob(blob_ctx3);
        compactor.ori_blob_mgr.add_blob(blob_ctx4);
        compactor.ori_blob_mgr.add_blob(blob_ctx5);

        let mut chunk_set1 = ChunkSet::new();
        chunk_set1.total_size = 4;
        let mut chunk_set2 = ChunkSet::new();
        chunk_set2.total_size = 6;
        let mut chunk_set3 = ChunkSet::new();
        chunk_set3.total_size = 5;

        compactor.states = vec![
            State::Original(chunk_set1),
            State::Original(chunk_set2),
            State::Rebuild(chunk_set3),
            State::ChunkDict,
            State::Invalid,
        ];

        let cfg = Config {
            min_used_ratio: 50,
            compact_blob_size: 10,
            max_compact_size: 8,
            layers_to_compact: 0,
            blobs_dir: "blobs_dir".to_string(),
        };

        assert!(compactor.do_compact(&cfg).is_ok());
        assert!(!compactor.states.last().unwrap().is_invalid());
    }
}
