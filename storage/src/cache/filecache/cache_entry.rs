// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::OpenOptions;
use std::io::Result;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use tokio::runtime::Runtime;

use crate::cache::cachedfile::FileCacheEntry;
use crate::cache::filecache::FileCacheMgr;
use crate::cache::state::{BlobStateMap, ChunkMap, DigestedChunkMap, IndexedChunkMap};
use crate::cache::worker::{AsyncPrefetchConfig, AsyncRequestState, AsyncWorkerMgr};
use crate::device::{BlobFeatures, BlobInfo};
use crate::meta::BlobMetaInfo;

impl FileCacheEntry {
    pub fn new(
        mgr: &FileCacheMgr,
        blob_info: Arc<BlobInfo>,
        prefetch_config: Arc<AsyncPrefetchConfig>,
        runtime: Arc<Runtime>,
        workers: Arc<AsyncWorkerMgr>,
    ) -> Result<Self> {
        let blob_file_path = format!("{}/{}", mgr.work_dir, blob_info.blob_id());
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(&blob_file_path)?;
        let (chunk_map, is_direct_chunkmap) =
            Self::create_chunk_map(mgr, &blob_info, &blob_file_path)?;
        let reader = mgr
            .backend
            .get_reader(blob_info.blob_id())
            .map_err(|_e| eio!("failed to get blob reader"))?;

        let blob_size = Self::get_blob_size(&reader, &blob_info)?;
        let compressor = blob_info.compressor();
        let digester = blob_info.digester();
        let is_stargz = blob_info.is_stargz();
        let is_compressed = mgr.is_compressed || is_stargz;
        let need_validate = (mgr.validate || !is_direct_chunkmap) && !is_stargz;
        let is_get_blob_object_supported = !mgr.is_compressed && is_direct_chunkmap && !is_stargz;

        trace!(
            "comp {} direct {} startgz {}",
            mgr.is_compressed,
            is_direct_chunkmap,
            is_stargz
        );
        let meta = if is_get_blob_object_supported && blob_info.meta_ci_is_valid() {
            // Set cache file to its expected size.
            let file_size = file.metadata()?.len();
            if file_size == 0 {
                file.set_len(blob_info.uncompressed_size())?;
            } else {
                assert_eq!(file_size, blob_info.uncompressed_size());
            }

            Some(Arc::new(BlobMetaInfo::new(
                &blob_file_path,
                &blob_info,
                Some(&reader),
            )?))
        } else {
            None
        };

        Ok(FileCacheEntry {
            blob_info,
            chunk_map,
            file: Arc::new(file),
            meta,
            metrics: mgr.metrics.clone(),
            prefetch_state: Arc::new(AtomicU32::new(AsyncRequestState::Init as u32)),
            reader,
            runtime,
            workers,

            blob_size,
            compressor,
            digester,
            is_get_blob_object_supported,
            is_compressed,
            is_direct_chunkmap,
            is_stargz,
            need_validate,
            prefetch_config,
        })
    }

    fn create_chunk_map(
        mgr: &FileCacheMgr,
        blob_info: &BlobInfo,
        blob_file: &str,
    ) -> Result<(Arc<dyn ChunkMap>, bool)> {
        let mut direct_chunkmap = true;
        // The builder now records the number of chunks in the blob table, so we can
        // use IndexedChunkMap as a chunk map, but for the old Nydus bootstrap, we
        // need downgrade to use DigestedChunkMap as a compatible solution.
        let chunk_map: Arc<dyn ChunkMap> = if mgr.disable_indexed_map
            || blob_info.is_stargz()
            || blob_info.has_feature(BlobFeatures::V5_NO_EXT_BLOB_TABLE)
        {
            direct_chunkmap = false;
            Arc::new(BlobStateMap::from(DigestedChunkMap::new()))
        } else {
            Arc::new(BlobStateMap::from(IndexedChunkMap::new(
                blob_file,
                blob_info.chunk_count(),
            )?))
        };

        Ok((chunk_map, direct_chunkmap))
    }
}
