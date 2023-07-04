// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Result;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, RwLock};

use tokio::runtime::Runtime;

use nydus_api::CacheConfigV2;
use nydus_utils::crypt;
use nydus_utils::metrics::BlobcacheMetrics;

use crate::backend::BlobBackend;
use crate::cache::cachedfile::{FileCacheEntry, FileCacheMeta};
use crate::cache::state::{
    BlobStateMap, ChunkMap, DigestedChunkMap, IndexedChunkMap, NoopChunkMap,
};
use crate::cache::worker::{AsyncPrefetchConfig, AsyncWorkerMgr};
use crate::cache::{BlobCache, BlobCacheMgr};
use crate::device::{BlobFeatures, BlobInfo};
use crate::RAFS_DEFAULT_CHUNK_SIZE;

/// An implementation of [BlobCacheMgr](../trait.BlobCacheMgr.html) to improve performance by
/// caching uncompressed blob with local storage.
#[derive(Clone)]
pub struct FileCacheMgr {
    blobs: Arc<RwLock<HashMap<String, Arc<FileCacheEntry>>>>,
    backend: Arc<dyn BlobBackend>,
    metrics: Arc<BlobcacheMetrics>,
    prefetch_config: Arc<AsyncPrefetchConfig>,
    runtime: Arc<Runtime>,
    worker_mgr: Arc<AsyncWorkerMgr>,
    work_dir: String,
    validate: bool,
    disable_indexed_map: bool,
    cache_raw_data: bool,
    cache_encrypted: bool,
    cache_convergent_encryption: bool,
    cache_encryption_key: String,
    closed: Arc<AtomicBool>,
}

impl FileCacheMgr {
    /// Create a new instance of `FileCacheMgr`.
    pub fn new(
        config: &CacheConfigV2,
        backend: Arc<dyn BlobBackend>,
        runtime: Arc<Runtime>,
        id: &str,
    ) -> Result<FileCacheMgr> {
        let blob_cfg = config.get_filecache_config()?;
        let work_dir = blob_cfg.get_work_dir()?;
        let metrics = BlobcacheMetrics::new(id, work_dir);
        let prefetch_config: Arc<AsyncPrefetchConfig> = Arc::new((&config.prefetch).into());
        let worker_mgr = AsyncWorkerMgr::new(metrics.clone(), prefetch_config.clone())?;

        Ok(FileCacheMgr {
            blobs: Arc::new(RwLock::new(HashMap::new())),
            backend,
            metrics,
            prefetch_config,
            runtime,
            worker_mgr: Arc::new(worker_mgr),
            work_dir: work_dir.to_owned(),
            disable_indexed_map: blob_cfg.disable_indexed_map,
            validate: config.cache_validate,
            cache_raw_data: config.cache_compressed,
            cache_encrypted: blob_cfg.enable_encryption,
            cache_convergent_encryption: blob_cfg.enable_convergent_encryption,
            cache_encryption_key: blob_cfg.encryption_key.clone(),
            closed: Arc::new(AtomicBool::new(false)),
        })
    }

    // Get the file cache entry for the specified blob object.
    fn get(&self, blob: &Arc<BlobInfo>) -> Option<Arc<FileCacheEntry>> {
        self.blobs.read().unwrap().get(&blob.blob_id()).cloned()
    }

    // Create a file cache entry for the specified blob object if not present, otherwise
    // return the existing one.
    fn get_or_create_cache_entry(&self, blob: &Arc<BlobInfo>) -> Result<Arc<FileCacheEntry>> {
        if let Some(entry) = self.get(blob) {
            return Ok(entry);
        }

        let entry = FileCacheEntry::new_file_cache(
            self,
            blob.clone(),
            self.prefetch_config.clone(),
            self.runtime.clone(),
            self.worker_mgr.clone(),
        )?;
        let entry = Arc::new(entry);
        let mut guard = self.blobs.write().unwrap();
        if let Some(entry) = guard.get(&blob.blob_id()) {
            Ok(entry.clone())
        } else {
            let blob_id = blob.blob_id();
            guard.insert(blob_id.clone(), entry.clone());
            self.metrics
                .underlying_files
                .lock()
                .unwrap()
                .insert(blob_id);
            Ok(entry)
        }
    }
}

impl BlobCacheMgr for FileCacheMgr {
    fn init(&self) -> Result<()> {
        AsyncWorkerMgr::start(self.worker_mgr.clone())
    }

    fn destroy(&self) {
        if !self.closed.load(Ordering::Acquire) {
            self.closed.store(true, Ordering::Release);
            self.worker_mgr.stop();
            self.backend().shutdown();
            self.metrics.release().unwrap_or_else(|e| error!("{:?}", e));
        }
    }

    fn gc(&self, id: Option<&str>) -> bool {
        let mut reclaim = Vec::new();

        if let Some(blob_id) = id {
            reclaim.push(blob_id.to_string());
        } else {
            let guard = self.blobs.write().unwrap();
            for (id, entry) in guard.iter() {
                if Arc::strong_count(entry) == 1 {
                    reclaim.push(id.to_owned());
                }
            }
        }

        for key in reclaim.iter() {
            let mut guard = self.blobs.write().unwrap();
            if let Some(entry) = guard.get(key) {
                if Arc::strong_count(entry) == 1 {
                    guard.remove(key);
                }
            }
        }

        self.blobs.read().unwrap().len() == 0
    }

    fn backend(&self) -> &(dyn BlobBackend) {
        self.backend.as_ref()
    }

    fn get_blob_cache(&self, blob_info: &Arc<BlobInfo>) -> Result<Arc<dyn BlobCache>> {
        self.get_or_create_cache_entry(blob_info)
            .map(|v| v as Arc<dyn BlobCache>)
    }

    fn check_stat(&self) {}
}

impl Drop for FileCacheMgr {
    fn drop(&mut self) {
        self.destroy();
    }
}

impl FileCacheEntry {
    fn new_file_cache(
        mgr: &FileCacheMgr,
        blob_info: Arc<BlobInfo>,
        prefetch_config: Arc<AsyncPrefetchConfig>,
        runtime: Arc<Runtime>,
        workers: Arc<AsyncWorkerMgr>,
    ) -> Result<Self> {
        let is_separate_meta = blob_info.has_feature(BlobFeatures::SEPARATE);
        let is_tarfs = blob_info.features().is_tarfs();
        let is_batch = blob_info.has_feature(BlobFeatures::BATCH);
        let is_zran = blob_info.has_feature(BlobFeatures::ZRAN);
        let blob_id = blob_info.blob_id();
        let blob_meta_id = if is_separate_meta {
            blob_info.get_blob_meta_id()?
        } else {
            blob_id.clone()
        };
        let reader = mgr
            .backend
            .get_reader(&blob_id)
            .map_err(|e| eio!(format!("failed to get reader for blob {}, {}", blob_id, e)))?;
        let blob_meta_reader = if is_separate_meta {
            mgr.backend.get_reader(&blob_meta_id).map_err(|e| {
                eio!(format!(
                    "failed to get reader for blob.meta {}, {}",
                    blob_id, e
                ))
            })?
        } else {
            reader.clone()
        };

        let blob_compressed_size = Self::get_blob_size(&reader, &blob_info)?;
        let blob_uncompressed_size = blob_info.uncompressed_size();
        let is_legacy_stargz = blob_info.is_legacy_stargz();

        let (
            file,
            meta,
            chunk_map,
            is_direct_chunkmap,
            is_get_blob_object_supported,
            need_validation,
        ) = if is_tarfs {
            let blob_file_path = format!("{}/{}", mgr.work_dir, blob_id);
            let file = OpenOptions::new()
                .create(false)
                .write(false)
                .read(true)
                .open(&blob_file_path)?;
            let chunk_map =
                Arc::new(BlobStateMap::from(NoopChunkMap::new(true))) as Arc<dyn ChunkMap>;
            (file, None, chunk_map, true, true, false)
        } else {
            let blob_file_path = format!("{}/{}", mgr.work_dir, blob_meta_id);
            let (chunk_map, is_direct_chunkmap) =
                Self::create_chunk_map(mgr, &blob_info, &blob_file_path)?;
            // Validation is supported by RAFS v5 (which has no meta_ci) or v6 with chunk digest array.
            let validation_supported = !blob_info.meta_ci_is_valid()
                || blob_info.has_feature(BlobFeatures::INLINED_CHUNK_DIGEST);
            let need_validation = ((mgr.validate && validation_supported) || !is_direct_chunkmap)
                && !is_legacy_stargz;
            // Set cache file to its expected size.
            let suffix = if mgr.cache_raw_data {
                ".blob.raw"
            } else {
                ".blob.data"
            };
            let blob_data_file_path = blob_file_path.clone() + suffix;
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .read(true)
                .open(&blob_data_file_path)?;
            let file_size = file.metadata()?.len();
            let cached_file_size = if mgr.cache_raw_data {
                blob_info.compressed_data_size()
            } else {
                blob_info.uncompressed_size()
            };
            if file_size == 0 {
                file.set_len(cached_file_size)?;
            } else if cached_file_size != 0 && file_size != cached_file_size {
                let msg = format!(
                    "blob data file size doesn't match: got 0x{:x}, expect 0x{:x}",
                    file_size, cached_file_size
                );
                return Err(einval!(msg));
            }
            let meta = if blob_info.meta_ci_is_valid() {
                let meta = FileCacheMeta::new(
                    blob_file_path,
                    blob_info.clone(),
                    Some(blob_meta_reader),
                    Some(runtime.clone()),
                    false,
                    need_validation,
                )?;
                Some(meta)
            } else {
                None
            };
            let is_get_blob_object_supported = meta.is_some() && is_direct_chunkmap;
            (
                file,
                meta,
                chunk_map,
                is_direct_chunkmap,
                is_get_blob_object_supported,
                need_validation,
            )
        };

        let (cache_cipher_object, cache_cipher_context) = if mgr.cache_encrypted {
            let key = hex::decode(mgr.cache_encryption_key.clone())
                .map_err(|_e| einval!("invalid cache file encryption key"))?;
            let cipher = crypt::Algorithm::Aes128Xts.new_cipher()?;
            let ctx = crypt::CipherContext::new(
                key,
                [0u8; 16].to_vec(),
                mgr.cache_convergent_encryption,
                crypt::Algorithm::Aes128Xts,
            )?;
            (Arc::new(cipher), Arc::new(ctx))
        } else {
            (Default::default(), Default::default())
        };

        trace!(
            "filecache entry: is_raw_data {}, direct {}, legacy_stargz {}, separate_meta {}, tarfs {}, batch {}, zran {}",
            mgr.cache_raw_data,
            is_direct_chunkmap,
            is_legacy_stargz,
            is_separate_meta,
            is_tarfs,
            is_batch,
            is_zran,
        );
        Ok(FileCacheEntry {
            blob_id,
            blob_info,
            cache_cipher_object,
            cache_cipher_context,
            chunk_map,
            file: Arc::new(file),
            meta,
            metrics: mgr.metrics.clone(),
            prefetch_state: Arc::new(AtomicU32::new(0)),
            reader,
            runtime,
            workers,

            blob_compressed_size,
            blob_uncompressed_size,
            is_get_blob_object_supported,
            is_raw_data: mgr.cache_raw_data,
            is_cache_encrypted: mgr.cache_encrypted,
            is_direct_chunkmap,
            is_legacy_stargz,
            is_tarfs,
            is_batch,
            is_zran,
            dio_enabled: false,
            need_validation,
            batch_size: RAFS_DEFAULT_CHUNK_SIZE,
            prefetch_config,
        })
    }

    fn create_chunk_map(
        mgr: &FileCacheMgr,
        blob_info: &BlobInfo,
        blob_file: &str,
    ) -> Result<(Arc<dyn ChunkMap>, bool)> {
        // The builder now records the number of chunks in the blob table, so we can
        // use IndexedChunkMap as a chunk map, but for the old Nydus bootstrap, we
        // need downgrade to use DigestedChunkMap as a compatible solution.
        let is_v5 = !blob_info.meta_ci_is_valid();
        let mut direct_chunkmap = true;
        let chunk_map: Arc<dyn ChunkMap> = if (is_v5 && mgr.disable_indexed_map)
            || blob_info.has_feature(BlobFeatures::_V5_NO_EXT_BLOB_TABLE)
        {
            direct_chunkmap = false;
            Arc::new(BlobStateMap::from(DigestedChunkMap::new()))
        } else {
            Arc::new(BlobStateMap::from(IndexedChunkMap::new(
                blob_file,
                blob_info.chunk_count(),
                true,
            )?))
        };

        Ok((chunk_map, direct_chunkmap))
    }
}

#[cfg(test)]
pub mod blob_cache_tests {
    use nydus_api::FileCacheConfig;
    use vmm_sys_util::tempdir::TempDir;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_blob_cache_config() {
        // new blob cache
        let tmp_dir = TempDir::new().unwrap();
        let dir = tmp_dir.as_path().to_path_buf();
        let s = format!(
            r###"
        {{
            "work_dir": {:?}
        }}
        "###,
            dir
        );

        let mut blob_config: FileCacheConfig = serde_json::from_str(&s).unwrap();
        assert!(!blob_config.disable_indexed_map);
        assert_eq!(blob_config.work_dir, dir.to_str().unwrap());

        let tmp_file = TempFile::new().unwrap();
        let file = tmp_file.as_path().to_path_buf();
        blob_config.work_dir = file.to_str().unwrap().to_owned();
        assert!(blob_config.get_work_dir().is_err());
    }

    /*
       #[test]
       fn test_add() {
           // new blob cache
           let tmp_dir = TempDir::new().unwrap();
           let s = format!(
               r###"
           {{
               "work_dir": {:?}
           }}
           "###,
               tmp_dir.as_path().to_path_buf().join("cache"),
           );

           let cache_config = CacheConfig {
               cache_validate: true,
               cache_compressed: false,
               cache_type: String::from("blobcache"),
               cache_config: serde_json::from_str(&s).unwrap(),
               prefetch_config: BlobPrefetchConfig::default(),
           };
           let blob_cache = filecache::new(
               cache_config,
               Arc::new(MockBackend {
                   metrics: BackendMetrics::new("id", "mock"),
               }) as Arc<dyn BlobBackend + Send + Sync>,
               compress::Algorithm::Lz4Block,
               digest::Algorithm::Blake3,
               "id",
           )
           .unwrap();

           // generate backend data
           let mut expect = vec![1u8; 100];
           let blob_id = "blobcache";
           blob_cache
               .backend
               .read(blob_id, expect.as_mut(), 0)
               .unwrap();

           // generate chunk and bio
           let mut chunk = MockChunkInfo::new();
           chunk.block_id = RafsDigest::from_buf(&expect, digest::Algorithm::Blake3);
           chunk.file_offset = 0;
           chunk.compress_offset = 0;
           chunk.compress_size = 100;
           chunk.decompress_offset = 0;
           chunk.decompress_size = 100;
           let bio = BlobIoDesc::new(
               Arc::new(chunk),
               Arc::new(BlobInfo {
                   chunk_count: 0,
                   readahead_offset: 0,
                   readahead_size: 0,
                   blob_id: blob_id.to_string(),
                   blob_index: 0,
                   blob_decompressed_size: 0,
                   blob_compressed_size: 0,
               }),
               50,
               50,
               RAFS_DEFAULT_BLOCK_SIZE as u32,
               true,
           );

           // read from cache
           let r1 = unsafe {
               let layout = Layout::from_size_align(50, 1).unwrap();
               let ptr = alloc_zeroed(layout);
               let vs = VolatileSlice::new(ptr, 50);
               blob_cache.read(&mut [bio.clone()], &[vs]).unwrap();
               Vec::from(from_raw_parts(ptr, 50))
           };

           let r2 = unsafe {
               let layout = Layout::from_size_align(50, 1).unwrap();
               let ptr = alloc_zeroed(layout);
               let vs = VolatileSlice::new(ptr, 50);
               blob_cache.read(&mut [bio], &[vs]).unwrap();
               Vec::from(from_raw_parts(ptr, 50))
           };

           assert_eq!(r1, &expect[50..]);
           assert_eq!(r2, &expect[50..]);
       }

       #[test]
       fn test_merge_bio() {
           let tmp_dir = TempDir::new().unwrap();
           let s = format!(
               r###"
           {{
               "work_dir": {:?}
           }}
           "###,
               tmp_dir.as_path().to_path_buf().join("cache"),
           );

           let cache_config = CacheConfig {
               cache_validate: true,
               cache_compressed: false,
               cache_type: String::from("blobcache"),
               cache_config: serde_json::from_str(&s).unwrap(),
               prefetch_worker: BlobPrefetchConfig::default(),
           };

           let blob_cache = filecache::new(
               cache_config,
               Arc::new(MockBackend {
                   metrics: BackendMetrics::new("id", "mock"),
               }) as Arc<dyn BlobBackend + Send + Sync>,
               compress::Algorithm::Lz4Block,
               digest::Algorithm::Blake3,
               "id",
           )
           .unwrap();

           let merging_size: u64 = 128 * 1024 * 1024;

           let single_chunk = MockChunkInfo {
               compress_offset: 1000,
               compress_size: merging_size as u32 - 1,
               ..Default::default()
           };

           let bio = BlobIoDesc::new(
               Arc::new(single_chunk.clone()),
               Arc::new(BlobInfo {
                   chunk_count: 0,
                   readahead_offset: 0,
                   readahead_size: 0,
                   blob_id: "1".to_string(),
                   blob_index: 0,
                   blob_decompressed_size: 0,
                   blob_compressed_size: 0,
               }),
               50,
               50,
               RAFS_DEFAULT_BLOCK_SIZE as u32,
               true,
           );

           let (mut send, recv) = spmc::channel::<MergedBackendRequest>();
           let mut bios = vec![bio];

           blob_cache.generate_merged_requests_for_prefetch(
               &mut bios,
               &mut send,
               merging_size as usize,
           );
           let mr = recv.recv().unwrap();

           assert_eq!(mr.blob_offset, single_chunk.compress_offset());
           assert_eq!(mr.blob_size, single_chunk.compress_size());

           // ---
           let chunk1 = MockChunkInfo {
               compress_offset: 1000,
               compress_size: merging_size as u32 - 2000,
               ..Default::default()
           };

           let bio1 = BlobIoDesc::new(
               Arc::new(chunk1.clone()),
               Arc::new(BlobInfo {
                   chunk_count: 0,
                   readahead_offset: 0,
                   readahead_size: 0,
                   blob_id: "1".to_string(),
                   blob_index: 0,
                   blob_decompressed_size: 0,
                   blob_compressed_size: 0,
               }),
               50,
               50,
               RAFS_DEFAULT_BLOCK_SIZE as u32,
               true,
           );

           let chunk2 = MockChunkInfo {
               compress_offset: 1000 + merging_size - 2000,
               compress_size: 200,
               ..Default::default()
           };

           let bio2 = BlobIoDesc::new(
               Arc::new(chunk2.clone()),
               Arc::new(BlobInfo {
                   chunk_count: 0,
                   readahead_offset: 0,
                   readahead_size: 0,
                   blob_id: "1".to_string(),
                   blob_index: 0,
                   blob_decompressed_size: 0,
                   blob_compressed_size: 0,
               }),
               50,
               50,
               RAFS_DEFAULT_BLOCK_SIZE as u32,
               true,
           );

           let mut bios = vec![bio1, bio2];
           let (mut send, recv) = spmc::channel::<MergedBackendRequest>();
           blob_cache.generate_merged_requests_for_prefetch(
               &mut bios,
               &mut send,
               merging_size as usize,
           );
           let mr = recv.recv().unwrap();

           assert_eq!(mr.blob_offset, chunk1.compress_offset());
           assert_eq!(
               mr.blob_size,
               chunk1.compress_size() + chunk2.compress_size()
           );

           // ---
           let chunk1 = MockChunkInfo {
               compress_offset: 1000,
               compress_size: merging_size as u32 - 2000,
               ..Default::default()
           };

           let bio1 = BlobIoDesc::new(
               Arc::new(chunk1.clone()),
               Arc::new(BlobInfo {
                   chunk_count: 0,
                   readahead_offset: 0,
                   readahead_size: 0,
                   blob_id: "1".to_string(),
                   blob_index: 0,
                   blob_decompressed_size: 0,
                   blob_compressed_size: 0,
               }),
               50,
               50,
               RAFS_DEFAULT_BLOCK_SIZE as u32,
               true,
           );

           let chunk2 = MockChunkInfo {
               compress_offset: 1000 + merging_size - 2000 + 1,
               compress_size: 200,
               ..Default::default()
           };

           let bio2 = BlobIoDesc::new(
               Arc::new(chunk2.clone()),
               Arc::new(BlobInfo {
                   chunk_count: 0,
                   readahead_offset: 0,
                   readahead_size: 0,
                   blob_id: "1".to_string(),
                   blob_index: 0,
                   blob_decompressed_size: 0,
                   blob_compressed_size: 0,
               }),
               50,
               50,
               RAFS_DEFAULT_BLOCK_SIZE as u32,
               true,
           );

           let mut bios = vec![bio1, bio2];
           let (mut send, recv) = spmc::channel::<MergedBackendRequest>();
           blob_cache.generate_merged_requests_for_prefetch(
               &mut bios,
               &mut send,
               merging_size as usize,
           );

           let mr = recv.recv().unwrap();
           assert_eq!(mr.blob_offset, chunk1.compress_offset());
           assert_eq!(mr.blob_size, chunk1.compress_size());

           let mr = recv.recv().unwrap();
           assert_eq!(mr.blob_offset, chunk2.compress_offset());
           assert_eq!(mr.blob_size, chunk2.compress_size());

           // ---
           let chunk1 = MockChunkInfo {
               compress_offset: 1000,
               compress_size: merging_size as u32 - 2000,
               ..Default::default()
           };

           let bio1 = BlobIoDesc::new(
               Arc::new(chunk1.clone()),
               Arc::new(BlobInfo {
                   chunk_count: 0,
                   readahead_offset: 0,
                   readahead_size: 0,
                   blob_id: "1".to_string(),
                   blob_index: 0,
                   blob_decompressed_size: 0,
                   blob_compressed_size: 0,
               }),
               50,
               50,
               RAFS_DEFAULT_BLOCK_SIZE as u32,
               true,
           );

           let chunk2 = MockChunkInfo {
               compress_offset: 1000 + merging_size - 2000,
               compress_size: 200,
               ..Default::default()
           };

           let bio2 = BlobIoDesc::new(
               Arc::new(chunk2.clone()),
               Arc::new(BlobInfo {
                   chunk_count: 0,
                   readahead_offset: 0,
                   readahead_size: 0,
                   blob_id: "2".to_string(),
                   blob_index: 0,
                   blob_decompressed_size: 0,
                   blob_compressed_size: 0,
               }),
               50,
               50,
               RAFS_DEFAULT_BLOCK_SIZE as u32,
               true,
           );

           let mut bios = vec![bio1, bio2];
           let (mut send, recv) = spmc::channel::<MergedBackendRequest>();
           blob_cache.generate_merged_requests_for_prefetch(
               &mut bios,
               &mut send,
               merging_size as usize,
           );

           let mr = recv.recv().unwrap();
           assert_eq!(mr.blob_offset, chunk1.compress_offset());
           assert_eq!(mr.blob_size, chunk1.compress_size());

           let mr = recv.recv().unwrap();
           assert_eq!(mr.blob_offset, chunk2.compress_offset());
           assert_eq!(mr.blob_size, chunk2.compress_size());

           // ---
           let chunk1 = MockChunkInfo {
               compress_offset: 1000,
               compress_size: merging_size as u32 - 2000,
               ..Default::default()
           };

           let bio1 = BlobIoDesc::new(
               Arc::new(chunk1.clone()),
               Arc::new(BlobInfo {
                   chunk_count: 0,
                   readahead_offset: 0,
                   readahead_size: 0,
                   blob_id: "1".to_string(),
                   blob_index: 0,
                   blob_decompressed_size: 0,
                   blob_compressed_size: 0,
               }),
               50,
               50,
               RAFS_DEFAULT_BLOCK_SIZE as u32,
               true,
           );

           let chunk2 = MockChunkInfo {
               compress_offset: 1000 + merging_size - 2000,
               compress_size: 200,
               ..Default::default()
           };

           let bio2 = BlobIoDesc::new(
               Arc::new(chunk2.clone()),
               Arc::new(BlobInfo {
                   chunk_count: 0,
                   readahead_offset: 0,
                   readahead_size: 0,
                   blob_id: "1".to_string(),
                   blob_index: 0,
                   blob_decompressed_size: 0,
                   blob_compressed_size: 0,
               }),
               50,
               50,
               RAFS_DEFAULT_BLOCK_SIZE as u32,
               true,
           );

           let chunk3 = MockChunkInfo {
               compress_offset: 1000 + merging_size - 2000,
               compress_size: 200,
               ..Default::default()
           };

           let bio3 = BlobIoDesc::new(
               Arc::new(chunk3.clone()),
               Arc::new(BlobInfo {
                   chunk_count: 0,
                   readahead_offset: 0,
                   readahead_size: 0,
                   blob_id: "2".to_string(),
                   blob_index: 0,
                   blob_decompressed_size: 0,
                   blob_compressed_size: 0,
               }),
               50,
               50,
               RAFS_DEFAULT_BLOCK_SIZE as u32,
               true,
           );

           let mut bios = vec![bio1, bio2, bio3];
           let (mut send, recv) = spmc::channel::<MergedBackendRequest>();
           blob_cache.generate_merged_requests_for_prefetch(
               &mut bios,
               &mut send,
               merging_size as usize,
           );

           let mr = recv.recv().unwrap();
           assert_eq!(mr.blob_offset, chunk1.compress_offset());
           assert_eq!(
               mr.blob_size,
               chunk1.compress_size() + chunk2.compress_size()
           );

           let mr = recv.recv().unwrap();
           assert_eq!(mr.blob_offset, chunk3.compress_offset());
           assert_eq!(mr.blob_size, chunk3.compress_size());
       }
    */
}
