// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Result, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use nix::sys::uio;
use nix::unistd::dup;
extern crate spmc;
use vm_memory::VolatileSlice;

use crate::metadata::digest::{self, RafsDigest};
use crate::metadata::layout::OndiskBlobTableEntry;
use crate::metadata::{RafsChunkInfo, RafsSuperMeta};
use crate::storage::backend::BlobBackend;
use crate::storage::cache::RafsCache;
use crate::storage::cache::*;
use crate::storage::device::RafsBio;
use crate::storage::factory::CacheConfig;
use crate::storage::utils::{alloc_buf, copyv, readv};

use nydus_utils::{einval, enoent, enosys, last_error};

#[derive(Clone, Eq, PartialEq)]
enum CacheStatus {
    Ready,
    NotReady,
}

struct BlobCacheEntry {
    status: CacheStatus,
    chunk: Arc<dyn RafsChunkInfo>,
    fd: RawFd,
}

impl BlobCacheEntry {
    fn new(chunk: Arc<dyn RafsChunkInfo>, fd: RawFd) -> BlobCacheEntry {
        BlobCacheEntry {
            status: CacheStatus::NotReady,
            chunk,
            fd,
        }
    }

    fn is_ready(&self) -> bool {
        self.status == CacheStatus::Ready
    }

    fn set_ready(&mut self) {
        self.status = CacheStatus::Ready
    }

    fn read_partial_chunk(
        &self,
        bufs: &[VolatileSlice],
        offset: u64,
        max_size: usize,
    ) -> Result<usize> {
        readv(self.fd, bufs, offset, max_size)
    }

    /// Persist a single chunk into local blob cache file. We have to write to the cache
    /// file in unit of chunk size
    fn cache(&mut self, buf: &[u8], offset: u64) -> Result<()> {
        loop {
            let ret = uio::pwrite(self.fd, buf, offset as i64).map_err(|_| last_error!());

            match ret {
                Ok(nr_write) => {
                    trace!("write {}(offset={}) bytes to cache file", nr_write, offset);
                    break;
                }
                Err(err) => {
                    // Retry if the IO is interrupted by signal.
                    if err.kind() != ErrorKind::Interrupted {
                        return Err(err);
                    }
                }
            }
        }

        self.set_ready();
        Ok(())
    }
}

#[derive(Default)]
struct BlobCacheState {
    chunk_map: HashMap<RafsDigest, Arc<Mutex<BlobCacheEntry>>>,
    file_map: HashMap<String, (File, u64)>,
    work_dir: String,
    backend_size_valid: bool,
}

impl BlobCacheState {
    fn get_blob_fd(
        &mut self,
        blob_id: &str,
        backend: &(dyn BlobBackend + Sync + Send),
    ) -> Result<(RawFd, u64)> {
        if let Some((file, size)) = self.file_map.get(blob_id) {
            return Ok((file.as_raw_fd(), *size));
        }

        let blob_file_path = format!("{}/{}", self.work_dir, blob_id);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(blob_file_path)?;
        let fd = file.as_raw_fd();

        let mut size = 0;
        if self.backend_size_valid {
            size = backend.blob_size(blob_id)?;
        }

        self.file_map.insert(blob_id.to_string(), (file, size));

        Ok((fd, size))
    }

    fn get(&self, blk: Arc<dyn RafsChunkInfo>) -> Option<Arc<Mutex<BlobCacheEntry>>> {
        // Do not expect poisoned lock here.
        self.chunk_map.get(&blk.block_id()).cloned()
    }

    fn set(
        &mut self,
        blob_id: &str,
        cki: Arc<dyn RafsChunkInfo>,
        backend: &(dyn BlobBackend + Sync + Send),
    ) -> Result<Arc<Mutex<BlobCacheEntry>>> {
        let block_id = cki.block_id();
        // Double check if someone else has inserted the blob chunk concurrently.
        if let Some(entry) = self.chunk_map.get(&block_id) {
            Ok(entry.clone())
        } else {
            let (fd, _) = self.get_blob_fd(blob_id, backend)?;
            let entry = Arc::new(Mutex::new(BlobCacheEntry::new(cki, fd)));
            self.chunk_map.insert(*block_id, entry.clone());
            Ok(entry)
        }
    }
}

#[derive(Clone)]
pub struct BlobCache {
    cache: Arc<RwLock<BlobCacheState>>,
    validate: bool,
    pub backend: Arc<dyn BlobBackend + Sync + Send>,
    prefetch_worker: PrefetchWorker,
    is_compressed: bool,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
}

impl BlobCache {
    fn entry_read(
        &self,
        blob_id: &str,
        entry: &Mutex<BlobCacheEntry>,
        bufs: &[VolatileSlice],
        offset: u64,
        size: usize,
    ) -> Result<usize> {
        let mut cache_entry = entry.lock().unwrap();
        let chunk = cache_entry.chunk.clone();
        let mut reuse = false;

        trace!("reading blobcache entry {:?}", chunk.cast_ondisk());

        // Hit cache if cache ready
        if !self.is_compressed && !self.need_validate() && cache_entry.is_ready() {
            trace!(
                "hit blob cache {} {}",
                chunk.block_id().to_string(),
                chunk.compress_size()
            );
            return cache_entry.read_partial_chunk(bufs, offset + chunk.decompress_offset(), size);
        }

        let d_size = chunk.decompress_size() as usize;
        let mut d;
        // one_chunk_buf is the decompressed data buffer
        let one_chunk_buf =
            if !self.is_compressed && bufs.len() == 1 && bufs[0].len() >= d_size && offset == 0 {
                // Optimize for the case where the first VolatileSlice covers the whole chunk.
                // Reuse the destination data buffer.
                reuse = true;
                unsafe { std::slice::from_raw_parts_mut(bufs[0].as_ptr(), d_size) }
            } else {
                d = alloc_buf(d_size);
                d.as_mut_slice()
            };

        // Try to recover cache from blobcache first
        // For gzip, we can only trust ready blobcache because we cannot validate chunks due to
        // stargz format limitations (missing chunk level digest)
        if (self.compressor() != compress::Algorithm::GZip || cache_entry.is_ready())
            && self
                .read_blobcache_chunk(cache_entry.fd, chunk.as_ref(), one_chunk_buf)
                .is_ok()
        {
            trace!(
                "recover blob cache {} {} resue {} offset {} size {}",
                chunk.block_id(),
                d_size,
                reuse,
                offset,
                size,
            );
        } else {
            self.read_backend_chunk(blob_id, chunk.as_ref(), one_chunk_buf, |c1, c2| {
                let (chunk, c_offset) = if self.is_compressed {
                    (c1, cache_entry.chunk.compress_offset())
                } else {
                    (c2, cache_entry.chunk.decompress_offset())
                };

                cache_entry.cache(chunk, c_offset)
            })?;
        }

        if reuse {
            Ok(one_chunk_buf.len())
        } else {
            copyv(one_chunk_buf, bufs, offset, size).map_err(|e| {
                error!("failed to copy from chunk buf to buf: {:?}", e);
                e
            })
        }
    }

    fn read_blobcache_chunk(
        &self,
        fd: RawFd,
        cki: &dyn RafsChunkInfo,
        chunk: &mut [u8],
    ) -> Result<()> {
        let offset = if self.is_compressed {
            cki.compress_offset()
        } else {
            cki.decompress_offset()
        };

        let mut d;
        let raw_chunk = if self.is_compressed && self.compressor() != compress::Algorithm::GZip {
            // Need to put compressed data into a temporary buffer so as to perform decompression.
            // TODO: Use a buffer pool for lower latency?
            //
            // gzip is special that it doesn't carry compress_size, instead, we make an IO stream out
            // of the blobcache file. So no need for an internal buffer here.
            let c_size = cki.compress_size() as usize;
            d = alloc_buf(c_size);
            d.as_mut_slice()
        } else {
            // We have this unsafe assignment as it can directly store data into call's buffer.
            unsafe { slice::from_raw_parts_mut(chunk.as_mut_ptr(), chunk.len()) }
        };

        let mut raw_stream = None;
        if self.compressor() != compress::Algorithm::GZip {
            debug!(
                "reading blobcache file fd {} offset {} size {}",
                fd,
                offset,
                raw_chunk.len()
            );
            let nr_read = uio::pread(fd, raw_chunk, offset as i64).map_err(|_| last_error!())?;
            if nr_read == 0 || nr_read != raw_chunk.len() {
                return Err(einval!());
            }
        } else {
            debug!(
                "using blobcache file fd {} offset {} as data stream",
                fd, offset,
            );
            let fd = dup(fd).map_err(|_| last_error!())?;
            let mut f = unsafe { File::from_raw_fd(fd) };
            f.seek(SeekFrom::Start(offset)).map_err(|_| last_error!())?;
            raw_stream = Some(f)
        }

        // Try to validate data just fetched from backend inside.
        self.process_raw_chunk(cki, raw_chunk, raw_stream, chunk, self.is_compressed)?;

        Ok(())
    }
}

impl RafsCache for BlobCache {
    fn backend(&self) -> &(dyn BlobBackend + Sync + Send) {
        self.backend.as_ref()
    }

    fn has(&self, blk: Arc<dyn RafsChunkInfo>) -> bool {
        // Doesn't expected poisoned lock here.
        self.cache
            .read()
            .unwrap()
            .chunk_map
            .contains_key(&blk.block_id())
    }

    fn init(&self, _sb_meta: &RafsSuperMeta, blobs: &[OndiskBlobTableEntry]) -> Result<()> {
        for b in blobs {
            let _ = self.backend.prefetch_blob(
                b.blob_id.as_str(),
                b.readahead_offset,
                b.readahead_size,
            );
        }
        // TODO start blob cache level prefetch
        Ok(())
    }

    fn evict(&self, blk: Arc<dyn RafsChunkInfo>) -> Result<()> {
        // Doesn't expected poisoned lock here.
        self.cache
            .write()
            .unwrap()
            .chunk_map
            .remove(&blk.block_id());

        Ok(())
    }

    fn flush(&self) -> Result<()> {
        Err(enosys!())
    }

    fn read(&self, bio: &RafsBio, bufs: &[VolatileSlice], offset: u64) -> Result<usize> {
        let blob_id = &bio.blob_id;

        let mut entry = self.cache.read().unwrap().get(bio.chunkinfo.clone());
        if entry.is_none() {
            let en =
                self.cache
                    .write()
                    .unwrap()
                    .set(blob_id, bio.chunkinfo.clone(), self.backend())?;
            entry = Some(en);
        };

        self.entry_read(blob_id, &entry.unwrap(), bufs, offset, bio.size)
    }

    fn write(&self, _blob_id: &str, _blk: &dyn RafsChunkInfo, _buf: &[u8]) -> Result<usize> {
        Err(enosys!())
    }

    fn blob_size(&self, blob_id: &str) -> Result<u64> {
        let (_, size) = self
            .cache
            .write()
            .unwrap()
            .get_blob_fd(blob_id, self.backend())?;
        Ok(size)
    }

    fn release(&self) {}
    /// Bypass memory blob cache index, fetch blocks from backend and directly
    /// mirror them into blob cache file.
    /// Continuous chunks may be compressed or not.
    fn prefetch(&self, bios: &mut [RafsBio]) -> Result<usize> {
        let (mut tx, rx) = spmc::channel::<MergedBackendRequest>();

        for num in 0..self.prefetch_worker.threads_count {
            let cache = Arc::clone(&self.cache);
            // Clone cache fulfils our requirement that invoke `read_chunks` and it's
            // hard to move `self` into closure.
            let cache_cloned = Arc::new(self.clone());
            let rx = rx.clone();
            let _thread = thread::Builder::new()
                .name(format!("prefetch_thread_{}", num))
                .spawn(move || {
                    'wait_mr: while let Ok(mr) = rx.recv() {
                        let blob_offset = mr.blob_offset;
                        let blob_size = mr.blob_size;
                        let continuous_chunks = &mr.chunks;
                        let blob_id = &mr.blob_id;
                        let mut issue_batch: bool;

                        trace!(
                            "Merged req id {} req offset {} size {}",
                            blob_id,
                            blob_offset,
                            blob_size
                        );

                        issue_batch = false;
                        // An immature trick here to detect if chunk already resides in
                        // blob cache file. Hopefully, we can have a more clever and agile
                        // way in the future. Principe is that if all chunks are Ready,
                        // abort this Merged Request. It might involve extra stress
                        // to local file system.
                        for c in continuous_chunks {
                            let d_size = c.decompress_size() as usize;
                            let entry = cache.write().expect("Expect cache lock not poisoned").set(
                                blob_id,
                                c.clone(),
                                cache_cloned.backend(),
                            );
                            if let Ok(entry) = entry {
                                if entry.lock().unwrap().is_ready() {
                                    continue;
                                }
                                if cache_cloned
                                    .read_blobcache_chunk(
                                        entry.lock().unwrap().fd,
                                        entry.lock().unwrap().chunk.as_ref(),
                                        alloc_buf(d_size).as_mut_slice(),
                                    )
                                    .is_err()
                                {
                                    // Aha, we have a not integrated chunk here. Issue the entire
                                    // merged request from backend to boost.
                                    issue_batch = true;
                                    break;
                                }
                            }
                        }

                        if !issue_batch {
                            continue 'wait_mr;
                        }

                        if let Ok(chunks) = cache_cloned.read_chunks(
                            blob_id,
                            blob_offset,
                            blob_size as usize,
                            &continuous_chunks,
                        ) {
                            for (i, c) in continuous_chunks.iter().enumerate() {
                                let mut cache_guard =
                                    cache.write().expect("Expect cache lock not poisoned");

                                if let Ok(entry) = cache_guard
                                    .set(blob_id, c.clone(), cache_cloned.backend())
                                    .map_err(|_| error!("Set cache index error!"))
                                {
                                    let offset = if cache_cloned.is_compressed {
                                        entry.lock().unwrap().chunk.compress_offset()
                                    } else {
                                        entry.lock().unwrap().chunk.decompress_offset()
                                    };

                                    // Ignore cache errors
                                    let _ =
                                        entry.lock().unwrap().cache(chunks[i].as_slice(), offset);
                                }
                            }
                        }
                    }
                    info!("Prefetch thread exits.")
                });
        }

        // Ideally, prefetch task can run within a separated thread from loading prefetch table.
        // However, due to current implementation, doing so needs modifying key data structure like
        // `Superblock` on `Rafs`. So let's suspend this action.
        let mut bios = bios.to_vec();
        let merging_size = self.prefetch_worker.merging_size;
        let _thread = thread::Builder::new().spawn({
            move || {
                generate_merged_requests(bios.as_mut_slice(), &mut tx, merging_size);
            }
        });

        Ok(0)
    }

    #[inline]
    fn digester(&self) -> digest::Algorithm {
        self.digester
    }

    #[inline]
    fn compressor(&self) -> compress::Algorithm {
        self.compressor
    }

    #[inline]
    fn need_validate(&self) -> bool {
        self.validate
    }
}

#[derive(Clone, Deserialize)]
struct BlobCacheConfig {
    #[serde(default = "default_work_dir")]
    work_dir: String,
}

fn default_work_dir() -> String {
    ".".to_string()
}

pub fn new(
    config: CacheConfig,
    backend: Arc<dyn BlobBackend + Sync + Send>,
    compressor: compress::Algorithm,
    digester: digest::Algorithm,
) -> Result<BlobCache> {
    let blob_config: BlobCacheConfig =
        serde_json::from_value(config.cache_config).map_err(|e| einval!(e))?;
    let work_dir = {
        let path = fs::metadata(&blob_config.work_dir)
            .or_else(|_| {
                fs::create_dir_all(&blob_config.work_dir)?;
                fs::metadata(&blob_config.work_dir)
            })
            .map_err(|e| {
                last_error!(format!(
                    "fail to stat blobcache work_dir {}: {}",
                    blob_config.work_dir, e
                ))
            })?;
        if path.is_dir() {
            Ok(blob_config.work_dir.as_str())
        } else {
            Err(enoent!(format!(
                "blobcache work_dir {} is not a directory",
                blob_config.work_dir
            )))
        }
    }?;

    Ok(BlobCache {
        cache: Arc::new(RwLock::new(BlobCacheState {
            chunk_map: HashMap::new(),
            file_map: HashMap::new(),
            work_dir: work_dir.to_string(),
            backend_size_valid: compressor == compress::Algorithm::GZip,
        })),
        validate: config.cache_validate,
        is_compressed: config.cache_compressed,
        backend,
        prefetch_worker: config.prefetch_worker,
        compressor,
        digester,
    })
}

#[cfg(test)]
mod blob_cache_tests {
    use std::alloc::{alloc, dealloc, Layout};
    use std::io::Result;
    use std::slice::from_raw_parts;
    use std::sync::Arc;

    use vm_memory::{VolatileMemory, VolatileSlice};
    use vmm_sys_util::tempdir::TempDir;

    use crate::metadata::digest::{self, RafsDigest};
    use crate::metadata::layout::OndiskChunkInfo;
    use crate::metadata::RAFS_DEFAULT_BLOCK_SIZE;
    use crate::storage::backend::BlobBackend;
    use crate::storage::cache::blobcache;
    use crate::storage::cache::PrefetchWorker;
    use crate::storage::cache::RafsCache;
    use crate::storage::compress;
    use crate::storage::device::RafsBio;
    use crate::storage::factory::CacheConfig;

    struct MockBackend {}

    impl BlobBackend for MockBackend {
        fn try_read(&self, _blob_id: &str, buf: &mut [u8], _offset: u64) -> Result<usize> {
            let mut i = 0;
            while i < buf.len() {
                buf[i] = i as u8;
                i += 1;
            }
            Ok(i)
        }

        fn write(&self, _blob_id: &str, _buf: &[u8], _offset: u64) -> Result<usize> {
            Ok(0)
        }

        fn blob_size(&self, _blob_id: &str) -> Result<u64> {
            Ok(0)
        }
    }

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
            prefetch_worker: PrefetchWorker::default(),
        };
        let blob_cache = blobcache::new(
            cache_config,
            Arc::new(MockBackend {}) as Arc<dyn BlobBackend + Send + Sync>,
            compress::Algorithm::LZ4Block,
            digest::Algorithm::Blake3,
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
        let mut chunk = OndiskChunkInfo::new();
        chunk.block_id = RafsDigest::from_buf(&expect, digest::Algorithm::Blake3).into();
        chunk.file_offset = 0;
        chunk.compress_offset = 0;
        chunk.compress_size = 100;
        chunk.decompress_offset = 0;
        chunk.decompress_size = 100;
        let bio = RafsBio::new(
            Arc::new(chunk),
            blob_id.to_string(),
            50,
            50,
            RAFS_DEFAULT_BLOCK_SIZE as u32,
        );

        // read from cache
        let r1 = unsafe {
            let layout = Layout::from_size_align(50, 1).unwrap();
            let ptr = alloc(layout);
            let vs = VolatileSlice::new(ptr, 50);
            blob_cache.read(&bio, &[vs], 50).unwrap();
            let data = Vec::from(from_raw_parts(ptr, 50).clone());
            dealloc(ptr, layout);
            data
        };

        let r2 = unsafe {
            let layout = Layout::from_size_align(50, 1).unwrap();
            let ptr = alloc(layout);
            let vs = VolatileSlice::new(ptr, 50);
            blob_cache.read(&bio, &[vs], 50).unwrap();
            let data = Vec::from(from_raw_parts(ptr, 50).clone());
            dealloc(ptr, layout);
            data
        };

        assert_eq!(r1, &expect[50..]);
        assert_eq!(r2, &expect[50..]);
    }
}
