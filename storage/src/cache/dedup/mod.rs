// Copyright (C) 2022-2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::Error;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use nydus_utils::digest::RafsDigest;

use crate::cache::dedup::db::CasDb;
use crate::device::{BlobChunkInfo, BlobInfo};
use crate::utils::copy_file_range;

mod db;

lazy_static::lazy_static!(
    static ref CAS_MGR: Mutex<Option<Arc<CasMgr>>> = Mutex::new(None);
);

/// Error codes related to local cas.
#[derive(Debug)]
pub enum CasError {
    Io(Error),
    Db(rusqlite::Error),
    R2D2(r2d2::Error),
}

impl Display for CasError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CasError::Io(e) => write!(f, "{}", e),
            CasError::Db(e) => write!(f, "{}", e),
            CasError::R2D2(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for CasError {}

impl From<rusqlite::Error> for CasError {
    fn from(e: rusqlite::Error) -> Self {
        CasError::Db(e)
    }
}

impl From<r2d2::Error> for CasError {
    fn from(e: r2d2::Error) -> Self {
        CasError::R2D2(e)
    }
}

impl From<Error> for CasError {
    fn from(e: Error) -> Self {
        CasError::Io(e)
    }
}

/// Specialized `Result` for local cas.
type Result<T> = std::result::Result<T, CasError>;

pub struct CasMgr {
    db: CasDb,
    fds: RwLock<HashMap<String, Arc<File>>>,
}

impl CasMgr {
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self> {
        let db = CasDb::from_file(db_path.as_ref())?;

        Ok(CasMgr {
            db,
            fds: RwLock::new(HashMap::new()),
        })
    }

    pub fn set_singleton(mgr: CasMgr) {
        *CAS_MGR.lock().unwrap() = Some(Arc::new(mgr));
    }

    pub fn get_singleton() -> Option<Arc<CasMgr>> {
        CAS_MGR.lock().unwrap().clone()
    }

    /// Deduplicate chunk data from existing data files.
    ///
    /// If any error happens, just pretend there's no source data available for dedup.
    pub fn dedup_chunk(
        &self,
        blob: &BlobInfo,
        chunk: &dyn BlobChunkInfo,
        cache_file: &File,
    ) -> bool {
        let key = Self::chunk_key(blob, chunk);
        if key.is_empty() {
            return false;
        }

        if let Ok(Some((path, offset))) = self.db.get_chunk_info(&key) {
            let guard = self.fds.read().unwrap();
            let mut d_file = guard.get(&path).cloned();
            drop(guard);

            // Open the source file for dedup on demand.
            match &d_file {
                None => {
                    match OpenOptions::new().read(true).open(&path) {
                        Err(e) => warn!("failed to open dedup source file {}, {}", path, e),
                        Ok(f) => {
                            let mut guard = self.fds.write().unwrap();
                            match guard.entry(path) {
                                Entry::Vacant(e) => {
                                    let f = Arc::new(f);
                                    e.insert(f.clone());
                                    d_file = Some(f);
                                }
                                Entry::Occupied(f) => {
                                    // Somebody else has inserted the file, use it
                                    d_file = Some(f.get().clone());
                                }
                            }
                        }
                    }
                }
                Some(file) if file.metadata().is_err() => {
                    // If the blob file no longer exists, delete if from fds and db.
                    let mut guard = self.fds.write().unwrap();
                    guard.remove(&path);
                    let blob_ids: &[String] = &[path];
                    if let Err(e) = self.db.delete_blobs(&blob_ids) {
                        warn!("failed to delete blobs: {}", e);
                    }
                    return false;
                }
                Some(_) => {}
            }

            if let Some(f) = d_file {
                match copy_file_range(
                    f,
                    offset,
                    cache_file,
                    chunk.uncompressed_offset(),
                    chunk.uncompressed_size() as usize,
                ) {
                    Ok(_) => {
                        return true;
                    }
                    Err(e) => warn!("{e}"),
                }
            }
        }

        false
    }

    /// Add an available chunk data into the CAS database.
    pub fn record_chunk(
        &self,
        blob: &BlobInfo,
        chunk: &dyn BlobChunkInfo,
        path: impl AsRef<Path>,
    ) -> Result<()> {
        let key = Self::chunk_key(blob, chunk);
        if key.is_empty() {
            return Ok(());
        }

        let path = path.as_ref().canonicalize()?;
        let path = path.display().to_string();
        self.record_chunk_raw(&key, &path, chunk.uncompressed_offset())
    }

    pub fn record_chunk_raw(&self, chunk_id: &str, path: &str, offset: u64) -> Result<()> {
        self.db.add_blob(path)?;
        self.db.add_chunk(chunk_id, offset, path)?;
        Ok(())
    }

    fn chunk_key(blob: &BlobInfo, chunk: &dyn BlobChunkInfo) -> String {
        let id = chunk.chunk_id();
        if *id == RafsDigest::default() {
            String::new()
        } else {
            blob.digester().to_string() + ":" + &chunk.chunk_id().to_string()
        }
    }

    /// Check if blobs in the database still exist on the filesystem and perform garbage collection.
    pub fn gc(&self) -> Result<()> {
        let all_blobs = self.db.get_all_blobs()?;
        let mut blobs_not_exist = Vec::new();
        for (_, file_path) in all_blobs {
            if !std::path::Path::new(&file_path).exists() {
                blobs_not_exist.push(file_path);
            }
        }

        // If there are any non-existent blobs, delete them from the database.
        if !blobs_not_exist.is_empty() {
            self.db.delete_blobs(&blobs_not_exist).map_err(|e| {
                warn!("failed to delete blobs: {}", e);
                e
            })?;
        }

        let mut guard = self.fds.write().unwrap();
        for path in blobs_not_exist {
            // Remove the non-existent blob paths from the cache.
            guard.remove(&path);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::BlobFeatures;
    use crate::test::MockChunkInfo;
    use crate::RAFS_DEFAULT_CHUNK_SIZE;
    use std::io::{Read, Write};
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_cas_chunk_op() {
        let dbfile = TempFile::new().unwrap();
        let tmpfile2 = TempFile::new().unwrap();
        let src_path = tmpfile2.as_path().display().to_string();
        let mgr = CasMgr::new(dbfile.as_path()).unwrap();

        let blob = BlobInfo::new(
            1,
            src_path.clone(),
            8192,
            8192,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            1,
            BlobFeatures::empty(),
        );
        let mut chunk = MockChunkInfo::new();
        chunk.block_id = RafsDigest { data: [3u8; 32] };
        chunk.uncompress_offset = 0;
        chunk.uncompress_size = 8192;
        let chunk = Arc::new(chunk) as Arc<dyn BlobChunkInfo>;

        let buf = vec![0x9u8; 8192];
        let mut src_file = tmpfile2.as_file().try_clone().unwrap();
        src_file.write_all(&buf).unwrap();
        mgr.record_chunk(&blob, chunk.as_ref(), &src_path).unwrap();

        let mut tmpfile3 = TempFile::new().unwrap().into_file();
        assert!(mgr.dedup_chunk(&blob, chunk.as_ref(), &tmpfile3));
        let mut buf2 = vec![0x0u8; 8192];
        tmpfile3.read_exact(&mut buf2).unwrap();
        assert_eq!(buf, buf2);
    }

    #[test]
    fn test_cas_dedup_chunk_failed() {
        let dbfile = TempFile::new().unwrap();
        let mgr = CasMgr::new(dbfile.as_path()).unwrap();

        let new_blob = BlobInfo::new(
            1,
            "test_blob".to_string(),
            8192,
            8192,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            1,
            BlobFeatures::empty(),
        );

        let mut chunk = MockChunkInfo::new();
        chunk.block_id = RafsDigest::default();
        chunk.uncompress_offset = 0;
        chunk.uncompress_size = 8192;
        let chunk = Arc::new(chunk) as Arc<dyn BlobChunkInfo>;

        let tmpfile = TempFile::new().unwrap().into_file();

        assert!(!mgr.dedup_chunk(&new_blob, chunk.as_ref(), &tmpfile));
    }

    #[test]
    fn test_cas_gc() {
        let dbfile = TempFile::new().unwrap();
        let mgr = CasMgr::new(dbfile.as_path()).unwrap();

        let tmpfile = TempFile::new().unwrap();
        let blob_path = tmpfile
            .as_path()
            .canonicalize()
            .unwrap()
            .display()
            .to_string();
        let blob = BlobInfo::new(
            1,
            blob_path.clone(),
            8192,
            8192,
            RAFS_DEFAULT_CHUNK_SIZE as u32,
            1,
            BlobFeatures::empty(),
        );
        let mut chunk = MockChunkInfo::new();
        chunk.block_id = RafsDigest { data: [3u8; 32] };
        chunk.uncompress_offset = 0;
        chunk.uncompress_size = 8192;
        let chunk = Arc::new(chunk) as Arc<dyn BlobChunkInfo>;
        mgr.record_chunk(&blob, chunk.as_ref(), &blob_path).unwrap();

        let all_blobs_before_gc = mgr.db.get_all_blobs().unwrap();
        assert_eq!(all_blobs_before_gc.len(), 1);

        drop(tmpfile);
        mgr.gc().unwrap();

        let all_blobs_after_gc = mgr.db.get_all_blobs().unwrap();
        assert_eq!(all_blobs_after_gc.len(), 0);
    }
}
