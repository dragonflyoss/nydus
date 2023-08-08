// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self, Display, Formatter};
use std::io;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension};

use crate::digest::RafsDigest;

/// Error codes related to local cas.
#[derive(Debug)]
pub enum CasError {
    Io(std::io::Error),
    Db(rusqlite::Error),
}

impl Display for CasError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CasError {}

impl From<rusqlite::Error> for CasError {
    fn from(e: rusqlite::Error) -> Self {
        CasError::Db(e)
    }
}

impl From<io::Error> for CasError {
    fn from(e: io::Error) -> Self {
        CasError::Io(e)
    }
}

/// Specialized `Result` for local cas.
type Result<T> = std::result::Result<T, CasError>;

pub struct CasMgr {
    conn: Connection,
}

impl CasMgr {
    pub fn new(path: impl AsRef<Path>) -> Result<CasMgr> {
        let mut db_path = path.as_ref().to_owned();
        db_path.push("cas.db");
        let conn = Connection::open(db_path)?;

        // create blob and chunk table for nydus v5
        conn.execute(
            "CREATE TABLE IF NOT EXISTS BlobInfos_V5 (
            BlobId     TEXT NOT NULL PRIMARY KEY,
            BlobInfo   TEXT NOT NULL,
            Backend    TEXT NOT NULL
        )",
            (),
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS BlobIndex_V5 ON BlobInfos_V5(BlobId)",
            (),
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS ChunkInfos_V5 (
            ChunkId           INTEGER PRIMARY KEY,
            ChunkDigestValue  TEXT NOT NULL,
            ChunkInfo         TEXT NOT NULL,
            BlobId            TEXT NOT NULL,
            UNIQUE(ChunkDigestValue, BlobId) ON CONFLICT IGNORE,
            FOREIGN KEY(BlobId) REFERENCES BlobInfos_V5(BlobId)
        )",
            (),
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ChunkIndex_V5 ON ChunkInfos_V5(ChunkDigestValue)",
            (),
        )?;

        // create blob and chunk table for nydus v6
        conn.execute(
            "CREATE TABLE IF NOT EXISTS BlobInfos_V6 (
            BlobId     TEXT NOT NULL PRIMARY KEY,
            BlobInfo   TEXT NOT NULL,
            Backend    TEXT NOT NULL
        )",
            (),
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS BlobIndex_V6 ON BlobInfos_V6(BlobId)",
            (),
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS ChunkInfos_V6 (
            ChunkId           INTEGER PRIMARY KEY,
            ChunkDigestValue  TEXT NOT NULL,
            ChunkInfo         TEXT NOT NULL,
            BlobId            TEXT NOT NULL,
            UNIQUE(ChunkDigestValue, BlobId) ON CONFLICT IGNORE,
            FOREIGN KEY(BlobId) REFERENCES BlobInfos_V6(BlobId)
        )",
            (),
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ChunkIndex_V6 ON ChunkInfos_V6(ChunkDigestValue)",
            (),
        )?;

        Ok(CasMgr { conn })
    }

    pub fn get_bootstrap(&mut self, _file: impl AsRef<Path>) -> Option<PathBuf> {
        unimplemented!()
    }

    pub fn add_bootstrap(
        &mut self,
        _source: impl AsRef<Path>,
        _target: impl AsRef<Path>,
    ) -> Result<()> {
        unimplemented!()
    }

    pub fn remove_bootstrap(&mut self, _file: impl AsRef<Path>) -> Result<()> {
        unimplemented!()
    }

    pub fn get_blob(&self, blob_id: &str, is_v6: bool) -> Result<Option<String>> {
        let sql = if is_v6 {
            "SELECT BlobInfo FROM BlobInfos_V6 WHERE BlobId = ?"
        } else {
            "SELECT BlobInfo FROM BlobInfos_V5 WHERE BlobId = ?"
        };

        if let Some(blob_info) = self
            .conn
            .query_row(sql, [blob_id], |row| row.get::<usize, String>(0))
            .optional()?
        {
            return Ok(Some(blob_info));
        };

        Ok(None)
    }

    pub fn get_backend_by_blob_id(&self, blob_id: &str, is_v6: bool) -> Result<Option<String>> {
        let sql = if is_v6 {
            "SELECT Backend FROM BlobInfos_V6 WHERE BlobId = ?"
        } else {
            "SELECT Backend FROM BlobInfos_V5 WHERE BlobId = ?"
        };

        if let Some(backend) = self
            .conn
            .query_row(sql, [blob_id], |row| row.get::<usize, String>(0))
            .optional()?
        {
            return Ok(Some(backend));
        };

        Ok(None)
    }

    pub fn get_all_blobs(&self, is_v6: bool) -> Result<Vec<(String, String)>> {
        let mut stmt = if is_v6 {
            self.conn
                .prepare("SELECT BlobId, BlobInfo FROM BlobInfos_V6")?
        } else {
            self.conn
                .prepare("SELECT BlobId, BlobInfo FROM BlobInfos_V5")?
        };

        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;

        let mut results: Vec<(String, String)> = Vec::new();
        for row in rows {
            results.push(row?);
        }

        Ok(results)
    }

    pub fn add_blobs(&mut self, blobs: &Vec<(String, String, String)>, is_v6: bool) -> Result<()> {
        let sql = if is_v6 {
            "INSERT OR IGNORE INTO BlobInfos_V6 (BlobId, BlobInfo, Backend)
                VALUES (?1, ?2, ?3)"
        } else {
            "INSERT OR IGNORE INTO BlobInfos_V5 (BlobId, BlobInfo, Backend)
                VALUES (?1, ?2, ?3)"
        };

        // let tran = self.conn.transaction()?;
        let tran = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;
        for blob in blobs {
            tran.execute(sql, (&blob.0, &blob.1, &blob.2)).unwrap();
        }
        tran.commit()?;

        Ok(())
    }

    pub fn delete_blobs(&mut self, blobs: &[String], is_v6: bool) -> Result<()> {
        let delete_blobs_sql = if is_v6 {
            "DELETE  FROM BlobInfos_V6 WHERE BlobId = (?1)"
        } else {
            "DELETE  FROM BlobInfos_V5 WHERE BlobId = (?1)"
        };

        let delete_chunks_sql = if is_v6 {
            "DELETE FROM ChunkInfos_V6 WHERE BlobId = (?1)"
        } else {
            "DELETE FROM ChunkInfos_V5 WHERE BlobId = (?1)"
        };

        let tran = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;
        for blob_id in blobs {
            tran.execute(delete_blobs_sql, [blob_id]).unwrap();
            tran.execute(delete_chunks_sql, [blob_id]).unwrap();
        }
        tran.commit()?;

        Ok(())
    }

    pub fn get_chunk(
        &self,
        chunk_id: &RafsDigest,
        blob_id: &str,
        is_v6: bool,
    ) -> Result<Option<(String, String)>> {
        let sql = if is_v6 {
            "SELECT BlobId, ChunkInfo
                FROM ChunkInfos_V6 INDEXED BY ChunkIndex_V6
                WHERE ChunkDigestValue = ?"
        } else {
            "SELECT BlobId, ChunkInfo
                FROM ChunkInfos_V5 INDEXED BY ChunkIndex_V5
                WHERE ChunkDigestValue = ?"
        };

        if let Some((new_blob_id, chunk_info)) = self
            .conn
            .query_row(sql, [String::from(chunk_id.to_owned()).as_str()], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .optional()?
        {
            trace!("new_blob_id = {}, chunk_info = {}", new_blob_id, chunk_info);

            if new_blob_id != *blob_id {
                return Ok(Some((new_blob_id, chunk_info)));
            }
        }

        Ok(None)
    }

    pub fn add_chunks(
        &mut self,
        chunks: &Vec<(String, String, String)>,
        is_v6: bool,
    ) -> Result<()> {
        let sql = if is_v6 {
            "INSERT OR IGNORE INTO ChunkInfos_V6 (ChunkDigestValue, ChunkInfo, BlobId)
                    VALUES (?1, ?2, ?3)"
        } else {
            "INSERT OR IGNORE INTO ChunkInfos_V5 (ChunkDigestValue, ChunkInfo, BlobId)
                    VALUES (?1, ?2, ?3)"
        };

        let tran = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;
        for chunk in chunks {
            tran.execute(sql, (&chunk.0, &chunk.1, &chunk.2)).unwrap();
        }
        tran.commit()?;

        Ok(())
    }

    pub fn delete_chunks(&mut self, blob_id: &str, chunk_id: &str, is_v6: bool) -> Result<()> {
        let sql = if is_v6 {
            "DELETE OR IGNORE FROM ChunkInfos_V6 WHERE BlobId = (?1) AND ChunkId = (?2)"
        } else {
            "DELETE OR IGNORE FROM ChunkInfos_V5 WHERE BlobId = (?1) AND ChunkId = (?2)"
        };

        let tran = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;
        tran.execute(sql, [blob_id, chunk_id]).unwrap();
        tran.commit()?;

        Ok(())
    }

    pub fn delete_chunks_by_blobid(&mut self, blob_id: &str, is_v6: bool) -> Result<()> {
        let sql = if is_v6 {
            "DELETE  FROM ChunkInfos_V6 WHERE BlobId = (?1)"
        } else {
            "DELETE  FROM ChunkInfos_V5 WHERE BlobId = (?1)"
        };

        let tran = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)?;
        tran.execute(sql, [blob_id]).unwrap();
        tran.commit()?;

        Ok(())
    }

    pub fn get_chunks_by_blobid(
        &self,
        blob_id: &str,
        is_v6: bool,
    ) -> Result<Vec<(String, String)>> {
        let sql = if is_v6 {
            "SELECT BlobId, ChunkInfo FROM ChunkInfos_V6 WHERE BlobId = (?1)"
        } else {
            "SELECT BlobId, ChunkInfo FROM ChunkInfos_V5 WHERE BlobId = (?1)"
        };

        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([blob_id], |row| Ok((row.get(0)?, row.get(1)?)))?;

        let mut results: Vec<(String, String)> = Vec::new();
        for row in rows {
            results.push(row?);
        }

        Ok(results)
    }

    pub fn get_all_chunks(&self, is_v6: bool) -> Result<Vec<(String, String)>> {
        let sql = if is_v6 {
            "SELECT BlobId, ChunkInfo FROM ChunkInfos_V6"
        } else {
            "SELECT BlobId, ChunkInfo FROM ChunkInfos_V5"
        };

        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;

        let mut results: Vec<(String, String)> = Vec::new();
        for row in rows {
            results.push(row?);
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::{fs, path::PathBuf};

    #[test]
    fn test_get_all_blobs() {
        let path = PathBuf::from("/tmp/local-cas");
        match fs::create_dir_all(path.clone()) {
            Ok(()) => println!("Directory created!"),
            Err(e) => println!("Error: {:?}", e),
        };
        let cas_mgr = CasMgr::new(path).unwrap();
        let vec = cas_mgr.get_all_blobs(false).unwrap();

        println!("v5 blobs");
        for (blob_id, _blob_info) in vec {
            let backend = cas_mgr
                .get_backend_by_blob_id(&blob_id, false)
                .unwrap()
                .unwrap();
            println!("blob_id: {}, backend: {}", blob_id, backend);
        }

        println!("v6 blobs");
        let vec = cas_mgr.get_all_blobs(true).unwrap();
        for (blob_id, _blob_info) in vec {
            let backend = cas_mgr
                .get_backend_by_blob_id(&blob_id, true)
                .unwrap()
                .unwrap();
            println!("blob_id: {}, backend: {}", blob_id, backend);
        }
    }

    #[test]
    fn test_get_all_chunks() {
        let path = PathBuf::from("/tmp/local-cas");
        match fs::create_dir_all(path.clone()) {
            Ok(()) => println!("Directory created!"),
            Err(e) => println!("Error: {:?}", e),
        };
        let cas_mgr = CasMgr::new(path).unwrap();
        let vec = cas_mgr.get_all_chunks(false).unwrap();
        for (blob_id, chunk_info) in vec {
            println!("[{}, {}]", blob_id, chunk_info);
        }

        let vec = cas_mgr.get_all_chunks(true).unwrap();
        for (blob_id, chunk_info) in vec {
            println!("[{}, {}]", blob_id, chunk_info);
        }
    }

    #[test]
    fn test_delete_chunks() {
        let path = PathBuf::from("/tmp/local-cas");
        match fs::create_dir_all(path.clone()) {
            Ok(()) => println!("Directory created!"),
            Err(e) => println!("Error: {:?}", e),
        };
        let mut cas_mgr = CasMgr::new(path).unwrap();
        let blobs = cas_mgr.get_all_blobs(false).unwrap();
        for (blob_id, _blob_info) in &blobs {
            println!("delete blob: [{}]", blob_id);
            cas_mgr.delete_chunks_by_blobid(blob_id, false).unwrap();
            cas_mgr.delete_chunks_by_blobid(blob_id, true).unwrap();
        }
    }

    #[test]
    fn test_delete_blobs() {
        let path = PathBuf::from("/tmp/local-cas");
        match fs::create_dir_all(path.clone()) {
            Ok(()) => println!("Directory created!"),
            Err(e) => println!("Error: {:?}", e),
        };
        let mut cas_mgr = CasMgr::new(path).unwrap();
        let blobs = cas_mgr.get_all_blobs(false).unwrap();
        for (blob_id, _blob_info) in &blobs {
            println!("delete blob: [{}]", blob_id);
            let blob_id = vec![blob_id.to_owned()];
            cas_mgr.delete_blobs(&blob_id, false).unwrap();
            cas_mgr.delete_blobs(&blob_id, true).unwrap();
        }
    }
}
