// Copyright (C) 2022-2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#![allow(unused)]

use std::path::Path;

use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{Connection, DropBehavior, OpenFlags, OptionalExtension, Transaction};

use super::Result;

pub struct CasDb {
    pool: Pool<SqliteConnectionManager>,
}

impl CasDb {
    pub fn new(path: impl AsRef<Path>) -> Result<CasDb> {
        let mut db_path = path.as_ref().to_owned();
        db_path.push("cas.db");
        Self::from_file(db_path)
    }

    pub fn from_file(db_path: impl AsRef<Path>) -> Result<CasDb> {
        let mgr = SqliteConnectionManager::file(db_path)
            .with_flags(OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE)
            .with_init(|c| c.execute_batch("PRAGMA journal_mode = WAL"));
        let pool = r2d2::Pool::builder().max_size(10).build(mgr)?;
        let conn = pool.get()?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS Blobs (
            BlobId     INTEGER PRIMARY KEY,
            FilePath   TEXT NOT NULL UNIQUE
        )",
            (),
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS Chunks (
            ChunkId           TEXT NOT NULL,
            ChunkOffset       INTEGER,
            BlobId            INTEGER,
            UNIQUE(ChunkId, BlobId) ON CONFLICT IGNORE,
            FOREIGN KEY(BlobId) REFERENCES Blobs(BlobId)
        )",
            (),
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ChunkIndex ON Chunks(ChunkId)",
            (),
        )?;

        Ok(CasDb { pool })
    }

    pub fn get_blob_id_with_tx(tran: &Transaction, blob: &str) -> Result<Option<u64>> {
        let sql = "SELECT BlobId FROM Blobs WHERE FilePath = ?";

        if let Some(id) = tran
            .query_row(sql, [blob], |row| row.get::<usize, u64>(0))
            .optional()?
        {
            return Ok(Some(id));
        }

        Ok(None)
    }

    pub fn get_blob_id(&self, blob: &str) -> Result<Option<u64>> {
        let sql = "SELECT BlobId FROM Blobs WHERE FilePath = ?";

        if let Some(id) = self
            .get_connection()?
            .query_row(sql, [blob], |row| row.get::<usize, u64>(0))
            .optional()?
        {
            return Ok(Some(id));
        }

        Ok(None)
    }

    pub fn get_blob_path(&self, id: u64) -> Result<Option<String>> {
        let sql = "SELECT FilePath FROM Blobs WHERE BlobId = ?";

        if let Some(path) = self
            .get_connection()?
            .query_row(sql, [id], |row| row.get::<usize, String>(0))
            .optional()?
        {
            return Ok(Some(path));
        };

        Ok(None)
    }

    pub fn get_all_blobs(&self) -> Result<Vec<(u64, String)>> {
        let conn = self.get_connection()?;
        let mut stmt = conn.prepare_cached("SELECT BlobId, FilePath FROM Blobs")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<usize, u64>(0)?, row.get(1)?)))?;
        let mut results: Vec<(u64, String)> = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn add_blobs(&mut self, blobs: &[String]) -> Result<()> {
        let sql = "INSERT OR IGNORE INTO Blobs (FilePath) VALUES (?1)";
        let mut conn = self.get_connection()?;
        let tran = Self::begin_transaction(&mut conn)?;

        for blob in blobs {
            if let Err(e) = tran.execute(sql, [blob]) {
                return Err(e.into());
            };
        }
        tran.commit()?;

        Ok(())
    }

    pub fn add_blob(&self, blob: &str) -> Result<u64> {
        let sql = "INSERT OR IGNORE INTO Blobs (FilePath) VALUES (?1)";
        let conn = self.get_connection()?;
        conn.execute(sql, [blob])?;
        Ok(conn.last_insert_rowid() as u64)
    }

    pub fn delete_blobs(&self, blobs: &[String]) -> Result<()> {
        let delete_blobs_sql = "DELETE FROM Blobs WHERE BlobId = (?1)";
        let delete_chunks_sql = "DELETE FROM Chunks WHERE BlobId = (?1)";
        let mut conn = self.get_connection()?;
        let tran = Self::begin_transaction(&mut conn)?;

        for blob in blobs {
            if let Some(id) = Self::get_blob_id_with_tx(&tran, blob)? {
                if let Err(e) = tran.execute(delete_chunks_sql, [id]) {
                    return Err(e.into());
                }
                if let Err(e) = tran.execute(delete_blobs_sql, [id]) {
                    return Err(e.into());
                }
            }
        }
        tran.commit()?;

        Ok(())
    }

    pub fn get_chunk_info(&self, chunk_id: &str) -> Result<Option<(String, u64)>> {
        let sql = "SELECT FilePath, ChunkOffset \
                FROM Chunks INDEXED BY ChunkIndex \
                JOIN Blobs ON Chunks.BlobId = Blobs.BlobId \
                WHERE ChunkId = ?\
                ORDER BY Blobs.BlobId LIMIT 1 OFFSET 0";

        if let Some((new_blob_id, chunk_info)) = self
            .get_connection()?
            .query_row(sql, [chunk_id], |row| {
                Ok((row.get(0)?, row.get::<usize, u64>(1)?))
            })
            .optional()?
        {
            return Ok(Some((new_blob_id, chunk_info)));
        }

        Ok(None)
    }

    pub fn add_chunks(&mut self, chunks: &[(String, u64, String)]) -> Result<()> {
        let sql = "INSERT OR IGNORE INTO Chunks (ChunkId, ChunkOffset, BlobId) VALUES (?1, ?2, ?3)";
        let mut conn = self.get_connection()?;
        let tran = Self::begin_transaction(&mut conn)?;

        for chunk in chunks {
            match Self::get_blob_id_with_tx(&tran, &chunk.2) {
                Err(e) => return Err(e),
                Ok(id) => {
                    if let Err(e) = tran.execute(sql, (&chunk.0, &chunk.1, id)) {
                        return Err(e.into());
                    }
                }
            }
        }
        tran.commit()?;

        Ok(())
    }

    pub fn add_chunk(&self, chunk_id: &str, chunk_offset: u64, blob_id: &str) -> Result<()> {
        let sql = "INSERT OR IGNORE INTO Chunks (ChunkId, ChunkOffset, BlobId) VALUES (?1, ?2, ?3)";
        let mut conn = self.get_connection()?;
        let tran = Self::begin_transaction(&mut conn)?;

        match Self::get_blob_id_with_tx(&tran, blob_id) {
            Err(e) => return Err(e),
            Ok(id) => {
                if let Err(e) = tran.execute(sql, (chunk_id, chunk_offset, id)) {
                    return Err(e.into());
                }
            }
        }
        tran.commit()?;

        Ok(())
    }

    fn begin_transaction(
        conn: &mut PooledConnection<SqliteConnectionManager>,
    ) -> Result<Transaction<'_>> {
        let mut tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.set_drop_behavior(DropBehavior::Rollback);
        Ok(tx)
    }

    fn get_connection(&self) -> Result<PooledConnection<SqliteConnectionManager>> {
        let conn = self.pool.get()?;
        conn.busy_handler(Some(|_v| true))?;
        Ok(conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_sys_util::tempdir::TempDir;

    #[test]
    fn test_cas_blob() {
        let tmpdir = TempDir::new().unwrap();

        let mut cas_mgr = CasDb::new(tmpdir.as_path()).unwrap();
        cas_mgr
            .add_blobs(&["/tmp/blob1".to_string(), "/tmp/blob2".to_string()])
            .unwrap();

        let mut mgr2 = CasDb::new(tmpdir.as_path()).unwrap();
        assert_eq!(mgr2.add_blob("/tmp/blob3").unwrap(), 3);

        drop(cas_mgr);

        assert_eq!(mgr2.get_blob_id("/tmp/blob1").unwrap(), Some(1));
        assert_eq!(mgr2.get_blob_id("/tmp/blob2").unwrap(), Some(2));
        assert_eq!(mgr2.get_blob_id("/tmp/blob3").unwrap(), Some(3));
        assert_eq!(mgr2.get_blob_id("/tmp/blob4").unwrap(), None);

        assert_eq!(
            mgr2.get_blob_path(1).unwrap(),
            Some("/tmp/blob1".to_string())
        );
        assert_eq!(
            mgr2.get_blob_path(2).unwrap(),
            Some("/tmp/blob2".to_string())
        );
        assert_eq!(
            mgr2.get_blob_path(3).unwrap(),
            Some("/tmp/blob3".to_string())
        );
        assert_eq!(mgr2.get_blob_path(4).unwrap(), None);

        let blobs = mgr2.get_all_blobs().unwrap();
        assert_eq!(blobs.len(), 3);

        mgr2.delete_blobs(&["/tmp/blob1".to_string(), "/tmp/blob2".to_string()])
            .unwrap();
        assert_eq!(mgr2.get_blob_path(1).unwrap(), None);
        assert_eq!(mgr2.get_blob_path(2).unwrap(), None);
        assert_eq!(
            mgr2.get_blob_path(3).unwrap(),
            Some("/tmp/blob3".to_string())
        );

        let blobs = mgr2.get_all_blobs().unwrap();
        assert_eq!(blobs.len(), 1);
    }

    #[test]
    fn test_cas_chunk() {
        let tmpdir = TempDir::new().unwrap();
        let mut cas_mgr = CasDb::new(tmpdir.as_path()).unwrap();
        cas_mgr
            .add_blobs(&["/tmp/blob1".to_string(), "/tmp/blob2".to_string()])
            .unwrap();

        cas_mgr
            .add_chunks(&[
                ("chunk1".to_string(), 4096, "/tmp/blob1".to_string()),
                ("chunk2".to_string(), 0, "/tmp/blob2".to_string()),
            ])
            .unwrap();

        let (file, offset) = cas_mgr.get_chunk_info("chunk1").unwrap().unwrap();
        assert_eq!(&file, "/tmp/blob1");
        assert_eq!(offset, 4096);
        let (file, offset) = cas_mgr.get_chunk_info("chunk2").unwrap().unwrap();
        assert_eq!(&file, "/tmp/blob2");
        assert_eq!(offset, 0);

        cas_mgr.add_chunk("chunk1", 8192, "/tmp/blob2").unwrap();
        let (file, offset) = cas_mgr.get_chunk_info("chunk1").unwrap().unwrap();
        assert_eq!(&file, "/tmp/blob1");
        assert_eq!(offset, 4096);

        cas_mgr.delete_blobs(&["/tmp/blob1".to_string()]).unwrap();
        let (file, offset) = cas_mgr.get_chunk_info("chunk1").unwrap().unwrap();
        assert_eq!(&file, "/tmp/blob2");
        assert_eq!(offset, 8192);

        cas_mgr.delete_blobs(&["/tmp/blob2".to_string()]).unwrap();
        let res = cas_mgr.get_chunk_info("chunk1").unwrap();
        assert!(res.is_none());
        let res = cas_mgr.get_chunk_info("chunk2").unwrap();
        assert!(res.is_none());
    }
}
