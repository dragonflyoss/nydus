// Copyright (C) 2022-2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self, Display, Formatter};
use std::io::Error;
use std::path::Path;

use rusqlite::{Connection, DropBehavior, OptionalExtension, Transaction};

/// Error codes related to local cas.
#[derive(Debug)]
pub enum CasError {
    Io(Error),
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

impl From<Error> for CasError {
    fn from(e: Error) -> Self {
        CasError::Io(e)
    }
}

/// Specialized `Result` for local cas.
type Result<T> = std::result::Result<T, CasError>;

pub struct CasDb {
    conn: Connection,
}

impl CasDb {
    pub fn new(path: impl AsRef<Path>) -> Result<CasDb> {
        let mut db_path = path.as_ref().to_owned();
        db_path.push("cas.db");
        let conn = Connection::open(db_path)?;

        // Always wait in case of busy.
        conn.busy_handler(Some(|_v| true))?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS Blobs (
            BlobId  INTEGER PRIMARY KEY,
            FilePath   TEXT NOT NULL UNIQUE
        )",
            (),
        )?;
        /*
        conn.execute(
            "CREATE INDEX IF NOT EXISTS BlobIndex ON Blobs(FilePath)",
            (),
        )?;
         */

        conn.execute(
            "CREATE TABLE IF NOT EXISTS Chunks (
            ChunkId           TEXT NOT NULL,
            ChunkOffset       INTEGER,
            BlobId            INTEGER,
            UNIQUE(ChunkId, BlobID) ON CONFLICT IGNORE,
            FOREIGN KEY(BlobId) REFERENCES Blobs(BlobId)
        )",
            (),
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ChunkIndex ON Chunks(ChunkId)",
            (),
        )?;
        /*
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ChunkBlobIndex ON Chunks(BlobId)",
            (),
        )?;
         */

        Ok(CasDb { conn })
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
            .conn
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
            .conn
            .query_row(sql, [id], |row| row.get::<usize, String>(0))
            .optional()?
        {
            return Ok(Some(path));
        };

        Ok(None)
    }

    pub fn get_all_blobs(&self) -> Result<Vec<(u64, String)>> {
        let mut stmt = self.conn.prepare("SELECT BlobId, FilePath FROM Blobs")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<usize, u64>(0)?, row.get(1)?)))?;
        let mut results: Vec<(u64, String)> = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn add_blobs(&mut self, blobs: &[String]) -> Result<()> {
        let sql = "INSERT OR IGNORE INTO Blobs (FilePath) VALUES (?1)";

        let tran = self.begin_transaction()?;
        for blob in blobs {
            if let Err(e) = tran.execute(sql, [blob]) {
                return Err(e.into());
            };
        }
        tran.commit()?;

        Ok(())
    }

    pub fn add_blob(&mut self, blob: &str) -> Result<u64> {
        let sql = "INSERT OR IGNORE INTO Blobs (FilePath) VALUES (?1)";
        self.conn.execute(sql, [blob])?;
        Ok(self.conn.last_insert_rowid() as u64)
    }

    pub fn delete_blobs(&mut self, blobs: &[String]) -> Result<()> {
        let delete_blobs_sql = "DELETE FROM Blobs WHERE FilePath = (?1)";
        let delete_chunks_sql = "DELETE FROM Chunks WHERE BlobId = (?1)";

        let tran = self.begin_transaction()?;
        for blob in blobs {
            if let Some(id) = Self::get_blob_id_with_tx(&tran, blob)? {
                if let Err(e) = tran.execute(delete_chunks_sql, [id]) {
                    return Err(e.into());
                }
            }
            if let Err(e) = tran.execute(delete_blobs_sql, [blob]) {
                return Err(e.into());
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
            .conn
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

        let tran = self.begin_transaction()?;
        for chunk in chunks {
            match Self::get_blob_id_with_tx(&tran, &chunk.2) {
                Err(e) => return Err(e.into()),
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

    pub fn add_chunk(&mut self, chunk_id: &str, chunk_offset: u64, blob_id: &str) -> Result<()> {
        let sql = "INSERT OR IGNORE INTO Chunks (ChunkId, ChunkOffset, BlobId) VALUES (?1, ?2, ?3)";

        let tran = self.begin_transaction()?;
        match Self::get_blob_id_with_tx(&tran, blob_id) {
            Err(e) => return Err(e.into()),
            Ok(id) => {
                if let Err(e) = tran.execute(sql, (chunk_id, chunk_offset, id)) {
                    return Err(e.into());
                }
            }
        }
        tran.commit()?;

        Ok(())
    }

    fn begin_transaction(&mut self) -> Result<Transaction> {
        let mut tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.set_drop_behavior(DropBehavior::Rollback);
        Ok(tx)
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
