// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{self, Display, Formatter};
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

        conn.execute(
            "CREATE TABLE IF NOT EXISTS BlobInfos (
            BlobId     TEXT NOT NULL PRIMARY KEY,
            BlobInfo   TEXT NOT NULL
        )",
            (),
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS BlobIndex ON BlobInfos(BlobId)",
            (),
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS ChunkInfos (
            ChunkId           INTEGER PRIMARY KEY,
            ChunkDigestValue  TEXT NOT NULL,
            ChunkInfo         TEXT NOT NULL,
            BlobId            TEXT NOT NULL,
            UNIQUE(ChunkDigestValue, BlobId) ON CONFLICT IGNORE,
            FOREIGN KEY(BlobId) REFERENCES BlobInfos(BlobId)
        )",
            (),
        )?;
        conn.execute(
            "CREATE INDEX IF NOT EXISTS ChunkIndex ON ChunkInfos(ChunkDigestValue)",
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

    pub fn get_blob(&self, blob_id: &str) -> Result<Option<String>> {
        if let Some(blob_info) = self
            .conn
            .query_row(
                "SELECT BlobInfo FROM BlobInfos WHERE BlobId = ?",
                [blob_id],
                |row| row.get::<usize, String>(0),
            )
            .optional()?
        {
            return Ok(Some(blob_info));
        };

        Ok(None)
    }

    pub fn add_blobs(&mut self, blobs: &Vec<(String, String)>) -> Result<()> {
        let tran = self.conn.transaction()?;
        for blob in blobs {
            tran.execute(
                "INSERT OR IGNORE INTO BlobInfos (BlobId, BlobInfo)
                VALUES (?1, ?2)",
                (&blob.0, &blob.1),
            )
            .unwrap();
        }
        tran.commit()?;

        Ok(())
    }

    pub fn delete_blobs(&self, _chunks: &[String]) -> Result<()> {
        unimplemented!()
    }

    pub fn get_chunk(
        &self,
        chunk_id: &RafsDigest,
        blob_id: &str,
    ) -> Result<Option<(String, String)>> {
        if let Some((new_blob_id, chunk_info)) = self
            .conn
            .query_row(
                "SELECT BlobId, ChunkInfo
                FROM ChunkInfos INDEXED BY ChunkIndex
                WHERE ChunkDigestValue = ?",
                [String::from(chunk_id.to_owned()).as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
        {
            if new_blob_id != *blob_id {
                return Ok(Some((new_blob_id, chunk_info)));
            }
        }

        Ok(None)
    }

    pub fn add_chunks(&mut self, chunks: &Vec<(String, String, String)>) -> Result<()> {
        let tran = self.conn.transaction()?;
        for chunk in chunks {
            tran.execute(
                "INSERT OR IGNORE INTO ChunkInfos (ChunkDigestValue, ChunkInfo, BlobId)
                    VALUES (?1, ?2, ?3)",
                (&chunk.0, &chunk.1, &chunk.2),
            )
            .unwrap();
        }
        tran.commit()?;

        Ok(())
    }

    pub fn delete_chunks(&self, _chunks: &[(String, String)]) -> Result<()> {
        unimplemented!()
    }
}
