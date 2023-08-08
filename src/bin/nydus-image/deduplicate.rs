// Copyright (C) 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Deduplicate for Chunk.
use anyhow::{Context, Result};
use nydus_api::ConfigV2;
use nydus_builder::Tree;
use nydus_rafs::metadata::RafsSuper;
use nydus_storage::device::BlobInfo;
use rusqlite::{params, Connection};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub enum DatabaseError {
    SqliteError(rusqlite::Error),
    PoisonError(String),
    // Add other database error variants here as needed, e.g.:
    // MysqlError(mysql::Error),
}

impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            DatabaseError::SqliteError(ref err) => err.fmt(f),
            DatabaseError::PoisonError(ref err) => write!(f, "PoisonError: {}", err),
            // Add other error type formatting here
        }
    }
}

impl std::error::Error for DatabaseError {}

impl From<rusqlite::Error> for DatabaseError {
    fn from(error: rusqlite::Error) -> Self {
        DatabaseError::SqliteError(error)
    }
}

pub trait Database {
    /// Creates a new chunk in the database.
    fn create_chunk_table(&self) -> Result<()>;

    /// Creates a new blob in the database.
    fn create_blob_table(&self) -> Result<()>;

    /// Inserts chunk information into the database.
    fn insert_chunk(&self, chunk_info: &Chunk) -> Result<()>;

    /// Inserts blob information into the database.
    fn insert_blob(&self, blob_info: &Blob) -> Result<()>;

    /// Retrieves all chunk information from the database.
    fn get_chunks(&self) -> Result<Vec<Chunk>>;

    /// Retrieves all blob information from the database.
    fn get_blobs(&self) -> Result<Vec<Blob>>;
}

pub struct SqliteDatabase {
    chunk_table: ChunkTable,
    blob_table: BlobTable,
}

impl SqliteDatabase {
    pub fn new(database_url: &str) -> Result<Self, rusqlite::Error> {
        // Delete the database file if it exists.
        if let Ok(metadata) = fs::metadata(database_url) {
            if metadata.is_file() {
                if let Err(err) = fs::remove_file(database_url) {
                    warn!(
                        "Warning: Unable to delete existing database file: {:?}.",
                        err
                    );
                }
            }
        }

        let chunk_table = ChunkTable::new(database_url)?;
        let blob_table = BlobTable::new(database_url)?;

        Ok(Self {
            chunk_table,
            blob_table,
        })
    }

    pub fn new_in_memory() -> Result<Self, rusqlite::Error> {
        let chunk_table = ChunkTable::new_in_memory()?;
        let blob_table = BlobTable::new_in_memory()?;
        Ok(Self {
            chunk_table,
            blob_table,
        })
    }
}

impl Database for SqliteDatabase {
    fn create_chunk_table(&self) -> Result<()> {
        ChunkTable::create(&self.chunk_table).context("Failed to create chunk table")
    }

    fn create_blob_table(&self) -> Result<()> {
        BlobTable::create(&self.blob_table).context("Failed to create blob table")
    }

    fn insert_chunk(&self, chunk: &Chunk) -> Result<()> {
        self.chunk_table
            .insert(chunk)
            .context("Failed to insert chunk")
    }

    fn insert_blob(&self, blob: &Blob) -> Result<()> {
        self.blob_table
            .insert(blob)
            .context("Failed to insert blob")
    }

    fn get_chunks(&self) -> Result<Vec<Chunk>> {
        ChunkTable::list_all(&self.chunk_table).context("Failed to get chunks")
    }

    fn get_blobs(&self) -> Result<Vec<Blob>> {
        BlobTable::list_all(&self.blob_table).context("Failed to get blobs")
    }
}

pub struct Deduplicate<D: Database + Send + Sync> {
    sb: RafsSuper,
    db: D,
}

const IN_MEMORY_DB_URL: &str = ":memory:";

impl Deduplicate<SqliteDatabase> {
    pub fn new(bootstrap_path: &Path, config: Arc<ConfigV2>, db_url: &str) -> anyhow::Result<Self> {
        let (sb, _) = RafsSuper::load_from_file(bootstrap_path, config, false)?;
        let db = if db_url == IN_MEMORY_DB_URL {
            SqliteDatabase::new_in_memory()?
        } else {
            SqliteDatabase::new(db_url)?
        };
        Ok(Self { sb, db })
    }

    pub fn save_metadata(&mut self) -> anyhow::Result<Vec<Arc<BlobInfo>>> {
        self.create_tables()?;
        let blob_infos = self.sb.superblock.get_blob_infos();
        self.insert_blobs(&blob_infos)?;
        self.insert_chunks(&blob_infos)?;
        Ok(blob_infos)
    }

    fn create_tables(&mut self) -> anyhow::Result<()> {
        self.db
            .create_chunk_table()
            .context("Failed to create chunk table.")?;
        self.db
            .create_blob_table()
            .context("Failed to create blob table.")?;
        Ok(())
    }

    fn insert_blobs(&mut self, blob_infos: &[Arc<BlobInfo>]) -> anyhow::Result<()> {
        for blob in blob_infos {
            self.db
                .insert_blob(&Blob {
                    blob_id: blob.blob_id().to_string(),
                    blob_compressed_size: blob.compressed_size(),
                    blob_uncompressed_size: blob.uncompressed_size(),
                })
                .context("Failed to insert blob")?;
        }
        Ok(())
    }

    fn insert_chunks(&mut self, blob_infos: &[Arc<BlobInfo>]) -> anyhow::Result<()> {
        let process_chunk = &mut |t: &Tree| -> Result<()> {
            let node = t.lock_node();
            for chunk in &node.chunks {
                let index = chunk.inner.blob_index();
                let chunk_blob_id = blob_infos[index as usize].blob_id();
                self.db
                    .insert_chunk(&Chunk {
                        chunk_blob_id,
                        chunk_digest: chunk.inner.id().to_string(),
                        chunk_compressed_size: chunk.inner.compressed_size(),
                        chunk_uncompressed_size: chunk.inner.uncompressed_size(),
                        chunk_compressed_offset: chunk.inner.compressed_offset(),
                        chunk_uncompressed_offset: chunk.inner.uncompressed_offset(),
                    })
                    .context("Failed to insert chunk")?;
            }
            Ok(())
        };
        let tree = Tree::from_bootstrap(&self.sb, &mut ())
            .context("Failed to load bootstrap for deduplication.")?;
        tree.walk_dfs_pre(process_chunk)?;
        Ok(())
    }
}

pub trait Table<T, Err>: Sync + Send + Sized + 'static
where
    Err: std::error::Error + 'static,
{
    /// clear table.
    fn clear(&self) -> Result<(), Err>;

    /// create table.
    fn create(&self) -> Result<(), Err>;

    /// insert data.
    fn insert(&self, table: &T) -> Result<(), Err>;

    /// select all data.
    fn list_all(&self) -> Result<Vec<T>, Err>;

    /// select data with offset and limit.
    fn list_paged(&self, offset: i64, limit: i64) -> Result<Vec<T>, Err>;
}

#[derive(Debug)]
pub struct ChunkTable {
    conn: Arc<Mutex<Connection>>,
}

impl ChunkTable {
    pub fn new(database_url: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(database_url)?;
        Ok(ChunkTable {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn new_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        Ok(ChunkTable {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

#[derive(Debug)]
pub struct Chunk {
    chunk_blob_id: String,
    chunk_digest: String,
    chunk_compressed_size: u32,
    chunk_uncompressed_size: u32,
    chunk_compressed_offset: u64,
    chunk_uncompressed_offset: u64,
}

impl Table<Chunk, DatabaseError> for ChunkTable {
    fn clear(&self) -> Result<(), DatabaseError> {
        self.conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?
            .execute("DROP TABLE chunk", [])
            .map_err(DatabaseError::SqliteError)?;
        Ok(())
    }

    fn create(&self) -> Result<(), DatabaseError> {
        self.conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?
            .execute(
                "CREATE TABLE IF NOT EXISTS chunk (
                    id               INTEGER PRIMARY KEY,
                    chunk_blob_id    TEXT NOT NULL,
                    chunk_digest     TEXT,
                    chunk_compressed_size  INT,
                    chunk_uncompressed_size  INT,
                    chunk_compressed_offset  INT,
                    chunk_uncompressed_offset  INT
                )",
                [],
            )
            .map_err(DatabaseError::SqliteError)?;
        Ok(())
    }

    fn insert(&self, chunk: &Chunk) -> Result<(), DatabaseError> {
        self.conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?
            .execute(
                "INSERT INTO chunk(
                    chunk_blob_id,
                    chunk_digest,
                    chunk_compressed_size,
                    chunk_uncompressed_size,
                    chunk_compressed_offset,
                    chunk_uncompressed_offset
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6);
                ",
                rusqlite::params![
                    chunk.chunk_blob_id,
                    chunk.chunk_digest,
                    chunk.chunk_compressed_size,
                    chunk.chunk_uncompressed_size,
                    chunk.chunk_compressed_offset,
                    chunk.chunk_uncompressed_offset,
                ],
            )
            .map_err(DatabaseError::SqliteError)?;
        Ok(())
    }

    fn list_all(&self) -> Result<Vec<Chunk>, DatabaseError> {
        let mut offset = 0;
        let limit: i64 = 100;
        let mut all_chunks = Vec::new();

        loop {
            let chunks = self.list_paged(offset, limit)?;
            if chunks.is_empty() {
                break;
            }

            all_chunks.extend(chunks);
            offset += limit;
        }

        Ok(all_chunks)
    }

    fn list_paged(&self, offset: i64, limit: i64) -> Result<Vec<Chunk>, DatabaseError> {
        let conn_guard = self
            .conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?;
        let mut stmt: rusqlite::Statement<'_> = conn_guard
            .prepare(
                "SELECT id, chunk_blob_id, chunk_digest, chunk_compressed_size,
                chunk_uncompressed_size, chunk_compressed_offset, chunk_uncompressed_offset from chunk
                ORDER BY id LIMIT ?1 OFFSET ?2",
            )?;
        let chunk_iterator = stmt.query_map(params![limit, offset], |row| {
            Ok(Chunk {
                chunk_blob_id: row.get(1)?,
                chunk_digest: row.get(2)?,
                chunk_compressed_size: row.get(3)?,
                chunk_uncompressed_size: row.get(4)?,
                chunk_compressed_offset: row.get(5)?,
                chunk_uncompressed_offset: row.get(6)?,
            })
        })?;
        let mut chunks = Vec::new();
        for chunk in chunk_iterator {
            chunks.push(chunk.map_err(DatabaseError::SqliteError)?);
        }
        Ok(chunks)
    }
}

#[derive(Debug)]
pub struct BlobTable {
    conn: Arc<Mutex<Connection>>,
}

impl BlobTable {
    pub fn new(database_url: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(database_url)?;
        Ok(BlobTable {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn new_in_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        Ok(BlobTable {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

pub struct Blob {
    blob_id: String,
    blob_compressed_size: u64,
    blob_uncompressed_size: u64,
}

impl Table<Blob, DatabaseError> for BlobTable {
    fn clear(&self) -> Result<(), DatabaseError> {
        self.conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?
            .execute("DROP TABLE blob", [])
            .map_err(DatabaseError::SqliteError)?;
        Ok(())
    }

    fn create(&self) -> Result<(), DatabaseError> {
        self.conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?
            .execute(
                "CREATE TABLE IF NOT EXISTS blob (
                    id                      INTEGER PRIMARY KEY,
                    blob_id                 TEXT NOT NULL,
                    blob_compressed_size    INT,
                    blob_uncompressed_size  INT
                )",
                [],
            )
            .map_err(DatabaseError::SqliteError)?;
        Ok(())
    }

    fn insert(&self, blob: &Blob) -> Result<(), DatabaseError> {
        self.conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?
            .execute(
                "INSERT INTO blob (
                    blob_id,
                    blob_compressed_size,
                    blob_uncompressed_size
                )
                VALUES (?1, ?2, ?3);
                ",
                rusqlite::params![
                    blob.blob_id,
                    blob.blob_compressed_size,
                    blob.blob_uncompressed_size
                ],
            )
            .map_err(DatabaseError::SqliteError)?;
        Ok(())
    }

    fn list_all(&self) -> Result<Vec<Blob>, DatabaseError> {
        let mut offset = 0;
        let limit: i64 = 100;
        let mut all_blobs = Vec::new();

        loop {
            let blobs = self.list_paged(offset, limit)?;
            if blobs.is_empty() {
                break;
            }

            all_blobs.extend(blobs);
            offset += limit;
        }

        Ok(all_blobs)
    }

    fn list_paged(&self, offset: i64, limit: i64) -> Result<Vec<Blob>, DatabaseError> {
        let conn_guard = self
            .conn
            .lock()
            .map_err(|e| DatabaseError::PoisonError(e.to_string()))?;
        let mut stmt: rusqlite::Statement<'_> = conn_guard.prepare(
            "SELECT blob_id, blob_compressed_size, blob_uncompressed_size from blob
                ORDER BY id LIMIT ?1 OFFSET ?2",
        )?;
        let blob_iterator = stmt.query_map(params![limit, offset], |row| {
            Ok(Blob {
                blob_id: row.get(0)?,
                blob_compressed_size: row.get(1)?,
                blob_uncompressed_size: row.get(2)?,
            })
        })?;
        let mut blobs = Vec::new();
        for blob in blob_iterator {
            blobs.push(blob.map_err(DatabaseError::SqliteError)?);
        }
        Ok(blobs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Result;

    #[test]
    fn test_blob_table() -> Result<(), Box<dyn std::error::Error>> {
        let blob_table = BlobTable::new_in_memory()?;
        blob_table.create()?;
        let blob = Blob {
            blob_id: "BLOB123".to_string(),
            blob_compressed_size: 1024,
            blob_uncompressed_size: 2048,
        };
        blob_table.insert(&blob)?;
        let blobs = blob_table.list_all()?;
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].blob_id, blob.blob_id);
        assert_eq!(blobs[0].blob_compressed_size, blob.blob_compressed_size);
        assert_eq!(blobs[0].blob_uncompressed_size, blob.blob_uncompressed_size);
        Ok(())
    }

    #[test]
    fn test_chunk_table() -> Result<(), Box<dyn std::error::Error>> {
        let chunk_table = ChunkTable::new_in_memory()?;
        chunk_table.create()?;
        let chunk = Chunk {
            chunk_blob_id: "BLOB123".to_string(),
            chunk_digest: "DIGEST123".to_string(),
            chunk_compressed_size: 512,
            chunk_uncompressed_size: 1024,
            chunk_compressed_offset: 0,
            chunk_uncompressed_offset: 0,
        };
        chunk_table.insert(&chunk)?;
        let chunks = chunk_table.list_all()?;
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].chunk_blob_id, chunk.chunk_blob_id);
        assert_eq!(chunks[0].chunk_digest, chunk.chunk_digest);
        assert_eq!(chunks[0].chunk_compressed_size, chunk.chunk_compressed_size);
        assert_eq!(
            chunks[0].chunk_uncompressed_size,
            chunk.chunk_uncompressed_size
        );
        assert_eq!(
            chunks[0].chunk_compressed_offset,
            chunk.chunk_compressed_offset
        );
        assert_eq!(
            chunks[0].chunk_uncompressed_offset,
            chunk.chunk_uncompressed_offset
        );
        Ok(())
    }

    #[test]
    fn test_blob_table_paged() -> Result<(), Box<dyn std::error::Error>> {
        let blob_table = BlobTable::new_in_memory()?;
        blob_table.create()?;
        for i in 0..200 {
            let blob = Blob {
                blob_id: format!("BLOB{}", i),
                blob_compressed_size: i,
                blob_uncompressed_size: i * 2,
            };
            blob_table.insert(&blob)?;
        }
        let blobs = blob_table.list_paged(100, 100)?;
        assert_eq!(blobs.len(), 100);
        assert_eq!(blobs[0].blob_id, "BLOB100");
        assert_eq!(blobs[0].blob_compressed_size, 100);
        assert_eq!(blobs[0].blob_uncompressed_size, 200);
        Ok(())
    }

    #[test]
    fn test_chunk_table_paged() -> Result<(), Box<dyn std::error::Error>> {
        let chunk_table = ChunkTable::new_in_memory()?;
        chunk_table.create()?;
        for i in 0..200 {
            let i64 = i as u64;
            let chunk = Chunk {
                chunk_blob_id: format!("BLOB{}", i),
                chunk_digest: format!("DIGEST{}", i),
                chunk_compressed_size: i,
                chunk_uncompressed_size: i * 2,
                chunk_compressed_offset: i64 * 3,
                chunk_uncompressed_offset: i64 * 4,
            };
            chunk_table.insert(&chunk)?;
        }
        let chunks = chunk_table.list_paged(100, 100)?;
        assert_eq!(chunks.len(), 100);
        assert_eq!(chunks[0].chunk_blob_id, "BLOB100");
        assert_eq!(chunks[0].chunk_digest, "DIGEST100");
        assert_eq!(chunks[0].chunk_compressed_size, 100);
        assert_eq!(chunks[0].chunk_uncompressed_size, 200);
        assert_eq!(chunks[0].chunk_compressed_offset, 300);
        assert_eq!(chunks[0].chunk_uncompressed_offset, 400);
        Ok(())
    }
}
