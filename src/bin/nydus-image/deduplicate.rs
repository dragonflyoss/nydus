// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Deduplicate for Chunk

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use nydus_api::ConfigV2;
use nydus_rafs::builder::Tree;
use nydus_rafs::metadata::RafsSuper;
use nydus_storage::device::BlobInfo;
use nydus_storage::meta::format_blob_features;
use rusqlite::{params, Connection};
pub struct Deduplicate {
    sb: RafsSuper,
}

impl Deduplicate {
    pub fn new(bootstrap_path: &Path, config: Arc<ConfigV2>) -> Result<Self> {
        let (sb, _) = RafsSuper::load_from_file(bootstrap_path, config, false)?;
        Ok(Self { sb })
    }

    /// save metadata to database: chunk and blob info
    pub fn save_metadata_to_database(&mut self) -> Result<Vec<Arc<BlobInfo>>> {
        let err = "failed to load bootstrap for deduplicate";
        let tree = Tree::from_bootstrap(&self.sb, &mut ()).context(err)?;

        // Connect to the database
        let database_file: &str = "metadata.db";
        let conn = Connection::open(database_file)?;

        // Create blob table and chunk table
        ChunkTable::creat_table(&conn)?;
        BlobTable::creat_table(&conn)?;

        let blob_infos = self.sb.superblock.get_blob_infos();
        for blob in &blob_infos {
            BlobTable::insert_data_into_table(
                &conn,
                &BlobTable {
                    blob_id: blob.blob_id().to_string(),
                    blob_size: blob.uncompressed_size().to_string(),
                    image_name: format_blob_features(blob.features()),
                },
            )?;
        }
        let pre = &mut |t: &Tree| -> Result<()> {
            let node = t.lock_node();
            for chunk in &node.chunks {
                let index: u32 = chunk.inner.blob_index();
                // Get blob id
                let chunk_blob_id = blob_infos[index as usize].blob_id();
                // Insert chunk into chunk table
                ChunkTable::insert_data_into_table(
                    &conn,
                    &ChunkTable {
                        id: 1,
                        chunk_blob_id,
                        chunk_digest: chunk.inner.id().to_string(),
                        chunk_compressed_size: chunk.inner.compressed_size(),
                        chunk_uncompressed_size: chunk.inner.uncompressed_size(),
                        chunk_compressed_offset: chunk.inner.compressed_offset(),
                        chunk_uncompressed_offset: chunk.inner.uncompressed_offset(),
                    },
                )?;
            }
            Ok(())
        };
        tree.walk_dfs_pre(pre)?;

        Ok(self.sb.superblock.get_blob_infos())
    }
}

#[allow(dead_code)]
pub trait Table: Sync + Send + Sized + 'static {
    // clear table
    fn clear(conn: Connection) -> Result<()>;

    //crate table
    fn creat_table(conn: &Connection) -> Result<()>;

    //insert
    fn insert_data_into_table(conn: &Connection, table: &Self) -> Result<()>;

    // search
    fn get_data_from_table(conn: &Connection) -> Result<Vec<Self>>;

    //delete

    //modify
}

#[derive(Debug)]
#[allow(dead_code)]
struct ChunkTable {
    id: i64,
    chunk_blob_id: String,
    chunk_digest: String,
    chunk_compressed_size: u32,
    chunk_uncompressed_size: u32,
    chunk_compressed_offset: u64,
    chunk_uncompressed_offset: u64,
}

impl Table for ChunkTable {
    fn clear(conn: Connection) -> Result<()> {
        let _ = conn.execute("DROP TABLE chunk", [])?;
        Ok(())
    }

    fn creat_table(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS chunk (
                id               INTEGER PRIMARY KEY ,
                chunk_blob_id    TEXT NOT NULL,
                chunk_digest     TEXT,
                chunk_compressed_size  INT,
                chunk_uncompressed_size  INT,
                chunk_compressed_offset  INT,
                chunk_uncompressed_offset  INT
            )",
            [],
        )?;
        Ok(())
    }

    fn insert_data_into_table(conn: &Connection, chunk_table: &ChunkTable) -> Result<()> {
        conn.execute(
            "INSERT INTO chunk(chunk_blob_id,chunk_digest,chunk_compressed_size,
                chunk_uncompressed_size,chunk_compressed_offset,chunk_uncompressed_offset)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6);
            ",
            params![
                chunk_table.chunk_blob_id,
                chunk_table.chunk_digest,
                chunk_table.chunk_compressed_size,
                chunk_table.chunk_uncompressed_size,
                chunk_table.chunk_compressed_offset,
                chunk_table.chunk_uncompressed_offset
            ],
        )?;

        Ok(())
    }

    fn get_data_from_table(conn: &Connection) -> Result<Vec<ChunkTable>> {
        let mut stmt = conn.prepare(
            "SELECT id, chunk_blob_id, chunk_digest,chunk_compressed_size,
        chunk_uncompressed_size, chunk_compressed_offset, chunk_uncompressed_offset from chunk",
        )?;
        let chunk_iterator = stmt.query_map([], |row| {
            Ok(ChunkTable {
                id: row.get(0)?,
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
            chunks.push(chunk?);
        }
        Ok(chunks)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct BlobTable {
    // id: i32,
    blob_id: String,
    blob_size: String,
    image_name: String,
}

impl Table for BlobTable {
    fn clear(conn: Connection) -> Result<()> {
        let _ = conn.execute("DROP TABLE blob", [])?;
        Ok(())
    }

    fn creat_table(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS blob (
                blob_id             TEXT PRIMARY KEY ,
                blob_size           TEXT NOT NULL,
                image_name          TEXT
            )",
            [],
        )?;
        Ok(())
    }

    fn insert_data_into_table(conn: &Connection, blob_table: &BlobTable) -> Result<()> {
        conn.execute(
            "INSERT INTO blob (blob_id, blob_size, image_name)
            SELECT ?1, ?2, ?3
            WHERE NOT EXISTS (
                SELECT blob_id
                FROM blob
                WHERE blob_id = ?4
            ) limit 1
            ;
            ",
            params![
                blob_table.blob_id,
                blob_table.blob_size,
                blob_table.image_name,
                blob_table.blob_id
            ],
        )?;

        Ok(())
    }

    fn get_data_from_table(conn: &Connection) -> Result<Vec<BlobTable>> {
        let mut stmt = conn.prepare("SELECT blob_id,blob_size,image_name from blob")?;
        let blob_iterator = stmt.query_map([], |row| {
            Ok(BlobTable {
                blob_id: row.get(0)?,
                blob_size: row.get(1)?,
                image_name: row.get(2)?,
            })
        })?;
        let mut blobs = Vec::new();
        for blob in blob_iterator {
            blobs.push(blob?);
        }
        Ok(blobs)
    }
}
