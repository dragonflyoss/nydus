// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;
use std::mem::size_of;
use std::path::Path;
use std::{fs::File, os::unix::fs::MetadataExt};

use serde::{Deserialize, Serialize};

use nydus_utils::filemap::FileMapState;

// Layout
//
// header: magic | version | chunk_meta_offset | object_meta_offset
// chunks: chunk_meta | chunk | chunk | ...
// objects: object_meta | [object_offsets] | object | object | ...

// 4096 bytes
#[repr(C)]
#[derive(Debug)]
pub struct Header {
    magic: u32,
    version: u32,

    chunk_meta_offset: u32,
    object_meta_offset: u32,

    reserved: [u8; 4080],
}

// 256 bytes
#[repr(C)]
#[derive(Debug)]
pub struct ChunkMeta {
    entry_count: u32,
    entry_size: u32,

    reserved: [u8; 248],
}

// 256 bytes
#[repr(C)]
#[derive(Debug)]
pub struct ObjectMeta {
    entry_count: u32,
    entry_size: u32,

    reserved: [u8; 248],
}

// 16 bytes
#[repr(C)]
#[derive(Debug)]
pub struct Chunk {
    pub object_index: u32,
    reserved: [u8; 4],
    pub object_offset: u64,
}

// 4 bytes
pub type ObjectOffset = u32;

#[derive(Debug)]
#[allow(dead_code)]
pub struct Object {
    entry_size: u32,
    encoded_data: Vec<u8>,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct LocalObject {
    #[serde(default, rename = "Path")]
    pub path: String,
}

pub struct MetaMap {
    map: FileMapState,
}

impl MetaMap {
    pub fn new<P: AsRef<Path>>(meta_path: P) -> Result<Self> {
        let file = File::open(meta_path)?;
        let size = file.metadata()?.size() as usize;
        let map = FileMapState::new(file, 0, size, false)?;
        Ok(Self { map })
    }

    pub fn get_object(&self, chunk_index: u32) -> Result<(&[u8], &Chunk)> {
        let header = self.map.get_ref::<Header>(0)?;
        let chunk_meta_offset = header.chunk_meta_offset;
        let object_meta_offset = header.object_meta_offset;

        let chunk_meta = self.map.get_ref::<ChunkMeta>(chunk_meta_offset as usize)?;
        let _object_meta = self
            .map
            .get_ref::<ObjectMeta>(object_meta_offset as usize)?;

        let chunk = self.map.get_ref::<Chunk>(
            chunk_meta_offset as usize
                + size_of::<ChunkMeta>()
                + chunk_index as usize * chunk_meta.entry_size as usize,
        )?;
        let object_index = chunk.object_index;
        // let object_offset_offset = if object_meta.entry_size == 0 {
        //     object_meta_offset as usize
        //         + size_of::<ObjectMeta>()
        //         + object_index as usize * size_of::<ObjectOffset>()
        // } else {
        //     object_meta_offset as usize
        //         + size_of::<ObjectMeta>()
        //         + object_index as usize
        //             * (size_of::<u32>() as usize + object_meta.entry_size as usize) as usize
        // };
        let object_offset_offset = object_meta_offset as usize
            + size_of::<ObjectMeta>()
            + object_index as usize * size_of::<ObjectOffset>();
        let object_offset = *self.map.get_ref::<ObjectOffset>(object_offset_offset)? as usize;

        let object_size = *self.map.get_ref::<u32>(object_offset)? as usize;

        let object_data: &[u8] = self
            .map
            .get_slice(object_offset + size_of::<u32>(), object_size)?;

        Ok((object_data, chunk))
    }
}
