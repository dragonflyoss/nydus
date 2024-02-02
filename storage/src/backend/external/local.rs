// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Result;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use crate::backend::external::{meta::MetaMap, ExternalBlobReader};
use crate::device::BlobChunkInfo;

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Object {
    #[serde(default, rename = "Path")]
    pub path: String,
}

pub struct LocalBackend {
    meta_map: MetaMap,
    root: PathBuf,
}

impl LocalBackend {
    pub fn new(meta_path: PathBuf, config: &HashMap<String, String>) -> Result<Self> {
        let meta_map = MetaMap::new(meta_path)?;
        let root = PathBuf::from(config.get("root").unwrap());
        Ok(Self { meta_map, root })
    }
}

impl ExternalBlobReader for LocalBackend {
    fn read(&self, buf: &mut [u8], chunks: &[&dyn BlobChunkInfo]) -> Result<usize> {
        let chunk_index = chunks[0].id();
        let (object_bytes, chunk) = self.meta_map.get_object(chunk_index)?;

        let object: Object = rmp_serde::from_slice(&object_bytes)
            .map_err(|_e| einval!("failed to deserialize object"))?;

        let path = self.root.join(&object.path);

        println!(
            "local_backend: path={:?}, object_offset={}, expected_size={}",
            path,
            chunk.object_offset,
            buf.len()
        );

        let file = std::fs::File::open(path)?;
        file.read_exact_at(buf, chunk.object_offset)?;

        Ok(buf.len())
    }
}
