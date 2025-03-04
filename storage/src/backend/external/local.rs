// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::result::Result;

use crate::backend::external::{meta::MetaMap, ExternalBlobReader};
use crate::device::BlobChunkInfo;

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Object {
    #[serde(default, rename = "p")]
    pub path: String,
}

pub struct LocalBackend {
    meta_map: MetaMap,
    root: PathBuf,
}

impl LocalBackend {
    pub fn new(meta_path: PathBuf, config: &HashMap<String, String>) -> Result<Self, String> {
        let meta_map = MetaMap::new(meta_path).map_err(|e| e.to_string())?;
        let root = PathBuf::from(
            config
                .get("root")
                .ok_or_else(|| "root is not specified in local backend config".to_string())?,
        );
        Ok(Self { meta_map, root })
    }
}

impl ExternalBlobReader for LocalBackend {
    fn read(&self, buf: &mut [u8], chunks: &[&dyn BlobChunkInfo]) -> Result<usize, String> {
        let chunk_index = chunks[0].id();
        let (object_bytes, chunk) = self
            .meta_map
            .get_object(chunk_index)
            .map_err(|e| e.to_string())?;

        let object: Object = rmp_serde::from_slice(&object_bytes)
            .map_err(|e| format!("failed to deserialize object: {}", e))?;

        let path = self.root.join(&object.path);

        let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
        file.read_exact_at(buf, chunk.object_offset)
            .map_err(|e| e.to_string())?;

        Ok(buf.len())
    }
}
