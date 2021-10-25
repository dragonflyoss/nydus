// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crate::core::tree::Tree;
use anyhow::{Context, Result};
use nydus_utils::digest::RafsDigest;
use rafs::metadata::layout::v5::{RafsV5BlobTable, RafsV5ChunkInfo};
use rafs::metadata::{RafsMode, RafsSuper};
use rafs::RafsIoReader;
use std::collections::{BTreeMap, HashMap};
use std::fs::OpenOptions;
use std::sync::{Arc, Mutex};

/// type=path
/// if no type, use bootstrap
/// for example:
///     bootstrap=image.boot
///     image.boot
///     ~/image/image.boot
///     boltdb=/var/db/dict.db
pub fn import_chunk_dict(arg: &str) -> Result<Arc<dyn ChunkDict>> {
    match arg.find('=') {
        None => {
            BootstrapChunkDict::from_bootstrap_file(arg).map(|d| Arc::new(d) as Arc<dyn ChunkDict>)
        }
        Some(idx) => {
            let file_type = &arg[0..idx];
            let file_path = &arg[idx + 1..];
            info!("import chunk dict file {}={}", file_type, file_path);
            match file_type {
                "bootstrap" => BootstrapChunkDict::from_bootstrap_file(file_path)
                    .map(|d| Arc::new(d) as Arc<dyn ChunkDict>),
                _ => Err(std::io::Error::from_raw_os_error(libc::EINVAL))
                    .with_context(|| format!("invalid chunk dict type {}", file_type)),
            }
        }
    }
}

pub trait ChunkDict {
    fn get_chunk(&self, digest: &RafsDigest) -> Option<&RafsV5ChunkInfo>;
    fn get_blobs(&self) -> Arc<RafsV5BlobTable>;
    fn set_real_blob_idx(&self, inner_idx: u32, out_idx: u32);
    fn get_real_blob_idx(&self, inner_idx: u32) -> u32;
}

pub struct BootstrapChunkDict {
    m: HashMap<RafsDigest, RafsV5ChunkInfo>,
    blobs: Arc<RafsV5BlobTable>,
    blob_idx_m: Mutex<BTreeMap<u32, u32>>,
}

impl ChunkDict for BootstrapChunkDict {
    fn get_chunk(&self, digest: &RafsDigest) -> Option<&RafsV5ChunkInfo> {
        self.m.get(digest)
    }

    fn get_blobs(&self) -> Arc<RafsV5BlobTable> {
        self.blobs.clone()
    }

    fn set_real_blob_idx(&self, inner_idx: u32, out_idx: u32) {
        self.blob_idx_m.lock().unwrap().insert(inner_idx, out_idx);
    }

    fn get_real_blob_idx(&self, inner_idx: u32) -> u32 {
        *self
            .blob_idx_m
            .lock()
            .unwrap()
            .get(&inner_idx)
            .unwrap_or(&inner_idx)
    }
}

impl BootstrapChunkDict {
    pub fn from_bootstrap_file(path: &str) -> Result<Self> {
        let mut m = HashMap::new();
        // open bootstrap file
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .with_context(|| format!("failed to open bootstrap file {:?}", path))?;
        let mut rs = RafsSuper {
            mode: RafsMode::Direct,
            validate_digest: true,
            ..Default::default()
        };
        let mut reader = Box::new(file) as RafsIoReader;
        rs.load(&mut reader)?;
        Tree::from_bootstrap(&rs, Some(&mut m)).context("failed to build tree from bootstrap")?;
        Ok(Self {
            m,
            blobs: rs.superblock.get_blob_table(),
            blob_idx_m: Mutex::new(BTreeMap::new()),
        })
    }
}
