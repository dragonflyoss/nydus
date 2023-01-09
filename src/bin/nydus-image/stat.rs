// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use nydus_api::ConfigV2;
use nydus_rafs::metadata::RafsSuper;
use nydus_utils::digest;
use serde::Serialize;

use crate::core::chunk_dict::{ChunkDict, HashChunkDict};
use crate::core::tree::Tree;

#[derive(Copy, Clone, Default, Serialize)]
struct DedupInfo {
    raw_chunks: u64,
    dedup_chunks: u64,
    comp_content_size: u64,
    comp_base_size: u64,
    comp_image_size: u64,
    uncomp_content_size: u64,
    uncomp_base_size: u64,
    uncomp_image_size: u64,
}

#[derive(Serialize)]
struct ImageInfo {
    dirs: u32,
    files: u32,
    symlinks: u32,
    chunks: u32,
    file_size: u64,
    comp_size: u64,
    uncomp_size: u64,
    padding_size: u64,
    chunk_sizes: [u32; 9],
    file_sizes: Vec<u64>,

    // Number of chunks in the base image after chunk deduplication.
    dedup_chunks: u64,
    // Sum of compressed size of all dedup chunks.
    dedup_comp_size: u64,
    // Sum of uncompressed size of all dedup chunks.
    dedup_uncomp_size: u64,
    // Base Image: number of chunks from all source images
    // Target Image: How many chunks are self-contained, not referring to base image.
    own_chunks: u64,
    // Sum of compressed size of all owned chunks.
    own_comp_size: u64,
    // Sum of uncompressed size of all owned chunks.
    own_uncomp_size: u64,
    // How many chunks of the target image are referring to the base image.
    ref_chunks: u64,
    // Sum of compressed size of all reference chunks.
    ref_comp_size: u64,
    // Sum of uncompressed size of all reference chunks.
    ref_uncomp_size: u64,
}

impl ImageInfo {
    fn new() -> Self {
        ImageInfo {
            dirs: 0,
            files: 0,
            symlinks: 0,
            chunks: 0,
            file_size: 0,
            padding_size: 0,
            comp_size: 0,
            uncomp_size: 0,
            chunk_sizes: [0; 9],
            file_sizes: vec![0; 45],
            dedup_chunks: 0,
            dedup_comp_size: 0,
            dedup_uncomp_size: 0,
            own_chunks: 0,
            own_comp_size: 0,
            own_uncomp_size: 0,
            ref_chunks: 0,
            ref_comp_size: 0,
            ref_uncomp_size: 0,
        }
    }

    fn dump(&self) {
        println!(
            r#"
Directories:            {dirs}
Files:                  {files}
Symlinks:               {symlinks}
Chunks:                 {chunks}
File Size:              {file_size}
Padding Size:           {padding_size}
Uncompressed Size:      {uncomp_size}
Compressed Size:        {comp_size}"#,
            dirs = self.dirs,
            files = self.files,
            symlinks = self.symlinks,
            chunks = self.chunks,
            file_size = self.file_size,
            padding_size = self.padding_size,
            uncomp_size = self.uncomp_size,
            comp_size = self.comp_size,
        );

        println!("\nFile Size Bits:\t\tFile Count:");
        for sz in 0..=44 {
            println!("{}:\t\t\t{}", sz, self.file_sizes[sz]);
        }

        println!("\nChunk Size Bits:\tChunk Count:");
        for sz in 12..=20 {
            println!("{}:\t\t\t{}", sz, self.chunk_sizes[sz - 12]);
        }

        println!("\nRaw Content Size:\t{}", self.file_size);
        println!("Comp Content Size:\t{}", self.comp_size);
        println!("Raw Chunk Count:\t{}", self.chunks);
        println!("Dedup Comp Size:\t{}", self.dedup_comp_size);
        println!("Dedup Uncomp Size:\t{}", self.dedup_uncomp_size);
        println!("Dedup Chunk Count:\t{}", self.dedup_chunks);
        println!("Owned Comp Size:\t{}", self.own_comp_size);
        println!("Owned Uncomp Size:\t{}", self.own_uncomp_size);
        println!("Owned Chunk Count:\t{}", self.own_chunks);
        println!("Referenced Comp Size:\t{}", self.ref_comp_size);
        println!("Referenced Uncomp Size:\t{}", self.ref_uncomp_size);
        println!("Referenced Chunk Count:\t{}", self.ref_chunks);
    }
}

#[derive(Serialize)]
pub(crate) struct ImageStat {
    pub dedup_enabled: bool,
    pub target_enabled: bool,

    base_image: ImageInfo,
    target_image: ImageInfo,
    #[serde(skip)]
    dedup_dict: HashChunkDict,
    #[serde(skip)]
    dedup_info: [DedupInfo; 20],
}

impl ImageStat {
    pub fn new(digester: digest::Algorithm) -> Self {
        ImageStat {
            dedup_enabled: false,
            target_enabled: false,

            base_image: ImageInfo::new(),
            target_image: ImageInfo::new(),
            dedup_dict: HashChunkDict::new(digester),
            dedup_info: [Default::default(); 20],
        }
    }

    pub fn stat(&mut self, path: &Path, is_base: bool, config: Arc<ConfigV2>) -> Result<()> {
        let (rs, _) = RafsSuper::load_from_file(path, config, false, false)?;
        let mut dict = HashChunkDict::new(rs.meta.get_digester());
        let mut hardlinks = HashSet::new();
        let tree =
            Tree::from_bootstrap(&rs, &mut dict).context("failed to load bootstrap for stats")?;
        let image = if is_base {
            &mut self.base_image
        } else {
            &mut self.target_image
        };

        tree.iterate(&mut |node| {
            if node.is_reg() {
                image.files += 1;
                if node.is_hardlink() {
                    if hardlinks.contains(&node.inode.ino()) {
                        return true;
                    }
                    hardlinks.insert(node.inode.ino());
                }
                let file_size = node.inode.size();
                let idx = std::cmp::min((64 - file_size.leading_zeros()) as usize, 44);
                image.file_sizes[idx] += 1;
                image.file_size += file_size;
                image.padding_size += ((file_size + 0xfff) & !0xfff) - file_size;

                image.chunks += node.chunks.len() as u32;
                for chunk in node.chunks.iter() {
                    image.comp_size += chunk.inner.compressed_size() as u64;
                    image.uncomp_size += chunk.inner.uncompressed_size() as u64;
                }

                for sz in 12..=20 {
                    image.chunk_sizes[sz - 12] += node.chunk_count(1 << sz);
                }
            } else if node.is_dir() {
                image.dirs += 1;
            } else if node.is_symlink() {
                image.symlinks += 1;
            }
            true
        })?;

        if is_base {
            for entry in dict.m.values() {
                image.own_chunks += 1;
                image.own_comp_size += entry.0.compressed_size() as u64;
                image.own_uncomp_size += entry.0.uncompressed_size() as u64;
                self.dedup_dict
                    .add_chunk(entry.0.clone(), rs.meta.get_digester());
            }
        } else {
            for entry in dict.m.values() {
                if self
                    .dedup_dict
                    .get_chunk(entry.0.id(), entry.0.uncompressed_size())
                    .is_some()
                {
                    image.ref_chunks += 1;
                    image.ref_comp_size += entry.0.compressed_size() as u64;
                    image.ref_uncomp_size += entry.0.uncompressed_size() as u64;
                } else {
                    image.own_chunks += 1;
                    image.own_comp_size += entry.0.compressed_size() as u64;
                    image.own_uncomp_size += entry.0.uncompressed_size() as u64;
                }
            }
        }

        Ok(())
    }

    pub fn finalize(&mut self) {
        self.base_image.uncomp_size += self.base_image.padding_size;

        if self.target_enabled {
            self.target_image.uncomp_size += self.target_image.padding_size;
        }

        if self.dedup_enabled {
            for entry in self.dedup_dict.m.values() {
                let count = entry.1.load(Ordering::Relaxed);
                let thresh = std::cmp::min(self.dedup_info.len(), count as usize);
                for idx in 0..thresh {
                    let info = &mut self.dedup_info[idx];
                    info.raw_chunks += count as u64;
                    info.dedup_chunks += 1;
                    info.uncomp_content_size += count as u64 * entry.0.uncompressed_size() as u64;
                    info.comp_content_size += count as u64 * entry.0.compressed_size() as u64;
                    info.uncomp_base_size += entry.0.uncompressed_size() as u64;
                    info.comp_base_size += entry.0.compressed_size() as u64;
                }
                if thresh < self.dedup_info.len() {
                    for idx in thresh..self.dedup_info.len() {
                        let info = &mut self.dedup_info[idx];
                        info.raw_chunks += count as u64;
                        info.dedup_chunks += count as u64;
                        info.uncomp_content_size +=
                            count as u64 * entry.0.uncompressed_size() as u64;
                        info.comp_content_size += count as u64 * entry.0.compressed_size() as u64;
                        info.uncomp_image_size += count as u64 * entry.0.uncompressed_size() as u64;
                        info.comp_image_size += count as u64 * entry.0.compressed_size() as u64;
                    }
                }

                self.base_image.dedup_chunks += 1;
                self.base_image.dedup_comp_size += entry.0.compressed_size() as u64;
                self.base_image.dedup_uncomp_size += entry.0.uncompressed_size() as u64;
            }
        }
    }

    pub fn dump_json(&self, path: &Path) -> Result<()> {
        let w = OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .open(path)
            .with_context(|| format!("Output file {:?} can't be opened", path))?;

        serde_json::to_writer(w, self).context("Write output file failed")?;

        Ok(())
    }

    pub fn dump(&self) {
        if self.target_enabled {
            println!("Target Image Statistics:");
            self.target_image.dump();
        }

        println!("\n\nBase Image Statistics:");
        self.base_image.dump();

        if self.dedup_enabled {
            println!("\n\nChunk Deduplication Statistics:");
            println!("Global Dedup Thresh:\tRaw Chunks:\tDedup Chunks:\tComp Content Size:\tComp Base Size:\tComp Image Size:\tUncomp Content Size:\tUncomp Base Size\tUncomp Image Size");
            for (idx, info) in self.dedup_info.iter().enumerate() {
                if info.dedup_chunks == 0 {
                    break;
                }
                println!(
                    "{:<24}0x{:<14x}0x{:<14x}0x{:<14x}0x{:<14x}0x{:<14x}0x{:<14x}0x{:<14x}0x{:<14x}",
                    idx + 1,
                    info.raw_chunks,
                    info.dedup_chunks,
                    info.comp_content_size,
                    info.comp_base_size,
                    info.comp_image_size,
                    info.uncomp_content_size,
                    info.uncomp_base_size,
                    info.uncomp_image_size,
                );
            }
        }
    }
}
