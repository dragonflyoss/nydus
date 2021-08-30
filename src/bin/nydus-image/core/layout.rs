// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use crate::core::context::BuildContext;
use crate::core::node::{Node, Overlay};

pub struct BlobLayout {}

impl BlobLayout {
    pub fn new() -> Self {
        BlobLayout {}
    }

    pub fn layout_blob_simple(ctx: &mut BuildContext) -> Result<(Vec<usize>, usize)> {
        let mut inodes = Vec::with_capacity(ctx.nodes.len());

        // NOTE: Don't try to sort readahead files by their sizes,  thus to keep files
        // belonging to the same directory arranged in adjacent in blob file. Together with
        // BFS style collecting descendants inodes, it will have a higher merging possibility.
        // Later, we might write chunks of data one by one according to inode number order.
        let mut readahead_files = ctx.prefetch.get_file_indexes();
        readahead_files.sort_unstable();
        for index in &readahead_files {
            let index = *index as usize - 1;
            let node = &ctx.nodes[index];
            if Self::should_dump_node(node) {
                inodes.push(index);
            }
        }
        let prefetch_entries = inodes.len();

        // Dump other normal nodes
        for index in 0..ctx.nodes.len() {
            let node = &ctx.nodes[index];
            if !ctx.prefetch.contains(node) {
                // Ignore lower layer node when dump blob
                if Self::should_dump_node(node) {
                    inodes.push(index);
                }
            }
        }

        Ok((inodes, prefetch_entries))
    }

    #[inline]
    fn should_dump_node(node: &Node) -> bool {
        node.overlay == Overlay::UpperAddition || node.overlay == Overlay::UpperModification
    }
}
