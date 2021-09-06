// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use crate::core::node::{Node, Overlay};
use crate::core::prefetch::Prefetch;

pub struct BlobLayout {}

impl BlobLayout {
    pub fn new() -> Self {
        BlobLayout {}
    }

    pub fn layout_blob_simple(prefetch: &Prefetch, nodes: &[Node]) -> Result<(Vec<usize>, usize)> {
        let mut inodes = Vec::with_capacity(nodes.len());

        // NOTE: Don't try to sort readahead files by their sizes,  thus to keep files
        // belonging to the same directory arranged in adjacent in blob file. Together with
        // BFS style collecting descendants inodes, it will have a higher merging possibility.
        // Later, we might write chunks of data one by one according to inode number order.
        let mut readahead_files = prefetch.get_file_indexes();
        readahead_files.sort_unstable();
        for index in &readahead_files {
            let index = *index as usize - 1;
            let node = &nodes[index];
            if Self::should_dump_node(node) {
                inodes.push(index);
            }
        }
        let prefetch_entries = inodes.len();

        // Dump other normal nodes
        for (index, _) in nodes.iter().enumerate() {
            let node = &nodes[index];
            if !prefetch.contains(node) {
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
