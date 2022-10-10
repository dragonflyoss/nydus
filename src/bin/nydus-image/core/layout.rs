// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use crate::core::node::{Node, Overlay};
use crate::core::prefetch::Prefetch;

#[derive(Clone)]
pub struct BlobLayout {}

impl BlobLayout {
    pub fn layout_blob_simple(prefetch: &Prefetch, nodes: &[Node]) -> Result<(Vec<usize>, usize)> {
        let mut inodes = Vec::with_capacity(nodes.len());

        // Put all prefetch inodes at the head
        // NOTE: Don't try to sort readahead files by their sizes,  thus to keep files
        // belonging to the same directory arranged in adjacent in blob file. Together with
        // BFS style collecting descendants inodes, it will have a higher merging possibility.
        // Later, we might write chunks of data one by one according to inode number order.
        let prefetches = prefetch.get_file_indexes();
        for index in prefetches {
            let index = index as usize - 1;
            let node = &nodes[index];
            if Self::should_dump_node(node) {
                inodes.push(index);
            }
        }
        let prefetch_entries = inodes.len();

        // Put all other non-prefetch inode at the tail
        for (index, node) in nodes.iter().enumerate() {
            // Ignore lower layer node when dump blob
            if !prefetch.contains(node) && Self::should_dump_node(node) {
                inodes.push(index);
            }
        }

        Ok((inodes, prefetch_entries))
    }

    #[inline]
    fn should_dump_node(node: &Node) -> bool {
        node.overlay == Overlay::UpperAddition || node.overlay == Overlay::UpperModification
    }
}
