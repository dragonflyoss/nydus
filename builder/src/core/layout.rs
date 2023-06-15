// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use std::ops::Deref;

use super::node::Node;
use crate::{Overlay, Prefetch, Tree, TreeNode};

#[derive(Clone)]
pub struct BlobLayout {}

impl BlobLayout {
    pub fn layout_blob_simple(prefetch: &Prefetch, tree: &Tree) -> Result<(Vec<TreeNode>, usize)> {
        let mut inodes = Vec::with_capacity(10000);

        // Put all prefetch inodes at the head
        // NOTE: Don't try to sort readahead files by their sizes,  thus to keep files
        // belonging to the same directory arranged in adjacent in blob file. Together with
        // BFS style collecting descendants inodes, it will have a higher merging possibility.
        // Later, we might write chunks of data one by one according to inode number order.
        let prefetches = prefetch.get_file_nodes();
        for n in prefetches {
            let node = n.lock().unwrap();
            if Self::should_dump_node(node.deref()) {
                inodes.push(n.clone());
            }
        }
        let prefetch_entries = inodes.len();

        tree.walk_bfs(true, &mut |n| -> Result<()> {
            let node = n.lock_node();
            // Ignore lower layer node when dump blob
            if !prefetch.contains(node.deref()) && Self::should_dump_node(node.deref()) {
                inodes.push(n.node.clone());
            }
            Ok(())
        })?;

        Ok((inodes, prefetch_entries))
    }

    #[inline]
    fn should_dump_node(node: &Node) -> bool {
        node.overlay == Overlay::UpperAddition || node.overlay == Overlay::UpperModification
    }
}
