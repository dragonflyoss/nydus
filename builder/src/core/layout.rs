// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use std::ops::Deref;

use super::node::Node;
use crate::{Overlay, Prefetch, TreeNode};

#[derive(Clone)]
pub struct BlobLayout {}

impl BlobLayout {
    pub fn layout_blob_simple(prefetch: &Prefetch) -> Result<(Vec<TreeNode>, usize)> {
        let (pre, non_pre) = prefetch.get_file_nodes();
        let mut inodes: Vec<TreeNode> = pre
            .into_iter()
            .filter(|x| Self::should_dump_node(x.lock().unwrap().deref()))
            .collect();
        let mut non_prefetch_inodes: Vec<TreeNode> = non_pre
            .into_iter()
            .filter(|x| Self::should_dump_node(x.lock().unwrap().deref()))
            .collect();

        let prefetch_entries = inodes.len();

        inodes.append(&mut non_prefetch_inodes);

        Ok((inodes, prefetch_entries))
    }

    #[inline]
    fn should_dump_node(node: &Node) -> bool {
        node.overlay == Overlay::UpperAddition || node.overlay == Overlay::UpperModification
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{core::node::NodeInfo, Tree};
    use nydus_rafs::metadata::{inode::InodeWrapper, RafsVersion};

    #[test]
    fn test_layout_blob_simple() {
        let mut inode = InodeWrapper::new(RafsVersion::V6);
        inode.set_mode(0o755 | libc::S_IFREG as u32);
        inode.set_size(1);
        let mut node1 = Node::new(inode.clone(), NodeInfo::default(), 1);
        node1.overlay = Overlay::UpperAddition;

        let tree = Tree::new(node1);

        let mut prefetch = Prefetch::default();
        prefetch.insert(&tree.node, tree.node.lock().unwrap().deref());

        let (inodes, prefetch_entries) = BlobLayout::layout_blob_simple(&prefetch).unwrap();
        assert_eq!(inodes.len(), 1);
        assert_eq!(prefetch_entries, 0);
    }
}
