// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021-2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Execute file/directory whiteout rules when merging multiple RAFS filesystems
//! according to the OCI or Overlayfs specifications.

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::os::unix::ffi::OsStrExt;
use std::str::FromStr;

use anyhow::{anyhow, Error, Result};

use super::node::Node;

/// Prefix for OCI whiteout file.
pub const OCISPEC_WHITEOUT_PREFIX: &str = ".wh.";
/// Prefix for OCI whiteout opaque.
pub const OCISPEC_WHITEOUT_OPAQUE: &str = ".wh..wh..opq";
/// Extended attribute key for Overlayfs whiteout opaque.
pub const OVERLAYFS_WHITEOUT_OPAQUE: &str = "trusted.overlay.opaque";

/// RAFS filesystem overlay specifications.
///
/// When merging multiple RAFS filesystems into one, special rules are needed to white out
/// files/directories in lower/parent filesystems. The whiteout specification defined by the
/// OCI image specification and Linux Overlayfs are widely adopted, so both of them are supported
/// by RAFS filesystem.
///
/// # Overlayfs Whiteout
///
/// In order to support rm and rmdir without changing the lower filesystem, an overlay filesystem
/// needs to record in the upper filesystem that files have been removed. This is done using
/// whiteouts and opaque directories (non-directories are always opaque).
///
/// A whiteout is created as a character device with 0/0 device number. When a whiteout is found
/// in the upper level of a merged directory, any matching name in the lower level is ignored,
/// and the whiteout itself is also hidden.
///
/// A directory is made opaque by setting the xattr “trusted.overlay.opaque” to “y”. Where the upper
/// filesystem contains an opaque directory, any directory in the lower filesystem with the same
/// name is ignored.
///
/// # OCI Image Whiteout
/// - A whiteout file is an empty file with a special filename that signifies a path should be
///   deleted.
/// - A whiteout filename consists of the prefix .wh. plus the basename of the path to be deleted.
/// - As files prefixed with .wh. are special whiteout markers, it is not possible to create a
///   filesystem which has a file or directory with a name beginning with .wh..
/// - Once a whiteout is applied, the whiteout itself MUST also be hidden.
/// - Whiteout files MUST only apply to resources in lower/parent layers.
/// - Files that are present in the same layer as a whiteout file can only be hidden by whiteout
///   files in subsequent layers.
/// - In addition to expressing that a single entry should be removed from a lower layer, layers
///   may remove all of the children using an opaque whiteout entry.
/// - An opaque whiteout entry is a file with the name .wh..wh..opq indicating that all siblings
///   are hidden in the lower layer.
#[derive(Clone, Copy, PartialEq)]
pub enum WhiteoutSpec {
    /// Overlay whiteout rules according to the OCI image specification.
    ///
    /// https://github.com/opencontainers/image-spec/blob/master/layer.md#whiteouts
    Oci,
    /// Overlay whiteout rules according to the Linux Overlayfs specification.
    ///
    /// "whiteouts and opaque directories" in https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt
    Overlayfs,
    /// No whiteout, keep all content from lower/parent filesystems.
    None,
}

impl Default for WhiteoutSpec {
    fn default() -> Self {
        Self::Oci
    }
}

impl FromStr for WhiteoutSpec {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "oci" => Ok(Self::Oci),
            "overlayfs" => Ok(Self::Overlayfs),
            "none" => Ok(Self::None),
            _ => Err(anyhow!("invalid whiteout spec")),
        }
    }
}

/// RAFS filesystem overlay operation types.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum WhiteoutType {
    OciOpaque,
    OciRemoval,
    OverlayFsOpaque,
    OverlayFsRemoval,
}

impl WhiteoutType {
    pub fn is_removal(&self) -> bool {
        *self == WhiteoutType::OciRemoval || *self == WhiteoutType::OverlayFsRemoval
    }
}

/// RAFS filesystem node overlay state.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub enum Overlay {
    Lower,
    UpperAddition,
    UpperModification,
}

impl Overlay {
    pub fn is_lower_layer(&self) -> bool {
        self == &Overlay::Lower
    }
}

impl Display for Overlay {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Overlay::Lower => write!(f, "LOWER"),
            Overlay::UpperAddition => write!(f, "ADDED"),
            Overlay::UpperModification => write!(f, "MODIFIED"),
        }
    }
}

impl Node {
    /// Check whether the inode is a special overlayfs whiteout file.
    pub fn is_overlayfs_whiteout(&self, spec: WhiteoutSpec) -> bool {
        if spec != WhiteoutSpec::Overlayfs {
            return false;
        }
        self.inode.is_chrdev()
            && nydus_utils::compact::major_dev(self.info.rdev) == 0
            && nydus_utils::compact::minor_dev(self.info.rdev) == 0
    }

    /// Check whether the inode (directory) is a overlayfs whiteout opaque.
    pub fn is_overlayfs_opaque(&self, spec: WhiteoutSpec) -> bool {
        if spec != WhiteoutSpec::Overlayfs || !self.is_dir() {
            return false;
        }

        // A directory is made opaque by setting the xattr "trusted.overlay.opaque" to "y".
        if let Some(v) = self
            .info
            .xattrs
            .get(&OsString::from(OVERLAYFS_WHITEOUT_OPAQUE))
        {
            if let Ok(v) = std::str::from_utf8(v.as_slice()) {
                return v == "y";
            }
        }

        false
    }

    /// Get whiteout type to process the inode.
    pub fn whiteout_type(&self, spec: WhiteoutSpec) -> Option<WhiteoutType> {
        if self.overlay == Overlay::Lower {
            return None;
        }

        match spec {
            WhiteoutSpec::Oci => {
                if let Some(name) = self.name().to_str() {
                    if name == OCISPEC_WHITEOUT_OPAQUE {
                        return Some(WhiteoutType::OciOpaque);
                    } else if name.starts_with(OCISPEC_WHITEOUT_PREFIX) {
                        return Some(WhiteoutType::OciRemoval);
                    }
                }
            }
            WhiteoutSpec::Overlayfs => {
                if self.is_overlayfs_whiteout(spec) {
                    return Some(WhiteoutType::OverlayFsRemoval);
                } else if self.is_overlayfs_opaque(spec) {
                    return Some(WhiteoutType::OverlayFsOpaque);
                }
            }
            WhiteoutSpec::None => {
                return None;
            }
        }

        None
    }

    /// Get original filename from a whiteout filename.
    pub fn origin_name(&self, t: WhiteoutType) -> Option<&OsStr> {
        if let Some(name) = self.name().to_str() {
            if t == WhiteoutType::OciRemoval {
                // the whiteout filename prefixes the basename of the path to be deleted with ".wh.".
                return Some(OsStr::from_bytes(
                    name[OCISPEC_WHITEOUT_PREFIX.len()..].as_bytes(),
                ));
            } else if t == WhiteoutType::OverlayFsRemoval {
                // the whiteout file has the same name as the file to be deleted.
                return Some(name.as_ref());
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use nydus_rafs::metadata::{inode::InodeWrapper, layout::v5::RafsV5Inode};

    use crate::core::node::NodeInfo;

    use super::*;

    #[test]
    fn test_white_spec_from_str() {
        let spec = WhiteoutSpec::default();
        assert!(matches!(spec, WhiteoutSpec::Oci));

        assert!(WhiteoutSpec::from_str("oci").is_ok());
        assert!(WhiteoutSpec::from_str("overlayfs").is_ok());
        assert!(WhiteoutSpec::from_str("none").is_ok());
        assert!(WhiteoutSpec::from_str("foo").is_err());
    }

    #[test]
    fn test_white_type_removal_check() {
        let t1 = WhiteoutType::OciOpaque;
        let t2 = WhiteoutType::OciRemoval;
        let t3 = WhiteoutType::OverlayFsOpaque;
        let t4 = WhiteoutType::OverlayFsRemoval;
        assert!(!t1.is_removal());
        assert!(t2.is_removal());
        assert!(!t3.is_removal());
        assert!(t4.is_removal());
    }

    #[test]
    fn test_overlay_low_layer_check() {
        let t1 = Overlay::Lower;
        let t2 = Overlay::UpperAddition;
        let t3 = Overlay::UpperModification;

        assert!(t1.is_lower_layer());
        assert!(!t2.is_lower_layer());
        assert!(!t3.is_lower_layer());
    }

    #[test]
    fn test_node() {
        let mut inode = InodeWrapper::V5(RafsV5Inode::default());
        inode.set_mode(libc::S_IFCHR);
        let node = Node::new(inode, NodeInfo::default(), 0);
        assert!(!node.is_overlayfs_whiteout(WhiteoutSpec::None));
        assert!(node.is_overlayfs_whiteout(WhiteoutSpec::Overlayfs));
        assert_eq!(
            node.whiteout_type(WhiteoutSpec::Overlayfs).unwrap(),
            WhiteoutType::OverlayFsRemoval
        );

        let mut inode = InodeWrapper::V5(RafsV5Inode::default());
        let mut info: NodeInfo = NodeInfo::default();
        assert!(info
            .xattrs
            .add(OVERLAYFS_WHITEOUT_OPAQUE.into(), "y".into())
            .is_ok());
        inode.set_mode(libc::S_IFDIR);
        let node = Node::new(inode, info, 0);
        assert!(!node.is_overlayfs_opaque(WhiteoutSpec::None));
        assert!(node.is_overlayfs_opaque(WhiteoutSpec::Overlayfs));
        assert_eq!(
            node.whiteout_type(WhiteoutSpec::Overlayfs).unwrap(),
            WhiteoutType::OverlayFsOpaque
        );

        let mut inode = InodeWrapper::V5(RafsV5Inode::default());
        let mut info = NodeInfo::default();
        assert!(info
            .xattrs
            .add(OVERLAYFS_WHITEOUT_OPAQUE.into(), "n".into())
            .is_ok());
        inode.set_mode(libc::S_IFDIR);
        let node = Node::new(inode, info, 0);
        assert!(!node.is_overlayfs_opaque(WhiteoutSpec::None));
        assert!(!node.is_overlayfs_opaque(WhiteoutSpec::Overlayfs));

        let mut inode = InodeWrapper::V5(RafsV5Inode::default());
        let mut info = NodeInfo::default();
        assert!(info
            .xattrs
            .add(OVERLAYFS_WHITEOUT_OPAQUE.into(), "y".into())
            .is_ok());
        inode.set_mode(libc::S_IFCHR);
        let node = Node::new(inode, info, 0);
        assert!(!node.is_overlayfs_opaque(WhiteoutSpec::None));
        assert!(!node.is_overlayfs_opaque(WhiteoutSpec::Overlayfs));

        let mut inode = InodeWrapper::V5(RafsV5Inode::default());
        let mut info = NodeInfo::default();
        assert!(info
            .xattrs
            .add(OVERLAYFS_WHITEOUT_OPAQUE.into(), "n".into())
            .is_ok());
        inode.set_mode(libc::S_IFDIR);
        let node = Node::new(inode, info, 0);
        assert!(!node.is_overlayfs_opaque(WhiteoutSpec::None));
        assert!(!node.is_overlayfs_opaque(WhiteoutSpec::Overlayfs));

        let inode = InodeWrapper::V5(RafsV5Inode::default());
        let info = NodeInfo::default();
        let mut node = Node::new(inode, info, 0);

        assert_eq!(node.whiteout_type(WhiteoutSpec::None), None);
        assert_eq!(node.whiteout_type(WhiteoutSpec::Oci), None);
        assert_eq!(node.whiteout_type(WhiteoutSpec::Overlayfs), None);

        node.overlay = Overlay::Lower;
        assert_eq!(node.whiteout_type(WhiteoutSpec::Overlayfs), None);

        let inode = InodeWrapper::V5(RafsV5Inode::default());
        let mut info = NodeInfo::default();
        let name = OCISPEC_WHITEOUT_PREFIX.to_string() + "foo";
        info.target_vec.push(name.clone().into());
        let node = Node::new(inode, info, 0);
        assert_eq!(
            node.whiteout_type(WhiteoutSpec::Oci).unwrap(),
            WhiteoutType::OciRemoval
        );
        assert_eq!(node.origin_name(WhiteoutType::OciRemoval).unwrap(), "foo");
        assert_eq!(node.origin_name(WhiteoutType::OciOpaque), None);
        assert_eq!(
            node.origin_name(WhiteoutType::OverlayFsRemoval).unwrap(),
            OsStr::new(&name)
        );

        let inode = InodeWrapper::V5(RafsV5Inode::default());
        let mut info = NodeInfo::default();
        info.target_vec.push(OCISPEC_WHITEOUT_OPAQUE.into());
        let node = Node::new(inode, info, 0);
        assert_eq!(
            node.whiteout_type(WhiteoutSpec::Oci).unwrap(),
            WhiteoutType::OciOpaque
        );
    }
}
