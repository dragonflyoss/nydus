// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::{Error as IoError, ErrorKind, Result};
use std::{any::TypeId, collections::HashMap};

use snapshot::Snapshot;
use versionize::{VersionMap, Versionize};

/// A list of versions.
type Versions = Vec<HashMap<TypeId, u16>>;

/// A trait for snapshotting.
/// This trait is used to save and restore a struct
/// which implements `versionize::Versionize`.
pub trait Snapshotter: Versionize + Sized {
    /// Returns a list of versions.
    fn get_versions() -> Versions;

    /// Returns a `VersionMap` with the versions defined by `get_versions`.
    fn new_version_map() -> VersionMap {
        let mut version_map = VersionMap::new();
        for (idx, map) in Self::get_versions().into_iter().enumerate() {
            if idx > 0 {
                version_map.new_version();
            }
            for (type_id, version) in map {
                version_map.set_type_version(type_id, version);
            }
        }
        version_map
    }

    /// Returns a new `Snapshot` with the versions defined by `get_versions`.
    fn new_snapshot() -> Snapshot {
        let vm = Self::new_version_map();
        let target_version = vm.latest_version();
        Snapshot::new(vm, target_version)
    }

    /// Saves the struct to a `Vec<u8>`.
    fn save(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut snapshot = Self::new_snapshot();
        snapshot.save(&mut buf, self).map_err(|e| {
            IoError::new(
                ErrorKind::Other,
                format!("Failed to save snapshot: {:?}", e),
            )
        })?;

        Ok(buf)
    }

    /// Restores the struct from a `Vec<u8>`.
    fn restore(buf: &mut Vec<u8>) -> Result<Self> {
        Snapshot::load(&mut buf.as_slice(), buf.len(), Self::new_version_map()).map_err(|e| {
            IoError::new(
                ErrorKind::Other,
                format!("Failed to load snapshot: {:?}", e),
            )
        })
    }
}
