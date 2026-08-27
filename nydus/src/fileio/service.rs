// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Mount lifecycle for the file-backed EROFS service.
//!
//! Two mounts stack here: the FUSE export holding the flattened image file,
//! and the kernel EROFS mount that consumes it. They must come down in the
//! opposite order they went up — EROFS keeps the backing file open, so
//! ending the FUSE session first leaves the EROFS mount reading a dead
//! session and the export busy.

use std::path::{Path, PathBuf};

use fuser::Notifier;
use nydus_error::{Context, Result};
use tracing::{debug, info, warn};

use super::fs::{FlatImageFs, IMAGE_INO, IMAGE_NAME};
use crate::mount::unmount;

/// Chunk size for warming the bootstrap into the export's page cache.
///
/// `FUSE_NOTIFY_STORE` carries its payload inline in a single notification,
/// so the bootstrap is pushed in slices rather than as one multi-MiB message.
const WARM_CHUNK_SIZE: u64 = 1 << 20;

/// Path of the exported image file inside the FUSE mount.
pub fn image_path(fuse_mountpoint: &Path) -> PathBuf {
    fuse_mountpoint.join(IMAGE_NAME)
}

/// Push the bootstrap region of the flattened image into the kernel page
/// cache of the exported file.
///
/// EROFS resolves every lookup, readdir, stat and xattr by reading metadata
/// bytes out of this file through `read_folio`, which faults one folio at a
/// time with no readahead. Without warming, walking a large image costs one
/// FUSE round trip per 4 KiB of metadata; afterwards metadata operations stay
/// entirely in-kernel.
///
/// Best effort by design: the kernel may drop the stored pages under memory
/// pressure and reads then fall back to the FUSE path, so a failure here is
/// logged rather than propagated.
pub fn warm_bootstrap(fs: &FlatImageFs, notifier: &Notifier, bootstrap_size: u64) {
    let end = bootstrap_size.min(fs.image_size());
    if end == 0 {
        return;
    }

    let mut offset = 0u64;
    while offset < end {
        let len = WARM_CHUNK_SIZE.min(end - offset);
        let data = match fs.read_image(offset, len as u32) {
            Ok(data) if !data.is_empty() => data,
            Ok(_) => break,
            Err(err) => {
                warn!("failed to read bootstrap at offset {offset} for warming: {err}");
                return;
            }
        };
        if let Err(err) = notifier.store(fuser::INodeNo(IMAGE_INO), offset, &data) {
            // A kernel that rejects the notification leaves the cold read path
            // intact, so stop warming instead of failing the mount.
            debug!("fuse notify store at offset {offset} rejected: {err}");
            return;
        }
        offset += data.len() as u64;
    }
    info!("warmed {offset} bytes of bootstrap metadata into the export page cache");
}

/// The FUSE export plus the EROFS mount stacked on it, torn down in
/// dependency order.
pub struct FileioService {
    session: fuser::BackgroundSession,
    fuse_mountpoint: PathBuf,
    erofs_mountpoint: Option<PathBuf>,
}

impl FileioService {
    /// Mount `fs` at `fuse_mountpoint` and serve it on background threads.
    pub fn mount(fs: FlatImageFs, fuse_mountpoint: &Path, config: &fuser::Config) -> Result<Self> {
        let session = fuser::Session::new(fs, fuse_mountpoint, config).with_context(|| {
            format!(
                "failed to mount fuse export at {}",
                fuse_mountpoint.display()
            )
        })?;
        let session = session
            .spawn()
            .context("failed to spawn fuse export session")?;
        Ok(Self {
            session,
            fuse_mountpoint: fuse_mountpoint.to_path_buf(),
            erofs_mountpoint: None,
        })
    }

    /// Notifier for pushing data into the export's page cache.
    pub fn notifier(&self) -> Notifier {
        self.session.notifier()
    }

    /// Record the EROFS mountpoint stacked on the export so shutdown unmounts
    /// it before ending the session.
    pub fn set_erofs_mountpoint(&mut self, mountpoint: &Path) {
        self.erofs_mountpoint = Some(mountpoint.to_path_buf());
    }

    /// Unmount EROFS first, then unmount the export and end the session.
    pub fn shutdown(self) {
        if let Some(mountpoint) = &self.erofs_mountpoint {
            if let Err(err) = unmount(mountpoint, || {}) {
                warn!("failed to unmount {}: {}", mountpoint.display(), err);
            }
        }
        // Unmounting is what makes the session threads return; joining alone
        // would block until something else tore the export down.
        if let Err(err) = self.session.umount_and_join() {
            warn!(
                "fuse export at {} ended with an error: {}",
                self.fuse_mountpoint.display(),
                err
            );
        }
        info!("stopped fuse export at {}", self.fuse_mountpoint.display());
    }
}
