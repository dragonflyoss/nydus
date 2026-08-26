// Copyright (C) 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! EROFS mount of the exported flattened image file.

use std::ffi::CString;
use std::path::Path;

use nydus_error::{Context, Result};

use crate::mount::path_cstring;

/// Mount the exported image file at `mountpoint` as read-only EROFS.
///
/// The source is a regular file, so `get_tree_bdev` fails with `-ENOTBLK` and
/// the kernel falls back to file-backed mode (`CONFIG_EROFS_FS_BACKED_BY_FILE`,
/// Linux >= 6.12), reading it through the VFS — which is what routes cold
/// ranges back to the FUSE export.
///
/// `direct_io` adds the `directio` option, which makes EROFS submit data reads
/// with `IOCB_DIRECT` so the export's own page cache stays empty. Every byte
/// EROFS reads is cached again against the inode the application reads, so
/// without it the image is held twice; measured on a 16 MiB read, the export
/// accumulated 16.2 MiB that `directio` reduces to zero. It costs roughly 30%
/// on cold reads, because each read becomes a FUSE round trip with no
/// intervening readahead, and nothing on warm reads. Metadata is unaffected
/// either way: `erofs_bread` resolves it through `read_mapping_folio`, which
/// the option does not touch.
pub fn mount_image_file(image: &Path, mountpoint: &Path, direct_io: bool) -> Result<()> {
    let source = path_cstring(image, "image file")?;
    let target = path_cstring(mountpoint, "mountpoint")?;
    let fs_type = CString::new("erofs").expect("erofs has no interior NUL");
    let options = direct_io.then(|| CString::new("directio").expect("static option has no NUL"));

    let ret = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fs_type.as_ptr(),
            libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID,
            options
                .as_ref()
                .map_or(std::ptr::null(), |opts| opts.as_ptr().cast()),
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to mount {} at {} as erofs (needs Linux >= 6.12 with CONFIG_EROFS_FS_BACKED_BY_FILE)",
                image.display(),
                mountpoint.display()
            )
        });
    }
    Ok(())
}
