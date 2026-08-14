pub mod align;
pub mod digest;
pub mod io;
pub mod le;

use std::fs;
use std::io::Write as _;
use std::path::Path;

use crate::blob::{BlobMetadata, BLOB_METADATA_SUFFIX};
use crate::erofs::{ErofsSuperblock, EROFS_SUPER_OFFSET};

pub use self::align::{align_up, round_up};
pub use self::digest::{
    hex_string, parse_sha256_hex, sha256_bytes, sha256_file, sha256_file_range, SHA256_DIGEST_SIZE,
};
pub use self::io::{pread_exact, write_zero_padding};

/// Assemble a minimal full blob (`payload + trivial bootstrap + blob
/// meta + footer`, production layout via
/// [`crate::blob::assemble_full_blob`]) into `dir`, named by its full
/// SHA256, optionally with a `.blob.meta` sidecar. Returns the full
/// blob id.
pub fn write_minimal_full_blob(
    dir: &Path,
    payload: &[u8],
    blob_metadata: &BlobMetadata,
    save_sidecar: bool,
) -> [u8; SHA256_DIGEST_SIZE] {
    let mut bootstrap = vec![0u8; 8192];
    let sb = ErofsSuperblock::new(0, 0, 0, 0, 0, 2, 1, 0, 0, &[0u8; 16]);
    let sb_start = EROFS_SUPER_OFFSET as usize;
    let sb_end = sb_start + sb.as_bytes().len();
    bootstrap[sb_start..sb_end].copy_from_slice(sb.as_bytes());

    let mut full_blob = Vec::new();
    full_blob.write_all(payload).unwrap();
    crate::blob::assemble_full_blob(
        &mut full_blob,
        payload.len() as u64,
        &bootstrap,
        blob_metadata,
    )
    .unwrap();
    let full_blob_id = sha256_bytes(&full_blob);

    fs::write(dir.join(hex_string(&full_blob_id)), &full_blob).unwrap();
    if save_sidecar {
        blob_metadata
            .save(&dir.join(format!(
                "{}{BLOB_METADATA_SUFFIX}",
                hex_string(&full_blob_id)
            )))
            .unwrap();
    }

    full_blob_id
}
