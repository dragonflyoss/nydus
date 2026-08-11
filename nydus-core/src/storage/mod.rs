pub mod backend;
pub mod cache;
pub mod group_map;
pub mod prefetch;

/// Fixture builders shared by the storage unit tests.
#[cfg(test)]
pub(crate) mod test_util {
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    use crate::metadata::{
        BlobFooter, BlobMeta, ErofsSuperblock, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE,
        EROFS_SUPER_OFFSET,
    };
    use crate::utils::{hex_string, sha256_bytes};

    /// Assemble a minimal full blob (`payload + trivial bootstrap + blob meta
    /// + footer`) into `dir`, named by its full SHA256, optionally with a
    /// `.blob.meta` sidecar. Returns the full blob id.
    pub(crate) fn write_full_blob(
        dir: &Path,
        payload: &[u8],
        blob_meta: &BlobMeta,
        save_sidecar: bool,
    ) -> [u8; EROFS_BLOB_ID_SIZE] {
        let mut bootstrap = vec![0u8; 8192];
        let sb = ErofsSuperblock::new(0, 0, 0, 0, 0, 2, 1, 0, 0, &[0u8; 16]);
        let sb_start = EROFS_SUPER_OFFSET as usize;
        let sb_end = sb_start + sb.as_bytes().len();
        bootstrap[sb_start..sb_end].copy_from_slice(sb.as_bytes());

        let footer = BlobFooter::new(
            0,
            payload.len() as u64,
            payload.len() as u64,
            (bootstrap.len() as u64 / EROFS_BLOCK_SIZE as u64) as u32,
            payload.len() as u64 + bootstrap.len() as u64,
            (blob_meta.metadata_size() / EROFS_BLOCK_SIZE as u64) as u32,
        )
        .unwrap();

        let mut full_blob = Vec::new();
        full_blob.write_all(payload).unwrap();
        full_blob.write_all(&bootstrap).unwrap();
        blob_meta.write_to(&mut full_blob).unwrap();
        footer.write_to(&mut full_blob).unwrap();
        let full_blob_id = sha256_bytes(&full_blob);

        fs::write(dir.join(hex_string(&full_blob_id)), &full_blob).unwrap();
        if save_sidecar {
            blob_meta
                .save(&dir.join(format!("{}.blob.meta", hex_string(&full_blob_id))))
                .unwrap();
        }

        full_blob_id
    }
}
