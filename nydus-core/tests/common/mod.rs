//! Helpers shared by the integration tests for assembling footer-based
//! full blobs. Thin infallible wrappers over the production helpers in
//! `nydus_core::utils` — fixtures use static sizes, so failures are bugs.

use std::io::Write;

pub fn align_up(value: u64, align: u64) -> u64 {
    nydus_core::utils::align_up(value, align).expect("test alignment overflow")
}

pub fn bytes_to_blocks(size: u64) -> u32 {
    nydus_core::utils::bytes_to_blocks(size, "test region").expect("test region not block aligned")
}

pub fn write_zero_padding(
    writer: &mut dyn Write,
    current: u64,
    aligned: u64,
) -> std::io::Result<()> {
    nydus_core::utils::write_zero_padding(writer, current, aligned)
}

/// Assemble a footer-based full blob (`data | pad | bootstrap | pad |
/// blob meta | footer`) in `blob_dir`, rename it to its hex digest, and
/// return the digest.
#[allow(dead_code)]
pub fn assemble_full_blob(
    blob_dir: &std::path::Path,
    data: &[u8],
    bootstrap_bytes: &[u8],
    blob_meta: &nydus_core::metadata::BlobMeta,
) -> [u8; nydus_core::metadata::EROFS_BLOB_ID_SIZE] {
    use nydus_core::metadata::{BlobFooter, NYDUS_BLOB_FOOTER_ALIGNMENT};

    let data_size = data.len() as u64;
    let bootstrap_offset = align_up(data_size, NYDUS_BLOB_FOOTER_ALIGNMENT);
    let bootstrap_blocks = bytes_to_blocks(bootstrap_bytes.len() as u64);
    let blob_meta_offset = align_up(
        bootstrap_offset + bootstrap_bytes.len() as u64,
        NYDUS_BLOB_FOOTER_ALIGNMENT,
    );
    let blob_meta_blocks = bytes_to_blocks(blob_meta.metadata_size());
    let footer = BlobFooter::new(
        0,
        data_size,
        bootstrap_offset,
        bootstrap_blocks,
        blob_meta_offset,
        blob_meta_blocks,
    )
    .expect("footer");

    let full_blob_path = blob_dir.join("full.blob");
    let mut full_blob = std::fs::File::create(&full_blob_path).expect("create full blob");
    full_blob.write_all(data).expect("write data");
    write_zero_padding(&mut full_blob, data_size, bootstrap_offset).expect("pad data");
    full_blob.write_all(bootstrap_bytes).expect("write bootstrap");
    write_zero_padding(
        &mut full_blob,
        bootstrap_offset + bootstrap_bytes.len() as u64,
        blob_meta_offset,
    )
    .expect("pad bootstrap");
    blob_meta.write_to(&mut full_blob).expect("write blob meta");
    footer.write_to(&mut full_blob).expect("write footer");
    drop(full_blob);

    let full_blob_id = nydus_core::utils::sha256_file(&full_blob_path).expect("hash full blob");
    let final_path = blob_dir.join(nydus_core::utils::hex_string(&full_blob_id));
    std::fs::rename(&full_blob_path, final_path).expect("rename full blob");
    full_blob_id
}
