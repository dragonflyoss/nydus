//! Helpers shared by the test suite for assembling footer-based full
//! blobs, delegating to the production `nydus_format::blob` assembler.

use std::io::Write;

/// Assemble a footer-based full blob (`data | pad | bootstrap | pad |
/// blob meta | footer`) in `blob_dir` via the production
/// `nydus_format::blob::finish_full_blob`, rename it to its hex digest, and
/// return the digest.
pub fn assemble_full_blob(
    blob_dir: &std::path::Path,
    data: &[u8],
    bootstrap_bytes: &[u8],
    blob_metadata: &nydus_format::blob::BlobMetadata,
) -> [u8; nydus_format::utils::SHA256_DIGEST_SIZE] {
    let full_blob_path = blob_dir.join("full.blob");
    let mut full_blob = std::fs::File::create(&full_blob_path).expect("create full blob");
    full_blob.write_all(data).expect("write data");
    nydus_format::blob::finish_full_blob(
        &mut full_blob,
        data.len() as u64,
        bootstrap_bytes,
        blob_metadata,
    )
    .expect("assemble full blob");
    drop(full_blob);

    let full_blob_digest =
        nydus_format::utils::sha256_file(&full_blob_path).expect("hash full blob");
    let final_path = blob_dir.join(nydus_format::utils::hex_string(&full_blob_digest));
    std::fs::rename(&full_blob_path, final_path).expect("rename full blob");
    full_blob_digest
}
