mod local;

use std::io;

use crate::metadata::{BlobMeta, EROFS_BLOB_ID_SIZE};

pub use local::LocalBackend;

pub trait BlobBackend: Send + Sync {
    fn load_blobmeta(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> io::Result<BlobMeta>;
    fn read_range(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        len: u32,
    ) -> io::Result<Vec<u8>>;
}
