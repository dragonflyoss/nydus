mod local;

use std::io;
use std::path::Path;

use crate::metadata::{BlobMeta, EROFS_BLOB_ID_SIZE};

pub use local::LocalBackend;

pub trait BlobBackend: Send + Sync {
    fn cache_key(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
    ) -> io::Result<[u8; EROFS_BLOB_ID_SIZE]> {
        Ok(*blob_id)
    }

    fn load_blob_meta(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE]) -> io::Result<BlobMeta>;

    fn download_blob_meta(&self, blob_id: &[u8; EROFS_BLOB_ID_SIZE], dst: &Path) -> io::Result<()> {
        let blob_meta = self.load_blob_meta(blob_id)?;
        blob_meta.save(dst).map_err(io::Error::other)
    }

    fn read_range_into(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        dst: &mut [u8],
    ) -> io::Result<()> {
        let data = self.read_range(blob_id, offset, dst.len() as u32)?;
        if data.len() != dst.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "backend returned short range",
            ));
        }
        dst.copy_from_slice(&data);
        Ok(())
    }

    fn read_range(
        &self,
        blob_id: &[u8; EROFS_BLOB_ID_SIZE],
        offset: u64,
        len: u32,
    ) -> io::Result<Vec<u8>>;
}
