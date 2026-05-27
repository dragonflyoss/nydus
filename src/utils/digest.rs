use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};

use crate::metadata::EROFS_BLOB_ID_SIZE;

pub fn sha256_bytes(data: &[u8]) -> [u8; EROFS_BLOB_ID_SIZE] {
    let mut digest = [0u8; EROFS_BLOB_ID_SIZE];
    digest.copy_from_slice(&Sha256::digest(data));
    digest
}

pub fn sha256_file(path: &Path) -> Result<[u8; EROFS_BLOB_ID_SIZE]> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open file for hashing: {}", path.display()))?;
    sha256_reader(&mut file, path)
}

pub fn sha256_file_region(path: &Path, offset: u64) -> Result<[u8; EROFS_BLOB_ID_SIZE]> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open file for hashing: {}", path.display()))?;
    let file_len = file
        .metadata()
        .with_context(|| format!("failed to stat file for hashing: {}", path.display()))?
        .len();
    if offset > file_len {
        bail!("hash region offset exceeds file size: {}", path.display());
    }

    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("failed to seek file for hashing: {}", path.display()))?;
    sha256_reader(&mut file, path)
}

pub fn sha256_file_range(path: &Path, offset: u64, len: u64) -> Result<[u8; EROFS_BLOB_ID_SIZE]> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open file for hashing: {}", path.display()))?;
    let file_len = file
        .metadata()
        .with_context(|| format!("failed to stat file for hashing: {}", path.display()))?
        .len();
    let end = offset
        .checked_add(len)
        .context("hash range offset overflow")?;
    if end > file_len {
        bail!("hash range exceeds file size: {}", path.display());
    }

    file.seek(SeekFrom::Start(offset))
        .with_context(|| format!("failed to seek file for hashing: {}", path.display()))?;
    let mut limited = file.take(len);
    sha256_reader(&mut limited, path)
}

pub fn parse_sha256_hex(value: &str) -> Result<[u8; EROFS_BLOB_ID_SIZE]> {
    if value.len() != EROFS_BLOB_ID_SIZE * 2 {
        bail!(
            "expected a {}-character sha256 hex string",
            EROFS_BLOB_ID_SIZE * 2
        );
    }

    let mut digest = [0u8; EROFS_BLOB_ID_SIZE];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_value(chunk[0]).ok_or_else(|| anyhow!("invalid sha256 hex string"))?;
        let lo = hex_value(chunk[1]).ok_or_else(|| anyhow!("invalid sha256 hex string"))?;
        digest[index] = (hi << 4) | lo;
    }
    Ok(digest)
}

pub fn hex_string(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

fn sha256_reader(reader: &mut dyn Read, path: &Path) -> Result<[u8; EROFS_BLOB_ID_SIZE]> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let read = reader
            .read(&mut buf)
            .with_context(|| format!("failed to read file for hashing: {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }

    let mut digest = [0u8; EROFS_BLOB_ID_SIZE];
    digest.copy_from_slice(&hasher.finalize());
    Ok(digest)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::{
        hex_string, parse_sha256_hex, sha256_bytes, sha256_file_range, sha256_file_region,
    };

    #[test]
    fn parse_sha256_hex_round_trips_hex_string() {
        let digest = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
            0xd0, 0xe0, 0xf0, 0x01,
        ];
        let encoded = hex_string(&digest);

        assert_eq!(parse_sha256_hex(&encoded).unwrap(), digest);
    }

    #[test]
    fn sha256_file_region_hashes_from_offset() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"prefix-payload").unwrap();

        assert_eq!(
            sha256_file_region(file.path(), 7).unwrap(),
            sha256_bytes(b"payload")
        );
    }

    #[test]
    fn sha256_file_range_hashes_bounded_region() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"prefix-payload-suffix").unwrap();

        assert_eq!(
            sha256_file_range(file.path(), 7, 7).unwrap(),
            sha256_bytes(b"payload")
        );
    }
}
