//! SHA-256 digests, the blob id of every nydus blob.

use crate::error::Result;
use sha2::{Digest, Sha256};
use std::io::{self, BufReader, Read};

/// Byte length of a SHA-256 digest.
pub const SHA256_DIGEST_SIZE: usize = 32;

/// Read buffer size when hashing a stream.
const HASH_READ_BUFFER_SIZE: usize = 64 * 1024;

/// The SHA-256 digest of `reader` read to its end.
pub fn sha256_reader(reader: impl Read) -> Result<[u8; SHA256_DIGEST_SIZE]> {
    let mut hasher = Sha256::new();
    io::copy(
        &mut BufReader::with_capacity(HASH_READ_BUFFER_SIZE, reader),
        &mut hasher,
    )?;

    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn sha256_reader_matches_the_known_vectors() {
        let test_cases = vec![
            (
                &b""[..],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                &b"abc"[..],
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
        ];

        for (data, expected) in test_cases {
            assert_eq!(hex::encode(sha256_reader(data).unwrap()), expected);
        }
    }

    #[test]
    fn sha256_reader_matches_the_one_shot_digest_across_buffer_boundaries() {
        let test_cases = vec![
            0,
            1,
            HASH_READ_BUFFER_SIZE - 1,
            HASH_READ_BUFFER_SIZE,
            3 * HASH_READ_BUFFER_SIZE + 7,
        ];

        for len in test_cases {
            let data = vec![0x5au8; len];
            let expected: [u8; SHA256_DIGEST_SIZE] = Sha256::digest(&data).into();
            assert_eq!(sha256_reader(&data[..]).unwrap(), expected);
        }
    }

    #[test]
    fn sha256_reader_hashes_a_file_like_its_bytes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("blob");
        let large = vec![0x5au8; 3 * HASH_READ_BUFFER_SIZE + 7];
        fs::write(&path, &large).unwrap();

        assert_eq!(
            sha256_reader(fs::File::open(&path).unwrap()).unwrap(),
            sha256_reader(&large[..]).unwrap()
        );
    }
}
