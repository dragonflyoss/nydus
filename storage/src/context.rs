// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::io::Result;

use crate::device::BlobChunkInfo;

// Openssl rejects keys with identical first and second halves for xts.
// Use a default key for such cases.
const DEFAULT_CE_KEY: [u8; 32] = [
    0xac, 0xed, 0x14, 0x69, 0x94, 0x23, 0x1e, 0xca, 0x44, 0x8c, 0xed, 0x2f, 0x6b, 0x40, 0x0c, 0x00,
    0xfd, 0xbb, 0x3f, 0xac, 0xdd, 0xc7, 0xd9, 0xee, 0x83, 0xf6, 0x5c, 0xd9, 0x3c, 0xaa, 0x28, 0x7c,
];

/// Struct to provide context information for data encryption/decryption.
#[derive(Default)]
pub struct CipherContext {
    key: Vec<u8>,
    convergent_encryption: bool,
}

impl CipherContext {
    /// Create a new instance of [CipherContext].
    pub fn new(key: Vec<u8>, convergent_encryption: bool) -> Result<Self> {
        if key.len() != 32 {
            return Err(einval!("invalid key length for encryption"));
        } else if key[0..16] == key[16..32] {
            return Err(einval!("invalid symmetry key for encryption"));
        }

        Ok(CipherContext {
            key,
            convergent_encryption,
        })
    }

    /// Get context information for chunk encryption/decryption.
    pub fn get_chunk_cipher_context<'a>(
        &'a self,
        chunk: &'a dyn BlobChunkInfo,
    ) -> (&'a [u8], Vec<u8>) {
        let iv = vec![0u8; 16];
        if self.convergent_encryption {
            let id = &chunk.chunk_id().data;
            if id[0..16] == id[16..32] {
                (&DEFAULT_CE_KEY, iv)
            } else {
                (&chunk.chunk_id().data, iv)
            }
        } else {
            (&self.key, iv)
        }
    }

    /// Get context information for meta data encryption/decryption.
    pub fn get_meta_cipher_context(&self) -> &[u8] {
        &self.key
    }
}
