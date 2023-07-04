// Copyright (C) 2022-2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::alloc::{alloc, Layout};
use std::borrow::Cow;
use std::convert::TryFrom;
use std::fmt::{self, Debug, Formatter};
use std::io::Error;
use std::str::FromStr;
use std::sync::Arc;

use openssl::{rand, symm};

// The length of the data unit to be encrypted.
pub const DATA_UNIT_LENGTH: usize = 16;
// The length of thd iv (Initialization Vector) to do AES-XTS encryption.
pub const AES_XTS_IV_LENGTH: usize = 16;
// The length of the key to do AES-128-XTS encryption.
pub const AES_128_XTS_KEY_LENGTH: usize = 32;
// The length of the key to do AES-256-XTS encryption.
pub const AES_256_XTS_KEY_LENGTH: usize = 64;
// The length of the key to do AES-256-GCM encryption.
pub const AES_256_GCM_KEY_LENGTH: usize = 32;

// The padding magic end.
pub const PADDING_MAGIC_END: [u8; 2] = [0x78, 0x90];
// DATA_UNIT_LENGTH + length of PADDING_MAGIC_END.
pub const PADDING_LENGTH: usize = 18;
// Openssl rejects keys with identical first and second halves for xts.
// Use a default key for such cases.
const DEFAULT_CE_KEY: [u8; 32] = [
    0xac, 0xed, 0x14, 0x69, 0x94, 0x23, 0x1e, 0xca, 0x44, 0x8c, 0xed, 0x2f, 0x6b, 0x40, 0x0c, 0x00,
    0xfd, 0xbb, 0x3f, 0xac, 0xdd, 0xc7, 0xd9, 0xee, 0x83, 0xf6, 0x5c, 0xd9, 0x3c, 0xaa, 0x28, 0x7c,
];
const DEFAULT_CE_KEY_64: [u8; 64] = [
    0xac, 0xed, 0x14, 0x69, 0x94, 0x23, 0x1e, 0xca, 0x44, 0x8c, 0xed, 0x2f, 0x6b, 0x40, 0x0c, 0x00,
    0xfd, 0xbb, 0x3f, 0xac, 0xdd, 0xc7, 0xd9, 0xee, 0x83, 0xf6, 0x5c, 0xd9, 0x3c, 0xaa, 0x28, 0x7c,
    0xfd, 0xbb, 0x3f, 0xac, 0xdd, 0xc7, 0xd9, 0xee, 0x83, 0xf6, 0x5c, 0xd9, 0x3c, 0xaa, 0x28, 0x7c,
    0xac, 0xed, 0x14, 0x69, 0x94, 0x23, 0x1e, 0xca, 0x44, 0x8c, 0xed, 0x2f, 0x6b, 0x40, 0x0c, 0x00,
];

/// Supported cipher algorithms.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Algorithm {
    #[default]
    None = 0,
    Aes128Xts = 1,
    Aes256Xts = 2,
    Aes256Gcm = 3,
}

impl Algorithm {
    /// Create a new cipher object.
    pub fn new_cipher(&self) -> Result<Cipher, Error> {
        match self {
            Algorithm::None => Ok(Cipher::None),
            Algorithm::Aes128Xts => {
                let cipher = symm::Cipher::aes_128_xts();
                Ok(Cipher::Aes128Xts(cipher))
            }
            Algorithm::Aes256Xts => {
                let cipher = symm::Cipher::aes_256_xts();
                Ok(Cipher::Aes256Xts(cipher))
            }
            Algorithm::Aes256Gcm => {
                let cipher = symm::Cipher::aes_256_gcm();
                Ok(Cipher::Aes256Gcm(cipher))
            }
        }
    }

    /// Check whether data encryption is enabled or not.
    pub fn is_encryption_enabled(&self) -> bool {
        *self != Algorithm::None
    }

    /// Check whether algorithm is AEAD.
    pub fn is_aead(&self) -> bool {
        match self {
            Algorithm::None => false,
            Algorithm::Aes128Xts => false,
            Algorithm::Aes256Xts => false,
            Algorithm::Aes256Gcm => true,
        }
    }

    /// Get size of tag associated with encrypted data.
    pub fn tag_size(&self) -> usize {
        match self {
            Algorithm::None => 0,
            Algorithm::Aes128Xts => 0,
            Algorithm::Aes256Xts => 0,
            Algorithm::Aes256Gcm => 12,
        }
    }

    /// Get key size of the encryption algorithm.
    pub fn key_length(&self) -> usize {
        match self {
            Algorithm::None => 0,
            Algorithm::Aes128Xts => AES_128_XTS_KEY_LENGTH,
            Algorithm::Aes256Xts => AES_256_XTS_KEY_LENGTH,
            Algorithm::Aes256Gcm => AES_256_GCM_KEY_LENGTH,
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for Algorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "aes128xts" => Ok(Self::Aes128Xts),
            "aes256xts" => Ok(Self::Aes256Xts),
            "aes256gcm" => Ok(Self::Aes256Gcm),
            _ => Err(einval!("cypher algorithm should be none or aes_gcm")),
        }
    }
}

impl TryFrom<u32> for Algorithm {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == Algorithm::None as u32 {
            Ok(Algorithm::None)
        } else if value == Algorithm::Aes128Xts as u32 {
            Ok(Algorithm::Aes128Xts)
        } else if value == Algorithm::Aes256Xts as u32 {
            Ok(Algorithm::Aes256Xts)
        } else if value == Algorithm::Aes256Gcm as u32 {
            Ok(Algorithm::Aes256Gcm)
        } else {
            Err(())
        }
    }
}

impl TryFrom<u64> for Algorithm {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value == Algorithm::None as u64 {
            Ok(Algorithm::None)
        } else if value == Algorithm::Aes128Xts as u64 {
            Ok(Algorithm::Aes128Xts)
        } else if value == Algorithm::Aes256Xts as u64 {
            Ok(Algorithm::Aes256Xts)
        } else if value == Algorithm::Aes256Gcm as u64 {
            Ok(Algorithm::Aes256Gcm)
        } else {
            Err(())
        }
    }
}

/// Cipher object to encrypt/decrypt data.
#[derive(Default)]
pub enum Cipher {
    #[default]
    None,
    Aes128Xts(symm::Cipher),
    Aes256Xts(symm::Cipher),
    Aes256Gcm(symm::Cipher),
}

impl Debug for Cipher {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Cipher::None => write!(f, "cipher: none"),
            Cipher::Aes128Xts(_) => write!(f, "cypher: aes128_xts"),
            Cipher::Aes256Xts(_) => write!(f, "cypher: aes256_xts"),
            Cipher::Aes256Gcm(_) => write!(f, "cipher: aes256_gcm"),
        }
    }
}

impl Cipher {
    /// Encrypt plaintext with optional IV and return the encrypted data.
    ///
    /// For XTS, the caller needs to ensure that the top half of key is not identical to the
    /// bottom half of the key, otherwise the encryption will fail.
    pub fn encrypt<'a>(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        data: &'a [u8],
    ) -> Result<Cow<'a, [u8]>, Error> {
        match self {
            Cipher::None => Ok(Cow::from(data)),
            Cipher::Aes128Xts(cipher) => {
                assert_eq!(key.len(), AES_128_XTS_KEY_LENGTH);
                let mut buf;
                let data = if data.len() >= DATA_UNIT_LENGTH {
                    data
                } else {
                    // CMS (Cryptographic Message Syntax).
                    // This pads with the same value as the number of padding bytes
                    // and appends the magic padding end.
                    let val = (DATA_UNIT_LENGTH - data.len()) as u8;
                    buf = [val; PADDING_LENGTH];
                    buf[..data.len()].copy_from_slice(data);
                    buf[DATA_UNIT_LENGTH..PADDING_LENGTH].copy_from_slice(&PADDING_MAGIC_END);
                    &buf
                };
                Self::cipher(*cipher, symm::Mode::Encrypt, key, iv, data)
                    .map(Cow::from)
                    .map_err(|e| eother!(format!("failed to encrypt data, {}", e)))
            }
            Cipher::Aes256Xts(cipher) => {
                assert_eq!(key.len(), AES_256_XTS_KEY_LENGTH);
                let mut buf;
                let data = if data.len() >= DATA_UNIT_LENGTH {
                    data
                } else {
                    let val = (DATA_UNIT_LENGTH - data.len()) as u8;
                    buf = [val; PADDING_LENGTH];
                    buf[..data.len()].copy_from_slice(data);
                    buf[DATA_UNIT_LENGTH..PADDING_LENGTH].copy_from_slice(&PADDING_MAGIC_END);
                    &buf
                };
                Self::cipher(*cipher, symm::Mode::Encrypt, key, iv, data)
                    .map(Cow::from)
                    .map_err(|e| eother!(format!("failed to encrypt data, {}", e)))
            }
            Cipher::Aes256Gcm(_cipher) => {
                Err(einval!("Cipher::entrypt() doesn't support Aes256Gcm"))
            }
        }
    }

    /// Decrypt encrypted data with optional IV and return the decrypted data.
    pub fn decrypt(&self, key: &[u8], iv: Option<&[u8]>, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut data = match self {
            Cipher::None => Ok(data.to_vec()),
            Cipher::Aes128Xts(cipher) => Self::cipher(*cipher, symm::Mode::Decrypt, key, iv, data)
                .map_err(|e| eother!(format!("failed to decrypt data, {}", e))),
            Cipher::Aes256Xts(cipher) => Self::cipher(*cipher, symm::Mode::Decrypt, key, iv, data)
                .map_err(|e| eother!(format!("failed to decrypt data, {}", e))),
            Cipher::Aes256Gcm(_cipher) => {
                Err(einval!("Cipher::detrypt() doesn't support Aes256Gcm"))
            }
        }?;

        // Trim possible padding.
        if data.len() == PADDING_LENGTH
            && data[PADDING_LENGTH - PADDING_MAGIC_END.len()..PADDING_LENGTH] == PADDING_MAGIC_END
        {
            let val = data[DATA_UNIT_LENGTH - 1] as usize;
            if val < DATA_UNIT_LENGTH {
                data.truncate(DATA_UNIT_LENGTH - val);
            } else {
                return Err(einval!(format!(
                    "Cipher::decrypt: invalid padding data, value {}",
                    val,
                )));
            }
        };

        Ok(data)
    }

    /// Encrypt plaintext and return the ciphertext with authentication tag.
    pub fn encrypt_aead(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        data: &[u8],
        tag: &mut [u8],
    ) -> Result<Vec<u8>, Error> {
        match self {
            Cipher::Aes256Gcm(cipher) => symm::encrypt_aead(*cipher, key, iv, &[], data, tag)
                .map_err(|e| eother!(format!("failed to encrypt data, {}", e))),
            _ => Err(einval!("invalid algorithm for encrypt_aead()")),
        }
    }

    /// Decrypt plaintext and return the encrypted data with authentication tag.
    pub fn decrypt_aead(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        data: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match self {
            Cipher::Aes256Gcm(cipher) => symm::decrypt_aead(*cipher, key, iv, &[], data, tag)
                .map_err(|e| eother!(format!("failed to encrypt data, {}", e))),
            _ => Err(einval!("invalid algorithm for decrypt_aead()")),
        }
    }

    /// Get size of tag associated with encrypted data.
    pub fn tag_size(&self) -> usize {
        match self {
            Cipher::Aes256Gcm(_) => 12,
            _ => 0,
        }
    }

    /// Get size of ciphertext from size of plaintext.
    pub fn encrypted_size(&self, plaintext_size: usize) -> usize {
        match self {
            Cipher::None => plaintext_size,
            Cipher::Aes128Xts(_) | Cipher::Aes256Xts(_) => {
                if plaintext_size < DATA_UNIT_LENGTH {
                    DATA_UNIT_LENGTH
                } else {
                    plaintext_size
                }
            }
            Cipher::Aes256Gcm(_) => {
                assert!(plaintext_size.checked_add(12).is_some());
                plaintext_size + 12
            }
        }
    }

    /// Tweak key for XTS mode.
    pub fn tweak_key_for_xts(key: &[u8]) -> Cow<[u8]> {
        let len = key.len() >> 1;
        if key[..len] == key[len..] {
            let mut buf = if key[len] == 0xa5 {
                vec![0x5a; key.len()]
            } else {
                vec![0xa5; key.len()]
            };
            buf[len..].copy_from_slice(&key[len..]);
            Cow::from(buf)
        } else {
            Cow::from(key)
        }
    }

    fn cipher(
        t: symm::Cipher,
        mode: symm::Mode,
        key: &[u8],
        iv: Option<&[u8]>,
        data: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut c = symm::Crypter::new(t, mode, key, iv)?;
        let mut out = alloc_buf(data.len() + t.block_size());
        let count = c.update(data, &mut out)?;
        let rest = c.finalize(&mut out[count..])?;
        out.truncate(count + rest);
        Ok(out)
    }

    pub fn generate_random_key(cipher_algo: Algorithm) -> Result<Vec<u8>, Error> {
        let length = cipher_algo.key_length();
        let mut buf = vec![0u8; length];
        if let Err(e) = rand::rand_bytes(&mut buf) {
            Err(eother!(format!(
                "failed to generate key for {}, {}",
                cipher_algo, e
            )))
        } else {
            Ok(Self::tweak_key_for_xts(&buf).to_vec())
        }
    }

    pub fn generate_random_iv() -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; AES_XTS_IV_LENGTH];
        if let Err(e) = rand::rand_bytes(&mut buf) {
            Err(eother!(format!("failed to generate iv, {}", e)))
        } else {
            Ok(buf)
        }
    }
}

/// Struct to provide context information for data encryption/decryption.
#[derive(Default, Debug, Clone)]
pub struct CipherContext {
    key: Vec<u8>,
    iv: Vec<u8>,
    convergent_encryption: bool,
    cipher_algo: Algorithm,
}

impl CipherContext {
    /// Create a new instance of [CipherContext].
    pub fn new(
        key: Vec<u8>,
        iv: Vec<u8>,
        convergent_encryption: bool,
        cipher_algo: Algorithm,
    ) -> Result<Self, Error> {
        let key_length = key.len();
        if key_length != cipher_algo.key_length() {
            return Err(einval!(format!(
                "invalid key length {} for {} encryption",
                key_length, cipher_algo
            )));
        } else if key[0..key_length >> 1] == key[key_length >> 1..key_length] {
            return Err(einval!("invalid symmetry key for encryption"));
        }

        Ok(CipherContext {
            key,
            iv,
            convergent_encryption,
            cipher_algo,
        })
    }

    /// Generate context information from data for encryption/decryption.
    pub fn generate_cipher_meta<'a>(&'a self, data: &'a [u8]) -> (&'a [u8], Vec<u8>) {
        let length = data.len();
        assert_eq!(length, self.cipher_algo.key_length());
        let iv = vec![0u8; AES_XTS_IV_LENGTH];
        if self.convergent_encryption {
            if length == AES_128_XTS_KEY_LENGTH && data[0..length >> 1] == data[length >> 1..length]
            {
                (&DEFAULT_CE_KEY, iv)
            } else if length == AES_256_XTS_KEY_LENGTH
                && data[0..length >> 1] == data[length >> 1..length]
            {
                (&DEFAULT_CE_KEY_64, iv)
            } else {
                (data, iv)
            }
        } else {
            (&self.key, iv)
        }
    }

    /// Get context information for meta data encryption/decryption.
    pub fn get_cipher_meta(&self) -> (&[u8], &[u8]) {
        (&self.key, &self.iv)
    }
}

/// A customized buf allocator that avoids zeroing
fn alloc_buf(size: usize) -> Vec<u8> {
    assert!(size < isize::MAX as usize);
    let layout = Layout::from_size_align(size, 0x1000)
        .unwrap()
        .pad_to_align();
    let ptr = unsafe { alloc(layout) };
    unsafe { Vec::from_raw_parts(ptr, size, layout.size()) }
}

// Encrypt data with Cipher and CipherContext.
pub fn encrypt_with_context<'a>(
    data: &'a [u8],
    cipher_obj: &Arc<Cipher>,
    cipher_ctx: &Option<CipherContext>,
    encrypted: bool,
) -> Result<Cow<'a, [u8]>, Error> {
    if encrypted {
        if let Some(cipher_ctx) = cipher_ctx {
            let (key, iv) = cipher_ctx.get_cipher_meta();
            Ok(cipher_obj.encrypt(key, Some(iv), data)?)
        } else {
            Err(einval!("the encrypt context can not be none"))
        }
    } else {
        Ok(Cow::Borrowed(data))
    }
}

// Decrypt data with Cipher and CipherContext.
pub fn decrypt_with_context<'a>(
    data: &'a [u8],
    cipher_obj: &Arc<Cipher>,
    cipher_ctx: &Option<CipherContext>,
    encrypted: bool,
) -> Result<Cow<'a, [u8]>, Error> {
    if encrypted {
        if let Some(cipher_ctx) = cipher_ctx {
            let (key, iv) = cipher_ctx.get_cipher_meta();
            Ok(Cow::from(cipher_obj.decrypt(key, Some(iv), data)?))
        } else {
            Err(einval!("the decrypt context can not be none"))
        }
    } else {
        Ok(Cow::Borrowed(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_xts_encrypt() {
        let mut key = [0xcu8; 32];
        key[31] = 0xa;

        let cipher = Algorithm::Aes128Xts.new_cipher().unwrap();
        assert_eq!(cipher.encrypted_size(1), 16);
        assert_eq!(cipher.encrypted_size(16), 16);
        assert_eq!(cipher.encrypted_size(17), 17);

        let ciphertext1 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        let ciphertext2 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        assert_eq!(ciphertext1, ciphertext2);
        assert_eq!(ciphertext2.len(), PADDING_LENGTH);

        let ciphertext3 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"11111111111111111")
            .unwrap();
        assert_eq!(ciphertext3.len(), 17);

        let ciphertext4 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"11111111111111111")
            .unwrap();
        assert_eq!(ciphertext4.len(), 17);
        assert_ne!(ciphertext4, ciphertext3);

        let ciphertext5 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"21111111111111111")
            .unwrap();
        assert_eq!(ciphertext5.len(), 17);
        assert_ne!(ciphertext5, ciphertext4);
    }

    #[test]
    fn test_aes_256_xts_encrypt() {
        let mut key = [0xcu8; 64];
        key[31] = 0xa;

        let cipher = Algorithm::Aes256Xts.new_cipher().unwrap();
        let ciphertext1 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        let ciphertext2 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        assert_eq!(ciphertext1, ciphertext2);
        assert_eq!(ciphertext2.len(), PADDING_LENGTH);

        let ciphertext3 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"11111111111111111")
            .unwrap();
        assert_eq!(ciphertext3.len(), 17);

        let ciphertext4 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"11111111111111111")
            .unwrap();
        assert_eq!(ciphertext4.len(), 17);
        assert_ne!(ciphertext4, ciphertext3);

        let ciphertext5 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"21111111111111111")
            .unwrap();
        assert_eq!(ciphertext5.len(), 17);
        assert_ne!(ciphertext5, ciphertext4);
    }

    #[test]
    fn test_aes_128_xts_decrypt() {
        let mut key = [0xcu8; 32];
        key[31] = 0xa;

        let cipher = Algorithm::Aes128Xts.new_cipher().unwrap();
        let ciphertext1 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        let plaintext1 = cipher
            .decrypt(key.as_slice(), Some(&[0u8; 16]), &ciphertext1)
            .unwrap();
        assert_eq!(&plaintext1, b"1");

        let ciphertext2 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"11111111111111111")
            .unwrap();
        let plaintext2 = cipher
            .decrypt(key.as_slice(), Some(&[0u8; 16]), &ciphertext2)
            .unwrap();
        assert_eq!(&plaintext2, b"11111111111111111");

        let ciphertext3 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"11111111111111111")
            .unwrap();
        let plaintext3 = cipher
            .decrypt(key.as_slice(), Some(&[1u8; 16]), &ciphertext3)
            .unwrap();
        assert_eq!(&plaintext3, b"11111111111111111");
    }

    #[test]
    fn test_aes_256_xts_decrypt() {
        let mut key = [0xcu8; 64];
        key[31] = 0xa;

        let cipher = Algorithm::Aes256Xts.new_cipher().unwrap();
        let ciphertext1 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        let plaintext1 = cipher
            .decrypt(key.as_slice(), Some(&[0u8; 16]), &ciphertext1)
            .unwrap();
        assert_eq!(&plaintext1, b"1");

        let ciphertext2 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"11111111111111111")
            .unwrap();
        let plaintext2 = cipher
            .decrypt(key.as_slice(), Some(&[0u8; 16]), &ciphertext2)
            .unwrap();
        assert_eq!(&plaintext2, b"11111111111111111");

        let ciphertext3 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"11111111111111111")
            .unwrap();
        let plaintext3 = cipher
            .decrypt(key.as_slice(), Some(&[1u8; 16]), &ciphertext3)
            .unwrap();
        assert_eq!(&plaintext3, b"11111111111111111");
    }

    #[test]
    fn test_aes_256_gcm() {
        let key = [0xcu8; 32];
        let mut tag = vec![0u8; 12];

        let cipher = Algorithm::Aes256Gcm.new_cipher().unwrap();
        assert_eq!(cipher.tag_size(), 12);
        assert_eq!(cipher.encrypted_size(1), 13);

        let ciphertext1 = cipher
            .encrypt_aead(key.as_slice(), Some(&[0u8; 16]), b"1", &mut tag)
            .unwrap();
        assert_eq!(ciphertext1.len(), 1);
        assert_eq!(tag.len(), 12);
        let plaintext1 = cipher
            .decrypt_aead(key.as_slice(), Some(&[0u8; 16]), &ciphertext1, &tag)
            .unwrap();
        assert_eq!(&plaintext1, b"1");

        let ciphertext2 = cipher
            .encrypt_aead(
                key.as_slice(),
                Some(&[0u8; 16]),
                b"11111111111111111",
                &mut tag,
            )
            .unwrap();
        assert_eq!(ciphertext2.len(), 17);
        assert_eq!(tag.len(), 12);
        let plaintext2 = cipher
            .decrypt_aead(key.as_slice(), Some(&[0u8; 16]), &ciphertext2, &tag)
            .unwrap();
        assert_eq!(&plaintext2, b"11111111111111111");

        let ciphertext3 = cipher
            .encrypt_aead(
                key.as_slice(),
                Some(&[1u8; 16]),
                b"11111111111111111",
                &mut tag,
            )
            .unwrap();
        assert_ne!(ciphertext3, ciphertext2);
        assert_eq!(ciphertext3.len(), 17);
        assert_eq!(tag.len(), 12);
        let plaintext3 = cipher
            .decrypt_aead(key.as_slice(), Some(&[1u8; 16]), &ciphertext3, &tag)
            .unwrap();
        assert_eq!(&plaintext3, b"11111111111111111");
    }

    #[test]
    fn test_tweak_key_for_xts() {
        let buf = vec![0x0; 32];
        let buf2 = Cipher::tweak_key_for_xts(&buf);
        assert_eq!(buf2[0], 0xa5);
        assert_eq!(buf2[16], 0x0);

        let buf = vec![0xa5; 32];
        let buf2 = Cipher::tweak_key_for_xts(&buf);
        assert_eq!(buf2[0], 0x5a);
        assert_eq!(buf2[16], 0xa5);
    }
}
