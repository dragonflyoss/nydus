// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::alloc::{alloc, Layout};
use std::borrow::Cow;
use std::convert::TryFrom;
use std::fmt::{self, Debug, Formatter};
use std::io::Error;
use std::str::FromStr;

use openssl::symm;

/// Supported cipher algorithms.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    None = 0,
    Aes128Xts = 1,
    Aes256Xts = 2,
    Aes256Gcm = 3,
}

impl Algorithm {
    /// Create a new cipher object.
    pub fn new_crypter(&self) -> Result<Crypter, Error> {
        match self {
            Algorithm::None => Ok(Crypter::None),
            Algorithm::Aes128Xts => {
                let cipher = symm::Cipher::aes_128_xts();
                Ok(Crypter::Aes128Xts(cipher))
            }
            Algorithm::Aes256Xts => {
                let cipher = symm::Cipher::aes_256_xts();
                Ok(Crypter::Aes256Xts(cipher))
            }
            Algorithm::Aes256Gcm => {
                let cipher = symm::Cipher::aes_256_gcm();
                Ok(Crypter::Aes256Gcm(cipher))
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
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::None
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

/// Support encryptor and decryptor.
pub enum Crypter {
    None,
    Aes128Xts(symm::Cipher),
    Aes256Xts(symm::Cipher),
    Aes256Gcm(symm::Cipher),
}

impl Default for Crypter {
    fn default() -> Self {
        Crypter::None
    }
}

impl Debug for Crypter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Crypter::None => write!(f, "cipher: none"),
            Crypter::Aes128Xts(_) => write!(f, "cypher: aes128_xts"),
            Crypter::Aes256Xts(_) => write!(f, "cypher: aes256_xts"),
            Crypter::Aes256Gcm(_) => write!(f, "cipher: aes256_gcm"),
        }
    }
}

impl Crypter {
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
            Crypter::None => Ok(Cow::from(data)),
            Crypter::Aes128Xts(cipher) => {
                assert_eq!(key.len(), 32);
                let mut buf;
                let data = if data.len() >= 16 {
                    data
                } else {
                    // CMS (Cryptographic Message Syntax).
                    // This pads with the same value as the number of padding bytes.
                    let val = (16 - data.len()) as u8;
                    buf = [val; 16];
                    buf[..data.len()].copy_from_slice(data);
                    &buf
                };
                Self::cipher(cipher.clone(), symm::Mode::Encrypt, key, iv, data)
                    .map(|v| Cow::from(v))
                    .map_err(|e| eother!(format!("failed to encrypt data, {}", e)))
            }
            Crypter::Aes256Xts(cipher) => {
                assert_eq!(key.len(), 64);
                let mut buf;
                let data = if data.len() >= 16 {
                    data
                } else {
                    // CMS (Cryptographic Message Syntax).
                    // This pads with the same value as the number of padding bytes.
                    let val = (16 - data.len()) as u8;
                    buf = [val; 16];
                    buf[..data.len()].copy_from_slice(data);
                    &buf
                };
                Self::cipher(cipher.clone(), symm::Mode::Encrypt, key, iv, data)
                    .map(|v| Cow::from(v))
                    .map_err(|e| eother!(format!("failed to encrypt data, {}", e)))
            }
            Crypter::Aes256Gcm(_cipher) => {
                Err(einval!("Crypter::entrypt() doesn't support Aes256Gcm"))
            }
        }
    }

    /// Decrypt encrypted data with optional IV and return the decrypted data.
    pub fn decrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        data: &[u8],
        size: usize,
    ) -> Result<Vec<u8>, Error> {
        let mut data = match self {
            Crypter::None => Ok(data.to_vec()),
            Crypter::Aes128Xts(cipher) => {
                Self::cipher(cipher.clone(), symm::Mode::Decrypt, key, iv, data)
                    .map_err(|e| eother!(format!("failed to decrypt data, {}", e)))
            }
            Crypter::Aes256Xts(cipher) => {
                Self::cipher(cipher.clone(), symm::Mode::Decrypt, key, iv, data)
                    .map_err(|e| eother!(format!("failed to decrypt data, {}", e)))
            }
            Crypter::Aes256Gcm(_cipher) => {
                Err(einval!("Crypter::detrypt() doesn't support Aes256Gcm"))
            }
        }?;

        // Trim possible padding.
        if data.len() > size {
            if data.len() != 16 {
                return Err(einval!("Crypter::decrypt: invalid padding data"));
            }
            let val = (16 - size) as u8;
            for idx in size..data.len() {
                if data[idx] != val {
                    return Err(einval!("Crypter::decrypt: invalid padding data"));
                }
            }
            data.truncate(size);
        }

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
            Crypter::Aes256Gcm(cipher) => {
                symm::encrypt_aead(cipher.clone(), key, iv, &[], data, tag)
                    .map_err(|e| eother!(format!("failed to encrypt data, {}", e)))
            }
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
            Crypter::Aes256Gcm(cipher) => {
                symm::decrypt_aead(cipher.clone(), key, iv, &[], data, tag)
                    .map_err(|e| eother!(format!("failed to encrypt data, {}", e)))
            }
            _ => Err(einval!("invalid algorithm for decrypt_aead()")),
        }
    }

    /// Get size of tag associated with encrypted data.
    pub fn tag_size(&self) -> usize {
        match self {
            Crypter::Aes256Gcm(_) => 12,
            _ => 0,
        }
    }

    /// Get size of ciphertext from size of plaintext.
    pub fn encrypted_size(&self, plaintext_size: usize) -> usize {
        match self {
            Crypter::None => plaintext_size,
            Crypter::Aes128Xts(_) | Crypter::Aes256Xts(_) => {
                if plaintext_size < 16 {
                    16
                } else {
                    plaintext_size
                }
            }
            Crypter::Aes256Gcm(_) => {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_xts_encrypt() {
        let mut key = [0xcu8; 32];
        key[31] = 0xa;

        let cipher = Algorithm::Aes128Xts.new_crypter().unwrap();
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
        assert_eq!(ciphertext2.len(), 16);

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

        let cipher = Algorithm::Aes256Xts.new_crypter().unwrap();
        let ciphertext1 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        let ciphertext2 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        assert_eq!(ciphertext1, ciphertext2);
        assert_eq!(ciphertext2.len(), 16);

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

        let cipher = Algorithm::Aes128Xts.new_crypter().unwrap();
        let ciphertext1 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        let plaintext1 = cipher
            .decrypt(key.as_slice(), Some(&[0u8; 16]), &ciphertext1, 1)
            .unwrap();
        assert_eq!(&plaintext1, b"1");

        let ciphertext2 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"11111111111111111")
            .unwrap();
        let plaintext2 = cipher
            .decrypt(key.as_slice(), Some(&[0u8; 16]), &ciphertext2, 17)
            .unwrap();
        assert_eq!(&plaintext2, b"11111111111111111");

        let ciphertext3 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"11111111111111111")
            .unwrap();
        let plaintext3 = cipher
            .decrypt(key.as_slice(), Some(&[1u8; 16]), &ciphertext3, 17)
            .unwrap();
        assert_eq!(&plaintext3, b"11111111111111111");
    }

    #[test]
    fn test_aes_256_xts_decrypt() {
        let mut key = [0xcu8; 64];
        key[31] = 0xa;

        let cipher = Algorithm::Aes256Xts.new_crypter().unwrap();
        let ciphertext1 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"1")
            .unwrap();
        let plaintext1 = cipher
            .decrypt(key.as_slice(), Some(&[0u8; 16]), &ciphertext1, 1)
            .unwrap();
        assert_eq!(&plaintext1, b"1");

        let ciphertext2 = cipher
            .encrypt(key.as_slice(), Some(&[0u8; 16]), b"11111111111111111")
            .unwrap();
        let plaintext2 = cipher
            .decrypt(key.as_slice(), Some(&[0u8; 16]), &ciphertext2, 17)
            .unwrap();
        assert_eq!(&plaintext2, b"11111111111111111");

        let ciphertext3 = cipher
            .encrypt(key.as_slice(), Some(&[1u8; 16]), b"11111111111111111")
            .unwrap();
        let plaintext3 = cipher
            .decrypt(key.as_slice(), Some(&[1u8; 16]), &ciphertext3, 17)
            .unwrap();
        assert_eq!(&plaintext3, b"11111111111111111");
    }

    #[test]
    fn test_aes_256_gcm() {
        let key = [0xcu8; 32];
        let mut tag = vec![0u8; 12];

        let cipher = Algorithm::Aes256Gcm.new_crypter().unwrap();
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
        let buf2 = Crypter::tweak_key_for_xts(&buf);
        assert_eq!(buf2[0], 0xa5);
        assert_eq!(buf2[16], 0x0);

        let buf = vec![0xa5; 32];
        let buf2 = Crypter::tweak_key_for_xts(&buf);
        assert_eq!(buf2[0], 0x5a);
        assert_eq!(buf2[16], 0xa5);
    }
}
