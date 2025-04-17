// Copyright 2025 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crc::Crc;
use crc::Table;
use std::fmt;
use std::fmt::Debug;
use std::io::Read;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Algorithm {
    None = 0,
    #[default]
    Crc32Iscsi = 1,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<u32> for Algorithm {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == Algorithm::None as u32 {
            Ok(Algorithm::None)
        } else if value == Algorithm::Crc32Iscsi as u32 {
            Ok(Algorithm::Crc32Iscsi)
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
        } else if value == Algorithm::Crc32Iscsi as u64 {
            Ok(Algorithm::Crc32Iscsi)
        } else {
            Err(())
        }
    }
}

pub struct Crc32 {
    crc: Crc<u32, Table<16>>,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new(Algorithm::Crc32Iscsi)
    }
}

impl Crc32 {
    pub fn new(algorithm: Algorithm) -> Self {
        let crc = match algorithm {
            Algorithm::Crc32Iscsi => &crc::CRC_32_ISCSI,
            _ => &crc::CRC_32_ISCSI,
        };
        Self {
            crc: Crc::<u32, Table<16>>::new(crc),
        }
    }

    pub fn from_buf(&self, bytes: &[u8]) -> u32 {
        self.crc.checksum(bytes)
    }

    /// Compute message crc32 by read data from the reader.
    pub fn from_reader<R: Read>(&self, reader: &mut R) -> std::io::Result<u32> {
        let mut digester = self.crc.digest();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let sz = reader.read(&mut buf)?;
            if sz == 0 {
                return Ok(digester.finalize());
            }
            digester.update(&buf[0..sz]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_from_buf() {
        let crc32 = Crc32::new(Algorithm::Crc32Iscsi);
        let data = b"123456789";
        let expected_checksum = 0xe3069283;
        let crc32_result = crc32.from_buf(data);
        assert_eq!(crc32_result, expected_checksum);
    }

    #[test]
    fn test_crc32_from_reader() {
        let crc32 = Crc32::new(Algorithm::Crc32Iscsi);
        let data = b"123456789";
        let expected_checksum = 0xe3069283;
        let mut reader = std::io::Cursor::new(data);
        let crc32_result = crc32.from_reader(&mut reader).unwrap();
        assert_eq!(crc32_result, expected_checksum);
    }
}
