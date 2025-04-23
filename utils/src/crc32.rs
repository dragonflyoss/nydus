// Copyright 2025 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use crc::Crc;
use crc::Table;
use nix::sys::uio;
use std::fmt;
use std::fmt::Debug;
use std::io::ErrorKind;
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

    pub fn digester(&self) -> crc::Digest<'_, u32, Table<16>> {
        self.crc.digest()
    }

    pub fn from_raw_fd(&self, fd: i32, offset: u64, size: u64) -> std::io::Result<u32> {
        let mut digester = self.crc.digest();
        let mut buf = vec![0u8; 1024 * 1024];
        let mut total_read: u64 = 0;
        loop {
            if total_read >= size {
                break;
            }
            let bytes_to_read = std::cmp::min((size - total_read) as usize, buf.len());
            let ret = uio::pread(fd, &mut buf[..bytes_to_read], (offset + total_read) as i64)
                .map_err(|_| last_error!());
            match ret {
                Ok(read_size) => {
                    if read_size == 0 {
                        break;
                    }
                    digester.update(&buf[..read_size]);
                    total_read += read_size as u64;
                }
                Err(err) => {
                    if err.kind() != ErrorKind::Interrupted {
                        return Err(err);
                    }
                }
            }
        }

        Ok(digester.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn test_display() {
        let algorithm = Algorithm::Crc32Iscsi;
        assert_eq!(format!("{}", algorithm), "Crc32Iscsi");
    }

    #[test]
    fn test_try_from_u32() {
        let value = Algorithm::None as u32;
        assert_eq!(Algorithm::try_from(value), Ok(Algorithm::None));

        let value = Algorithm::Crc32Iscsi as u32;
        assert_eq!(Algorithm::try_from(value), Ok(Algorithm::Crc32Iscsi));

        let value = 999u32;
        assert_eq!(Algorithm::try_from(value), Err(()));
    }

    #[test]
    fn test_try_from_u64() {
        let value = Algorithm::None as u64;
        assert_eq!(Algorithm::try_from(value), Ok(Algorithm::None));

        let value = Algorithm::Crc32Iscsi as u64;
        assert_eq!(Algorithm::try_from(value), Ok(Algorithm::Crc32Iscsi));

        let value = 999u64;
        assert_eq!(Algorithm::try_from(value), Err(()));
    }

    #[test]
    fn test_default() {
        let crc32 = Crc32::default();
        let data = b"123456789";
        let expected_checksum = 0xe3069283;
        let crc32_result = crc32.from_buf(data);
        assert_eq!(crc32_result, expected_checksum);

        let crc32_2 = Crc32::new(Algorithm::None);
        let crc32_result2 = crc32_2.from_buf(data);
        assert_eq!(crc32_result2, expected_checksum);
    }

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

    #[test]
    fn test_digester() {
        let crc32 = Crc32::new(Algorithm::Crc32Iscsi);
        let mut digester = crc32.digester();
        digester.update(b"123456789");
        assert_eq!(digester.finalize(), 0xe3069283);
    }

    #[test]
    fn test_crc32_from_raw_fd() {
        use std::io::Write;
        use tempfile::tempfile;

        let mut file = tempfile().unwrap();
        file.write_all(b"123456789").unwrap();
        let fd = file.as_raw_fd();
        let crc32 = Crc32::new(Algorithm::Crc32Iscsi);
        let result = crc32.from_raw_fd(fd, 0, 9).unwrap();

        let expected_checksum = 0xe3069283;
        assert_eq!(result, expected_checksum);

        // invalid fd
        assert!(crc32.from_raw_fd(-1, 0, 9).is_err());
    }
}
