//! Byte-level IO helpers: exact positional reads from a shared descriptor
//! and zero padding for stream writers.

use std::io::{self, Read, Write};
use std::os::fd::RawFd;

/// Reads exactly `buf.len()` bytes at `offset` from `fd`, a cache file
/// descriptor from [`BlobCache::cache_fd`](crate::cache::BlobCache::cache_fd),
/// without moving the file position, so the shared descriptor stays safe.
/// Retries on `EINTR` and zero-fills the remainder past EOF, since a block
/// device reply must be full length.
pub fn pread_exact(fd: RawFd, buf: &mut [u8], offset: u64) -> io::Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        // SAFETY: the pointer and length name the unfilled tail of `buf`,
        // which stays exclusively borrowed for the duration of the call.
        let ret = unsafe {
            libc::pread(
                fd,
                buf[filled..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - filled,
                (offset + filled as u64) as libc::off_t,
            )
        };
        match ret {
            0 => {
                buf[filled..].fill(0);
                return Ok(());
            }
            n if n > 0 => filled += n as usize,
            _ => {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
    }

    Ok(())
}

/// Writes `count` zero bytes to `writer`.
pub fn write_zeros(writer: &mut dyn Write, count: u64) -> io::Result<()> {
    io::copy(&mut io::repeat(0).take(count), writer)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn pread_exact_reads_at_the_offset_and_zero_fills_past_eof() {
        let mut file = tempfile::tempfile().unwrap();
        let content: Vec<u8> = (0u8..100).collect();
        file.write_all(&content).unwrap();

        let test_cases = vec![
            (0, 0, Vec::new()),
            (0, 8, content[..8].to_vec()),
            (40, 10, content[40..50].to_vec()),
            (80, 64, [&content[80..], &[0u8; 44][..]].concat()),
            (100, 4, vec![0u8; 4]),
            (200, 4, vec![0u8; 4]),
        ];

        for (offset, len, expected) in test_cases {
            let mut buf = vec![0xaau8; len];
            pread_exact(file.as_raw_fd(), &mut buf, offset).unwrap();
            assert_eq!(buf, expected);
        }
    }

    #[test]
    fn pread_exact_fails_on_a_bad_descriptor() {
        let mut buf = [0u8; 4];
        assert_eq!(
            pread_exact(-1, &mut buf, 0).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn write_zeros_writes_count_zero_bytes() {
        let test_cases = vec![0, 1, 4096, 10_000];

        for count in test_cases {
            let mut written = Vec::new();
            write_zeros(&mut written, count).unwrap();
            assert_eq!(written, vec![0u8; count as usize]);
        }
    }
}
