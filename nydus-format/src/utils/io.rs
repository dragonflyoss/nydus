use std::io::{self, Read, Write};
use std::os::fd::RawFd;

/// Read exactly `buf.len()` bytes from `fd` at `offset` without moving the
/// file position (safe on a shared fd). Retries on `EINTR` and zero-fills the
/// remainder on EOF: the cache file's block-aligned sizing should never
/// produce one, but block-device replies must be full-length.
pub fn pread_exact(fd: RawFd, buf: &mut [u8], offset: u64) -> io::Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
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
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
        }
    }
    Ok(())
}

/// Write `count` zero bytes to `writer`.
pub fn write_zeros(writer: &mut dyn Write, count: u64) -> io::Result<()> {
    io::copy(&mut io::repeat(0).take(count), writer)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd as _;

    #[test]
    fn pread_exact_zero_len_is_noop() {
        // An empty buffer must return immediately without touching the fd.
        let mut buf = [0u8; 0];
        pread_exact(libc::STDIN_FILENO, &mut buf, 0).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn pread_exact_zero_fills_past_eof() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"nydus").unwrap();

        let mut buf = [0xffu8; 8];
        pread_exact(file.as_raw_fd(), &mut buf, 0).unwrap();
        assert_eq!(&buf, b"nydus\0\0\0");
    }

    #[test]
    fn pread_exact_zero_fills_past_eof_without_duplicating() {
        let mut f = tempfile::tempfile().unwrap();
        let content: Vec<u8> = (0u8..100).collect();
        f.write_all(&content).unwrap();

        // Read [80, 144) from a 100-byte file: the first pread returns only
        // 20 bytes, so the loop must advance the offset, hit EOF, and
        // zero-fill the tail — not re-read the same 20 bytes forever.
        let mut buf = [0xAAu8; 64];
        pread_exact(f.as_raw_fd(), &mut buf, 80).unwrap();
        assert_eq!(&buf[..20], &content[80..]);
        assert!(
            buf[20..].iter().all(|&b| b == 0),
            "tail past EOF must be zero-filled, not duplicated file data"
        );
    }
}
