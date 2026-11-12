use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

use nydus_format::erofs::EROFS_BLOCK_SIZE;

/// Write packed decoded chunks into the shared 4 KiB-aligned cache layout.
pub fn write_decoded_group(
    file: &std::fs::File,
    first_block: u64,
    lengths: &[u32],
    payload: &[u8],
) -> io::Result<u64> {
    let mut batch = ScatterBatch::new(file);
    let mut block = first_block;
    let mut consumed = 0usize;
    for &len in lengths {
        if len == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty chunk"));
        }
        let end = consumed
            .checked_add(len as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "group size overflow"))?;
        let chunk = payload.get(consumed..end).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "group payload is too short")
        })?;
        let offset = block
            .checked_mul(EROFS_BLOCK_SIZE as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cache offset overflow"))?;
        batch.push(offset, chunk)?;
        block = block
            .checked_add((len as u64).div_ceil(EROFS_BLOCK_SIZE as u64))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "cache size overflow"))?;
        consumed = end;
    }
    if consumed != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "group payload has trailing bytes",
        ));
    }
    batch.flush()?;
    Ok(block)
}

static ZERO_BLOCK: [u8; EROFS_BLOCK_SIZE as usize] = [0u8; EROFS_BLOCK_SIZE as usize];

/// Gathers scattered chunks into contiguous `pwritev` runs.
pub(super) struct ScatterBatch<'a> {
    file: &'a File,
    iov: Vec<libc::iovec>,
    payload: std::marker::PhantomData<&'a [u8]>,
    run_start: u64,
    run_end: u64,
    max_iov: usize,
}

impl<'a> ScatterBatch<'a> {
    pub(super) fn new(file: &'a File) -> Self {
        // SAFETY: sysconf has no preconditions; a failure returns -1.
        let iov_max = unsafe { libc::sysconf(libc::_SC_IOV_MAX) };
        Self {
            file,
            iov: Vec::new(),
            payload: std::marker::PhantomData,
            run_start: 0,
            run_end: 0,
            max_iov: usize::try_from(iov_max).unwrap_or(1024).clamp(2, 1024),
        }
    }

    pub(super) fn push(&mut self, offset: u64, bytes: &'a [u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        // Start a new run when this is the first chunk, the chunk is not
        // past the run's end (never happens for a valid layout), the gap
        // spans a whole block or the batch is full (leaving room for the
        // gap and the chunk).
        let gap = offset.saturating_sub(self.run_end);
        if self.iov.is_empty()
            || offset < self.run_end
            || gap >= EROFS_BLOCK_SIZE as u64
            || self.iov.len() + 2 > self.max_iov
        {
            self.flush()?;
            self.run_start = offset;
            self.run_end = offset;
        } else if gap > 0 {
            self.iov.push(libc::iovec {
                iov_base: ZERO_BLOCK.as_ptr() as *mut libc::c_void,
                iov_len: gap as usize,
            });
        }
        self.iov.push(libc::iovec {
            iov_base: bytes.as_ptr() as *mut libc::c_void,
            iov_len: bytes.len(),
        });
        self.run_end = offset + bytes.len() as u64;
        Ok(())
    }

    pub(super) fn flush(&mut self) -> io::Result<()> {
        let mut offset = self.run_start;
        let mut iov = std::mem::take(&mut self.iov);
        let mut first = 0usize;
        while first < iov.len() {
            // SAFETY: push borrows all payloads for 'a; every pointer remains valid until flush completes.
            let written = unsafe {
                libc::pwritev(
                    self.file.as_raw_fd(),
                    iov[first..].as_ptr(),
                    (iov.len() - first) as libc::c_int,
                    offset as libc::off_t,
                )
            };
            if written < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "cache file write returned zero",
                ));
            }
            offset += written as u64;
            let mut remaining = written as usize;
            while remaining > 0 {
                let entry = &mut iov[first];
                if remaining >= entry.iov_len {
                    remaining -= entry.iov_len;
                    first += 1;
                } else {
                    // SAFETY: remaining is smaller than this iovec's borrowed slice length.
                    entry.iov_base = unsafe { (entry.iov_base as *mut u8).add(remaining) }.cast();
                    entry.iov_len -= remaining;
                    remaining = 0;
                }
            }
        }
        iov.clear();
        self.iov = iov;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, OpenOptions};
    use tempfile::tempdir;

    #[test]
    fn decoded_group_preserves_padding_and_validates_lengths() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let payload = vec![42; 4096 + 3 + 8192];
        assert_eq!(
            write_decoded_group(&file, 1, &[4096, 3, 8192], &payload).unwrap(),
            5
        );
        let actual = fs::read(&path).unwrap();
        assert_eq!(actual.len(), 5 * 4096);
        assert!(actual[..4096].iter().all(|b| *b == 0));
        assert!(actual[4096..8195].iter().all(|b| *b == 42));
        assert!(actual[8195..12288].iter().all(|b| *b == 0));
        assert!(actual[12288..].iter().all(|b| *b == 42));
        for lengths in [vec![0], vec![4], vec![1]] {
            assert!(write_decoded_group(&file, 0, &lengths, &[1, 2, 3]).is_err());
        }
    }

    /// Scattered chunks reach their padded offsets with zero tail gaps,
    /// whole-block gaps stay unwritten, and runs split at the iovec limit.
    #[test]
    fn scatter_batch_gathers_chunks_into_contiguous_runs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cache");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let block = EROFS_BLOCK_SIZE as u64;
        // (offset, fill, len): tail gaps below a block between chunks, then a
        // two-block hole before the last chunk.
        let chunks = [
            (0, 0xa1u8, 100usize),
            (block, 0xb2, 5000),
            (3 * block, 0xc3, 40),
            (6 * block, 0xd4, 4096),
            (7 * block, 0xe5, 1),
        ];
        let data: Vec<Vec<u8>> = chunks.iter().map(|(_, b, n)| vec![*b; *n]).collect();
        let mut expected = vec![0u8; 7 * block as usize + 1];
        for ((offset, _, _), bytes) in chunks.iter().zip(&data) {
            expected[*offset as usize..*offset as usize + bytes.len()].copy_from_slice(bytes);
        }

        for max_iov in [2usize, 3, 1024] {
            file.set_len(0).unwrap();
            let mut batch = ScatterBatch::new(&file);
            batch.max_iov = max_iov;
            for ((offset, _, _), bytes) in chunks.iter().zip(&data) {
                batch.push(*offset, bytes).unwrap();
            }
            batch.flush().unwrap();
            let written = fs::read(&path).unwrap();
            assert_eq!(written, expected, "max_iov {max_iov}");
        }

        // The whole-block hole before block 6 is never written: the file is
        // sparse there (best effort, so only the content is asserted above)
        // and the run restarts at the hole's end.
        let mut batch = ScatterBatch::new(&file);
        batch.push(3 * block, &data[2]).unwrap();
        assert_eq!(batch.iov.len(), 1);
        batch.push(6 * block, &data[3]).unwrap();
        assert_eq!(batch.iov.len(), 1, "a whole-block gap starts a new run");
        assert_eq!(batch.run_start, 6 * block);
        batch.push(7 * block, &data[4]).unwrap();
        assert_eq!(batch.iov.len(), 2, "back-to-back blocks share a run");
        batch.flush().unwrap();
    }
}
