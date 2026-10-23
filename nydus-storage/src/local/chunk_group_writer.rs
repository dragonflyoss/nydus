//! The writer of a chunk group into the cache file: the chunks sit on their
//! blocks with zero padding between them, and one `pwritev` writes a run of
//! them at once.

use std::fs::File;
use std::io;
use std::marker::PhantomData;
use std::os::fd::AsRawFd;

use nydus_format::erofs::EROFS_BLOCK_SIZE;

/// The most buffers one `pwritev` gathers, the kernel's `IOV_MAX`.
const MAX_WRITE_IOVECS: usize = 1024;

/// A block of zeros, the gap filler between the chunks of a `pwritev` run.
static ZERO_BLOCK: [u8; EROFS_BLOCK_SIZE as usize] = [0u8; EROFS_BLOCK_SIZE as usize];

/// The writer of a chunk group's chunks into the cache file, gathering the
/// consecutive ones into one `pwritev` each.
pub(super) struct ChunkGroupWriter<'a> {
    /// The cache file.
    file: &'a File,

    /// The gathered buffers of the pending run.
    iov: Vec<libc::iovec>,

    /// The borrow of every queued chunk, which the iovecs point into.
    chunks: PhantomData<&'a [u8]>,

    /// The offset the pending run starts at.
    run_start: u64,

    /// The offset the pending run ends at.
    run_end: u64,

    /// The most buffers one `pwritev` gathers.
    max_iov: usize,
}

/// Implements the chunk group writer.
impl<'a> ChunkGroupWriter<'a> {
    /// Creates a writer into `file` with nothing pending.
    pub(super) fn new(file: &'a File) -> Self {
        // SAFETY: sysconf has no preconditions; a failure returns -1.
        let iov_max = unsafe { libc::sysconf(libc::_SC_IOV_MAX) };
        Self {
            file,
            iov: Vec::new(),
            chunks: PhantomData,
            run_start: 0,
            run_end: 0,
            max_iov: usize::try_from(iov_max)
                .unwrap_or(MAX_WRITE_IOVECS)
                .clamp(2, MAX_WRITE_IOVECS),
        }
    }

    /// Queues the chunk `bytes` at `offset` for the pending run, flushing
    /// the run first when the chunk does not extend it: it is the first
    /// chunk, lies before the run's end, which never happens for a valid
    /// layout, follows a gap of a whole block, or the run has no room left
    /// for the gap and the chunk.
    pub(super) fn write_at(&mut self, offset: u64, bytes: &'a [u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }

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

    /// Writes the pending run, retrying a short write from where it stopped.
    pub(super) fn flush(&mut self) -> io::Result<()> {
        let mut offset = self.run_start;
        let mut iov = std::mem::take(&mut self.iov);
        let mut first = 0usize;
        while first < iov.len() {
            // SAFETY: `write_at` borrows every chunk for 'a, so every pointer
            // stays valid until the flush completes.
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
                    // SAFETY: `remaining` is smaller than the length of the
                    // slice this iovec borrows.
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
    fn write_at_gathers_chunks_into_contiguous_runs() {
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
            let mut writer = ChunkGroupWriter::new(&file);
            writer.max_iov = max_iov;
            for ((offset, _, _), bytes) in chunks.iter().zip(&data) {
                writer.write_at(*offset, bytes).unwrap();
            }
            writer.flush().unwrap();
            let written = fs::read(&path).unwrap();
            assert_eq!(written, expected, "max_iov {max_iov}");
        }

        let mut writer = ChunkGroupWriter::new(&file);
        writer.write_at(3 * block, &data[2]).unwrap();
        assert_eq!(writer.iov.len(), 1);
        writer.write_at(6 * block, &data[3]).unwrap();
        assert_eq!(writer.iov.len(), 1);
        assert_eq!(writer.run_start, 6 * block);
        writer.write_at(7 * block, &data[4]).unwrap();
        assert_eq!(writer.iov.len(), 2);
        writer.flush().unwrap();
    }
}
