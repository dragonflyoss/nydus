//! The buffers a fetch fills: the encoded bytes of a window and the decode
//! scratch, large ones as anonymous mappings handed back to the kernel with
//! the job.

use std::io;

/// The fetch buffers of one job: the encoded bytes of a window and the
/// decode scratch, released with the job so the large mappings go back to
/// the kernel.
#[derive(Default)]
pub(crate) struct ChunkGroupBuffers {
    /// The encoded bytes of the fetched window.
    encoded: ChunkGroupBuffer,

    /// The decode scratch, the size of the largest chunk group.
    decoded: ChunkGroupBuffer,
}

/// Implements the fetch buffers.
impl ChunkGroupBuffers {
    /// Returns both buffers sized to `encoded_len` and `decoded_len`,
    /// borrowed together so a caller decodes from one into the other.
    pub(crate) fn resize(
        &mut self,
        encoded_len: usize,
        decoded_len: usize,
    ) -> io::Result<(&mut [u8], &mut [u8])> {
        let encoded = self.encoded.resize(encoded_len)?;
        let decoded = self.decoded.resize(decoded_len)?;
        Ok((encoded, decoded))
    }
}

/// A transient buffer that bypasses the heap arenas for large sizes, as an
/// anonymous mapping advised onto huge pages on Linux.
#[derive(Default)]
pub(crate) struct ChunkGroupBuffer {
    /// The heap buffer of a small size.
    heap: Vec<u8>,

    /// The anonymous mapping of a large size.
    mapping: Option<memmap2::MmapMut>,

    /// The size of the last [`resize`](Self::resize).
    len: usize,
}

/// Implements the chunk group buffer.
impl ChunkGroupBuffer {
    /// The size from which the buffer is an anonymous mapping rather than a
    /// heap allocation.
    const MAPPING_MIN_SIZE: usize = 1024 * 1024;

    /// The size from which the mapping is advised onto huge pages.
    const HUGE_PAGE_SIZE: usize = 2 * 1024 * 1024;

    /// Returns the buffer resized to `len`, a mapping reused when it is
    /// large enough.
    pub(crate) fn resize(&mut self, len: usize) -> io::Result<&mut [u8]> {
        self.len = len;
        if len < Self::MAPPING_MIN_SIZE {
            self.mapping = None;
            self.heap.resize(len, 0);
            return Ok(&mut self.heap);
        }

        if self
            .mapping
            .as_ref()
            .is_none_or(|mapping| mapping.len() < len)
        {
            let mapping = memmap2::MmapMut::map_anon(len)?;
            #[cfg(target_os = "linux")]
            if len >= Self::HUGE_PAGE_SIZE {
                if let Err(err) = mapping.advise(memmap2::Advice::HugePage) {
                    tracing::debug!("failed to advise huge pages for a fetch buffer: {}", err);
                }
            }
            self.mapping = Some(mapping);
        }

        self.heap = Vec::new();
        Ok(&mut self.mapping.as_mut().expect("mapping allocated above")[..len])
    }

    /// Returns the size of the last [`resize`](Self::resize).
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Returns the bytes, as many as the last [`resize`](Self::resize).
    pub(crate) fn bytes(&self) -> &[u8] {
        match &self.mapping {
            Some(mapping) => &mapping[..self.len],
            None => &self.heap,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_group_buffer_reuses_and_releases_large_mappings() {
        let mut buffer = ChunkGroupBuffer::default();
        assert!(buffer.resize(0).unwrap().is_empty());
        buffer.resize(4096).unwrap().fill(1);
        assert!(buffer.mapping.is_none());
        let large = buffer.resize(2 * 1024 * 1024).unwrap();
        assert!(large.iter().all(|byte| *byte == 0));
        large.fill(2);
        let address = large.as_ptr();
        let smaller = buffer.resize(1024 * 1024).unwrap();
        assert_eq!(smaller.as_ptr(), address);
        assert!(smaller.iter().all(|byte| *byte == 2));
        assert_eq!(buffer.heap.capacity(), 0);
        assert_eq!(
            buffer.resize(3 * 1024 * 1024).unwrap().len(),
            3 * 1024 * 1024
        );
        assert_eq!(buffer.resize(4096).unwrap(), &[0; 4096]);
        assert!(buffer.mapping.is_none());
        assert_eq!(buffer.len(), 4096);
        assert_eq!(buffer.bytes(), &[0; 4096]);
    }

    #[test]
    fn chunk_group_buffer_preserves_contents_around_the_huge_page_size() {
        let test_cases = vec![
            2 * 1024 * 1024 - 1,
            2 * 1024 * 1024,
            2 * 1024 * 1024 + 1,
            4 * 1024 * 1024,
        ];

        let mut buffer = ChunkGroupBuffer::default();
        for len in test_cases {
            let bytes = buffer.resize(len).unwrap();
            assert!(bytes.iter().all(|byte| *byte == 0));
            bytes.fill(0xa5);
            let address = bytes.as_ptr();
            let bytes = buffer.resize(len).unwrap();
            assert_eq!(bytes.as_ptr(), address);
            assert!(bytes.iter().all(|byte| *byte == 0xa5));
            buffer.resize(0).unwrap();
            assert!(buffer.mapping.is_none());
        }
    }
}
