use crc32c::crc32c;
use nydus_error::{Context, Error, Result};
use nydus_format::blob::{
    BlobMetadata, BlobMetadataBlockGroup, BlobMetadataChunk, BlobMetadataCompressor,
    BlobMetadataDigester, DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE,
};
use nydus_format::erofs::{
    ErofsChunkAddr, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE, EROFS_NULL_ADDR,
    Z_EROFS_FRAGMENT_INODE_FLAG,
};
use nydus_format::utils::align_up_usize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::mem;
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// Manages writing chunk data to a separate blob device. Chunk bytes
/// (tail-block padding included) stream straight into block groups, so the
/// group stream equals the logical space and blob meta carries only the
/// block group table.
pub struct BlobWriter<W> {
    writer: W,
    file_chunk_size: u32,
    block_group_size: u32,
    compressor: BlobMetadataCompressor,
    digester: BlobMetadataDigester,
    next_blkaddr: u64,
    next_compressed_offset: u64,
    // `None` when the caller names the blob itself (`--blob-id`), so no
    // sha256 pass over the data region is needed.
    data_hasher: Option<Sha256>,
    block_group_block_offset: u64,
    block_group_buffer: Vec<u8>,
    blob_metadata_chunks: Vec<BlobMetadataChunk>,
    blob_metadata_block_groups: Vec<BlobMetadataBlockGroup>,
    // Reused per-file read buffer: a fresh 1 MiB Vec per file costs an
    // mmap/munmap plus page faults for every source file.
    chunk_buf: Vec<u8>,
    // Lazily started background crc32+zstd pipeline for block groups.
    encoder: Option<BlockGroupEncoder>,
    // z_erofs mode only: when non-zero, files of at least
    // `data_alignment_threshold` bytes start on a `data_alignment`-byte
    // boundary of the device data, so fixed-offset block dedup (e.g. cloud
    // disks chunking volumes at a fixed granularity) sees identical blocks
    // for identical files regardless of their neighbours. The gap is
    // zero-filled and no pcluster references it.
    data_alignment: u32,
    data_alignment_threshold: u64,
    // z_erofs LZ4 mode: when non-zero, regular-file data is compressed into
    // pclusters of at most this many bytes and written straight to `writer`,
    // addressed from `z_next_blkaddr` in the final (single-device) image.
    // `z_base_blkaddr` is where the device starts in that space, so
    // `z_next_blkaddr - z_base_blkaddr` is the offset within the device data.
    zlz4_pcluster: u32,
    z_base_blkaddr: u64,
    z_next_blkaddr: u64,
    z_win_buf: Vec<u8>,
    z_dst_buf: Vec<u8>,
    // z_erofs fragments: regular files of at most `z_frag_threshold` bytes are
    // appended to one packed stream, compressed as its window fills, instead
    // of getting their own pclusters; `finish_zlz4_packed` flushes it as the
    // packed inode, so neighbouring small files share pclusters and one read
    // serves many of them. Zero disables fragments.
    z_frag_threshold: u64,
    z_packed: Option<ZPackedStream>,
}

/// The packed inode under construction: a resumable compressor plus its own
/// source window, so small files are compressed as they arrive.
struct ZPackedStream {
    stream: ZStream,
    win: Vec<u8>,
    size: u64,
}

/// Resumable z_erofs LZ4 compression state of one inode: the growing inode
/// tail (map header + full lcluster indexes), the compressed block count and
/// the `start..filled` span of the caller's window buffer still awaiting a
/// pcluster. Consumed bytes advance `start`; the buffer is compacted only
/// when the free space in front grows to half of it, so compaction costs at
/// most one memmove per byte of input while every pcluster still sees at
/// least [`ZLZ4_SRC_WINDOW`] bytes of look-ahead.
struct ZStream {
    tail: Vec<u8>,
    compressed_blocks: u64,
    start: usize,
    filled: usize,
}

impl ZStream {
    fn new() -> Self {
        use nydus_format::erofs::{Z_EROFS_ADVISE_BIG_PCLUSTER_1, Z_EROFS_MAP_HEADER_SIZE};
        // Map header: h_advise = BIG_PCLUSTER_1, algorithm 0 (lz4),
        // lclusterbits == blkszbits. Followed by 8 reserved bytes: full
        // lcluster indexes start at ALIGN(end, 8) + 16 (legacy layout).
        let mut tail = Vec::with_capacity(Z_EROFS_MAP_HEADER_SIZE + 8 + 64);
        tail.extend_from_slice(&[0u8; 4]);
        tail.extend_from_slice(&Z_EROFS_ADVISE_BIG_PCLUSTER_1.to_le_bytes());
        tail.push(0);
        tail.push(0);
        tail.extend_from_slice(&[0u8; 8]);
        Self {
            tail,
            compressed_blocks: 0,
            start: 0,
            filled: 0,
        }
    }

    fn pending(&self) -> usize {
        self.filled - self.start
    }

    fn into_meta(self) -> Result<ZFileMeta> {
        let compressed_blocks = u32::try_from(self.compressed_blocks).map_err(|err| {
            Error::Overflow(format!("z_erofs compressed block count exceeds u32: {err}"))
        })?;
        Ok(ZFileMeta {
            tail: self.tail,
            compressed_blocks,
        })
    }
}

/// Minimum source look-ahead for the destSize greedy packer: one pcluster
/// may consume far more logical data than its physical size when data is
/// highly compressible, so the window must be much larger than the pcluster.
const ZLZ4_SRC_WINDOW: usize = 1 << 20;

/// Size of a window buffer: twice the look-ahead, so the front half can fill
/// with consumed bytes before one compaction restores a full look-ahead.
const ZLZ4_WIN_BUF: usize = 2 * ZLZ4_SRC_WINDOW;

/// Greedily compress as much of `src` as fits in `dst` (liblz4
/// `LZ4_compress_destSize`). Returns (consumed source bytes, produced output
/// bytes); (0, 0) when not even the first byte fits.
fn lz4_compress_dest_size(src: &[u8], dst: &mut [u8]) -> (usize, usize) {
    use std::os::raw::{c_char, c_int};
    extern "C" {
        // In the liblz4 static library that lz4-sys links but missing from
        // its Rust bindings.
        fn LZ4_compress_destSize(
            src: *const c_char,
            dst: *mut c_char,
            src_size: *mut c_int,
            target_dst_size: c_int,
        ) -> c_int;
    }
    let mut src_size = src.len().min(i32::MAX as usize) as c_int;
    // SAFETY: both pointers reference live slices of the given sizes;
    // LZ4_compress_destSize writes at most `dst.len()` bytes and updates
    // `src_size` to the number of source bytes consumed.
    let written = unsafe {
        LZ4_compress_destSize(
            src.as_ptr() as *const c_char,
            dst.as_mut_ptr() as *mut c_char,
            &mut src_size,
            dst.len() as c_int,
        )
    };
    if written <= 0 {
        (0, 0)
    } else {
        (src_size as usize, written as usize)
    }
}

/// Compress all of `src` into `dst` (liblz4 `LZ4_compress_default`), returning
/// the output size or `None` when it does not fit.
fn lz4_compress(src: &[u8], dst: &mut [u8]) -> Option<usize> {
    use std::os::raw::{c_char, c_int};
    let src_size = c_int::try_from(src.len()).ok()?;
    let dst_size = c_int::try_from(dst.len()).ok()?;
    // SAFETY: both pointers reference live slices of the given sizes and
    // LZ4_compress_default writes at most `dst_size` bytes.
    let written = unsafe {
        lz4_sys::LZ4_compress_default(
            src.as_ptr() as *const c_char,
            dst.as_mut_ptr() as *mut c_char,
            src_size,
            dst_size,
        )
    };
    (written > 0).then_some(written as usize)
}

/// Worst-case LZ4 block output size for `len` input bytes.
fn lz4_compress_bound(len: usize) -> usize {
    // SAFETY: pure arithmetic on the argument.
    unsafe { lz4_sys::LZ4_compressBound(len as std::os::raw::c_int) as usize }
}

/// Per-file z_erofs metadata produced by [`BlobWriter::write_reader_zlz4`]:
/// the inode tail (map header plus full lcluster indexes) and the file's
/// compressed block count for the inode `i_u` field.
pub struct ZFileMeta {
    pub tail: Vec<u8>,
    pub compressed_blocks: u32,
}

const MAX_COMPRESSED_SIZE_PERCENT: u128 = 70;

/// One block of zeros for hashing and storing tail-block padding without
/// allocating; padding never exceeds a single EROFS block.
const ZERO_BLOCK: [u8; EROFS_BLOCK_SIZE as usize] = [0u8; EROFS_BLOCK_SIZE as usize];

/// Number of background block-group encoder threads. Encoding (crc32 + zstd)
/// runs well ahead of the single-threaded produce side, so two workers fully
/// hide it; more would only grow the in-flight memory.
const ENCODE_WORKERS: usize = 2;
/// Maximum encode jobs in flight before the producer drains one; bounds the
/// extra peak memory to a couple of block groups (in + encoded out each).
const ENCODE_MAX_IN_FLIGHT: usize = 2;

struct EncodeJob {
    seq: u64,
    data: Vec<u8>,
}

struct EncodedBlockGroup {
    data: Vec<u8>,
    crc32: u32,
    /// `Some` when compression met the format's worthwhile threshold.
    compressed: Option<Vec<u8>>,
}

/// Offloads per-block-group crc32 + zstd to background threads while the
/// caller keeps producing. Results are drained strictly in submission order
/// so the written stream and metadata tables stay deterministic; input
/// buffers circulate back for reuse.
struct BlockGroupEncoder {
    tx: Option<mpsc::Sender<EncodeJob>>,
    encoded_rx: mpsc::Receiver<(u64, EncodedBlockGroup)>,
    pending: BTreeMap<u64, EncodedBlockGroup>,
    next_seq_in: u64,
    next_seq_out: u64,
    free_buffers: Vec<Vec<u8>>,
    workers: Vec<JoinHandle<()>>,
}

impl BlockGroupEncoder {
    fn new(compressor: BlobMetadataCompressor) -> Self {
        let (tx, rx) = mpsc::channel::<EncodeJob>();
        let (encoded_tx, encoded_rx) = mpsc::channel();
        let rx = Arc::new(Mutex::new(rx));
        let workers = (0..ENCODE_WORKERS)
            .map(|_| {
                let rx = Arc::clone(&rx);
                let encoded_tx = encoded_tx.clone();
                std::thread::spawn(move || loop {
                    let job = match rx.lock().unwrap_or_else(|p| p.into_inner()).recv() {
                        Ok(job) => job,
                        Err(_) => break,
                    };
                    let crc32 = crc32c(&job.data);
                    let compressed = match compressor {
                        BlobMetadataCompressor::None => None,
                        BlobMetadataCompressor::Zstd => zstd::bulk::compress(&job.data, 0)
                            .ok()
                            .filter(|c| compression_is_worthwhile(c.len(), job.data.len())),
                        BlobMetadataCompressor::Lz4Block => {
                            let compressed = lz4_flex::block::compress(&job.data);
                            compression_is_worthwhile(compressed.len(), job.data.len())
                                .then_some(compressed)
                        }
                    };
                    let encoded = EncodedBlockGroup {
                        data: job.data,
                        crc32,
                        compressed,
                    };
                    if encoded_tx.send((job.seq, encoded)).is_err() {
                        break;
                    }
                })
            })
            .collect();
        Self {
            tx: Some(tx),
            encoded_rx,
            pending: BTreeMap::new(),
            next_seq_in: 0,
            next_seq_out: 0,
            free_buffers: Vec::new(),
            workers,
        }
    }

    fn submit(&mut self, data: Vec<u8>) -> Result<()> {
        let job = EncodeJob {
            seq: self.next_seq_in,
            data,
        };
        self.next_seq_in += 1;
        self.tx
            .as_ref()
            .expect("encoder is alive until finish")
            .send(job)
            .map_err(|_| Error::Runtime("block group encoder threads exited early".to_string()))
    }

    fn in_flight(&self) -> usize {
        (self.next_seq_in - self.next_seq_out) as usize
    }

    /// Receive the next completed group in submission order.
    fn recv_next(&mut self) -> Result<EncodedBlockGroup> {
        loop {
            if let Some(encoded) = self.pending.remove(&self.next_seq_out) {
                self.next_seq_out += 1;
                return Ok(encoded);
            }
            let (seq, encoded) = self.encoded_rx.recv().map_err(|_| {
                Error::Runtime("block group encoder threads exited early".to_string())
            })?;
            self.pending.insert(seq, encoded);
        }
    }

    fn take_buffer(&mut self) -> Option<Vec<u8>> {
        self.free_buffers.pop()
    }

    fn recycle_buffer(&mut self, mut buf: Vec<u8>) {
        if self.free_buffers.len() < ENCODE_MAX_IN_FLIGHT {
            buf.clear();
            self.free_buffers.push(buf);
        }
    }
}

impl Drop for BlockGroupEncoder {
    fn drop(&mut self) {
        self.tx.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

impl BlobWriter<File> {
    pub fn new(path: &Path, chunk_size: u32) -> Result<Self> {
        Self::new_with_compressor(path, chunk_size, BlobMetadataCompressor::None)
    }

    pub fn new_with_compressor(
        path: &Path,
        file_chunk_size: u32,
        compressor: BlobMetadataCompressor,
    ) -> Result<Self> {
        if file_chunk_size < EROFS_BLOCK_SIZE {
            return Err(Error::InvalidParameter(
                "blob writer file chunk size must be at least one EROFS block".to_string(),
            ));
        }
        if !file_chunk_size.is_power_of_two() || file_chunk_size % EROFS_BLOCK_SIZE != 0 {
            return Err(Error::InvalidParameter(
                "blob writer file chunk size must be power-of-two and block-aligned".to_string(),
            ));
        }

        let file = File::create(path)
            .with_context(|| format!("failed to create blob device: {}", path.display()))?;
        let block_group_size = file_chunk_size.max(DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE);
        Self::from_writer(file, file_chunk_size, block_group_size, compressor)
    }
}

impl<W: Write> BlobWriter<W> {
    pub fn from_writer(
        writer: W,
        file_chunk_size: u32,
        block_group_size: u32,
        compressor: BlobMetadataCompressor,
    ) -> Result<Self> {
        if file_chunk_size < EROFS_BLOCK_SIZE {
            return Err(Error::InvalidParameter(
                "blob writer file chunk size must be at least one EROFS block".to_string(),
            ));
        }
        if !file_chunk_size.is_power_of_two() || file_chunk_size % EROFS_BLOCK_SIZE != 0 {
            return Err(Error::InvalidParameter(
                "blob writer file chunk size must be power-of-two and block-aligned".to_string(),
            ));
        }
        if block_group_size < file_chunk_size {
            return Err(Error::InvalidParameter(
                "blob writer block_group size must be at least the file chunk size".to_string(),
            ));
        }
        // The blob meta header stores the block group's block count as a log2
        // exponent (`block_group_block_count_bits`), so it must be a power of
        // two; being a power of two >= the (block-aligned) chunk size also
        // makes it block aligned by construction.
        if !block_group_size.is_power_of_two() {
            return Err(Error::InvalidParameter(
                "blob writer block_group size must be a power of two".to_string(),
            ));
        }

        Ok(Self {
            writer,
            file_chunk_size,
            block_group_size,
            compressor,
            digester: BlobMetadataDigester::Blake3,
            next_blkaddr: 0,
            next_compressed_offset: 0,
            data_hasher: Some(Sha256::new()),
            block_group_block_offset: 0,
            block_group_buffer: Vec::with_capacity(block_group_size as usize),
            blob_metadata_chunks: Vec::new(),
            blob_metadata_block_groups: Vec::new(),
            chunk_buf: vec![0u8; file_chunk_size as usize],
            encoder: None,
            data_alignment: 0,
            data_alignment_threshold: 0,
            zlz4_pcluster: 0,
            z_base_blkaddr: 0,
            z_next_blkaddr: 0,
            z_win_buf: Vec::new(),
            z_dst_buf: Vec::new(),
            z_frag_threshold: 0,
            z_packed: None,
        })
    }

    /// Selects the chunk digest algorithm recorded in the blob meta;
    /// `None` writes zero digests and skips hashing.
    pub fn set_digester(&mut self, digester: BlobMetadataDigester) {
        self.digester = digester;
    }

    /// Stops hashing the data region. Only valid when the caller supplies
    /// the blob id, since [`Self::data_digest`] then returns `None`.
    pub fn disable_data_digest(&mut self) {
        self.data_hasher = None;
    }

    /// Enables aligned placement in z_erofs mode: files of at least
    /// `threshold` bytes start on an `alignment`-byte boundary of the device
    /// data. `alignment` must be a power of two and block-aligned; zero
    /// disables alignment.
    pub fn set_data_alignment(&mut self, alignment: u32, threshold: u64) -> Result<()> {
        if alignment != 0 && (!alignment.is_power_of_two() || alignment % EROFS_BLOCK_SIZE != 0) {
            return Err(Error::InvalidParameter(
                "data alignment must be a power of two and block-aligned".to_string(),
            ));
        }
        self.data_alignment = alignment;
        self.data_alignment_threshold = threshold;
        Ok(())
    }

    pub fn total_blocks(&self) -> u64 {
        self.next_blkaddr
    }

    /// Enables z_erofs LZ4 mode: file data is compressed into pclusters of
    /// at most `pcluster` bytes (a power-of-two multiple of the block size)
    /// and addressed from `blkaddr_base` in the final single-device image.
    pub fn set_zlz4(&mut self, pcluster: u32, blkaddr_base: u64) -> Result<()> {
        if !pcluster.is_power_of_two() || pcluster % EROFS_BLOCK_SIZE != 0 {
            return Err(Error::InvalidParameter(
                "z_erofs pcluster size must be a power of two and block-aligned".to_string(),
            ));
        }
        self.zlz4_pcluster = pcluster;
        self.z_base_blkaddr = blkaddr_base;
        self.z_next_blkaddr = blkaddr_base;
        self.z_win_buf = vec![0u8; ZLZ4_WIN_BUF];
        self.z_dst_buf = vec![0u8; lz4_compress_bound(ZLZ4_WIN_BUF)];
        Ok(())
    }

    pub fn zlz4_enabled(&self) -> bool {
        self.zlz4_pcluster != 0
    }

    /// Enables z_erofs fragments (kernel 6.1+): regular files of at most
    /// `threshold` bytes are packed together and compressed as one packed
    /// inode, finished by [`Self::finish_zlz4_packed`]. Requires z_erofs
    /// mode; zero disables fragments.
    pub fn set_zlz4_fragments(&mut self, threshold: u64) -> Result<()> {
        if threshold == 0 {
            self.z_frag_threshold = 0;
            self.z_packed = None;
            return Ok(());
        }
        if !self.zlz4_enabled() {
            return Err(Error::InvalidParameter(
                "z_erofs fragments require z_erofs LZ4 mode".to_string(),
            ));
        }
        self.z_frag_threshold = threshold;
        self.z_packed = Some(ZPackedStream {
            stream: ZStream::new(),
            win: vec![0u8; ZLZ4_WIN_BUF],
            size: 0,
        });
        Ok(())
    }

    /// Appends a small file to the packed stream (compressing whatever full
    /// windows result) and returns its inode tail: just the 8-byte fragment
    /// header (offset | flag), no lcluster indexes.
    fn write_reader_fragment(
        &mut self,
        reader: &mut dyn Read,
        file_size: u64,
    ) -> Result<ZFileMeta> {
        let mut packed = self
            .z_packed
            .take()
            .expect("fragments enabled implies a packed stream");
        let offset = packed.size;
        let result = if offset & Z_EROFS_FRAGMENT_INODE_FLAG != 0 {
            Err(Error::Overflow(
                "fragment offset exceeds 63 bits".to_string(),
            ))
        } else {
            self.z_feed(&mut packed.stream, &mut packed.win, reader, file_size)
        };
        packed.size += file_size;
        self.z_packed = Some(packed);
        result?;
        Ok(ZFileMeta {
            tail: (offset | Z_EROFS_FRAGMENT_INODE_FLAG)
                .to_le_bytes()
                .to_vec(),
            compressed_blocks: 0,
        })
    }

    /// Flushes the packed inode's last pclusters and returns its metadata plus
    /// uncompressed size, or `None` when no file was packed. Must be called
    /// once, after all files were written. The stream is zero-padded to a
    /// whole number of blocks first so `merge` can concatenate the packed
    /// inodes of several layers on the lcluster grid.
    pub fn finish_zlz4_packed(&mut self) -> Result<Option<(ZFileMeta, u64)>> {
        let Some(mut packed) = self.z_packed.take() else {
            return Ok(None);
        };
        self.z_frag_threshold = 0;
        if packed.size == 0 {
            return Ok(None);
        }
        let padding = packed.size.next_multiple_of(EROFS_BLOCK_SIZE as u64) - packed.size;
        if padding > 0 {
            self.z_feed(
                &mut packed.stream,
                &mut packed.win,
                &mut std::io::repeat(0),
                padding,
            )?;
            packed.size += padding;
        }
        self.z_flush(&mut packed.stream, &mut packed.win)?;
        Ok(Some((packed.stream.into_meta()?, packed.size)))
    }

    /// End of the compressed data region (absolute block address).
    pub fn z_end_blkaddr(&self) -> u64 {
        self.z_next_blkaddr
    }

    /// [`Self::write_reader_zlz4`] for a file on disk.
    pub fn write_file_zlz4(&mut self, path: &Path, file_size: u64) -> Result<ZFileMeta> {
        let mut f = File::open(path)
            .with_context(|| format!("failed to open source file: {}", path.display()))?;
        self.write_reader_zlz4(&mut f, file_size)
            .with_context(|| format!("failed to compress source file: {}", path.display()))
    }

    /// Compresses exactly `file_size` bytes from `reader` into z_erofs LZ4
    /// pclusters written straight to the output (see [`Self::z_emit`]), and
    /// returns the inode tail (map header + full lcluster indexes) plus the
    /// compressed block count. Files up to the fragment threshold are packed
    /// instead (see [`Self::write_reader_fragment`]).
    pub fn write_reader_zlz4(
        &mut self,
        reader: &mut dyn Read,
        file_size: u64,
    ) -> Result<ZFileMeta> {
        if self.z_frag_threshold != 0 && file_size > 0 && file_size <= self.z_frag_threshold {
            return self.write_reader_fragment(reader, file_size);
        }

        let block_size = EROFS_BLOCK_SIZE as usize;
        // Aligned placement (dedup phase): pad the compressed stream with zero
        // blocks so large files start on a `data_alignment` boundary of the
        // device data (not of the image: the device is its own file on the
        // volume, and merge may map it anywhere), keeping their pclusters on
        // the volume dedup grid.
        if self.data_alignment != 0 && file_size >= self.data_alignment_threshold {
            let alignment_blocks = (self.data_alignment / EROFS_BLOCK_SIZE) as u64;
            let offset = self.z_next_blkaddr - self.z_base_blkaddr;
            let gap = offset.next_multiple_of(alignment_blocks) - offset;
            if gap > 0 {
                self.write_z_padding(gap as usize * block_size)?;
                self.z_next_blkaddr += gap;
            }
        }
        let mut stream = ZStream::new();
        let mut win_buf = mem::take(&mut self.z_win_buf);
        let result = self
            .z_feed(&mut stream, &mut win_buf, reader, file_size)
            .and_then(|()| self.z_flush(&mut stream, &mut win_buf));
        self.z_win_buf = win_buf;
        result?;
        stream.into_meta()
    }

    /// Reads `len` source bytes into the stream's window. When the buffer is
    /// full, the consumed front half is compacted away if it has grown that
    /// far, else a pcluster is emitted (with at least [`ZLZ4_SRC_WINDOW`]
    /// bytes of look-ahead). Bytes left in the window await more input or
    /// [`Self::z_flush`].
    fn z_feed(
        &mut self,
        st: &mut ZStream,
        win_buf: &mut [u8],
        reader: &mut dyn Read,
        mut len: u64,
    ) -> Result<()> {
        while len > 0 {
            if st.filled == ZLZ4_WIN_BUF {
                if st.start >= ZLZ4_SRC_WINDOW {
                    win_buf.copy_within(st.start..st.filled, 0);
                    st.filled -= st.start;
                    st.start = 0;
                } else {
                    self.z_emit(st, win_buf, false)?;
                    continue;
                }
            }
            let want = (ZLZ4_WIN_BUF - st.filled).min(len as usize);
            reader
                .read_exact(&mut win_buf[st.filled..st.filled + want])
                .context("failed to read source data")?;
            st.filled += want;
            len -= want as u64;
        }
        Ok(())
    }

    /// Emits pclusters for everything left in the window (end of the inode)
    /// and resets the window.
    fn z_flush(&mut self, st: &mut ZStream, win_buf: &mut [u8]) -> Result<()> {
        while st.pending() > 0 {
            self.z_emit(st, win_buf, true)?;
        }
        st.start = 0;
        st.filled = 0;
        Ok(())
    }

    /// Emits one pcluster from the front of the pending window. Pclusters
    /// are packed greedily: `LZ4_compress_destSize` consumes as much source
    /// as compresses into one pcluster, the consumed size is rounded down to
    /// the lcluster boundary and re-compressed so every pcluster starts on an
    /// lcluster (clusterofs 0); at `at_eof` the final partial lcluster is
    /// taken whole. Windows that cannot save a block are stored as
    /// per-lcluster PLAIN. Compressed payloads are tail-aligned in their
    /// pcluster (ZERO_PADDING).
    fn z_emit(&mut self, st: &mut ZStream, win_buf: &mut [u8], at_eof: bool) -> Result<()> {
        use nydus_format::erofs::{
            Z_EROFS_LCLUSTER_TYPE_HEAD1, Z_EROFS_LCLUSTER_TYPE_NONHEAD,
            Z_EROFS_LCLUSTER_TYPE_PLAIN, Z_EROFS_LI_D0_CBLKCNT,
        };
        let block_size = EROFS_BLOCK_SIZE as usize;
        let pcluster = self.zlz4_pcluster as usize;
        let pending = &win_buf[st.start..st.filled];
        // Greedy pass: how much source fits into one pcluster.
        let (consumed, greedy_len) =
            lz4_compress_dest_size(pending, &mut self.z_dst_buf[..pcluster]);

        // Take a whole number of lclusters, except at the file tail.
        let (take, compressed_len) = if at_eof && consumed == pending.len() {
            (consumed, greedy_len)
        } else {
            let mut take = consumed / block_size * block_size;
            if take == 0 {
                // Incompressible head: fall back to one raw lcluster.
                (pending.len().min(block_size), usize::MAX)
            } else {
                // Re-compress the aligned prefix so the pcluster still
                // starts on an lcluster boundary (clusterofs stays 0).
                // Rarely it compresses worse than the greedy pass; shrink
                // until it fits the pcluster, else store it raw.
                loop {
                    match lz4_compress(&pending[..take], &mut self.z_dst_buf) {
                        Some(len) if len <= pcluster => break (take, len),
                        _ if take > block_size => take -= block_size,
                        _ => break (take, usize::MAX),
                    }
                }
            }
        };

        let lclusters = take.div_ceil(block_size);
        let compressed_pblks = if compressed_len == usize::MAX {
            usize::MAX
        } else {
            compressed_len.div_ceil(block_size)
        };
        let (head_type, phys_blocks) = if compressed_pblks < lclusters {
            (Z_EROFS_LCLUSTER_TYPE_HEAD1, compressed_pblks)
        } else {
            (Z_EROFS_LCLUSTER_TYPE_PLAIN, lclusters)
        };

        let blkaddr = u32::try_from(self.z_next_blkaddr).map_err(|err| {
            Error::Overflow(format!("z_erofs pcluster address exceeds u32: {err}"))
        })?;
        let cblkcnt = u16::try_from(phys_blocks)
            .ok()
            .filter(|&blocks| blocks < Z_EROFS_LI_D0_CBLKCNT)
            .ok_or_else(|| {
                Error::Overflow("z_erofs pcluster block count exceeds CBLKCNT".to_string())
            })?;

        // Lcluster indexes for this pcluster. An incompressible window
        // becomes per-lcluster single-block PLAIN pclusters (the layout
        // mkfs.erofs emits); multi-block raw pclusters are avoided.
        if head_type == Z_EROFS_LCLUSTER_TYPE_PLAIN {
            for i in 0..lclusters {
                st.tail
                    .extend_from_slice(&Z_EROFS_LCLUSTER_TYPE_PLAIN.to_le_bytes());
                st.tail.extend_from_slice(&0u16.to_le_bytes());
                st.tail
                    .extend_from_slice(&(blkaddr + i as u32).to_le_bytes());
            }
        } else {
            for i in 0..lclusters {
                if i == 0 {
                    st.tail.extend_from_slice(&head_type.to_le_bytes());
                    st.tail.extend_from_slice(&0u16.to_le_bytes()); // clusterofs
                    st.tail.extend_from_slice(&blkaddr.to_le_bytes());
                } else {
                    let delta0 = if i == 1 {
                        Z_EROFS_LI_D0_CBLKCNT | cblkcnt
                    } else {
                        i as u16
                    };
                    let delta1 = (lclusters - 1 - i) as u16;
                    st.tail
                        .extend_from_slice(&Z_EROFS_LCLUSTER_TYPE_NONHEAD.to_le_bytes());
                    st.tail.extend_from_slice(&0u16.to_le_bytes());
                    st.tail.extend_from_slice(&delta0.to_le_bytes());
                    st.tail.extend_from_slice(&delta1.to_le_bytes());
                }
            }
        }

        // Pcluster payload: compressed data tail-aligned (ZERO_PADDING),
        // raw data head-aligned with tail-block zero padding.
        if head_type == Z_EROFS_LCLUSTER_TYPE_HEAD1 {
            self.write_z_padding(phys_blocks * block_size - compressed_len)?;
            self.writer
                .write_all(&self.z_dst_buf[..compressed_len])
                .context("failed to write z_erofs pcluster")?;
        } else {
            self.writer
                .write_all(&win_buf[st.start..st.start + take])
                .context("failed to write z_erofs raw pcluster")?;
            self.write_z_padding(phys_blocks * block_size - take)?;
        }

        self.z_next_blkaddr += phys_blocks as u64;
        st.compressed_blocks += phys_blocks as u64;
        st.start += take;
        Ok(())
    }

    fn write_z_padding(&mut self, mut padding: usize) -> Result<()> {
        while padding > 0 {
            let chunk = padding.min(ZERO_BLOCK.len());
            self.writer
                .write_all(&ZERO_BLOCK[..chunk])
                .context("failed to write z_erofs padding")?;
            padding -= chunk;
        }
        Ok(())
    }

    pub fn data_size(&self) -> u64 {
        self.next_compressed_offset
    }

    pub fn data_digest(&self) -> Option<[u8; EROFS_BLOB_ID_SIZE]> {
        let hasher = self.data_hasher.as_ref()?;
        let mut digest = [0u8; EROFS_BLOB_ID_SIZE];
        digest.copy_from_slice(&hasher.clone().finalize());
        Some(digest)
    }

    pub fn into_parts(self) -> (W, Option<Sha256>) {
        (self.writer, self.data_hasher)
    }

    pub fn blob_metadata_chunks(&self) -> &[BlobMetadataChunk] {
        &self.blob_metadata_chunks
    }

    pub fn blob_metadata_block_groups(&self) -> &[BlobMetadataBlockGroup] {
        &self.blob_metadata_block_groups
    }

    pub fn blob_metadata(&self, source_offset_bias: u64) -> Result<BlobMetadata> {
        let mut block_groups = Vec::with_capacity(self.blob_metadata_block_groups.len());
        for block_group in &self.blob_metadata_block_groups {
            block_groups.push(block_group.checked_add_compressed_offset(source_offset_bias)?);
        }

        Ok(BlobMetadata::new(
            self.compressor,
            self.digester,
            self.file_chunk_size / EROFS_BLOCK_SIZE,
            self.blob_metadata_chunks.clone(),
            block_groups,
            false,
        )?)
    }

    pub fn write_blob_metadata(&mut self, path: &Path, source_offset_bias: u64) -> Result<()> {
        self.finish()?;
        Ok(self.blob_metadata(source_offset_bias)?.save(path)?)
    }

    pub fn finish(&mut self) -> Result<()> {
        // The data stream is byte granular, so the tail block group must be
        // zero padded to a whole block before it is flushed (block groups
        // always describe whole uncompressed blocks).
        if !self.block_group_buffer.is_empty() {
            let padded =
                align_up_usize(self.block_group_buffer.len(), EROFS_BLOCK_SIZE as usize)
                    .ok_or_else(|| Error::Overflow("block group padding overflow".to_string()))?;
            self.block_group_buffer.resize(padded, 0);
        }
        self.flush_block_group()?;
        self.drain_all_encoded()?;
        self.writer.flush().context("failed to flush blob device")
    }

    /// Process a regular file: read it in chunk-sized pieces and append every
    /// chunk to the blob device.
    pub fn write_file_chunks(
        &mut self,
        path: &Path,
        file_size: u64,
    ) -> Result<Vec<ErofsChunkAddr>> {
        if file_size == 0 {
            return Ok(Vec::new());
        }

        let mut f = File::open(path)
            .with_context(|| format!("failed to open source file: {}", path.display()))?;
        self.write_reader_chunks(&mut f, file_size)
            .with_context(|| format!("failed to chunk source file: {}", path.display()))
    }

    /// Process exactly `file_size` bytes from `reader` (e.g. a tar entry) in
    /// chunk-sized pieces and append every chunk to the blob device.
    pub fn write_reader_chunks(
        &mut self,
        reader: &mut dyn Read,
        file_size: u64,
    ) -> Result<Vec<ErofsChunkAddr>> {
        if file_size == 0 {
            return Ok(Vec::new());
        }

        let chunk_size = self.file_chunk_size as u64;
        let chunk_count = file_size.div_ceil(chunk_size);
        let mut indexes = Vec::with_capacity(chunk_count as usize);
        let mut chunk_buf = mem::take(&mut self.chunk_buf);
        if chunk_buf.len() < self.file_chunk_size as usize {
            chunk_buf = vec![0u8; self.file_chunk_size as usize];
        }
        for i in 0..chunk_count {
            let remaining = file_size - i * chunk_size;
            let to_read = remaining.min(chunk_size) as usize;

            if let Err(err) = reader
                .read_exact(&mut chunk_buf[..to_read])
                .context("failed to read source data")
            {
                self.chunk_buf = chunk_buf;
                return Err(err);
            }

            // A fully-zero chunk (a real filesystem hole reads back as zeros,
            // and so does zero-filled data) is not stored at all: it gets a
            // null chunk index (all 48 address bits set on disk), which every
            // read path already decodes as a hole and satisfies with zeros.
            // No blob data, no blob-meta chunk entry, and no blob cache
            // traffic is ever spent on it — native EROFS mounts handle the
            // null address the same way in-kernel.
            if chunk_buf[..to_read].iter().all(|&byte| byte == 0) {
                indexes.push(ErofsChunkAddr {
                    blkaddr: EROFS_NULL_ADDR,
                    device_id: 0,
                });
                continue;
            }

            // Pad only up to the last block of the chunk's real data, not to the
            // full file chunk size. A full chunk is already block-aligned, while
            // a partial (tail) chunk keeps zero padding confined to its final
            // block so block groups pack dense real blocks instead of large zero runs.
            let write_len =
                align_up_usize(to_read, EROFS_BLOCK_SIZE as usize).expect("alignment overflowed");
            let blkaddr = match self.append_chunk(&chunk_buf[..to_read], write_len) {
                Ok(blkaddr) => blkaddr,
                Err(err) => {
                    self.chunk_buf = chunk_buf;
                    return Err(err);
                }
            };

            indexes.push(ErofsChunkAddr {
                blkaddr,
                device_id: 1,
            });
        }
        self.chunk_buf = chunk_buf;

        Ok(indexes)
    }

    fn append_chunk(&mut self, data: &[u8], write_len: usize) -> Result<u64> {
        let addr = self.next_blkaddr;
        let block_count = u32::try_from(write_len / EROFS_BLOCK_SIZE as usize).map_err(|err| {
            Error::Overflow(format!("blob meta chunk block count exceeds u32: {err}"))
        })?;

        let next_blkaddr = addr
            .checked_add(block_count as u64)
            .filter(|count| *count <= u32::MAX as u64)
            .ok_or_else(|| {
                Error::Overflow(format!(
                "decoded blob exceeds 32-bit block count: start {addr}, chunk blocks {block_count}"
            ))
            })?;
        self.next_blkaddr = next_blkaddr;

        // Record the chunk by its absolute block position; chunks are tracked
        // independently of block groups as a digest index only. The digest
        // covers the block-aligned payload (real bytes plus tail-block zero
        // padding), hashed in place to avoid materialising a padded copy.
        let digest = match self.digester {
            BlobMetadataDigester::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(data);
                if write_len > data.len() {
                    hasher.update(&ZERO_BLOCK[..write_len - data.len()]);
                }
                *hasher.finalize().as_bytes()
            }
            BlobMetadataDigester::None => [0u8; 32],
        };
        let chunk = BlobMetadataChunk::new(digest, addr, block_count)?;
        self.blob_metadata_chunks.push(chunk);

        // The group stream mirrors the logical space one-to-one, so the
        // tail-block padding must be stored physically.
        self.append_to_block_group_stream(data)?;
        if write_len > data.len() {
            self.append_to_block_group_stream(&ZERO_BLOCK[..write_len - data.len()])?;
        }
        Ok(addr)
    }

    /// Append data to the current block group, flushing whenever it fills to
    /// the block group size, so block groups are pure block runs of exactly
    /// `block_group_size` (except the last).
    fn append_to_block_group_stream(&mut self, mut data: &[u8]) -> Result<()> {
        let block_group_size = self.block_group_size as usize;
        while !data.is_empty() {
            let space = block_group_size - self.block_group_buffer.len();
            let take = space.min(data.len());
            self.block_group_buffer.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.block_group_buffer.len() == block_group_size {
                self.flush_block_group()?;
            }
        }
        Ok(())
    }

    fn flush_block_group(&mut self) -> Result<()> {
        if self.block_group_buffer.is_empty() {
            return Ok(());
        }

        if self.encoder.is_none() {
            self.encoder = Some(BlockGroupEncoder::new(self.compressor));
        }
        let encoder = self.encoder.as_mut().expect("encoder initialised above");
        let replacement = encoder
            .take_buffer()
            .unwrap_or_else(|| Vec::with_capacity(self.block_group_size as usize));
        let uncompressed = mem::replace(&mut self.block_group_buffer, replacement);
        encoder.submit(uncompressed)?;
        while self
            .encoder
            .as_ref()
            .expect("encoder initialised above")
            .in_flight()
            > ENCODE_MAX_IN_FLIGHT
        {
            self.drain_one_encoded()?;
        }
        Ok(())
    }

    /// Write out the next completed block group, in submission order.
    fn drain_one_encoded(&mut self) -> Result<()> {
        let group = self
            .encoder
            .as_mut()
            .expect("drain is only called with a live encoder")
            .recv_next()?;
        let uncompressed_len = group.data.len();
        let encoded: &[u8] = group.compressed.as_deref().unwrap_or(&group.data);

        // Encoded block group payloads are packed back-to-back in the data region.
        // No block padding is inserted between compressed block groups; they are read
        // by byte range, and only the data region as a whole is later aligned
        // (by the build assembler) so the embedded bootstrap starts on a block.
        let compressed_offset = self.next_compressed_offset;
        self.writer
            .write_all(encoded)
            .context("failed to write to blob device")?;
        if let Some(hasher) = self.data_hasher.as_mut() {
            hasher.update(encoded);
        }
        self.next_compressed_offset = compressed_offset + encoded.len() as u64;

        let block_count =
            u32::try_from(uncompressed_len / EROFS_BLOCK_SIZE as usize).map_err(|err| {
                Error::Overflow(format!(
                    "blob meta block group uncompressed block count exceeds u32: {err}"
                ))
            })?;
        let entry = BlobMetadataBlockGroup::new(
            self.block_group_block_offset,
            block_count,
            compressed_offset,
            encoded.len() as u32,
            group.crc32,
            0,
            0,
            false,
        )?;
        self.blob_metadata_block_groups.push(entry);
        self.block_group_block_offset += block_count as u64;

        self.encoder
            .as_mut()
            .expect("drain is only called with a live encoder")
            .recycle_buffer(group.data);
        Ok(())
    }

    fn drain_all_encoded(&mut self) -> Result<()> {
        while self
            .encoder
            .as_ref()
            .is_some_and(|encoder| encoder.in_flight() > 0)
        {
            self.drain_one_encoded()?;
        }
        Ok(())
    }
}

/// Format-compatibility policy shared by build and `nydus optimize`: a block group
/// is stored compressed only when it saves at least 30% — both paths must
/// agree or an optimized blob would encode block groups differently from its source.
pub(crate) fn compression_is_worthwhile(compressed_len: usize, uncompressed_len: usize) -> bool {
    (compressed_len as u128) * 100 <= (uncompressed_len as u128) * MAX_COMPRESSED_SIZE_PERCENT
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_format::blob::DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE;
    use std::fs;
    use tempfile::tempdir;
    #[test]
    fn blob_metadata_block_group_round_trips_minimal_fields() {
        let payload = vec![0u8; 0x3000];
        // Compressed byte offset is a plain byte position (not block aligned).
        let entry =
            BlobMetadataBlockGroup::new(2, 3, 0x12345, 0x400, crc32c(&payload), 0, 0, false)
                .unwrap();

        assert_eq!(entry.uncompressed_block_offset(), 2);
        assert_eq!(entry.uncompressed_block_count(), 3);
        assert_eq!(entry.uncompressed_offset(), 0x2000);
        assert_eq!(entry.uncompressed_size(), 0x3000);
        assert_eq!(entry.compressed_offset(), 0x12345);
        assert_eq!(entry.compressed_size(), 0x400);
        assert_eq!(entry.crc32(), crc32c(&payload));
    }

    #[test]
    fn blob_writer_rejects_block_count_overflow_before_mutation() {
        let mut writer = BlobWriter::from_writer(
            Vec::new(),
            EROFS_BLOCK_SIZE,
            DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE,
            BlobMetadataCompressor::None,
        )
        .unwrap();
        writer.next_blkaddr = u32::MAX as u64 - 1;
        let data = [1; EROFS_BLOCK_SIZE as usize];
        assert_eq!(
            writer.append_chunk(&data, data.len()).unwrap(),
            u32::MAX as u64 - 1
        );
        assert_eq!(writer.next_blkaddr, u32::MAX as u64);
        let buffer = writer.block_group_buffer.clone();
        let chunks = writer.blob_metadata_chunks.len();
        assert!(writer.append_chunk(&data, data.len()).is_err());
        assert_eq!(writer.next_blkaddr, u32::MAX as u64);
        assert_eq!(writer.blob_metadata_chunks.len(), chunks);
        assert_eq!(writer.block_group_buffer, buffer);
        assert!(writer.writer.is_empty());
        assert!(writer.encoder.is_none());
    }

    #[test]
    fn blob_writer_tracks_unique_blob_metadata_chunks() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let file_a = dir.path().join("a.bin");
        let file_b = dir.path().join("b.bin");

        let mut content_a = vec![b'a'; DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize];
        content_a.extend(vec![b'b'; EROFS_BLOCK_SIZE as usize]);
        fs::write(&file_a, &content_a).unwrap();
        fs::write(
            &file_b,
            vec![b'a'; DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize],
        )
        .unwrap();

        // Pin the block group size to the chunk size so the 513-block layout
        // below packs across several block groups.
        let mut writer = BlobWriter::from_writer(
            File::create(&blob_path).unwrap(),
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            BlobMetadataCompressor::None,
        )
        .unwrap();
        let indexes_a = writer
            .write_file_chunks(&file_a, content_a.len() as u64)
            .unwrap();
        let indexes_b = writer
            .write_file_chunks(&file_b, DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as u64)
            .unwrap();
        writer.finish().unwrap();

        assert_eq!(indexes_a.len(), 2);
        assert_eq!(indexes_b.len(), 1);
        assert_eq!(indexes_a[0].blkaddr, 0);
        assert_eq!(indexes_a[1].blkaddr, 256);
        // Dense logical packing: file_a's 4KiB tail chunk occupies a single
        // block, so file_b starts right after it instead of being padded to a
        // full chunk.
        assert_eq!(indexes_b[0].blkaddr, 257);
        assert_eq!(writer.total_blocks(), 513);

        let entries = writer.blob_metadata_chunks();
        let block_groups = writer.blob_metadata_block_groups();
        assert_eq!(entries.len(), 3);
        assert_eq!(block_groups.len(), 3);
        // Chunks record absolute block offsets, independent of block groups.
        assert_eq!(entries[0].uncompressed_block_offset(), 0);
        assert_eq!(entries[0].uncompressed_block_count(), 256);
        assert_eq!(entries[1].uncompressed_block_offset(), 256);
        assert_eq!(entries[1].uncompressed_block_count(), 1);
        assert_eq!(entries[2].uncompressed_block_offset(), 257);
        assert_eq!(entries[2].uncompressed_block_count(), 256);
        // Block groups pack whole blocks up to the block group size (256 blocks) regardless
        // of chunk boundaries: file_a's tail block and file_b's leading blocks
        // share block group 1, and the remainder spills into block group 2.
        assert_eq!(block_groups[0].uncompressed_block_offset(), 0);
        assert_eq!(block_groups[0].uncompressed_block_count(), 256);
        assert_eq!(block_groups[0].compressed_offset(), 0);
        assert_eq!(
            block_groups[0].compressed_size(),
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE
        );
        assert_eq!(block_groups[1].uncompressed_block_offset(), 256);
        assert_eq!(block_groups[1].uncompressed_block_count(), 256);
        assert_eq!(
            block_groups[1].compressed_offset(),
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as u64
        );
        assert_eq!(
            block_groups[1].compressed_size(),
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE
        );
        assert_eq!(block_groups[2].uncompressed_block_offset(), 512);
        assert_eq!(block_groups[2].uncompressed_block_count(), 1);
        // Block groups pack back-to-back in the data region with no inter-block group padding.
        assert_eq!(
            block_groups[2].compressed_offset(),
            2 * DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as u64
        );
        assert_eq!(block_groups[2].compressed_size(), EROFS_BLOCK_SIZE);
    }

    #[test]
    fn blob_writer_allows_small_file_chunks_with_default_size_blob_metadata_block_groups() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let input_path = dir.path().join("input.bin");
        let mut content = vec![b'a'; EROFS_BLOCK_SIZE as usize];
        content.extend(vec![b'b'; EROFS_BLOCK_SIZE as usize]);
        fs::write(&input_path, &content).unwrap();

        let mut writer = BlobWriter::new(&blob_path, EROFS_BLOCK_SIZE).unwrap();
        let indexes = writer
            .write_file_chunks(&input_path, content.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        let blob_metadata = writer.blob_metadata(0).unwrap();

        assert_eq!(indexes.len(), 2);
        assert_eq!(indexes[0].blkaddr, 0);
        assert_eq!(indexes[1].blkaddr, 1);
        assert_eq!(blob_metadata.header().chunk_size(), EROFS_BLOCK_SIZE);
        assert_eq!(blob_metadata.block_groups().len(), 1);
        assert_eq!(blob_metadata.block_groups()[0].uncompressed_size(), 8192);
    }

    #[test]
    fn blob_writer_turns_zero_chunks_into_holes() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let input_path = dir.path().join("input.bin");
        // chunk 0: data, chunk 1: all zeros, chunk 2: data (partial tail).
        let mut content = vec![b'a'; EROFS_BLOCK_SIZE as usize];
        content.extend(vec![0u8; EROFS_BLOCK_SIZE as usize]);
        content.extend(vec![b'c'; 100]);
        fs::write(&input_path, &content).unwrap();

        let mut writer = BlobWriter::new(&blob_path, EROFS_BLOCK_SIZE).unwrap();
        let indexes = writer
            .write_file_chunks(&input_path, content.len() as u64)
            .unwrap();
        writer.finish().unwrap();

        // The all-zero chunk becomes a hole: a null chunk index with no blob
        // reference, no blob-meta chunk entry, and no bytes in the data region.
        assert_eq!(indexes.len(), 3);
        assert_eq!(indexes[0].blkaddr, 0);
        assert_eq!(indexes[1].blkaddr, EROFS_NULL_ADDR);
        assert_eq!(indexes[2].blkaddr, 1);
        assert_eq!(writer.total_blocks(), 2);
        let data = fs::read(&blob_path).unwrap();
        assert_eq!(data.len(), 2 * EROFS_BLOCK_SIZE as usize);
        assert!(!data[..EROFS_BLOCK_SIZE as usize].iter().any(|&b| b != b'a'));

        // The on-disk null index encodes the all-ones sentinel.
        let raw =
            nydus_format::erofs::ErofsChunkIndex::new(indexes[1].blkaddr, indexes[1].device_id)
                .unwrap();
        assert_eq!(raw.blkaddr(), EROFS_NULL_ADDR);
    }

    #[test]
    fn blob_writer_handles_fully_zero_file() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let input_path = dir.path().join("input.bin");
        let content = vec![0u8; 2 * EROFS_BLOCK_SIZE as usize];
        fs::write(&input_path, &content).unwrap();

        let mut writer = BlobWriter::new(&blob_path, EROFS_BLOCK_SIZE).unwrap();
        let indexes = writer
            .write_file_chunks(&input_path, content.len() as u64)
            .unwrap();
        writer.finish().unwrap();

        // Every chunk is a hole: nothing lands in the blob at all.
        assert_eq!(indexes.len(), 2);
        assert!(indexes.iter().all(|ci| ci.blkaddr == EROFS_NULL_ADDR));
        assert!(writer.blob_metadata_block_groups().is_empty());
        assert_eq!(writer.total_blocks(), 0);
        assert_eq!(fs::read(&blob_path).unwrap().len(), 0);
    }

    #[test]
    fn blob_writer_stores_uncompressed_when_zstd_saves_too_little() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let input_path = dir.path().join("input.bin");
        let content = pseudo_random_bytes(DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as usize);
        fs::write(&input_path, &content).unwrap();

        let mut writer = BlobWriter::new_with_compressor(
            &blob_path,
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            BlobMetadataCompressor::Zstd,
        )
        .unwrap();
        writer
            .write_file_chunks(&input_path, content.len() as u64)
            .unwrap();
        writer.finish().unwrap();

        let block_groups = writer.blob_metadata_block_groups();
        assert_eq!(block_groups.len(), 1);
        assert_eq!(block_groups[0].uncompressed_block_count(), 256);
        assert_eq!(
            block_groups[0].uncompressed_size(),
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as u64
        );
        assert_eq!(
            u64::from(block_groups[0].compressed_size()),
            block_groups[0].uncompressed_size()
        );
        assert_eq!(fs::read(&blob_path).unwrap(), content);
    }

    #[test]
    fn blob_writer_writes_blob_metadata_file() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let blob_metadata_path = dir.path().join("blob.blob.meta");
        let input_path = dir.path().join("input.bin");
        fs::write(&input_path, vec![b'x'; 4096]).unwrap();

        let mut writer =
            BlobWriter::new(&blob_path, DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE).unwrap();
        writer.write_file_chunks(&input_path, 4096).unwrap();
        writer
            .write_blob_metadata(&blob_metadata_path, 8192)
            .unwrap();

        let raw = fs::read(&blob_metadata_path).unwrap();
        // 4 KiB header block + one block group, padded to a block.
        assert_eq!(raw.len(), 8192);

        let blob_metadata = BlobMetadata::from_path(&blob_metadata_path, false).unwrap();
        assert_eq!(blob_metadata.header().chunk_count(), 1);
        assert_eq!(blob_metadata.header().block_group_count(), 1);
        assert_eq!(blob_metadata.header().chunk_table_size(), 48);
        assert_eq!(blob_metadata.header().block_group_table_size(), 40);
        assert_eq!(blob_metadata.header().padded_size(), 8192);
        assert_eq!(blob_metadata.chunks()[0].uncompressed_block_offset(), 0);
        assert_eq!(blob_metadata.block_groups()[0].compressed_offset(), 8192);
    }
    #[test]
    fn blob_writer_stores_duplicate_content_verbatim() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let file_a = dir.path().join("a.bin");
        let file_b = dir.path().join("b.bin");
        let body = pseudo_random_bytes((1 << 20) + 100);
        fs::write(&file_a, &body).unwrap();
        fs::write(&file_b, &body).unwrap();

        let mut writer = BlobWriter::new_with_compressor(
            &blob_path,
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE,
            BlobMetadataCompressor::None,
        )
        .unwrap();
        writer
            .write_file_chunks(&file_a, body.len() as u64)
            .unwrap();
        writer
            .write_file_chunks(&file_b, body.len() as u64)
            .unwrap();
        writer.finish().unwrap();

        let padded = align_up_usize(body.len(), EROFS_BLOCK_SIZE as usize)
            .expect("alignment overflowed") as u64;
        assert_eq!(writer.data_size(), 2 * padded);
        assert_eq!(writer.total_blocks() * EROFS_BLOCK_SIZE as u64, 2 * padded);

        let blob_metadata = writer.blob_metadata(0).unwrap();
        assert_eq!(blob_metadata.header().chunk_count(), 4);
        assert_eq!(blob_metadata.uncompressed_size(), 2 * padded);

        let data = fs::read(&blob_path).unwrap();
        assert_eq!(data.len() as u64, 2 * padded);
        assert_eq!(&data[..body.len()], &body[..]);
        assert!(data[body.len()..padded as usize].iter().all(|b| *b == 0));
        assert_eq!(
            &data[padded as usize..padded as usize + body.len()],
            &body[..]
        );
    }

    #[test]
    fn blob_writer_keeps_zero_chunk_elision_and_stores_tail_padding() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let input_path = dir.path().join("input.bin");
        let mut content = vec![b'a'; EROFS_BLOCK_SIZE as usize];
        content.extend(vec![0u8; EROFS_BLOCK_SIZE as usize]);
        content.extend(vec![b'c'; 100]);
        fs::write(&input_path, &content).unwrap();

        let mut writer = BlobWriter::new(&blob_path, EROFS_BLOCK_SIZE).unwrap();
        let indexes = writer
            .write_file_chunks(&input_path, content.len() as u64)
            .unwrap();
        writer.finish().unwrap();

        assert_eq!(indexes.len(), 3);
        assert_eq!(indexes[0].blkaddr, 0);
        assert_eq!(indexes[1].blkaddr, EROFS_NULL_ADDR);
        assert_eq!(indexes[2].blkaddr, 1);
        assert_eq!(writer.total_blocks(), 2);

        let data = fs::read(&blob_path).unwrap();
        assert_eq!(data.len(), 2 * EROFS_BLOCK_SIZE as usize);
        assert!(data[..EROFS_BLOCK_SIZE as usize].iter().all(|b| *b == b'a'));
        let tail = &data[EROFS_BLOCK_SIZE as usize..];
        assert!(tail[..100].iter().all(|b| *b == b'c'));
        assert!(tail[100..].iter().all(|b| *b == 0));
    }

    fn pseudo_random_bytes(len: usize) -> Vec<u8> {
        let mut value = 0x1234_5678_9abc_def0u64;
        (0..len)
            .map(|_| {
                value ^= value << 13;
                value ^= value >> 7;
                value ^= value << 17;
                value as u8
            })
            .collect()
    }

    // ---- z_erofs LZ4 mode ----

    use nydus_format::erofs::{
        Z_EROFS_FRAGMENT_INODE_FLAG, Z_EROFS_LCLUSTER_INDEX_SIZE, Z_EROFS_LCLUSTER_TYPE_HEAD1,
        Z_EROFS_LCLUSTER_TYPE_NONHEAD, Z_EROFS_LCLUSTER_TYPE_PLAIN, Z_EROFS_LI_D0_CBLKCNT,
        Z_EROFS_LI_LCLUSTER_TYPE_MASK, Z_EROFS_MAP_HEADER_SIZE,
    };

    const Z_BASE: u64 = 16;
    const BLOCK: usize = EROFS_BLOCK_SIZE as usize;

    fn z_writer() -> BlobWriter<Vec<u8>> {
        let mut writer = BlobWriter::from_writer(
            Vec::new(),
            EROFS_BLOCK_SIZE,
            1 << 20,
            BlobMetadataCompressor::None,
        )
        .unwrap();
        writer.set_zlz4(16 * EROFS_BLOCK_SIZE, Z_BASE).unwrap();
        writer
    }

    /// Full lcluster indexes of a tail as (type, clusterofs, blkaddr or
    /// delta0|delta1) triples.
    fn lclusters(tail: &[u8]) -> Vec<(u16, u16, u32)> {
        tail[Z_EROFS_MAP_HEADER_SIZE + 8..]
            .chunks_exact(Z_EROFS_LCLUSTER_INDEX_SIZE)
            .map(|index| {
                (
                    u16::from_le_bytes([index[0], index[1]]) & Z_EROFS_LI_LCLUSTER_TYPE_MASK,
                    u16::from_le_bytes([index[2], index[3]]),
                    u32::from_le_bytes(index[4..8].try_into().unwrap()),
                )
            })
            .collect()
    }

    /// Decodes a COMPRESSED_FULL file the way the kernel does: PLAIN lclusters
    /// are raw blocks, HEAD1 pclusters span the following NONHEAD lclusters,
    /// take their physical size from the first NONHEAD's CBLKCNT (one block
    /// when there is none) and hold LZ4 data tail-aligned behind zero padding.
    fn decode_z_file(data: &[u8], tail: &[u8], size: usize) -> Vec<u8> {
        let indexes = lclusters(tail);
        assert_eq!(indexes.len(), size.div_ceil(BLOCK));
        let mut out = Vec::with_capacity(size);
        let mut i = 0;
        while i < indexes.len() {
            let (kind, clusterofs, blkaddr) = indexes[i];
            assert_eq!(clusterofs, 0);
            let phys = |blkaddr: u32| (blkaddr as u64 - Z_BASE) as usize * BLOCK;
            let remaining = size - i * BLOCK;
            match kind {
                Z_EROFS_LCLUSTER_TYPE_PLAIN => {
                    let start = phys(blkaddr);
                    out.extend_from_slice(&data[start..start + remaining.min(BLOCK)]);
                    i += 1;
                }
                Z_EROFS_LCLUSTER_TYPE_HEAD1 => {
                    let mut j = i + 1;
                    while j < indexes.len() && indexes[j].0 == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                        j += 1;
                    }
                    let lclusters = j - i;
                    assert!(lclusters >= 2, "a compressed pcluster spans >= 2 lclusters");
                    let delta0 = indexes[i + 1].2 as u16;
                    assert_ne!(delta0 & Z_EROFS_LI_D0_CBLKCNT, 0);
                    let cblkcnt = (delta0 & !Z_EROFS_LI_D0_CBLKCNT) as usize;
                    for k in 2..lclusters {
                        let delta0 = indexes[i + k].2 as u16;
                        let delta1 = (indexes[i + k].2 >> 16) as u16;
                        assert_eq!((delta0 as usize, delta1 as usize), (k, lclusters - 1 - k));
                    }
                    let start = phys(blkaddr);
                    let pcluster = &data[start..start + cblkcnt * BLOCK];
                    let payload_start = pcluster.iter().position(|b| *b != 0).unwrap();
                    let logical = remaining.min(lclusters * BLOCK);
                    out.extend_from_slice(
                        &lz4_flex::block::decompress(&pcluster[payload_start..], logical).unwrap(),
                    );
                    i = j;
                }
                other => panic!("unexpected lcluster type {other}"),
            }
        }
        out
    }

    #[test]
    fn zlz4_incompressible_data_becomes_per_block_plain_lclusters() {
        let mut writer = z_writer();
        let src = pseudo_random_bytes(3 * BLOCK + 100);
        let meta = writer
            .write_reader_zlz4(&mut &src[..], src.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        let (data, _) = writer.into_parts();

        let indexes = lclusters(&meta.tail);
        assert_eq!(indexes.len(), 4);
        for (i, &(kind, _, blkaddr)) in indexes.iter().enumerate() {
            assert_eq!(kind, Z_EROFS_LCLUSTER_TYPE_PLAIN);
            assert_eq!(blkaddr as u64, Z_BASE + i as u64);
        }
        assert_eq!(meta.compressed_blocks, 4);
        assert_eq!(data.len(), 4 * BLOCK);
        assert_eq!(decode_z_file(&data, &meta.tail, src.len()), src);
        assert!(
            data[3 * BLOCK + 100..].iter().all(|b| *b == 0),
            "tail block zero padded"
        );
    }

    #[test]
    fn zlz4_compressible_data_packs_big_pclusters_with_cblkcnt() {
        let mut writer = z_writer();
        // A quarter noise, the rest zeros per block: roughly 4:1 (LZ4 stores
        // the noise as literals), so 1MiB needs several multi-block
        // pclusters.
        let mut src = pseudo_random_bytes(1 << 20);
        for block in src.chunks_exact_mut(BLOCK) {
            block[BLOCK / 4..].fill(0);
        }
        let meta = writer
            .write_reader_zlz4(&mut &src[..], src.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        let (data, _) = writer.into_parts();

        let indexes = lclusters(&meta.tail);
        assert_eq!(indexes.len(), 256);
        assert_eq!(indexes[0].0, Z_EROFS_LCLUSTER_TYPE_HEAD1);
        let heads = indexes
            .iter()
            .filter(|(kind, ..)| *kind == Z_EROFS_LCLUSTER_TYPE_HEAD1)
            .count();
        assert!(
            heads > 1 && heads < 256,
            "{heads} pclusters for 256 lclusters"
        );
        assert_eq!(data.len(), meta.compressed_blocks as usize * BLOCK);
        assert!(
            meta.compressed_blocks < 256 / 2,
            "compressed to less than half"
        );
        assert_eq!(decode_z_file(&data, &meta.tail, src.len()), src);
    }

    #[test]
    fn zlz4_files_larger_than_the_window_buffer_round_trip() {
        let mut writer = z_writer();
        // 5MiB mixes compressible runs and noise so the window compacts
        // several times and both pcluster kinds occur.
        let mut src = Vec::with_capacity(5 << 20);
        for i in 0..(5 << 20) / BLOCK {
            if i % 3 == 0 {
                src.extend(pseudo_random_bytes(BLOCK).iter().skip(i % 17));
                src.resize((i + 1) * BLOCK, 0x5a);
            } else {
                src.extend(std::iter::repeat_n((i % 200) as u8, BLOCK));
            }
        }
        src.truncate((5 << 20) - 1234);
        let meta = writer
            .write_reader_zlz4(&mut &src[..], src.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        let (data, _) = writer.into_parts();
        assert_eq!(data.len(), meta.compressed_blocks as usize * BLOCK);
        assert_eq!(decode_z_file(&data, &meta.tail, src.len()), src);
    }

    #[test]
    fn zlz4_alignment_pads_files_at_or_above_the_threshold() {
        let mut writer = z_writer();
        writer
            .set_data_alignment(8 * EROFS_BLOCK_SIZE, 2 * BLOCK as u64)
            .unwrap();
        let small = pseudo_random_bytes(BLOCK);
        let big = pseudo_random_bytes(3 * BLOCK);
        let small_meta = writer
            .write_reader_zlz4(&mut &small[..], small.len() as u64)
            .unwrap();
        let big_meta = writer
            .write_reader_zlz4(&mut &big[..], big.len() as u64)
            .unwrap();
        let again = writer
            .write_reader_zlz4(&mut &small[..], small.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        let (data, _) = writer.into_parts();

        assert_eq!(lclusters(&small_meta.tail)[0].2 as u64, Z_BASE);
        // The big file starts on the next 8-block boundary of the device
        // data (offset 8, not of the image address space).
        assert_eq!(lclusters(&big_meta.tail)[0].2 as u64, Z_BASE + 8);
        assert!(
            data[BLOCK..8 * BLOCK].iter().all(|b| *b == 0),
            "gap is zero"
        );
        // Small files are not aligned, they follow immediately.
        assert_eq!(lclusters(&again.tail)[0].2 as u64, Z_BASE + 11);
        assert_eq!(writer_end(&data), 12);
        assert_eq!(decode_z_file(&data, &big_meta.tail, big.len()), big);
    }

    fn writer_end(data: &[u8]) -> usize {
        data.len() / BLOCK
    }

    #[test]
    fn zlz4_fragments_pack_small_files_into_a_block_padded_packed_inode() {
        let mut writer = z_writer();
        writer.set_zlz4_fragments(BLOCK as u64).unwrap();
        let a = b"first small file".to_vec();
        let b = pseudo_random_bytes(BLOCK);
        let c = b"third".to_vec();
        let big = pseudo_random_bytes(BLOCK + 1);
        let empty: Vec<u8> = Vec::new();
        let ma = writer
            .write_reader_zlz4(&mut &a[..], a.len() as u64)
            .unwrap();
        let mb = writer
            .write_reader_zlz4(&mut &b[..], b.len() as u64)
            .unwrap();
        let mbig = writer
            .write_reader_zlz4(&mut &big[..], big.len() as u64)
            .unwrap();
        let mc = writer
            .write_reader_zlz4(&mut &c[..], c.len() as u64)
            .unwrap();
        let mempty = writer.write_reader_zlz4(&mut &empty[..], 0).unwrap();
        let (packed, packed_size) = writer.finish_zlz4_packed().unwrap().unwrap();
        assert!(
            writer.finish_zlz4_packed().unwrap().is_none(),
            "flushed once"
        );
        writer.finish().unwrap();
        let (data, _) = writer.into_parts();

        // Fragment tails: 8 bytes, bit 63 set, offset into the packed inode.
        let fragment_offset = |meta: &ZFileMeta| {
            assert_eq!(meta.tail.len(), Z_EROFS_MAP_HEADER_SIZE);
            assert_eq!(meta.compressed_blocks, 0);
            let head = u64::from_le_bytes(meta.tail[..].try_into().unwrap());
            assert_ne!(head & Z_EROFS_FRAGMENT_INODE_FLAG, 0);
            head ^ Z_EROFS_FRAGMENT_INODE_FLAG
        };
        assert_eq!(fragment_offset(&ma), 0);
        assert_eq!(fragment_offset(&mb), a.len() as u64);
        assert_eq!(fragment_offset(&mc), (a.len() + b.len()) as u64);
        // Above the threshold: its own pclusters. Empty: a plain z tail with
        // no lclusters.
        assert_eq!(lclusters(&mbig.tail).len(), 2);
        assert_eq!(mempty.tail.len(), Z_EROFS_MAP_HEADER_SIZE + 8);
        assert_eq!(mempty.compressed_blocks, 0);

        let logical = a.len() + b.len() + c.len();
        assert_eq!(packed_size as usize, logical.next_multiple_of(BLOCK));
        let decoded = decode_z_file(&data, &packed.tail, packed_size as usize);
        assert_eq!(&decoded[..a.len()], &a[..]);
        assert_eq!(&decoded[a.len()..a.len() + b.len()], &b[..]);
        assert_eq!(&decoded[a.len() + b.len()..logical], &c[..]);
        assert!(decoded[logical..].iter().all(|b| *b == 0));
        assert_eq!(decode_z_file(&data, &mbig.tail, big.len()), big);
    }
}
