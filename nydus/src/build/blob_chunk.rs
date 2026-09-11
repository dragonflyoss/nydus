use crc32c::crc32c;
use nydus_error::{Context, Error, Result};
use nydus_format::blob::{
    encode_pack_layout, BlobMetadata, BlobMetadataBlockGroup, BlobMetadataChunk,
    BlobMetadataCompressor, BlobMetadataDigester, BlobMetadataFlags,
    DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE,
};
use nydus_format::erofs::{
    ErofsChunkAddr, ZAlgorithm, ZComprCfgs, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE, EROFS_NULL_ADDR,
    Z_EROFS_FRAGMENT_INODE_FLAG, Z_EROFS_LCLUSTER_INDEX_SIZE,
};
use nydus_format::utils::align_up_usize;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::mem;
use std::path::Path;
use std::rc::Rc;
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
    z_pcluster: u32,
    z_algorithm: ZAlgorithm,
    z_base_blkaddr: u64,
    z_next_blkaddr: u64,
    // Lazily started z_erofs compression pipeline (see `ZPipeline`) and the
    // inodes whose segments are in flight, in submission order.
    z_pipeline: Option<ZPipeline>,
    z_open_files: VecDeque<ZAccum>,
    // z_erofs fragments: regular files of at most `z_frag_threshold` bytes are
    // appended to one packed stream, compressed segment by segment as it
    // fills, instead of getting their own pclusters; `finish_z_packed`
    // flushes it as the packed inode, so neighbouring small files share
    // pclusters and one read serves many of them. Zero disables fragments.
    z_frag_threshold: u64,
    z_packed: Option<ZPackedStream>,
    z_fragment_dedup: bool,
    // Dense block groups (`BlobMetadataFlags::DENSE_GROUPS`): the group
    // stream carries chunk bytes without tail-block padding and is cut at
    // block-aligned points, so groups span a variable number of padded
    // blocks. Regular files of at most `pack_threshold` bytes are bundled
    // into pack chunks, each file still starting on its own block of the
    // padded address space the EROFS chunk indexes address.
    dense: bool,
    pack_threshold: u64,
    pack: Option<PackAccum>,
    pack_layout: Vec<u8>,
    // Padded byte position just past the last byte in `block_group_buffer`
    // and the padded block where the next group's span starts (the
    // previous group's end), plus the spans of groups handed to the
    // encoder, in submission order.
    dense_group_end: u64,
    dense_next_group_block: u64,
    dense_group_spans: VecDeque<(u64, u64)>,
}

/// A pack chunk under construction: consecutive small files appended back
/// to back, each reserving its padded blocks from `start_blkaddr` on.
struct PackAccum {
    start_blkaddr: u64,
    bytes: Vec<u8>,
    file_lens: Vec<u32>,
    blocks: u64,
}

/// The packed inode under construction: the bytes not yet handed to a
/// compression segment, the total packed so far, and the growing inode.
struct ZPackedStream {
    buf: Vec<u8>,
    size: u64,
    accum: ZAccum,
    fragments: HashMap<([u8; 32], u64), u64>,
}

/// A z_erofs inode being assembled from committed segments: its tail (map
/// header + full lcluster indexes so far) and compressed block count, and
/// the handle its metadata is published through once the last segment lands.
struct ZAccum {
    tail: Vec<u8>,
    blocks: u64,
    handle: ZFileRef,
}

impl ZAccum {
    fn new(algorithm: ZAlgorithm, handle: ZFileRef) -> Self {
        Self {
            tail: z_map_header(algorithm),
            blocks: 0,
            handle,
        }
    }

    fn into_meta(self) -> Result<ZFileMeta> {
        let compressed_blocks = u32::try_from(self.blocks).map_err(|err| {
            Error::Overflow(format!("z_erofs compressed block count exceeds u32: {err}"))
        })?;
        Ok(ZFileMeta {
            tail: self.tail,
            compressed_blocks,
        })
    }
}

/// Map header of a z_erofs inode: `h_advise = BIG_PCLUSTER_1`, the HEAD1
/// algorithm in the low nibble of `h_algorithmtype`, lclusterbits ==
/// blkszbits, followed by the 8 reserved bytes; full lcluster indexes start
/// right after (the legacy layout).
fn z_map_header(algorithm: ZAlgorithm) -> Vec<u8> {
    use nydus_format::erofs::{Z_EROFS_ADVISE_BIG_PCLUSTER_1, Z_EROFS_MAP_HEADER_SIZE};
    let mut tail = Vec::with_capacity(Z_EROFS_MAP_HEADER_SIZE + 8 + 64);
    tail.extend_from_slice(&[0u8; 4]);
    tail.extend_from_slice(&Z_EROFS_ADVISE_BIG_PCLUSTER_1.to_le_bytes());
    tail.push(algorithm.as_type());
    tail.push(0);
    tail.extend_from_slice(&[0u8; 8]);
    tail
}

/// The z_erofs metadata of one file, published when its last segment is
/// committed. Handles are cheap to clone (hardlinks share one) and resolve
/// only after [`BlobWriter::finish`]; the tree keeps them until then.
#[derive(Clone)]
pub struct ZFileRef(Rc<RefCell<Option<ZFileMeta>>>);

impl ZFileRef {
    fn pending() -> Self {
        Self(Rc::new(RefCell::new(None)))
    }

    fn ready(meta: ZFileMeta) -> Self {
        Self(Rc::new(RefCell::new(Some(meta))))
    }

    fn set(&self, meta: ZFileMeta) {
        *self.0.borrow_mut() = Some(meta);
    }

    /// The published metadata; an error while the file is still in flight.
    pub fn resolve(&self) -> Result<ZFileMeta> {
        self.0.borrow().clone().ok_or_else(|| {
            Error::Runtime("z_erofs file metadata read before the blob was finished".to_string())
        })
    }
}

/// Source bytes handed to one z_erofs compression job. Pcluster boundaries
/// are forced at segment ends, which costs at most one under-filled
/// pcluster per segment; 4MiB keeps that under 1% while bounding the memory
/// of a job (its source plus output) and letting a single large file spread
/// over every worker.
const Z_SEGMENT_SIZE: usize = 4 << 20;
/// Jobs in flight per worker before the producer commits one; bounds peak
/// memory to about `2 * workers * 2 * Z_SEGMENT_SIZE`.
const Z_MAX_IN_FLIGHT_PER_WORKER: usize = 2;

struct ZJob {
    seq: u64,
    src: Vec<u8>,
    /// Whether the segment ends its inode: only then may the last pcluster
    /// take a partial lcluster.
    at_eof: bool,
}

/// One compressed segment: the pclusters back to back (payloads zero padded
/// as on disk), their full lcluster indexes with block addresses relative to
/// the segment start, and the physical block count. `src` circulates back.
struct ZSegment {
    data: Vec<u8>,
    indexes: Vec<u8>,
    phys_blocks: u32,
    src: Vec<u8>,
}

/// What a committed segment belongs to and how to place it.
struct ZPending {
    target: ZTarget,
    at_eof: bool,
    /// Block alignment of the device data the segment must start on (0: none).
    align_blocks: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ZTarget {
    /// The front of `BlobWriter::z_open_files`.
    File,
    Packed,
}

/// Compresses z_erofs segments on background threads while the producer
/// keeps reading source data. Results are committed strictly in submission
/// order (the next segment's addresses depend on the previous one's size),
/// so the output stays deterministic: it depends only on the source bytes
/// and the segment size, never on scheduling.
struct ZPipeline {
    tx: Option<mpsc::Sender<ZJob>>,
    done_rx: mpsc::Receiver<(u64, ZSegment)>,
    reordered: BTreeMap<u64, ZSegment>,
    next_seq_in: u64,
    next_seq_out: u64,
    pending: VecDeque<ZPending>,
    free_buffers: Vec<Vec<u8>>,
    workers: Vec<JoinHandle<()>>,
}

impl ZPipeline {
    fn new(algorithm: ZAlgorithm, pcluster: usize) -> Self {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .min(8);
        let (tx, rx) = mpsc::channel::<ZJob>();
        let (done_tx, done_rx) = mpsc::channel();
        let rx = Arc::new(Mutex::new(rx));
        let workers = (0..threads)
            .map(|_| {
                let rx = Arc::clone(&rx);
                let done_tx = done_tx.clone();
                std::thread::spawn(move || {
                    let mut compressor = ZCompressor::new(algorithm, pcluster);
                    loop {
                        let job = match rx.lock().unwrap_or_else(|p| p.into_inner()).recv() {
                            Ok(job) => job,
                            Err(_) => break,
                        };
                        let segment =
                            z_compress_segment(job.src, job.at_eof, pcluster, &mut compressor);
                        if done_tx.send((job.seq, segment)).is_err() {
                            break;
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        Self {
            tx: Some(tx),
            done_rx,
            reordered: BTreeMap::new(),
            next_seq_in: 0,
            next_seq_out: 0,
            pending: VecDeque::new(),
            free_buffers: Vec::new(),
            workers,
        }
    }

    fn max_in_flight(&self) -> usize {
        self.workers.len() * Z_MAX_IN_FLIGHT_PER_WORKER
    }

    fn in_flight(&self) -> usize {
        (self.next_seq_in - self.next_seq_out) as usize
    }

    fn submit(&mut self, src: Vec<u8>, pending: ZPending) -> Result<()> {
        let job = ZJob {
            seq: self.next_seq_in,
            src,
            at_eof: pending.at_eof,
        };
        self.next_seq_in += 1;
        self.pending.push_back(pending);
        self.tx
            .as_ref()
            .expect("pipeline is alive until dropped")
            .send(job)
            .map_err(|_| Error::Runtime("z_erofs compression threads exited early".to_string()))
    }

    /// The next completed segment in submission order, with its placement.
    fn recv_next(&mut self) -> Result<(ZSegment, ZPending)> {
        let placement = self
            .pending
            .pop_front()
            .ok_or_else(|| Error::Runtime("no z_erofs segment in flight".to_string()))?;
        loop {
            if let Some(segment) = self.reordered.remove(&self.next_seq_out) {
                self.next_seq_out += 1;
                return Ok((segment, placement));
            }
            let (seq, segment) = self.done_rx.recv().map_err(|_| {
                Error::Runtime("z_erofs compression threads exited early".to_string())
            })?;
            self.reordered.insert(seq, segment);
        }
    }

    fn take_buffer(&mut self) -> Vec<u8> {
        self.free_buffers
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(Z_SEGMENT_SIZE))
    }

    fn recycle_buffer(&mut self, mut buf: Vec<u8>) {
        if self.free_buffers.len() < self.max_in_flight() {
            buf.clear();
            self.free_buffers.push(buf);
        }
    }
}

impl Drop for ZPipeline {
    fn drop(&mut self) {
        self.tx.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// zstd window log for z_erofs pclusters: 512KiB, what erofs-utils picks
/// for 64KiB pclusters (`min(1MiB, 8 * pcluster)`), recorded in the
/// superblock's zstd config so the kernel sizes its decompression streams.
pub const Z_ZSTD_WINDOWLOG: u8 = 19;
/// zstd compression level for z_erofs pclusters (the zstd default).
const Z_ZSTD_LEVEL: i32 = 3;

/// One worker's compressor state: the algorithm and its scratch output
/// buffer (plus the zstd context, which is expensive to recreate).
enum ZCompressor {
    Lz4 {
        dst: Vec<u8>,
    },
    Zstd {
        cctx: zstd::bulk::Compressor<'static>,
        dst: Vec<u8>,
        best: Vec<u8>,
    },
}

impl ZCompressor {
    fn new(algorithm: ZAlgorithm, pcluster: usize) -> Self {
        match algorithm {
            ZAlgorithm::Lz4 => Self::Lz4 {
                dst: vec![0u8; lz4_compress_bound(Z_SEGMENT_SIZE)],
            },
            ZAlgorithm::Zstd => {
                let mut cctx =
                    zstd::bulk::Compressor::new(Z_ZSTD_LEVEL).expect("zstd compression context");
                cctx.set_parameter(zstd::zstd_safe::CParameter::WindowLog(
                    Z_ZSTD_WINDOWLOG as u32,
                ))
                .expect("zstd window log within bounds");
                Self::Zstd {
                    // Slack past the pcluster tells "just over" apart from
                    // a hard failure, as erofs-utils does.
                    dst: vec![0u8; pcluster + 32],
                    best: vec![0u8; pcluster + 32],
                    cctx,
                }
            }
        }
    }

    /// Picks the next pcluster from `pending`: how many source bytes it
    /// covers (a whole number of lclusters unless `at_eof` lets the final
    /// partial one in) and the compressed size, `usize::MAX` when the head
    /// must be stored raw. The compressed bytes are left at the start of
    /// the returned scratch buffer. `suggested_len` seeds the zstd search;
    /// bounds and fitting checks still determine the accepted prefix.
    fn fit_pcluster(
        &mut self,
        pending: &[u8],
        at_eof: bool,
        pcluster: usize,
        suggested_len: usize,
    ) -> (usize, usize, &[u8]) {
        let block_size = EROFS_BLOCK_SIZE as usize;
        match self {
            Self::Lz4 { dst } => {
                // Greedy pass: how much source fits into one pcluster.
                let (consumed, greedy_len) = lz4_compress_dest_size(pending, &mut dst[..pcluster]);
                if at_eof && consumed == pending.len() {
                    return (consumed, greedy_len, dst);
                }
                let mut take = consumed / block_size * block_size;
                if take == 0 {
                    // Incompressible head: fall back to one raw lcluster.
                    return (pending.len().min(block_size), usize::MAX, dst);
                }
                // Re-compress the aligned prefix so the pcluster still
                // starts on an lcluster boundary (clusterofs stays 0).
                // Rarely it compresses worse than the greedy pass; shrink
                // until it fits the pcluster, else store it raw.
                loop {
                    match lz4_compress(&pending[..take], dst) {
                        Some(len) if len <= pcluster => return (take, len, dst),
                        _ if take > block_size => take -= block_size,
                        _ => return (take, usize::MAX, dst),
                    }
                }
            }
            Self::Zstd { cctx, dst, best } => {
                // zstd has no destSize mode: search the largest lcluster
                // count whose frame fits, steering by the measured ratio
                // (erofs-utils' fitblk). Candidates are whole lclusters;
                // at eof the final partial one is a candidate too.
                let candidates = if at_eof {
                    pending.len().div_ceil(block_size)
                } else {
                    pending.len() / block_size
                };
                if candidates == 0 {
                    return (pending.len(), usize::MAX, dst);
                }
                let len_of = |k: usize| (k * block_size).min(pending.len());
                let mut fits = 0usize; // largest candidate that fits
                let mut fits_len = usize::MAX;
                let mut fails = candidates + 1; // smallest that does not
                let mut k = (suggested_len / block_size).clamp(1, candidates);
                loop {
                    k = k.clamp(fits + 1, fails - 1);
                    match cctx.compress_to_buffer(&pending[..len_of(k)], &mut dst[..]) {
                        Ok(csize) if csize <= pcluster => {
                            fits = k;
                            fits_len = csize;
                            if fails <= fits + 1 || csize + 1 >= pcluster {
                                break;
                            }
                            best[..csize].copy_from_slice(&dst[..csize]);
                            k = (pcluster * k / csize).max(k + 1);
                        }
                        _ => {
                            fails = k;
                            if fails <= fits + 1 {
                                break;
                            }
                            k = (fits + fails) / 2;
                        }
                    }
                }
                if fits == 0 {
                    return (pending.len().min(block_size), usize::MAX, dst);
                }
                if k != fits {
                    mem::swap(dst, best);
                }
                (len_of(fits), fits_len, dst)
            }
        }
    }
}

/// Compresses one segment into z_erofs pclusters. Pclusters are packed
/// greedily: each consumes as much source as compresses into one pcluster,
/// rounded down to the lcluster boundary so every pcluster starts on an
/// lcluster (clusterofs 0); at `at_eof` the final partial lcluster is taken
/// whole. Windows that cannot save a block are stored as per-lcluster
/// PLAIN. Compressed payloads are tail-aligned in their pcluster
/// (ZERO_PADDING). Index block addresses are relative to the segment; the
/// committer adds the segment's position.
fn z_compress_segment(
    src: Vec<u8>,
    at_eof: bool,
    pcluster: usize,
    compressor: &mut ZCompressor,
) -> ZSegment {
    use nydus_format::erofs::{
        Z_EROFS_LCLUSTER_TYPE_HEAD1, Z_EROFS_LCLUSTER_TYPE_NONHEAD, Z_EROFS_LCLUSTER_TYPE_PLAIN,
        Z_EROFS_LI_D0_CBLKCNT,
    };
    let block_size = EROFS_BLOCK_SIZE as usize;
    let mut data = Vec::with_capacity(src.len() / 2 + pcluster);
    let mut indexes = Vec::with_capacity(src.len() / block_size * Z_EROFS_LCLUSTER_INDEX_SIZE);
    let mut rel_blk: u32 = 0;
    let mut pos = 0;
    let mut suggested_len = 4 * pcluster;
    while pos < src.len() {
        let pending = &src[pos..];
        let (take, compressed_len, dst) =
            compressor.fit_pcluster(pending, at_eof, pcluster, suggested_len);
        suggested_len = take;

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
        // A pcluster never exceeds `pcluster` (< CBLKCNT blocks) bytes.
        let cblkcnt = phys_blocks as u16;

        // Lcluster indexes for this pcluster. An incompressible window
        // becomes per-lcluster single-block PLAIN pclusters (the layout
        // mkfs.erofs emits); multi-block raw pclusters are avoided.
        if head_type == Z_EROFS_LCLUSTER_TYPE_PLAIN {
            for i in 0..lclusters {
                indexes.extend_from_slice(&Z_EROFS_LCLUSTER_TYPE_PLAIN.to_le_bytes());
                indexes.extend_from_slice(&0u16.to_le_bytes());
                indexes.extend_from_slice(&(rel_blk + i as u32).to_le_bytes());
            }
        } else {
            for i in 0..lclusters {
                if i == 0 {
                    indexes.extend_from_slice(&head_type.to_le_bytes());
                    indexes.extend_from_slice(&0u16.to_le_bytes()); // clusterofs
                    indexes.extend_from_slice(&rel_blk.to_le_bytes());
                } else {
                    let delta0 = if i == 1 {
                        Z_EROFS_LI_D0_CBLKCNT | cblkcnt
                    } else {
                        i as u16
                    };
                    let delta1 = (lclusters - 1 - i) as u16;
                    indexes.extend_from_slice(&Z_EROFS_LCLUSTER_TYPE_NONHEAD.to_le_bytes());
                    indexes.extend_from_slice(&0u16.to_le_bytes());
                    indexes.extend_from_slice(&delta0.to_le_bytes());
                    indexes.extend_from_slice(&delta1.to_le_bytes());
                }
            }
        }

        // Pcluster payload: compressed data tail-aligned (ZERO_PADDING),
        // raw data head-aligned with tail-block zero padding.
        if head_type == Z_EROFS_LCLUSTER_TYPE_HEAD1 {
            data.resize(data.len() + phys_blocks * block_size - compressed_len, 0);
            data.extend_from_slice(&dst[..compressed_len]);
        } else {
            data.extend_from_slice(&pending[..take]);
            data.resize(data.len() + phys_blocks * block_size - take, 0);
        }

        rel_blk += phys_blocks as u32;
        pos += take;
    }
    ZSegment {
        data,
        indexes,
        phys_blocks: rel_blk,
        src,
    }
}

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

/// Per-file z_erofs metadata produced by [`BlobWriter::write_reader_z`]:
/// the inode tail (map header plus full lcluster indexes) and the file's
/// compressed block count for the inode `i_u` field.
#[derive(Clone, Debug)]
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
            z_pcluster: 0,
            z_algorithm: ZAlgorithm::Lz4,
            z_base_blkaddr: 0,
            z_next_blkaddr: 0,
            z_pipeline: None,
            z_open_files: VecDeque::new(),
            z_frag_threshold: 0,
            z_packed: None,
            z_fragment_dedup: true,
            dense: false,
            pack_threshold: 0,
            pack: None,
            pack_layout: Vec::new(),
            dense_group_end: 0,
            dense_next_group_block: 0,
            dense_group_spans: VecDeque::new(),
        })
    }

    /// Enables dense block groups: chunk bytes are encoded back to back
    /// without tail-block padding, and regular files of at most
    /// `pack_threshold` bytes (zero packs nothing; at most the chunk size)
    /// are bundled into pack chunks. Must be set before any data is written.
    pub fn set_dense(&mut self, pack_threshold: u64) -> Result<()> {
        if self.next_blkaddr != 0 || !self.block_group_buffer.is_empty() {
            return Err(Error::InvalidParameter(
                "dense block groups must be enabled before writing data".to_string(),
            ));
        }
        if pack_threshold > self.file_chunk_size as u64 {
            return Err(Error::InvalidParameter(format!(
                "pack threshold {pack_threshold} exceeds the {}-byte chunk size",
                self.file_chunk_size
            )));
        }
        self.dense = true;
        self.pack_threshold = pack_threshold;
        Ok(())
    }

    /// Whether dense block groups are enabled.
    pub fn is_dense(&self) -> bool {
        self.dense
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

    /// Enables z_erofs mode: file data is compressed with `algorithm` into
    /// pclusters of at most `pcluster` bytes (a power-of-two multiple of the
    /// block size) and addressed from `blkaddr_base` in the final
    /// single-device image.
    pub fn set_z_erofs(
        &mut self,
        algorithm: ZAlgorithm,
        pcluster: u32,
        blkaddr_base: u64,
    ) -> Result<()> {
        if !pcluster.is_power_of_two() || pcluster % EROFS_BLOCK_SIZE != 0 {
            return Err(Error::InvalidParameter(
                "z_erofs pcluster size must be a power of two and block-aligned".to_string(),
            ));
        }
        self.z_pcluster = pcluster;
        self.z_algorithm = algorithm;
        self.z_base_blkaddr = blkaddr_base;
        self.z_next_blkaddr = blkaddr_base;
        Ok(())
    }

    pub fn z_erofs_enabled(&self) -> bool {
        self.z_pcluster != 0
    }

    /// The superblock compression config this writer's pclusters need.
    pub fn z_compr_cfgs(&self) -> ZComprCfgs {
        match self.z_algorithm {
            ZAlgorithm::Lz4 => ZComprCfgs {
                lz4_max_pclusterblks: Some((self.z_pcluster / EROFS_BLOCK_SIZE) as u16),
                zstd_windowlog: None,
            },
            ZAlgorithm::Zstd => ZComprCfgs {
                lz4_max_pclusterblks: None,
                zstd_windowlog: Some(Z_ZSTD_WINDOWLOG),
            },
        }
    }

    /// Enables z_erofs fragments (kernel 6.1+): regular files of at most
    /// `threshold` bytes are packed together, sharing offsets for identical
    /// SHA256 content digests and sizes, and compressed as one packed inode,
    /// finished by [`Self::finish_z_packed`]. Requires z_erofs
    /// mode; zero disables fragments.
    pub fn set_z_fragments(&mut self, threshold: u64) -> Result<()> {
        if threshold == 0 {
            self.z_frag_threshold = 0;
            self.z_packed = None;
            return Ok(());
        }
        if !self.z_erofs_enabled() {
            return Err(Error::InvalidParameter(
                "z_erofs fragments require z_erofs mode".to_string(),
            ));
        }
        self.z_frag_threshold = threshold;
        self.z_packed = Some(ZPackedStream {
            buf: Vec::new(),
            size: 0,
            accum: ZAccum::new(self.z_algorithm, ZFileRef::pending()),
            fragments: HashMap::new(),
        });
        Ok(())
    }

    /// Enables or disables sharing packed offsets between identical
    /// fragments; the setting applies to fragments packed afterwards.
    pub fn set_z_fragment_dedup(&mut self, dedup: bool) {
        self.z_fragment_dedup = dedup;
    }

    /// Appends a small file to the packed stream (submitting every full
    /// segment that results) and returns its inode tail: just the 8-byte
    /// fragment header (offset | flag), no lcluster indexes.
    fn write_reader_fragment(&mut self, reader: &mut dyn Read, file_size: u64) -> Result<ZFileRef> {
        let packed = self
            .z_packed
            .as_mut()
            .expect("fragments enabled implies a packed stream");
        let mut offset = packed.size;
        if offset & Z_EROFS_FRAGMENT_INODE_FLAG != 0 {
            return Err(Error::Overflow(
                "fragment offset exceeds 63 bits".to_string(),
            ));
        }
        let start = packed.buf.len();
        packed.buf.resize(start + file_size as usize, 0);
        if let Err(error) = reader.read_exact(&mut packed.buf[start..]) {
            packed.buf.truncate(start);
            return Err(error).context("failed to read source data");
        }
        if self.z_fragment_dedup {
            let digest: [u8; 32] = Sha256::digest(&packed.buf[start..]).into();
            if let Some(existing) = packed.fragments.get(&(digest, file_size)) {
                offset = *existing;
                packed.buf.truncate(start);
            } else {
                packed.fragments.insert((digest, file_size), offset);
                packed.size += file_size;
            }
        } else {
            packed.size += file_size;
        }
        // Committing may land packed segments, so the stream stays in place
        // while full segments are submitted.
        loop {
            let packed = self.z_packed.as_mut().expect("checked above");
            if packed.buf.len() < Z_SEGMENT_SIZE {
                break;
            }
            let rest = packed.buf.split_off(Z_SEGMENT_SIZE);
            let segment = mem::replace(&mut packed.buf, rest);
            self.z_submit(segment, ZTarget::Packed, false, 0)?;
        }
        Ok(ZFileRef::ready(ZFileMeta {
            tail: (offset | Z_EROFS_FRAGMENT_INODE_FLAG)
                .to_le_bytes()
                .to_vec(),
            compressed_blocks: 0,
        }))
    }

    /// Flushes the packed inode's last pclusters and returns its metadata plus
    /// uncompressed size, or `None` when no file was packed. Must be called
    /// once, after all files were written; it commits every segment still in
    /// flight. The stream is zero-padded to a whole number of blocks first so
    /// `merge` can concatenate the packed inodes of several layers on the
    /// lcluster grid.
    pub fn finish_z_packed(&mut self) -> Result<Option<(ZFileMeta, u64)>> {
        let Some(mut packed) = self.z_packed.take() else {
            return Ok(None);
        };
        self.z_frag_threshold = 0;
        if packed.size == 0 {
            return Ok(None);
        }
        let padded = packed.size.next_multiple_of(EROFS_BLOCK_SIZE as u64);
        packed
            .buf
            .resize(packed.buf.len() + (padded - packed.size) as usize, 0);
        packed.size = padded;
        // Segments are committed into the packed accumulator, so it must be
        // in place while the pipeline drains.
        let final_segment = mem::take(&mut packed.buf);
        self.z_packed = Some(packed);
        if !final_segment.is_empty() {
            self.z_submit(final_segment, ZTarget::Packed, true, 0)?;
        }
        self.z_drain_all()?;
        let packed = self.z_packed.take().expect("packed stream restored above");
        Ok(Some((packed.accum.into_meta()?, packed.size)))
    }

    /// End of the compressed data region (absolute block address). Only
    /// final once every segment was committed (after `finish`).
    pub fn z_end_blkaddr(&self) -> u64 {
        self.z_next_blkaddr
    }

    /// [`Self::write_reader_z`] for a file on disk.
    pub fn write_file_z(&mut self, path: &Path, file_size: u64) -> Result<ZFileRef> {
        let mut f = File::open(path)
            .with_context(|| format!("failed to open source file: {}", path.display()))?;
        self.write_reader_z(&mut f, file_size)
            .with_context(|| format!("failed to compress source file: {}", path.display()))
    }

    /// Compresses exactly `file_size` bytes from `reader` into z_erofs LZ4
    /// pclusters: the data is cut into [`Z_SEGMENT_SIZE`] segments handed to
    /// the compression workers, and committed to the output in order as the
    /// caller keeps producing. The returned handle resolves to the inode
    /// tail (map header + full lcluster indexes) and compressed block count
    /// once the blob is finished. Files up to the fragment threshold are
    /// packed instead (see [`Self::write_reader_fragment`]).
    pub fn write_reader_z(&mut self, reader: &mut dyn Read, file_size: u64) -> Result<ZFileRef> {
        if self.z_frag_threshold != 0 && file_size > 0 && file_size <= self.z_frag_threshold {
            return self.write_reader_fragment(reader, file_size);
        }
        let handle = ZFileRef::pending();
        if file_size == 0 {
            let meta = ZAccum::new(self.z_algorithm, handle.clone()).into_meta()?;
            handle.set(meta);
            return Ok(handle);
        }
        // Aligned placement (dedup phase): the committer pads the compressed
        // stream with zero blocks so large files start on a `data_alignment`
        // boundary of the device data (not of the image: the device is its
        // own file on the volume, and merge may map it anywhere), keeping
        // their pclusters on the volume dedup grid.
        let align_blocks = if self.data_alignment != 0 && file_size >= self.data_alignment_threshold
        {
            (self.data_alignment / EROFS_BLOCK_SIZE) as u64
        } else {
            0
        };
        self.z_open_files
            .push_back(ZAccum::new(self.z_algorithm, handle.clone()));
        let mut left = file_size;
        let mut first = true;
        while left > 0 {
            let len = left.min(Z_SEGMENT_SIZE as u64) as usize;
            let mut src = self.z_pipeline().take_buffer();
            src.resize(len, 0);
            reader
                .read_exact(&mut src)
                .context("failed to read source data")?;
            left -= len as u64;
            self.z_submit(
                src,
                ZTarget::File,
                left == 0,
                if first { align_blocks } else { 0 },
            )?;
            first = false;
        }
        Ok(handle)
    }

    fn z_pipeline(&mut self) -> &mut ZPipeline {
        let pcluster = self.z_pcluster as usize;
        let algorithm = self.z_algorithm;
        self.z_pipeline
            .get_or_insert_with(|| ZPipeline::new(algorithm, pcluster))
    }

    /// Segments the pipeline holds before the producer must commit one.
    #[cfg(test)]
    pub(crate) fn z_max_in_flight(&mut self) -> usize {
        self.z_pipeline().max_in_flight()
    }

    /// Hands a segment to the workers, committing finished ones first when
    /// too many are in flight.
    fn z_submit(
        &mut self,
        src: Vec<u8>,
        target: ZTarget,
        at_eof: bool,
        align_blocks: u64,
    ) -> Result<()> {
        while self.z_pipeline().in_flight() >= self.z_pipeline().max_in_flight() {
            self.z_commit_next()?;
        }
        self.z_pipeline().submit(
            src,
            ZPending {
                target,
                at_eof,
                align_blocks,
            },
        )
    }

    /// Commits every segment in flight.
    fn z_drain_all(&mut self) -> Result<()> {
        while self.z_pipeline.as_ref().is_some_and(|p| p.in_flight() > 0) {
            self.z_commit_next()?;
        }
        Ok(())
    }

    /// Commits the next segment in submission order: pads for alignment,
    /// writes its pclusters at the current address, rebases its lcluster
    /// indexes onto that address and appends them to the owning inode, and
    /// publishes the inode's metadata when this was its last segment.
    fn z_commit_next(&mut self) -> Result<()> {
        use nydus_format::erofs::{Z_EROFS_LCLUSTER_TYPE_NONHEAD, Z_EROFS_LI_LCLUSTER_TYPE_MASK};
        let block_size = EROFS_BLOCK_SIZE as usize;
        let (mut segment, placement) = self.z_pipeline().recv_next()?;
        if placement.align_blocks != 0 {
            let offset = self.z_next_blkaddr - self.z_base_blkaddr;
            let gap = offset.next_multiple_of(placement.align_blocks) - offset;
            if gap > 0 {
                self.write_z_padding(gap as usize * block_size)?;
                self.z_next_blkaddr += gap;
            }
        }
        let base = u32::try_from(self.z_next_blkaddr).map_err(|err| {
            Error::Overflow(format!("z_erofs pcluster address exceeds u32: {err}"))
        })?;
        for index in segment
            .indexes
            .chunks_exact_mut(Z_EROFS_LCLUSTER_INDEX_SIZE)
        {
            let advise = u16::from_le_bytes([index[0], index[1]]);
            if advise & Z_EROFS_LI_LCLUSTER_TYPE_MASK == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                continue;
            }
            let rel = u32::from_le_bytes(index[4..8].try_into().expect("4-byte blkaddr"));
            let abs = base.checked_add(rel).ok_or_else(|| {
                Error::Overflow("z_erofs pcluster address exceeds u32".to_string())
            })?;
            index[4..8].copy_from_slice(&abs.to_le_bytes());
        }
        self.writer
            .write_all(&segment.data)
            .context("failed to write z_erofs pclusters")?;
        self.z_next_blkaddr += segment.phys_blocks as u64;

        let accum = match placement.target {
            ZTarget::File => self
                .z_open_files
                .front_mut()
                .ok_or_else(|| Error::Runtime("z_erofs segment without an inode".to_string()))?,
            ZTarget::Packed => {
                &mut self
                    .z_packed
                    .as_mut()
                    .ok_or_else(|| Error::Runtime("packed segment after finish".to_string()))?
                    .accum
            }
        };
        accum.tail.extend_from_slice(&segment.indexes);
        accum.blocks += segment.phys_blocks as u64;
        if placement.at_eof && placement.target == ZTarget::File {
            let accum = self.z_open_files.pop_front().expect("checked above");
            let handle = accum.handle.clone();
            handle.set(accum.into_meta()?);
        }
        let src = mem::take(&mut segment.src);
        self.z_pipeline().recycle_buffer(src);
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

        if self.dense {
            return Ok(BlobMetadata::new_dense(
                self.compressor,
                self.digester,
                self.file_chunk_size / EROFS_BLOCK_SIZE,
                self.block_group_size / EROFS_BLOCK_SIZE,
                self.blob_metadata_chunks.clone(),
                block_groups,
                self.pack_layout.clone(),
                false,
                BlobMetadataFlags::empty(),
            )?);
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
        self.flush_pack()?;
        // The padded data stream is byte granular, so the tail block group
        // must be zero padded to a whole block before it is flushed (block
        // groups always describe whole uncompressed blocks). Dense groups
        // carry no padding: their span rounds up on its own.
        if !self.dense && !self.block_group_buffer.is_empty() {
            let padded =
                align_up_usize(self.block_group_buffer.len(), EROFS_BLOCK_SIZE as usize)
                    .ok_or_else(|| Error::Overflow("block group padding overflow".to_string()))?;
            self.block_group_buffer.resize(padded, 0);
        }
        self.flush_block_group()?;
        self.drain_all_encoded()?;
        self.z_drain_all()?;
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

        // Dense mode bundles small files into pack chunks; anything else
        // closes the open pack first so the encoded stream, the chunk table
        // and the padded address space all keep the same order.
        if self.dense && self.pack_threshold > 0 && file_size <= self.pack_threshold {
            let to_read = file_size as usize;
            if let Err(err) = reader
                .read_exact(&mut chunk_buf[..to_read])
                .context("failed to read source data")
            {
                self.chunk_buf = chunk_buf;
                return Err(err);
            }
            let index = if chunk_buf[..to_read].iter().all(|&byte| byte == 0) {
                ErofsChunkAddr {
                    blkaddr: EROFS_NULL_ADDR,
                    device_id: 0,
                }
            } else {
                match self.pack_file(&chunk_buf[..to_read]) {
                    Ok(blkaddr) => ErofsChunkAddr {
                        blkaddr,
                        device_id: 1,
                    },
                    Err(err) => {
                        self.chunk_buf = chunk_buf;
                        return Err(err);
                    }
                }
            };
            self.chunk_buf = chunk_buf;
            return Ok(vec![index]);
        }
        if let Err(err) = self.flush_pack() {
            self.chunk_buf = chunk_buf;
            return Err(err);
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
        // independently of block groups as a digest index only. A padded
        // blob's digest covers the block-aligned payload (real bytes plus
        // tail-block zero padding), hashed in place to avoid materialising a
        // padded copy; a dense blob's covers the bytes it actually stores.
        let digest = match self.digester {
            BlobMetadataDigester::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(data);
                if !self.dense && write_len > data.len() {
                    hasher.update(&ZERO_BLOCK[..write_len - data.len()]);
                }
                *hasher.finalize().as_bytes()
            }
            BlobMetadataDigester::None => [0u8; 32],
        };
        if self.dense {
            let chunk =
                BlobMetadataChunk::new_dense(digest, addr, block_count, data.len() as u32, false)?;
            self.blob_metadata_chunks.push(chunk);
            self.append_dense_piece(data, addr * EROFS_BLOCK_SIZE as u64)?;
            return Ok(addr);
        }
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

    /// Dense mode: append one small file to the open pack (starting a new
    /// pack when there is none or the file would not fit), reserving its
    /// padded blocks, and return the block it starts on.
    fn pack_file(&mut self, data: &[u8]) -> Result<u64> {
        let blocks = data.len().div_ceil(EROFS_BLOCK_SIZE as usize) as u64;
        if self
            .pack
            .as_ref()
            .is_some_and(|pack| pack.bytes.len() + data.len() > self.file_chunk_size as usize)
        {
            self.flush_pack()?;
        }
        let next_blkaddr = self
            .next_blkaddr
            .checked_add(blocks)
            .filter(|count| *count <= u32::MAX as u64)
            .ok_or_else(|| {
                Error::Overflow(format!(
                    "decoded blob exceeds 32-bit block count: start {}, file blocks {blocks}",
                    self.next_blkaddr
                ))
            })?;
        let pack = self.pack.get_or_insert_with(|| PackAccum {
            start_blkaddr: self.next_blkaddr,
            bytes: Vec::with_capacity(self.file_chunk_size as usize),
            file_lens: Vec::new(),
            blocks: 0,
        });
        let blkaddr = pack.start_blkaddr + pack.blocks;
        pack.bytes.extend_from_slice(data);
        pack.file_lens.push(data.len() as u32);
        pack.blocks += blocks;
        self.next_blkaddr = next_blkaddr;
        Ok(blkaddr)
    }

    /// Dense mode: close the open pack into a pack chunk entry, a pack
    /// layout record, and its files' bytes on the group stream.
    fn flush_pack(&mut self) -> Result<()> {
        let Some(pack) = self.pack.take() else {
            return Ok(());
        };
        let digest = match self.digester {
            BlobMetadataDigester::Blake3 => *blake3::hash(&pack.bytes).as_bytes(),
            BlobMetadataDigester::None => [0u8; 32],
        };
        let block_count = u32::try_from(pack.blocks).map_err(|err| {
            Error::Overflow(format!("blob meta pack block count exceeds u32: {err}"))
        })?;
        self.blob_metadata_chunks.push(BlobMetadataChunk::new_dense(
            digest,
            pack.start_blkaddr,
            block_count,
            pack.bytes.len() as u32,
            true,
        )?);
        encode_pack_layout(&pack.file_lens, &mut self.pack_layout);

        // Files go on the stream one by one so every file start is a legal
        // cut point (each starts on its own padded block).
        let mut padded = pack.start_blkaddr * EROFS_BLOCK_SIZE as u64;
        let mut start = 0usize;
        for len in pack.file_lens {
            let end = start + len as usize;
            self.append_dense_piece(&pack.bytes[start..end], padded)?;
            padded += (len as u64).div_ceil(EROFS_BLOCK_SIZE as u64) * EROFS_BLOCK_SIZE as u64;
            start = end;
        }
        Ok(())
    }

    /// Dense mode: append a piece (a chunk or a packed file) whose first
    /// byte sits at padded position `padded_start`, a block boundary. The
    /// group budget is the block group size of dense bytes; when a piece
    /// straddles it, the cut lands on the last block-aligned point within
    /// the piece so every group span stays whole blocks and every block
    /// belongs to exactly one group.
    fn append_dense_piece(&mut self, data: &[u8], padded_start: u64) -> Result<()> {
        let block_group_size = self.block_group_size as usize;
        let block = EROFS_BLOCK_SIZE as usize;
        let mut offset = 0usize;
        while offset < data.len() {
            let space = block_group_size - self.block_group_buffer.len();
            let remaining = data.len() - offset;
            let take = if space >= remaining {
                remaining
            } else {
                space / block * block
            };
            if take == 0 {
                // Only reachable with a non-empty buffer: an empty group has a
                // full budget, which is at least one block.
                self.flush_block_group()?;
                continue;
            }
            self.block_group_buffer
                .extend_from_slice(&data[offset..offset + take]);
            offset += take;
            self.dense_group_end = padded_start + offset as u64;
            if self.block_group_buffer.len() == block_group_size {
                self.flush_block_group()?;
            }
        }
        Ok(())
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
        if self.dense {
            // The span starts where the previous group ended and runs to the
            // block holding the last appended byte.
            let end_block = self.dense_group_end.div_ceil(EROFS_BLOCK_SIZE as u64);
            self.dense_group_spans
                .push_back((self.dense_next_group_block, end_block));
            self.dense_next_group_block = end_block;
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
        let entry = if self.dense {
            let (start_block, end_block) = self
                .dense_group_spans
                .pop_front()
                .expect("every submitted dense group queued its span");
            let span = u32::try_from(end_block - start_block).map_err(|err| {
                Error::Overflow(format!("blob meta block group span exceeds u32: {err}"))
            })?;
            BlobMetadataBlockGroup::new_dense(
                start_block,
                span,
                compressed_offset,
                encoded.len() as u32,
                group.crc32,
                0,
                0,
                false,
                uncompressed_len as u32,
            )?
        } else {
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
            self.block_group_block_offset += block_count as u64;
            entry
        };
        self.blob_metadata_block_groups.push(entry);

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

    /// Dense groups: small files pack back to back, larger files lose their
    /// tail padding, groups cut on block-aligned points and the blob meta
    /// scatters every group back onto the padded blocks the chunk indexes
    /// address.
    #[test]
    fn blob_writer_dense_groups_pack_small_files_and_scatter_back() {
        let block = EROFS_BLOCK_SIZE as usize;
        // 8 KiB chunks, 16 KiB groups: a few files are enough to cross both.
        let mut writer = BlobWriter::from_writer(
            Vec::new(),
            2 * block as u32,
            4 * block as u32,
            BlobMetadataCompressor::None,
        )
        .unwrap();
        writer.set_dense(1000).unwrap();
        let files: Vec<Vec<u8>> = vec![
            pseudo_random_bytes(100),           // packed
            pseudo_random_bytes(900),           // packed, same pack
            pseudo_random_bytes(5000),          // plain chunk, 2 blocks, closes the pack
            pseudo_random_bytes(300),           // packed, new pack
            vec![0u8; 500],                     // all zero: a hole, no bytes stored
            pseudo_random_bytes(3 * block + 7), // two chunks (8 KiB + 4103), 4 blocks
            pseudo_random_bytes(1),             // packed, new pack
        ];
        let mut indexes = Vec::new();
        for file in &files {
            let mut cursor = std::io::Cursor::new(file);
            indexes.push(
                writer
                    .write_reader_chunks(&mut cursor, file.len() as u64)
                    .unwrap(),
            );
        }
        writer.finish().unwrap();
        let blob_metadata = writer.blob_metadata(0).unwrap();
        assert!(blob_metadata.is_dense());

        // Padded placement: 100 -> block 0, 900 -> 1, 5000 -> 2..4, 300 -> 4,
        // hole -> none, 12295 -> 5..9, 1 -> 9; ten blocks in all.
        let addrs: Vec<Vec<u64>> = indexes
            .iter()
            .map(|index| index.iter().map(|i| i.blkaddr).collect())
            .collect();
        assert_eq!(addrs[0], vec![0]);
        assert_eq!(addrs[1], vec![1]);
        assert_eq!(addrs[2], vec![2]);
        assert_eq!(addrs[3], vec![4]);
        assert_eq!(addrs[4], vec![EROFS_NULL_ADDR]);
        assert_eq!(addrs[5], vec![5, 7]);
        assert_eq!(addrs[6], vec![9]);
        assert_eq!(writer.total_blocks(), 10);
        assert_eq!(blob_metadata.uncompressed_size(), 10 * block as u64);

        // Chunk table: pack(100+900), chunk 5000, pack(300), chunk 8192,
        // chunk 4103, pack(1). The dense stream is their bytes back to back.
        let chunks = blob_metadata.chunks();
        let expect: [(bool, u32, u64, u32); 6] = [
            (true, 1000, 0, 2),
            (false, 5000, 2, 2),
            (true, 300, 4, 1),
            (false, 2 * block as u32, 5, 2),
            (false, block as u32 + 7, 7, 2),
            (true, 1, 9, 1),
        ];
        assert_eq!(chunks.len(), expect.len());
        for (chunk, (pack, len, addr, blocks)) in chunks.iter().zip(expect) {
            assert_eq!(chunk.is_pack(), pack);
            assert_eq!(chunk.byte_len(), len);
            assert_eq!(chunk.uncompressed_block_offset(), addr);
            assert_eq!(chunk.uncompressed_block_count(), blocks);
        }
        assert_eq!(
            blob_metadata
                .pack_files(0)
                .unwrap()
                .collect::<nydus_format::error::Result<Vec<_>>>()
                .unwrap(),
            vec![100, 900]
        );

        // Groups: 16 KiB of dense bytes each, cut on block-aligned points.
        // Stream: 1000 | 5000 | 300 | 8192 | 4103 | 1 = 18596 bytes. After
        // 1000 + 5000 + 300 + 8192 = 14492 bytes only 1892 remain in the
        // budget, and the 4103-byte chunk has no block-aligned cut below
        // 4096, so the first group closes there (within a block of full)
        // and the rest goes to the last group.
        let groups = blob_metadata.block_groups();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].dense_size(), 14492);
        assert_eq!(groups[0].uncompressed_block_offset(), 0);
        assert_eq!(groups[0].uncompressed_block_count(), 7);
        assert_eq!(groups[1].dense_size(), 4104);
        assert_eq!(groups[1].uncompressed_block_offset(), 7);
        assert_eq!(groups[1].uncompressed_block_count(), 3);
        let total_dense: u64 = groups.iter().map(|g| g.dense_size() as u64).sum();
        assert_eq!(total_dense, 18596);
        assert_eq!(
            blob_metadata.block_group_index_from_uncompressed_offset(6 * block as u64 + 4095),
            Some(0)
        );
        assert_eq!(
            blob_metadata.block_group_index_from_uncompressed_offset(7 * block as u64),
            Some(1)
        );

        // Stored plain (compressor None): the data region is the dense
        // stream. Scatter every group and compare with the files.
        let (data, _) = writer.into_parts();
        assert_eq!(data.len(), 18596);
        let mut padded = vec![0u8; 10 * block];
        for (index, group) in groups.iter().enumerate() {
            let start = group.compressed_offset() as usize;
            let payload = &data[start..start + group.compressed_size() as usize];
            assert_eq!(crc32c(payload), group.crc32());
            blob_metadata
                .for_each_decoded_piece(index, payload, &mut |offset, bytes| {
                    padded[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
                    Ok(())
                })
                .unwrap();
        }
        for (file, addrs) in files.iter().zip(&addrs) {
            let mut expected = Vec::new();
            for (i, addr) in addrs.iter().enumerate() {
                let len = (file.len() - i * 2 * block).min(2 * block);
                if *addr == EROFS_NULL_ADDR {
                    expected.extend(vec![0u8; len]);
                } else {
                    let start = *addr as usize * block;
                    expected.extend_from_slice(&padded[start..start + len]);
                }
            }
            assert_eq!(&expected, file);
        }
        // Tail padding stays zero.
        assert!(padded[100..block].iter().all(|b| *b == 0));
        assert!(padded[4 * block + 300..5 * block].iter().all(|b| *b == 0));
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
        z_writer_with(ZAlgorithm::Lz4)
    }

    fn z_writer_with(algorithm: ZAlgorithm) -> BlobWriter<Vec<u8>> {
        let mut writer = BlobWriter::from_writer(
            Vec::new(),
            EROFS_BLOCK_SIZE,
            1 << 20,
            BlobMetadataCompressor::None,
        )
        .unwrap();
        writer
            .set_z_erofs(algorithm, 16 * EROFS_BLOCK_SIZE, Z_BASE)
            .unwrap();
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
                    let payload = &pcluster[payload_start..];
                    let decoded = match ZAlgorithm::from_type(tail[6] & 0x0f).unwrap() {
                        ZAlgorithm::Lz4 => lz4_flex::block::decompress(payload, logical).unwrap(),
                        ZAlgorithm::Zstd => zstd::bulk::decompress(payload, logical).unwrap(),
                    };
                    assert_eq!(decoded.len(), logical);
                    out.extend_from_slice(&decoded);
                    i = j;
                }
                other => panic!("unexpected lcluster type {other}"),
            }
        }
        out
    }

    #[test]
    fn z_erofs_zstd_hints_handle_entropy_changes_and_worker_reuse() {
        let pcluster = 16 * BLOCK;
        let mut source = pseudo_random_bytes(1 << 20);
        source[..256 << 10].fill(0);
        source[512 << 10..768 << 10].fill(0x33);
        source.extend_from_slice(&pseudo_random_bytes(BLOCK + 37));
        let mut writer = z_writer_with(ZAlgorithm::Zstd);
        let handle = writer
            .write_reader_z(&mut &source[..], source.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        let meta = handle.resolve().unwrap();
        let (data, _) = writer.into_parts();
        assert_eq!(decode_z_file(&data, &meta.tail, source.len()), source);

        for at_eof in [false, true] {
            let mut input = source.clone();
            if !at_eof {
                input.truncate(input.len() / BLOCK * BLOCK);
            }
            let mut compressor = ZCompressor::new(ZAlgorithm::Zstd, pcluster);
            let first = z_compress_segment(input.clone(), at_eof, pcluster, &mut compressor);
            z_compress_segment(vec![0; Z_SEGMENT_SIZE], false, pcluster, &mut compressor);
            z_compress_segment(
                pseudo_random_bytes(Z_SEGMENT_SIZE),
                false,
                pcluster,
                &mut compressor,
            );
            let repeated = z_compress_segment(input, at_eof, pcluster, &mut compressor);
            assert_eq!(first.data, repeated.data);
            assert_eq!(first.indexes, repeated.indexes);
            assert_eq!(first.phys_blocks, repeated.phys_blocks);
        }

        let mut compressor = ZCompressor::new(ZAlgorithm::Zstd, pcluster);
        for suggested_len in [0, 1, pcluster, usize::MAX] {
            let (take, size, compressed) =
                compressor.fit_pcluster(&source, true, pcluster, suggested_len);
            assert!(take > 0 && take <= source.len());
            assert!(take == source.len() || take % BLOCK == 0);
            assert!(size <= pcluster);
            assert_eq!(
                zstd::bulk::decompress(&compressed[..size], take).unwrap(),
                source[..take]
            );
        }
    }

    #[test]
    fn z_erofs_zstd_pclusters_round_trip_and_declare_the_algorithm() {
        let mut writer = z_writer_with(ZAlgorithm::Zstd);
        assert_eq!(
            writer.z_compr_cfgs(),
            ZComprCfgs {
                lz4_max_pclusterblks: None,
                zstd_windowlog: Some(Z_ZSTD_WINDOWLOG),
            }
        );
        // Noise (PLAIN), a compressible run (multi-block pclusters), and a
        // file past the segment size so several segments are joined.
        let noise = pseudo_random_bytes(2 * BLOCK + 17);
        let mut mixed = pseudo_random_bytes(1 << 20);
        for block in mixed.chunks_exact_mut(BLOCK) {
            block[BLOCK / 8..].fill(0x33);
        }
        let mut long = Vec::with_capacity(Z_SEGMENT_SIZE + BLOCK);
        while long.len() < Z_SEGMENT_SIZE + BLOCK {
            long.extend_from_slice(&pseudo_random_bytes(3 * BLOCK)[..BLOCK]);
            long.extend(std::iter::repeat_n(0x7eu8, 5 * BLOCK));
        }
        long.truncate(Z_SEGMENT_SIZE + BLOCK + 99);
        let handles = [&noise, &mixed, &long].map(|src| {
            writer
                .write_reader_z(&mut &src[..], src.len() as u64)
                .unwrap()
        });
        writer.finish().unwrap();
        let metas = handles.map(|h| h.resolve().unwrap());
        let (data, _) = writer.into_parts();

        for meta in &metas {
            assert_eq!(meta.tail[6], ZAlgorithm::Zstd.as_type());
        }
        let noise_indexes = lclusters(&metas[0].tail);
        assert!(noise_indexes
            .iter()
            .all(|(kind, ..)| *kind == Z_EROFS_LCLUSTER_TYPE_PLAIN));
        let heads = lclusters(&metas[1].tail)
            .iter()
            .filter(|(kind, ..)| *kind == Z_EROFS_LCLUSTER_TYPE_HEAD1)
            .count();
        assert!(heads > 1 && heads < 256, "{heads} zstd pclusters");
        assert!(
            metas[1].compressed_blocks < 128,
            "compressed to less than half"
        );
        let total: u32 = metas.iter().map(|m| m.compressed_blocks).sum();
        assert_eq!(data.len(), total as usize * BLOCK);
        assert_eq!(decode_z_file(&data, &metas[0].tail, noise.len()), noise);
        assert_eq!(decode_z_file(&data, &metas[1].tail, mixed.len()), mixed);
        assert_eq!(decode_z_file(&data, &metas[2].tail, long.len()), long);
    }

    #[test]
    fn z_erofs_incompressible_data_becomes_per_block_plain_lclusters() {
        let mut writer = z_writer();
        let src = pseudo_random_bytes(3 * BLOCK + 100);
        let meta = writer
            .write_reader_z(&mut &src[..], src.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        let meta = meta.resolve().unwrap();
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
    fn z_erofs_compressible_data_packs_big_pclusters_with_cblkcnt() {
        let mut writer = z_writer();
        // A quarter noise, the rest zeros per block: roughly 4:1 (LZ4 stores
        // the noise as literals), so 1MiB needs several multi-block
        // pclusters.
        let mut src = pseudo_random_bytes(1 << 20);
        for block in src.chunks_exact_mut(BLOCK) {
            block[BLOCK / 4..].fill(0);
        }
        let meta = writer
            .write_reader_z(&mut &src[..], src.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        let meta = meta.resolve().unwrap();
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
    fn z_erofs_files_larger_than_the_window_buffer_round_trip() {
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
            .write_reader_z(&mut &src[..], src.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        let meta = meta.resolve().unwrap();
        let (data, _) = writer.into_parts();
        assert_eq!(data.len(), meta.compressed_blocks as usize * BLOCK);
        assert_eq!(decode_z_file(&data, &meta.tail, src.len()), src);
    }

    #[test]
    fn z_erofs_alignment_pads_files_at_or_above_the_threshold() {
        let mut writer = z_writer();
        writer
            .set_data_alignment(8 * EROFS_BLOCK_SIZE, 2 * BLOCK as u64)
            .unwrap();
        let small = pseudo_random_bytes(BLOCK);
        let big = pseudo_random_bytes(3 * BLOCK);
        let small_meta = writer
            .write_reader_z(&mut &small[..], small.len() as u64)
            .unwrap();
        let big_meta = writer
            .write_reader_z(&mut &big[..], big.len() as u64)
            .unwrap();
        let again = writer
            .write_reader_z(&mut &small[..], small.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        let (small_meta, big_meta, again) = (
            small_meta.resolve().unwrap(),
            big_meta.resolve().unwrap(),
            again.resolve().unwrap(),
        );
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
    fn z_erofs_fragments_pack_small_files_into_a_block_padded_packed_inode() {
        let mut writer = z_writer();
        writer.set_z_fragments(BLOCK as u64).unwrap();
        let a = b"first small file".to_vec();
        let b = pseudo_random_bytes(BLOCK);
        let c = b"third".to_vec();
        let big = pseudo_random_bytes(BLOCK + 1);
        let empty: Vec<u8> = Vec::new();
        let ma = writer.write_reader_z(&mut &a[..], a.len() as u64).unwrap();
        let mb = writer.write_reader_z(&mut &b[..], b.len() as u64).unwrap();
        let mbig = writer
            .write_reader_z(&mut &big[..], big.len() as u64)
            .unwrap();
        let mc = writer.write_reader_z(&mut &c[..], c.len() as u64).unwrap();
        let mempty = writer.write_reader_z(&mut &empty[..], 0).unwrap();
        let (packed, packed_size) = writer.finish_z_packed().unwrap().unwrap();
        assert!(writer.finish_z_packed().unwrap().is_none(), "flushed once");
        writer.finish().unwrap();
        let (ma, mb, mbig, mc, mempty) = (
            ma.resolve().unwrap(),
            mb.resolve().unwrap(),
            mbig.resolve().unwrap(),
            mc.resolve().unwrap(),
            mempty.resolve().unwrap(),
        );
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

    #[test]
    fn z_erofs_fragments_reuse_content_after_segments_are_committed() {
        for algorithm in [ZAlgorithm::Lz4, ZAlgorithm::Zstd] {
            let mut writer = z_writer_with(algorithm);
            writer.set_z_fragments(64 << 10).unwrap();
            let content = pseudo_random_bytes(64 << 10);
            let original = writer
                .write_reader_z(&mut &content[..], content.len() as u64)
                .unwrap();
            let mut distinct = content.clone();
            for index in 0..(Z_SEGMENT_SIZE * 2 / content.len()) {
                distinct[..8].copy_from_slice(&(index as u64).to_le_bytes());
                writer
                    .write_reader_z(&mut &distinct[..], distinct.len() as u64)
                    .unwrap();
            }
            let size_before = writer.z_packed.as_ref().unwrap().size;
            let duplicate = writer
                .write_reader_z(&mut &content[..], content.len() as u64)
                .unwrap();
            assert_eq!(
                original.resolve().unwrap().tail,
                duplicate.resolve().unwrap().tail
            );
            assert_eq!(writer.z_packed.as_ref().unwrap().size, size_before);
            assert!(writer
                .write_reader_z(&mut &content[..100], content.len() as u64)
                .is_err());
            assert_eq!(writer.z_packed.as_ref().unwrap().size, size_before);
            let retried = writer
                .write_reader_z(&mut &content[..], content.len() as u64)
                .unwrap();
            assert_eq!(
                original.resolve().unwrap().tail,
                retried.resolve().unwrap().tail
            );
            let (packed, packed_size) = writer.finish_z_packed().unwrap().unwrap();
            writer.finish().unwrap();
            let (data, _) = writer.into_parts();
            let decoded = decode_z_file(&data, &packed.tail, packed_size as usize);
            assert_eq!(&decoded[..content.len()], &content);
            for (index, chunk) in decoded[content.len()..]
                .chunks_exact(content.len())
                .enumerate()
            {
                distinct[..8].copy_from_slice(&(index as u64).to_le_bytes());
                assert_eq!(chunk, &distinct);
            }
        }
    }

    #[test]
    fn z_erofs_fragments_store_identical_content_separately_without_dedup() {
        let mut writer = z_writer_with(ZAlgorithm::Lz4);
        writer.set_z_fragments(64 << 10).unwrap();
        writer.set_z_fragment_dedup(false);
        let content = pseudo_random_bytes(4096 + 7);
        let first = writer
            .write_reader_z(&mut &content[..], content.len() as u64)
            .unwrap();
        let second = writer
            .write_reader_z(&mut &content[..], content.len() as u64)
            .unwrap();
        assert_ne!(
            first.resolve().unwrap().tail,
            second.resolve().unwrap().tail
        );
        let (packed, packed_size) = writer.finish_z_packed().unwrap().unwrap();
        writer.finish().unwrap();
        let (data, _) = writer.into_parts();
        assert_eq!(
            packed_size as usize,
            (2 * content.len()).next_multiple_of(BLOCK)
        );
        let decoded = decode_z_file(&data, &packed.tail, packed_size as usize);
        assert_eq!(&decoded[..content.len()], &content);
        assert_eq!(&decoded[content.len()..2 * content.len()], &content);
    }

    #[test]
    fn z_erofs_fragments_beyond_the_pipeline_depth_commit_while_packing() {
        let mut writer = z_writer();
        writer.set_z_fragments(64 << 10).unwrap();
        // Enough small files to fill more segments than the pipeline holds,
        // so submitting a packed segment has to commit an earlier packed one
        // while the packed stream is being appended to.
        let segments = writer.z_max_in_flight() + 2;
        let mut file = pseudo_random_bytes(64 << 10);
        let count = segments * Z_SEGMENT_SIZE / file.len();
        let handles = (0..count)
            .map(|index| {
                file[..8].copy_from_slice(&(index as u64).to_le_bytes());
                writer
                    .write_reader_z(&mut &file[..], file.len() as u64)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let (packed, packed_size) = writer.finish_z_packed().unwrap().unwrap();
        writer.finish().unwrap();
        let (data, _) = writer.into_parts();

        assert_eq!(packed_size as usize, count * file.len());
        for (i, handle) in handles.iter().enumerate() {
            let meta = handle.resolve().unwrap();
            let head = u64::from_le_bytes(meta.tail[..].try_into().unwrap());
            assert_eq!(head ^ Z_EROFS_FRAGMENT_INODE_FLAG, (i * file.len()) as u64);
        }
        let decoded = decode_z_file(&data, &packed.tail, packed_size as usize);
        for (index, chunk) in decoded.chunks_exact(file.len()).enumerate() {
            file[..8].copy_from_slice(&(index as u64).to_le_bytes());
            assert_eq!(chunk, &file);
        }
    }
}
