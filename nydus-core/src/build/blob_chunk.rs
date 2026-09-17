use crc32c::crc32c;
use nydus_error::{Context, Error, Result};
use nydus_format::blob::{
    BlobMetadata, BlobMetadataChunkGroup, BlobMetadataCompressor, BlobMetadataDigest,
    BlobMetadataDigester,
};
use nydus_format::erofs::{
    ErofsChunkAddr, ZAlgorithm, ZComprCfgs, EROFS_BLOB_ID_SIZE, EROFS_BLOCK_SIZE, EROFS_NULL_ADDR,
    Z_EROFS_FRAGMENT_INODE_FLAG, Z_EROFS_LCLUSTER_INDEX_SIZE,
};
use nydus_format::utils::write_zeros;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io::{Read, Write};
use std::mem;
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;

pub fn validate_chunk_size(chunk_size: u32) -> Result<()> {
    if chunk_size < EROFS_BLOCK_SIZE {
        return Err(Error::InvalidParameter(format!(
            "chunk size {chunk_size} must be >= block size {EROFS_BLOCK_SIZE}"
        )));
    }
    if !chunk_size.is_power_of_two() {
        return Err(Error::InvalidParameter(format!(
            "chunk size {chunk_size} must be a power of two"
        )));
    }
    if chunk_size % EROFS_BLOCK_SIZE != 0 {
        return Err(Error::InvalidParameter(format!(
            "chunk size {chunk_size} must be block aligned"
        )));
    }
    Ok(())
}

/// Manages writing chunk data to a separate blob device. Every file is cut
/// into chunks of at most the chunk size, and the chunk groups tile the
/// padded address space the EROFS chunk indexes address back to back, each
/// spanning exactly its chunks' blocks: a chunk that reaches the chunk
/// group minimum size is a group of its own, smaller chunks are
/// packed in order into shared groups closed at content-defined boundaries
/// (see [`Self::append_chunk`]). Each chunk starts on its own block, while
/// the group payload carries the chunks' bytes back to back without the
/// block padding. The blob meta records the groups, the packs' member
/// lengths and one digest per group (see
/// `nydus_format::blob::BlobMetadata`).
///
/// Because a chunk's address is only known once its group closes, the chunk
/// addresses handed out by [`Self::write_reader_chunks`] are placeholders
/// until [`Self::finish`]; [`Self::resolve_chunk_addr`] turns them into
/// block addresses afterwards (see `inode::resolve_chunk_addrs`). Raw
/// device mode places chunks immediately and needs no resolution.
pub struct BlobWriter<W> {
    writer: W,
    file_chunk_size: u32,
    compressor: BlobMetadataCompressor,
    digester: BlobMetadataDigester,
    // Raw device mode: the next block of the padded device. Chunk mode: the
    // block right after the last sealed group; groups tile the address
    // space back to back, each spanning its chunks' block-rounded lengths.
    next_blkaddr: u64,
    next_compressed_offset: u64,
    // `None` when the caller names the blob itself (`--blob-id`), so no
    // sha256 pass over the data region is needed.
    data_hasher: Option<Sha256>,
    /// The pack minimum, lone-chunk threshold and lookup granule in bytes.
    chunk_group_min_size: u32,
    // Chunk mode: the pack of small chunks under construction, closed at a
    // content-defined boundary once it spans `pack_min_blocks` (see
    // `PACK_STRICT_MASK`) or when the next chunk would take it past
    // `pack_span_blocks`.
    open_bin: Option<Bin>,
    pack_min_blocks: u64,
    pack_target_blocks: u64,
    pack_span_blocks: u64,
    // The final block address of every placed chunk, indexed by the
    // placement id handed out as its placeholder address; `PENDING` until
    // the chunk's group closes.
    placements: Vec<u64>,
    // Groups closed so far (the next group's index), all chunk byte
    // lengths in group order, including lone chunks, one digest per sealed
    // group, and the sealed groups in group order.
    next_group: u64,
    members: Vec<u32>,
    digests: Vec<BlobMetadataDigest>,
    blob_metadata_chunk_groups: Vec<BlobMetadataChunkGroup>,
    // Reused per-file read buffer: a fresh 1 MiB Vec per file costs an
    // mmap/munmap plus page faults for every source file.
    chunk_buf: Vec<u8>,
    // Lazily started background crc32+zstd pipeline for chunk groups.
    encoder: Option<ChunkGroupEncoder>,
    // Raw device mode (native uncompressed layers): every chunk is written
    // to `writer` at its padded address, tail padding included, so the
    // output is the padded address space itself. No chunk groups, blob meta
    // or digests are produced.
    raw_device: bool,
    // Native modes only: when non-zero, files of at least
    // `data_alignment_threshold` bytes start on a `data_alignment`-byte
    // boundary of the device data, so fixed-offset block dedup (e.g. cloud
    // disks chunking volumes at a fixed granularity) sees identical blocks
    // for identical files regardless of their neighbours. The gap is
    // zero-filled and nothing references it.
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
}

/// A chunk group under construction: the chunks packed so far, their
/// lengths, digests and placement ids, and the blocks they span.
struct Bin {
    data: Vec<u8>,
    lens: Vec<u32>,
    digests: Vec<BlobMetadataDigest>,
    placements: Vec<usize>,
    blocks: u64,
}

enum ChunkInput<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl ChunkInput<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(data) => data,
            Self::Owned(data) => data,
        }
    }
}

/// Content-defined pack boundaries, normalized around the chunk group
/// minimum size: a pack spanning at least the minimum closes after a chunk whose digest's
/// low `PACK_STRICT_MASK` bits are zero (one chunk in 64), one spanning at
/// least `PACK_TARGET_MULTIPLE` times the minimum after a chunk with the
/// low `PACK_LOOSE_MASK` bits zero (one in 32), and one that would grow past
/// `PACK_SPAN_MULTIPLE` times the minimum closes regardless. Digest marks
/// depend on each chunk's content, while accepting a mark also depends on
/// the accumulated span. Shared marks can resynchronise near-identical
/// inputs, enabling identical packs to share cache entries, but the minimum,
/// target and forced span boundaries mean resynchronisation is not guaranteed.
const PACK_STRICT_MASK: u8 = 0x3f;
const PACK_LOOSE_MASK: u8 = 0x1f;
const PACK_TARGET_MULTIPLE: u64 = 2;
const PACK_SPAN_MULTIPLE: u32 = 4;

/// Default chunk group minimum size, the least address space any chunk
/// group but a blob's last spans, independent of the chunk size: a chunk of at
/// least this size stands alone, smaller ones are packed until the pack
/// spans it. 2 MiB: the granularity a content-addressed cache deduplicates
/// at, with non-final packs of 2–8 MiB; a smaller
/// minimum trades object count and compression ratio for less
/// retransmission when a few files change (see
/// `--chunk-group-minimum-size`).
pub const DEFAULT_CHUNK_GROUP_MIN_SIZE: u32 = 2 * 1024 * 1024;

/// The largest chunk group minimum size: four times it is the span the
/// blob meta's group span field encodes at most (2 GiB).
pub const MAX_CHUNK_GROUP_MIN_SIZE: u32 = 1 << 29;

/// Placeholder value of a chunk whose group has not closed yet.
const PENDING: u64 = u64::MAX;

struct ZPackedStream {
    buf: Vec<u8>,
    size: u64,
    accum: ZAccum,
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
pub struct ZFileRef(Arc<OnceLock<ZFileMeta>>);

impl ZFileRef {
    fn pending() -> Self {
        Self(Arc::new(OnceLock::new()))
    }

    fn ready(meta: ZFileMeta) -> Self {
        Self(Arc::new(OnceLock::from(meta)))
    }

    fn set(&self, meta: ZFileMeta) -> Result<()> {
        self.0
            .set(meta)
            .map_err(|_| Error::Runtime("z_erofs file metadata published twice".to_string()))
    }

    /// The published metadata; an error while the file is still in flight.
    pub fn resolve(&self) -> Result<ZFileMeta> {
        self.0.get().cloned().ok_or_else(|| {
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
    /// bounds and fitting checks still determine the accepted prefix. Zstd
    /// stops searching once a frame fills at least 98% of the pcluster budget.
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
                            if fails <= fits + 1 || csize >= pcluster * 98 / 100 {
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

/// Number of background chunk-group encoder threads. Encoding (crc32 + zstd)
/// runs well ahead of the single-threaded produce side, so two workers fully
/// hide it; more would only grow the in-flight memory.
const ENCODE_WORKERS: usize = 2;
/// Maximum encode jobs in flight before the producer drains one; bounds the
/// extra peak memory to a couple of chunk groups (in + encoded out each).
const ENCODE_MAX_IN_FLIGHT: usize = 2;

struct EncodeJob {
    seq: u64,
    data: Vec<u8>,
    chunk_count: u32,
}

struct EncodedChunkGroup {
    data: Vec<u8>,
    chunk_count: u32,
    crc32: u32,
    /// `Some` when compression met the format's worthwhile threshold.
    compressed: Option<Vec<u8>>,
}

/// Encode one group payload with `compressor`; `None` for the plain
/// compressor or when encoding fails.
fn encode_payload(compressor: BlobMetadataCompressor, data: &[u8]) -> Option<Vec<u8>> {
    match compressor {
        BlobMetadataCompressor::None => None,
        BlobMetadataCompressor::Zstd => zstd::bulk::compress(data, 0).ok(),
        BlobMetadataCompressor::Lz4Block => Some(lz4_flex::block::compress(data)),
    }
}

/// Offloads per-chunk-group crc32 + zstd to background threads while the
/// caller keeps producing. Results are drained strictly in submission order
/// so the written stream and metadata tables stay deterministic; input
/// buffers circulate back for reuse.
struct ChunkGroupEncoder {
    tx: Option<mpsc::Sender<EncodeJob>>,
    encoded_rx: mpsc::Receiver<(u64, EncodedChunkGroup)>,
    pending: BTreeMap<u64, EncodedChunkGroup>,
    next_seq_in: u64,
    next_seq_out: u64,
    free_buffers: Vec<Vec<u8>>,
    workers: Vec<JoinHandle<()>>,
}

impl ChunkGroupEncoder {
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
                    let compressed = encode_payload(compressor, &job.data)
                        .filter(|c| compression_is_worthwhile(c.len(), job.data.len()));
                    let encoded = EncodedChunkGroup {
                        data: job.data,
                        chunk_count: job.chunk_count,
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

    fn submit(&mut self, data: Vec<u8>, chunk_count: u32) -> Result<()> {
        let job = EncodeJob {
            seq: self.next_seq_in,
            data,
            chunk_count,
        };
        self.next_seq_in += 1;
        self.tx
            .as_ref()
            .expect("encoder is alive until finish")
            .send(job)
            .map_err(|_| Error::Runtime("chunk group encoder threads exited early".to_string()))
    }

    fn in_flight(&self) -> usize {
        (self.next_seq_in - self.next_seq_out) as usize
    }

    /// Receive the next completed group in submission order.
    fn recv_next(&mut self) -> Result<EncodedChunkGroup> {
        loop {
            if let Some(encoded) = self.pending.remove(&self.next_seq_out) {
                self.next_seq_out += 1;
                return Ok(encoded);
            }
            let (seq, encoded) = self.encoded_rx.recv().map_err(|_| {
                Error::Runtime("chunk group encoder threads exited early".to_string())
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

impl Drop for ChunkGroupEncoder {
    fn drop(&mut self) {
        self.tx.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// How a [`BlobWriter`] lays out and encodes file data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobLayout {
    /// Compressed chunk groups described by blob meta: the layout the nydus
    /// daemons fetch on demand. A chunk of at least `chunk_group_min_size`
    /// bytes (a power of two of at least one block) is a group of its
    /// own, so its encoded bytes are one frame named by its digest; smaller
    /// chunks are packed in order into shared groups spanning at least
    /// `chunk_group_min_size` bytes of address space (a power of two of at
    /// least one block) that close at content-defined boundaries (see
    /// [`PACK_STRICT_MASK`]). The minimum is independent of the file chunk
    /// size: when larger, even full chunks join packs. Every group but the
    /// last spans at least the minimum, recorded as the blob meta's lookup
    /// granule; the standalone-chunk threshold is a writer rule only.
    ChunkGroups { chunk_group_min_size: u32 },
    /// The padded address space written as-is: a native uncompressed EROFS
    /// device the kernel mounts directly (`erofs-none`). No chunk groups,
    /// blob meta or digests are produced. When `data_alignment` is non-zero,
    /// files of at least `data_alignment_threshold` bytes start on a
    /// `data_alignment`-byte boundary of the device data.
    RawDevice {
        data_alignment: u32,
        data_alignment_threshold: u64,
    },
    /// Native z_erofs pclusters of at most `pcluster` bytes (a power-of-two
    /// multiple of the block size) compressed with `algorithm`, addressed
    /// from `base_blkaddr` in the final single-device image. Regular files
    /// of at most `fragment_threshold` bytes (zero: none) are packed into the
    /// shared fragment inode. Alignment as for [`Self::RawDevice`].
    ZErofs {
        algorithm: ZAlgorithm,
        pcluster: u32,
        base_blkaddr: u64,
        fragment_threshold: u64,
        data_alignment: u32,
        data_alignment_threshold: u64,
    },
}

#[cfg(test)]
impl<W: Write> BlobWriter<W> {
    /// A plain chunk-group writer with BLAKE3 digests that packs every
    /// chunk smaller than half the chunk size with a chunk group minimum
    /// size of half the chunk size (at least one block), for tests.
    pub(crate) fn plain(writer: W, chunk_size: u32) -> Self {
        Self::new(
            writer,
            chunk_size,
            BlobMetadataCompressor::None,
            BlobMetadataDigester::Blake3,
            true,
            BlobLayout::ChunkGroups {
                chunk_group_min_size: (chunk_size / 2).max(EROFS_BLOCK_SIZE),
            },
        )
        .expect("valid test writer")
    }
}

impl<W: Write> BlobWriter<W> {
    /// A writer over `writer` cutting files into `chunk_size` chunks (a
    /// block-aligned power of two), encoding groups with `compressor` and
    /// recording a `digester` digest per chunk group, laid out per `layout`.
    /// With `hash_data` the data region is SHA256 hashed as it is written
    /// ([`Self::data_digest`]); a caller naming the blob itself (`--blob-id`)
    /// skips that pass.
    pub fn new(
        writer: W,
        chunk_size: u32,
        compressor: BlobMetadataCompressor,
        digester: BlobMetadataDigester,
        hash_data: bool,
        layout: BlobLayout,
    ) -> Result<Self> {
        validate_chunk_size(chunk_size)?;
        let alignment = |alignment: u32| -> Result<u32> {
            if alignment != 0 && (!alignment.is_power_of_two() || alignment % EROFS_BLOCK_SIZE != 0)
            {
                return Err(Error::InvalidParameter(
                    "data alignment must be a power of two and block-aligned".to_string(),
                ));
            }
            Ok(alignment)
        };
        let mut writer = Self {
            writer,
            file_chunk_size: chunk_size,
            compressor,
            digester,
            next_blkaddr: 0,
            next_compressed_offset: 0,
            data_hasher: hash_data.then(Sha256::new),
            chunk_group_min_size: DEFAULT_CHUNK_GROUP_MIN_SIZE,
            open_bin: None,
            pack_min_blocks: 0,
            pack_target_blocks: 0,
            pack_span_blocks: 0,
            placements: Vec::new(),
            next_group: 0,
            members: Vec::new(),
            digests: Vec::new(),
            blob_metadata_chunk_groups: Vec::new(),
            chunk_buf: vec![0u8; chunk_size as usize],
            encoder: None,
            raw_device: false,
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
        };
        match layout {
            BlobLayout::ChunkGroups {
                chunk_group_min_size,
            } => {
                if !chunk_group_min_size.is_power_of_two()
                    || !(EROFS_BLOCK_SIZE..=MAX_CHUNK_GROUP_MIN_SIZE)
                        .contains(&chunk_group_min_size)
                {
                    return Err(Error::InvalidParameter(format!(
                        "chunk group minimum size {chunk_group_min_size} must be a power of two between {EROFS_BLOCK_SIZE} and {MAX_CHUNK_GROUP_MIN_SIZE} bytes"
                    )));
                }
                writer.chunk_group_min_size = chunk_group_min_size;
                writer.pack_min_blocks = u64::from(chunk_group_min_size / EROFS_BLOCK_SIZE);
                writer.pack_target_blocks = writer.pack_min_blocks * PACK_TARGET_MULTIPLE;
                writer.pack_span_blocks = writer.pack_min_blocks * u64::from(PACK_SPAN_MULTIPLE);
            }
            BlobLayout::RawDevice {
                data_alignment,
                data_alignment_threshold,
            } => {
                writer.raw_device = true;
                writer.digester = BlobMetadataDigester::None;
                writer.data_alignment = alignment(data_alignment)?;
                writer.data_alignment_threshold = data_alignment_threshold;
            }
            BlobLayout::ZErofs {
                algorithm,
                pcluster,
                base_blkaddr,
                fragment_threshold,
                data_alignment,
                data_alignment_threshold,
            } => {
                if !pcluster.is_power_of_two()
                    || pcluster % EROFS_BLOCK_SIZE != 0
                    || pcluster > 1024 * 1024
                {
                    return Err(Error::InvalidParameter(
                        "z_erofs pcluster size must be a block-aligned power of two up to 1 MiB"
                            .to_string(),
                    ));
                }
                writer.z_pcluster = pcluster;
                writer.z_algorithm = algorithm;
                writer.z_base_blkaddr = base_blkaddr;
                writer.z_next_blkaddr = base_blkaddr;
                writer.z_frag_threshold = fragment_threshold;
                if fragment_threshold != 0 {
                    writer.z_packed = Some(ZPackedStream {
                        buf: Vec::new(),
                        size: 0,
                        accum: ZAccum::new(algorithm, ZFileRef::pending()),
                    });
                }
                writer.data_alignment = alignment(data_alignment)?;
                writer.data_alignment_threshold = data_alignment_threshold;
            }
        }
        Ok(writer)
    }

    /// Whether the writer is in raw device mode (see [`BlobLayout::RawDevice`]).
    pub fn is_raw_device(&self) -> bool {
        self.raw_device
    }

    /// Blocks of the padded address space: in chunk mode, the closed groups'
    /// spans (final once [`Self::finish`] returned); in raw device mode, the
    /// blocks written so far.
    pub fn total_blocks(&self) -> u64 {
        self.next_blkaddr
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

    /// Appends a small file to the packed stream (submitting every full
    /// segment that results) and returns its inode tail: just the 8-byte
    /// fragment header (offset | flag), no lcluster indexes.
    fn write_reader_fragment(&mut self, reader: &mut dyn Read, file_size: u64) -> Result<ZFileRef> {
        let packed = self
            .z_packed
            .as_mut()
            .expect("fragments enabled implies a packed stream");
        let offset = packed.size;
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
        packed.size += file_size;
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
            handle.set(meta)?;
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
            handle.set(accum.into_meta()?)?;
        }
        let src = mem::take(&mut segment.src);
        self.z_pipeline().recycle_buffer(src);
        Ok(())
    }

    fn write_z_padding(&mut self, padding: usize) -> Result<()> {
        write_zeros(&mut self.writer, padding as u64).context("failed to write z_erofs padding")
    }

    pub fn data_size(&self) -> u64 {
        self.next_compressed_offset
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.placements.is_empty()
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

    /// Lengths of all sealed chunks in group order, including lone chunks.
    pub fn blob_metadata_chunk_lengths(&self) -> &[u32] {
        &self.members
    }

    /// The sealed groups so far, in group order.
    pub fn blob_metadata_chunk_groups(&self) -> &[BlobMetadataChunkGroup] {
        &self.blob_metadata_chunk_groups
    }

    /// The most a group spans: a lone chunk is at most a file chunk, a pack
    /// at most `pack_span_blocks`.
    fn group_span_blocks(&self) -> u32 {
        u32::try_from(
            self.pack_span_blocks
                .max(u64::from(self.file_chunk_size / EROFS_BLOCK_SIZE)),
        )
        .expect("the pack span is bounded by MAX_CHUNK_GROUP_MIN_SIZE")
    }

    /// The blob meta describing everything written; call after
    /// [`Self::finish`].
    pub fn blob_metadata(&self) -> Result<BlobMetadata> {
        if self.raw_device {
            return Err(Error::InvalidParameter(
                "a raw device blob carries no blob meta".to_string(),
            ));
        }
        Ok(BlobMetadata::new(
            self.compressor,
            self.digester,
            self.group_span_blocks(),
            self.chunk_group_min_size,
            self.blob_metadata_chunk_groups.clone(),
            self.members.clone(),
            self.digests.clone(),
        )?)
    }

    /// Consume the finished writer and move its metadata tables into the
    /// standard blob metadata representation. Raw-device blobs return no
    /// metadata. Call finish first so all open groups are sealed.
    pub fn into_parts_with_metadata(self) -> Result<(W, Option<Sha256>, Option<BlobMetadata>)> {
        self.into_parts_with_metadata_kind(false)
    }

    pub(crate) fn into_incremental_parts(self) -> Result<(W, Option<Sha256>, BlobMetadata)> {
        let (writer, data_hasher, blob_metadata) = self.into_parts_with_metadata_kind(true)?;
        let blob_metadata = blob_metadata.ok_or_else(|| {
            Error::InvalidParameter("a raw device blob carries no blob meta".to_string())
        })?;
        Ok((writer, data_hasher, blob_metadata))
    }

    fn into_parts_with_metadata_kind(
        self,
        incremental: bool,
    ) -> Result<(W, Option<Sha256>, Option<BlobMetadata>)> {
        if self.raw_device {
            return Ok((self.writer, self.data_hasher, None));
        }
        let group_span_blocks = self.group_span_blocks();
        let blob_metadata = if incremental {
            BlobMetadata::new_incremental(
                self.compressor,
                self.digester,
                group_span_blocks,
                self.chunk_group_min_size,
                self.blob_metadata_chunk_groups,
                self.members,
                self.digests,
            )?
        } else {
            BlobMetadata::new(
                self.compressor,
                self.digester,
                group_span_blocks,
                self.chunk_group_min_size,
                self.blob_metadata_chunk_groups,
                self.members,
                self.digests,
            )?
        };
        Ok((self.writer, self.data_hasher, Some(blob_metadata)))
    }

    pub fn write_blob_metadata(&mut self, path: &Path) -> Result<()> {
        self.finish()?;
        Ok(self.blob_metadata()?.save(path)?)
    }

    /// Closes every open group, drains the encoders and flushes the output.
    /// Chunk addresses are final afterwards (see
    /// [`Self::resolve_chunk_addr`]).
    pub fn finish(&mut self) -> Result<()> {
        self.close_open_bin()?;
        self.drain_all_encoded()?;
        self.z_drain_all()?;
        self.writer.flush().context("failed to flush blob device")
    }

    /// Replace the placeholder block address of a chunk handed out by
    /// [`Self::write_reader_chunks`] with its final address; a no-op for
    /// holes, raw device chunks and other devices' chunks. Only valid after
    /// [`Self::finish`].
    pub fn resolve_chunk_addr(&self, addr: &mut ErofsChunkAddr) -> Result<()> {
        self.resolve_chunk_addr_for_device(addr, 1)
    }

    pub(crate) fn try_resolve_chunk_addr_for_device(
        &self,
        addr: &mut ErofsChunkAddr,
        device_id: u16,
    ) -> Result<bool> {
        if self.raw_device || addr.device_id != device_id || addr.blkaddr == EROFS_NULL_ADDR {
            return Ok(true);
        }
        let placement = usize::try_from(addr.blkaddr)
            .ok()
            .and_then(|id| self.placements.get(id).copied())
            .ok_or_else(|| {
                Error::Runtime(format!("chunk placement {} is unknown", addr.blkaddr))
            })?;
        if placement == PENDING {
            return Ok(false);
        }
        addr.blkaddr = placement;
        Ok(true)
    }

    pub(crate) fn resolve_chunk_addr_for_device(
        &self,
        addr: &mut ErofsChunkAddr,
        device_id: u16,
    ) -> Result<()> {
        if !self.try_resolve_chunk_addr_for_device(addr, device_id)? {
            return Err(Error::Runtime(format!(
                "chunk placement {} is still pending; finish the blob first",
                addr.blkaddr
            )));
        }
        Ok(())
    }

    /// Append one caller-provided file chunk as real blob data.
    pub fn write_data_chunk(&mut self, data: &[u8]) -> Result<u64> {
        self.validate_data_chunk_len(data.len())?;
        self.append_chunk(data)
    }

    /// Append one owned file chunk without copying it into a staging buffer.
    pub(crate) fn write_data_chunk_owned(&mut self, data: Vec<u8>) -> Result<u64> {
        self.validate_data_chunk_len(data.len())?;
        if self.raw_device || self.z_erofs_enabled() {
            return Err(Error::InvalidParameter(
                "owned chunks require chunk-group layout".to_string(),
            ));
        }
        self.append_owned_chunk(data)
    }

    /// Append one file chunk by filling a reusable source buffer.
    pub(crate) fn write_data_chunk_from_source<F>(&mut self, len: usize, fill: F) -> Result<u64>
    where
        F: FnOnce(&mut [u8]) -> Result<()>,
    {
        self.write_chunk_from_source(len, false, fill)?
            .ok_or_else(|| Error::Runtime("source chunk was unexpectedly elided".to_string()))
    }

    pub(crate) fn write_nonzero_data_chunk_from_source<F>(
        &mut self,
        len: usize,
        fill: F,
    ) -> Result<Option<u64>>
    where
        F: FnOnce(&mut [u8]) -> Result<()>,
    {
        self.write_chunk_from_source(len, true, fill)
    }

    fn write_chunk_from_source<F>(
        &mut self,
        len: usize,
        skip_zero: bool,
        fill: F,
    ) -> Result<Option<u64>>
    where
        F: FnOnce(&mut [u8]) -> Result<()>,
    {
        self.validate_data_chunk_len(len)?;
        if self.raw_device || self.z_erofs_enabled() {
            return Err(Error::InvalidParameter(
                "source-backed chunks require chunk-group layout".to_string(),
            ));
        }
        let mut data = self.take_source_buffer();
        data.resize(len, 0);
        if let Err(err) = fill(&mut data) {
            self.recycle_source_buffer(data);
            return Err(err);
        }
        if skip_zero && data.iter().all(|byte| *byte == 0) {
            self.recycle_source_buffer(data);
            return Ok(None);
        }
        self.append_owned_chunk(data).map(Some)
    }

    fn validate_data_chunk_len(&self, len: usize) -> Result<()> {
        if len == 0 || len > self.file_chunk_size as usize {
            return Err(Error::InvalidParameter(format!(
                "chunk payload {len} must be between 1 and {} bytes",
                self.file_chunk_size
            )));
        }
        Ok(())
    }

    /// Process a regular file: read it in chunk-sized chunks and append every
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
    /// chunk-sized chunks and append every chunk to the blob device. In
    /// chunk mode the returned block addresses are placeholders until
    /// [`Self::finish`] (see [`Self::resolve_chunk_addr`]).
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
        let mut indexes = Vec::with_capacity(chunk_count.min(1024) as usize);
        if self.raw_device && self.data_alignment != 0 && file_size >= self.data_alignment_threshold
        {
            self.align_raw_device()?;
        }
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
            // No blob data, no blob-meta chunk, and no blob cache traffic is
            // ever spent on it — native EROFS mounts handle the null address
            // the same way in-kernel.
            if chunk_buf[..to_read].iter().all(|&byte| byte == 0) {
                indexes.push(ErofsChunkAddr {
                    blkaddr: EROFS_NULL_ADDR,
                    device_id: 0,
                });
                continue;
            }

            let blkaddr = match self.append_chunk(&chunk_buf[..to_read]) {
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

    /// Pads the raw device with zero blocks so the next chunk starts on the
    /// configured data alignment.
    fn align_raw_device(&mut self) -> Result<()> {
        let align_blocks = u64::from(self.data_alignment / EROFS_BLOCK_SIZE);
        let target = self.next_blkaddr.next_multiple_of(align_blocks);
        let gap = (target - self.next_blkaddr) as usize * EROFS_BLOCK_SIZE as usize;
        self.write_raw_padding(gap)?;
        self.next_blkaddr = target;
        Ok(())
    }

    /// Writes `padding` zero bytes to the raw device, hashing them like data.
    fn write_raw_padding(&mut self, mut padding: usize) -> Result<()> {
        while padding > 0 {
            let chunk = padding.min(ZERO_BLOCK.len());
            self.writer
                .write_all(&ZERO_BLOCK[..chunk])
                .context("failed to write device padding")?;
            if let Some(hasher) = self.data_hasher.as_mut() {
                hasher.update(&ZERO_BLOCK[..chunk]);
            }
            self.next_compressed_offset += chunk as u64;
            padding -= chunk;
        }
        Ok(())
    }

    /// Append one chunk (a whole small file, or one chunk of a larger one).
    /// In raw device mode the padded chunk is written straight to the
    /// device and its block address returned. Otherwise the chunk's length
    /// and digest are recorded and its bytes go into a group: a chunk that
    /// reaches the chunk group minimum size closes
    /// as a group of its own; a smaller one joins the open pack (closing it
    /// first when the chunk would take it past the pack span), and the pack
    /// closes when it reaches the span exactly or after a chunk whose digest
    /// marks a boundary once the pack spans the minimum (see
    /// [`PACK_STRICT_MASK`]; with no digester packs simply fill the span).
    /// Returns the chunk's placement id, the placeholder
    /// [`Self::resolve_chunk_addr`] resolves.
    fn append_chunk(&mut self, data: &[u8]) -> Result<u64> {
        let blocks = data.len().div_ceil(EROFS_BLOCK_SIZE as usize) as u64;
        if self.raw_device {
            let addr = self.next_blkaddr;
            let next_blkaddr = addr
                .checked_add(blocks)
                .filter(|count| *count <= u32::MAX as u64)
                .ok_or_else(|| {
                    Error::Overflow(format!(
                        "device exceeds 32-bit block count: start {addr}, chunk blocks {blocks}"
                    ))
                })?;
            self.writer
                .write_all(data)
                .context("failed to write to blob device")?;
            if let Some(hasher) = self.data_hasher.as_mut() {
                hasher.update(data);
            }
            self.next_compressed_offset += data.len() as u64;
            let padded = blocks as usize * EROFS_BLOCK_SIZE as usize;
            self.write_raw_padding(padded - data.len())?;
            self.next_blkaddr = next_blkaddr;
            return Ok(addr);
        }
        self.append_group_chunk(ChunkInput::Borrowed(data))
    }

    /// Append an owned chunk, moving a lone chunk or a new pack directly
    /// into the encoder instead of copying through an intermediate buffer.
    fn append_owned_chunk(&mut self, data: Vec<u8>) -> Result<u64> {
        debug_assert!(!self.raw_device && !self.z_erofs_enabled());
        self.append_group_chunk(ChunkInput::Owned(data))
    }

    /// Add a borrowed or owned chunk through the shared chunk-group state
    /// machine. Owned buffers are moved into lone groups and new packs.
    fn append_group_chunk(&mut self, input: ChunkInput<'_>) -> Result<u64> {
        let data = input.as_slice();
        let blocks = data.len().div_ceil(EROFS_BLOCK_SIZE as usize) as u64;
        let len = u32::try_from(data.len())
            .map_err(|err| Error::Overflow(format!("blob meta chunk length exceeds u32: {err}")))?;
        let digest = match self.digester {
            BlobMetadataDigester::Blake3 => {
                Some(BlobMetadataDigest::new(*blake3::hash(data).as_bytes()))
            }
            BlobMetadataDigester::None => None,
        };
        let placement = self.placements.len();
        self.placements.push(PENDING);

        if len >= self.chunk_group_min_size {
            let data = match input {
                ChunkInput::Borrowed(data) => data.to_vec(),
                ChunkInput::Owned(data) => data,
            };
            self.submit_bin(Bin {
                data,
                lens: vec![len],
                digests: digest.into_iter().collect(),
                placements: vec![placement],
                blocks,
            })?;
            return Ok(placement as u64);
        }

        let span_blocks = self.pack_span_blocks;
        if let Some(bin) = self.open_bin.as_ref() {
            if bin.blocks + blocks > span_blocks {
                self.close_open_bin()?;
            }
        }
        let cut_byte = digest.map(|digest| digest.digest()[31]);
        let (min_blocks, target_blocks) = (self.pack_min_blocks, self.pack_target_blocks);
        let recycle = if let Some(bin) = self.open_bin.as_mut() {
            match input {
                ChunkInput::Borrowed(data) => {
                    bin.data.extend_from_slice(data);
                    None
                }
                ChunkInput::Owned(data) => {
                    bin.data.extend_from_slice(&data);
                    Some(data)
                }
            }
        } else {
            let data = match input {
                ChunkInput::Borrowed(data) => {
                    let buffer = self
                        .encoder
                        .as_mut()
                        .and_then(ChunkGroupEncoder::take_buffer)
                        .unwrap_or_else(|| Vec::with_capacity(self.file_chunk_size as usize));
                    let mut buffer = buffer;
                    buffer.extend_from_slice(data);
                    buffer
                }
                ChunkInput::Owned(data) => data,
            };
            self.open_bin = Some(Bin {
                data,
                lens: Vec::new(),
                digests: Vec::new(),
                placements: Vec::new(),
                blocks: 0,
            });
            None
        };
        if let Some(data) = recycle {
            self.recycle_source_buffer(data);
        }
        let bin = self.open_bin.as_mut().expect("pack was opened");
        bin.lens.push(len);
        bin.digests.extend(digest);
        bin.placements.push(placement);
        bin.blocks += blocks;
        let cuts = cut_byte.is_some_and(|byte| {
            let mask = if bin.blocks < target_blocks {
                PACK_STRICT_MASK
            } else {
                PACK_LOOSE_MASK
            };
            bin.blocks >= min_blocks && byte & mask == 0
        });
        if bin.blocks == span_blocks || cuts {
            self.close_open_bin()?;
        }
        Ok(placement as u64)
    }

    fn take_source_buffer(&mut self) -> Vec<u8> {
        let mut buffer = mem::take(&mut self.chunk_buf);
        if buffer.capacity() == 0 {
            buffer = self
                .encoder
                .as_mut()
                .and_then(ChunkGroupEncoder::take_buffer)
                .unwrap_or_else(|| Vec::with_capacity(self.file_chunk_size as usize));
        }
        buffer
    }

    fn recycle_source_buffer(&mut self, mut buffer: Vec<u8>) {
        buffer.clear();
        if self.chunk_buf.capacity() == 0 {
            self.chunk_buf = buffer;
        } else if let Some(encoder) = self.encoder.as_mut() {
            encoder.recycle_buffer(buffer);
        }
    }

    /// Close the open pack, if any, as the next group.
    fn close_open_bin(&mut self) -> Result<()> {
        match self.open_bin.take() {
            Some(bin) => self.submit_bin(bin),
            None => Ok(()),
        }
    }

    /// Seal `bin` as the next group: place it right after the previous one
    /// in the address space, resolve its chunks' addresses, record a pack's
    /// member lengths and the group's digest, and hand the payload to the
    /// encoders.
    fn submit_bin(&mut self, bin: Bin) -> Result<()> {
        let group = self.next_group;
        let first_block = self.next_blkaddr;
        let end_block = first_block + bin.blocks;
        if end_block > u32::MAX as u64 {
            return Err(Error::Overflow(format!(
                "blob exceeds 32-bit block count: group {group} ends at block {end_block}"
            )));
        }
        let mut block = first_block;
        for (&len, &placement) in bin.lens.iter().zip(&bin.placements) {
            self.placements[placement] = block;
            block += u64::from(len).div_ceil(u64::from(EROFS_BLOCK_SIZE));
        }
        debug_assert_eq!(block, end_block);
        self.members.extend_from_slice(&bin.lens);
        let chunk_count = u32::try_from(bin.lens.len())
            .map_err(|_| Error::Overflow("chunk group holds too many chunks".to_string()))?;
        // The chunk digests already computed for the boundary decision name
        // the group; a single chunk's digest is reused as is.
        let members: Vec<[u8; 32]> = bin.digests.iter().map(|digest| *digest.digest()).collect();
        self.digests.extend(BlobMetadataDigest::of_group(&members));
        self.next_group = group + 1;
        self.next_blkaddr = end_block;

        let compressor = self.compressor;
        let encoder = self
            .encoder
            .get_or_insert_with(|| ChunkGroupEncoder::new(compressor));
        encoder.submit(bin.data, chunk_count)?;
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

    /// Write out the next completed chunk group, in submission order.
    fn drain_one_encoded(&mut self) -> Result<()> {
        let group = self
            .encoder
            .as_mut()
            .expect("drain is only called with a live encoder")
            .recv_next()?;
        let encoded: &[u8] = group.compressed.as_deref().unwrap_or(&group.data);

        // Encoded chunk group payloads are packed back-to-back in the data
        // region. No block padding is inserted between them; they are read
        // by byte range, and only the data region as a whole is later
        // aligned (by the build assembler) so the embedded bootstrap starts
        // on a block.
        self.writer
            .write_all(encoded)
            .context("failed to write to blob device")?;
        if let Some(hasher) = self.data_hasher.as_mut() {
            hasher.update(encoded);
        }
        self.next_compressed_offset += encoded.len() as u64;
        self.blob_metadata_chunk_groups
            .push(BlobMetadataChunkGroup::new(
                u32::try_from(encoded.len()).map_err(|err| {
                    Error::Overflow(format!("encoded chunk group exceeds u32: {err}"))
                })?,
                u32::try_from(group.data.len()).map_err(|err| {
                    Error::Overflow(format!("chunk group payload exceeds u32: {err}"))
                })?,
                group.chunk_count,
                group.crc32,
                None,
            )?);

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

/// Format-compatibility policy shared by build and `nydus optimize`: a
/// chunk group is stored compressed only when it saves at least 30% — both
/// paths must agree, and since a stored encoding is then always smaller
/// than its payload, equal sizes unambiguously mean "stored plain".
pub(crate) fn compression_is_worthwhile(compressed_len: usize, uncompressed_len: usize) -> bool {
    (compressed_len as u128) * 100 <= (uncompressed_len as u128) * MAX_COMPRESSED_SIZE_PERCENT
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Geometry the layout assertions below are written against: 64 KiB
    /// chunks (16 blocks) and a 32 KiB chunk group minimum size (what `plain`
    /// picks), so
    /// packs span at least 8 blocks, target 16 and hold at most 32,
    /// independent of the CLI defaults.
    const TEST_CHUNK_SIZE: u32 = 64 * 1024;
    const TEST_CHUNK_BLOCKS: u64 = (TEST_CHUNK_SIZE / EROFS_BLOCK_SIZE) as u64;
    const TEST_GROUP_MIN_SIZE: u32 = TEST_CHUNK_SIZE / 2;
    use std::fs;
    use tempfile::tempdir;

    fn plain_writer(chunk_size: u32) -> BlobWriter<Vec<u8>> {
        BlobWriter::plain(Vec::new(), chunk_size)
    }

    fn writer(
        chunk_size: u32,
        compressor: BlobMetadataCompressor,
        layout: BlobLayout,
    ) -> BlobWriter<Vec<u8>> {
        BlobWriter::new(
            Vec::new(),
            chunk_size,
            compressor,
            BlobMetadataDigester::Blake3,
            true,
            layout,
        )
        .unwrap()
    }

    fn file_writer(path: &Path, chunk_size: u32) -> BlobWriter<File> {
        BlobWriter::plain(File::create(path).unwrap(), chunk_size)
    }

    /// How a chunk's digest marks a pack boundary (see `PACK_STRICT_MASK`).
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mark {
        /// Ends no pack.
        Plain,
        /// Ends a pack that reached the target span (low five bits zero).
        Loose,
        /// Ends a pack that reached the minimum span (low six bits zero).
        Strict,
    }

    fn mark_of(data: &[u8]) -> Mark {
        let byte = blake3::hash(data).as_bytes()[31];
        if byte & PACK_STRICT_MASK == 0 {
            Mark::Strict
        } else if byte & PACK_LOOSE_MASK == 0 {
            Mark::Loose
        } else {
            Mark::Plain
        }
    }

    /// `len` bytes of `seed` (its last byte varied, then the fill) whose
    /// chunk carries the wanted boundary mark, so the tests choose their
    /// boundaries.
    fn filled(len: usize, seed: u8, mark: Mark) -> Vec<u8> {
        (seed..=u8::MAX)
            .chain(0..seed)
            .flat_map(|byte| {
                (0..=u8::MAX).map(move |last| {
                    let mut data = vec![byte; len];
                    *data.last_mut().expect("chunks are not empty") = last;
                    data
                })
            })
            .find(|data| mark_of(data) == mark)
            .expect("some fill gives the wanted boundary")
    }

    /// Write `bytes` as one file and return its resolved-later addresses.
    fn write(writer: &mut BlobWriter<Vec<u8>>, bytes: &[u8]) -> Vec<ErofsChunkAddr> {
        writer
            .write_reader_chunks(&mut &bytes[..], bytes.len() as u64)
            .unwrap()
    }

    fn resolve(writer: &BlobWriter<Vec<u8>>, addrs: &mut [ErofsChunkAddr]) -> Vec<u64> {
        for addr in addrs.iter_mut() {
            writer.resolve_chunk_addr(addr).unwrap();
        }
        addrs.iter().map(|addr| addr.blkaddr).collect()
    }

    /// Rebuild the padded address space from the written data region and
    /// the blob meta, group by group.
    fn scatter(writer: &BlobWriter<Vec<u8>>) -> Vec<u8> {
        let meta = writer.blob_metadata().unwrap();
        let data = &writer.writer;
        let mut padded = vec![0u8; meta.uncompressed_size() as usize];
        for group in meta.chunk_groups() {
            let range = group.compressed_range();
            let encoded = &data[range.start as usize..range.end as usize];
            let payload = if meta.is_plain(&group) {
                encoded.to_vec()
            } else {
                zstd::bulk::decompress(encoded, meta.payload_size(&group) as usize).unwrap()
            };
            assert_eq!(crc32c(&payload), group.crc32());
            meta.for_each_decoded_chunk(group.index() as usize, &payload, &mut |offset, bytes| {
                padded[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);
                Ok(())
            })
            .unwrap();
        }
        padded
    }

    #[test]
    fn blob_writer_handles_single_chunk_groups_and_untrusted_sizes() {
        let mut writer = plain_writer(EROFS_BLOCK_SIZE);
        assert!(writer
            .write_reader_chunks(&mut std::io::empty(), u64::MAX)
            .is_err());
        let mut addrs = Vec::new();
        for bytes in [vec![1], vec![2; EROFS_BLOCK_SIZE as usize]] {
            addrs.extend(write(&mut writer, &bytes));
        }
        writer.finish().unwrap();
        // The whole chunk is a group of its own the moment it arrives, ahead
        // of the pack the one-byte chunk opened (packs may span two blocks).
        assert_eq!(resolve(&writer, &mut addrs), vec![1, 0]);
        let metadata = writer.blob_metadata().unwrap();
        assert_eq!(metadata.chunk_group_count(), 2);
        assert_eq!(metadata.chunk_group_index_of(0), Some(0));
        assert_eq!(metadata.chunk_group_index_of(4096), Some(1));
        for algorithm in [ZAlgorithm::Lz4, ZAlgorithm::Zstd] {
            assert!(BlobWriter::new(
                Vec::new(),
                EROFS_BLOCK_SIZE,
                BlobMetadataCompressor::None,
                BlobMetadataDigester::None,
                false,
                BlobLayout::ZErofs {
                    algorithm,
                    pcluster: 8 * 1024 * 1024,
                    base_blkaddr: 0,
                    fragment_threshold: 0,
                    data_alignment: 0,
                    data_alignment_threshold: 0,
                },
            )
            .is_err());
        }
        assert!(BlobWriter::new(
            Vec::new(),
            EROFS_BLOCK_SIZE,
            BlobMetadataCompressor::None,
            BlobMetadataDigester::None,
            false,
            BlobLayout::RawDevice {
                data_alignment: 3 * EROFS_BLOCK_SIZE,
                data_alignment_threshold: 0,
            },
        )
        .is_err());
    }

    #[test]
    fn blob_writer_packs_small_chunks_in_order_and_resolves_addresses() {
        let mut writer = plain_writer(TEST_CHUNK_SIZE);
        let files: Vec<Vec<u8>> = [
            (28_000usize, b'1'),
            (28_000, b'2'),
            (28_000, b'3'),
            (28_000, b'4'),
            (20_000, b'5'),
            (8_000, b'6'),
            (4_000, b'7'),
        ]
        .iter()
        .map(|(len, seed)| filled(*len, *seed, Mark::Plain))
        .collect();
        let mut addrs = Vec::new();
        for file in &files {
            addrs.extend(write(&mut writer, file));
        }
        // Files 1..4 fill 28 of a pack's 32-block span; file 5 (5 blocks)
        // does not fit, so the pack closes as group 0 (28 blocks) and file 5
        // opens the next, which files 6 and 7 (2 + 1 blocks) join; finish
        // closes it as group 1 (8 blocks) right after group 0. No digest
        // marks a boundary, so nothing closes early.
        assert_eq!(writer.next_group, 1);
        assert_eq!(
            writer.open_bin.as_ref().map(|bin| bin.lens.clone()),
            Some(vec![20_000, 8_000, 4_000])
        );
        assert!(addrs
            .iter()
            .any(|addr| writer.resolve_chunk_addr(&mut addr.clone()).is_err()));
        writer.finish().unwrap();
        assert_eq!(writer.total_blocks(), 28 + 8);
        assert_eq!(resolve(&writer, &mut addrs), vec![0, 7, 14, 21, 28, 33, 35]);
        assert_eq!(
            writer.blob_metadata_chunk_lengths(),
            &[28_000, 28_000, 28_000, 28_000, 20_000, 8_000, 4_000]
        );
        let groups = writer.blob_metadata_chunk_groups();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].chunk_count(), 4);
        assert_eq!(groups[0].compressed_size(), 112_000);
        assert_eq!(groups[1].chunk_count(), 3);
        assert_eq!(groups[1].compressed_size(), 32_000);
        // The data region holds the payloads back to back in file order.
        let expected: Vec<u8> = files.concat();
        assert_eq!(writer.writer, expected);
        assert_eq!(writer.data_size(), expected.len() as u64);

        let padded = scatter(&writer);
        let block = EROFS_BLOCK_SIZE as usize;
        assert_eq!(padded.len(), 36 * block);
        for (file, addr) in files.iter().zip(&addrs) {
            let offset = addr.blkaddr as usize * block;
            assert_eq!(&padded[offset..offset + file.len()], &file[..]);
            let end = offset + file.len().next_multiple_of(block);
            assert!(padded[offset + file.len()..end]
                .iter()
                .all(|byte| *byte == 0));
        }
    }

    #[test]
    fn blob_writer_closes_full_chunks_as_their_own_groups() {
        let mut writer = plain_writer(TEST_CHUNK_SIZE);
        // 2.25 chunks whose quarter-chunk tail does not mark a boundary, then a
        // small file that does not either.
        let tail = filled(TEST_CHUNK_SIZE as usize / 4, b'x', Mark::Plain);
        let mut big = vec![tail[0]; TEST_CHUNK_SIZE as usize * 2];
        big.extend_from_slice(&tail);
        let small = filled(100, b's', Mark::Plain);
        let mut addrs = write(&mut writer, &big);
        addrs.extend(write(&mut writer, &small));
        // Both full chunks closed at once; the quarter chunk waits in the open
        // pack that the small file joins.
        assert_eq!(writer.next_group, 2);
        assert_eq!(
            writer.open_bin.as_ref().map(|bin| bin.lens.clone()),
            Some(vec![TEST_CHUNK_SIZE / 4, 100])
        );
        writer.finish().unwrap();
        // Two full chunks, then the pack right behind them.
        assert_eq!(
            resolve(&writer, &mut addrs),
            vec![
                0,
                TEST_CHUNK_BLOCKS,
                2 * TEST_CHUNK_BLOCKS,
                2 * TEST_CHUNK_BLOCKS + TEST_CHUNK_BLOCKS / 4
            ]
        );
        assert_eq!(writer.blob_metadata_chunk_groups().len(), 3);
        assert_eq!(
            writer.blob_metadata_chunk_lengths(),
            &[TEST_CHUNK_SIZE, TEST_CHUNK_SIZE, TEST_CHUNK_SIZE / 4, 100]
        );
        // One digest per group: the two full chunks are equal bytes and
        // name their groups by their own digest; the pack's is derived.
        assert_eq!(writer.digests.len(), 3);
        assert_eq!(writer.digests[0].digest(), writer.digests[1].digest());
        assert_eq!(
            writer.digests[0].digest(),
            blake3::hash(&big[..TEST_CHUNK_SIZE as usize]).as_bytes()
        );
        assert_eq!(
            writer.digests[2],
            BlobMetadataDigest::of_group(&[
                *blake3::hash(&tail).as_bytes(),
                *blake3::hash(&small).as_bytes()
            ])
            .unwrap()
        );
        let meta = writer.blob_metadata().unwrap();
        // 16 + 16 blocks for the full chunks, 4 + 1 for the pack.
        assert_eq!(meta.uncompressed_block_count(), 2 * TEST_CHUNK_BLOCKS + 5);
        assert_eq!(meta.compressed_end(), big.len() as u64 + 100);
    }

    #[test]
    fn blob_writer_closes_packs_at_content_defined_boundaries() {
        // 64 KiB chunks: a pack spans at least 8 blocks, targets 16 and
        // holds at most 32. One-block files: a strict mark ends a pack once
        // it spans the minimum, a loose one once it spans the target, plain
        // ones never do.
        let plain = |seed| filled(EROFS_BLOCK_SIZE as usize, seed, Mark::Plain);
        let loose = |seed| filled(EROFS_BLOCK_SIZE as usize, seed, Mark::Loose);
        let strict = |seed| filled(EROFS_BLOCK_SIZE as usize, seed, Mark::Strict);
        let mut files = vec![
            strict(b'a'), // too early: the pack spans one block
            plain(b'b'),
            loose(b'c'), // too early as well
            plain(b'd'),
            plain(b'e'),
            plain(b'f'),
            plain(b'g'),
            strict(b'h'), // 8 blocks and strict: closes {a..h}
        ];
        files.extend((0..8).map(|i| plain(b'i' + i))); // 8 blocks
        files.push(loose(b'q')); // 9 blocks: past the minimum, under the target
        files.extend((0..6).map(|i| plain(b'r' + i))); // 16 blocks
        files.push(loose(b'x')); // 16 blocks and loose: closes {i..x}
        files.push(plain(b'y'));
        files.push(plain(b'z')); // finish closes {y, z}
        let mut writer = plain_writer(TEST_CHUNK_SIZE);
        let mut addrs = Vec::new();
        for file in &files {
            addrs.extend(write(&mut writer, file));
        }
        assert_eq!(writer.next_group, 2);
        writer.finish().unwrap();
        let meta = writer.blob_metadata().unwrap();
        let runs: Vec<usize> = meta
            .chunk_groups()
            .map(|group| group.chunk_count() as usize)
            .collect();
        assert_eq!(runs, vec![8, 16, 2]);
        // One-block chunks back to back: the address space is dense.
        assert_eq!(
            resolve(&writer, &mut addrs),
            (0..files.len() as u64).collect::<Vec<_>>()
        );
        assert_eq!(meta.uncompressed_block_count(), files.len() as u64);
        assert_eq!(meta.group_span(), 2 * TEST_CHUNK_SIZE);

        // The boundary depends on the chunk alone: a different prefix cuts
        // at the same marked files, so the packs after it are identical.
        let mut other = plain_writer(TEST_CHUNK_SIZE);
        write(&mut other, &plain(b'0'));
        write(&mut other, &plain(b'1'));
        for file in &files[1..] {
            write(&mut other, file);
        }
        other.finish().unwrap();
        let other_meta = other.blob_metadata().unwrap();
        // Group digests name the packs, so identical packs compare equal.
        let (first, second) = (meta.digests(), other_meta.digests());
        assert_ne!(first[0], second[0]);
        assert_eq!(&first[1..], &second[1..]);

        // Without digests packs simply fill the span.
        let mut undigested = BlobWriter::new(
            Vec::new(),
            TEST_CHUNK_SIZE,
            BlobMetadataCompressor::None,
            BlobMetadataDigester::None,
            true,
            BlobLayout::ChunkGroups {
                chunk_group_min_size: TEST_GROUP_MIN_SIZE,
            },
        )
        .unwrap();
        for file in &files {
            write(&mut undigested, file);
        }
        undigested.finish().unwrap();
        assert_eq!(undigested.blob_metadata().unwrap().chunk_group_count(), 1);
    }

    #[test]
    fn blob_writer_rejects_block_count_overflow_before_mutation() {
        let mut writer = plain_writer(EROFS_BLOCK_SIZE);
        writer.next_blkaddr = u32::MAX as u64 - 1;
        let data = [1; EROFS_BLOCK_SIZE as usize];
        let placement = writer.append_chunk(&data).unwrap();
        assert_eq!(writer.placements[placement as usize], u32::MAX as u64 - 1);
        assert_eq!(writer.next_blkaddr, u32::MAX as u64);
        let groups = writer.next_group;
        assert!(writer.append_chunk(&data).is_err());
        assert_eq!(writer.next_blkaddr, u32::MAX as u64);
        assert_eq!(writer.next_group, groups);
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

        let mut writer = file_writer(&blob_path, EROFS_BLOCK_SIZE);
        let mut indexes = writer
            .write_file_chunks(&input_path, content.len() as u64)
            .unwrap();
        writer.finish().unwrap();
        for index in indexes.iter_mut() {
            writer.resolve_chunk_addr(index).unwrap();
        }

        // The all-zero chunk becomes a hole: a null chunk index with no blob
        // reference, no blob-meta chunk, and no bytes in the data region.
        // The tail chunk is stored without padding.
        assert_eq!(indexes.len(), 3);
        assert_eq!(indexes[0].blkaddr, 0);
        assert_eq!(indexes[1].blkaddr, EROFS_NULL_ADDR);
        assert_eq!(indexes[1].device_id, 0);
        assert_eq!(indexes[2].blkaddr, 1);
        assert_eq!(writer.total_blocks(), 2);
        assert_eq!(writer.blob_metadata_chunk_groups().len(), 2);
        assert_eq!(
            writer.blob_metadata_chunk_lengths(),
            &[EROFS_BLOCK_SIZE, 100]
        );
        let meta = writer.blob_metadata().unwrap();
        assert_eq!(
            (0..2)
                .flat_map(|group| meta.chunk_group_chunks(group))
                .collect::<Vec<_>>(),
            vec![(0, 0, EROFS_BLOCK_SIZE), (0, 4096, 100)]
        );
        let data = fs::read(&blob_path).unwrap();
        assert_eq!(data.len(), EROFS_BLOCK_SIZE as usize + 100);
        assert!(!data[..EROFS_BLOCK_SIZE as usize].iter().any(|&b| b != b'a'));
        assert!(data[EROFS_BLOCK_SIZE as usize..].iter().all(|&b| b == b'c'));

        // The on-disk null index encodes the all-ones sentinel.
        let raw =
            nydus_format::erofs::ErofsChunkIndex::new(indexes[1].blkaddr, indexes[1].device_id)
                .unwrap();
        assert_eq!(raw.blkaddr(), EROFS_NULL_ADDR);
    }

    #[test]
    fn blob_writer_handles_fully_zero_file() {
        let mut writer = plain_writer(EROFS_BLOCK_SIZE);
        let content = vec![0u8; 2 * EROFS_BLOCK_SIZE as usize];
        let indexes = write(&mut writer, &content);
        writer.finish().unwrap();

        // Every chunk is a hole: nothing lands in the blob at all.
        assert_eq!(indexes.len(), 2);
        assert!(indexes.iter().all(|ci| ci.blkaddr == EROFS_NULL_ADDR));
        assert!(writer.blob_metadata_chunk_groups().is_empty());
        assert_eq!(writer.total_blocks(), 0);
        assert!(writer.writer.is_empty());
        assert_eq!(writer.blob_metadata().unwrap().chunk_group_count(), 0);
    }

    #[test]
    fn blob_writer_isolates_chunks_at_or_above_the_group_minimum() {
        // 64 KiB chunks, 16 KiB threshold: 4 KiB | 20 KiB | 8 KiB | 16 KiB | 64 KiB.
        let minimum = 16 * 1024;
        let mut writer = writer(
            TEST_CHUNK_SIZE,
            BlobMetadataCompressor::Zstd,
            BlobLayout::ChunkGroups {
                chunk_group_min_size: minimum,
            },
        );
        let files: Vec<Vec<u8>> = [4 * 1024, 20 * 1024, 8 * 1024, 16 * 1024, 64 * 1024]
            .iter()
            .enumerate()
            .map(|(index, len)| filled(*len, b'a' + index as u8, Mark::Plain))
            .collect();
        let mut addrs = Vec::new();
        for file in &files {
            addrs.extend(write(&mut writer, file));
        }
        writer.finish().unwrap();
        let addrs = resolve(&writer, &mut addrs);
        let meta = writer.blob_metadata().unwrap();
        assert_eq!(meta.lookup_granule(), minimum);
        // Groups close in write order: {20K}, {16K}, {64K}, then the pack
        // {4K, 8K} at finish; each starts where the previous one ends.
        let runs: Vec<Vec<u32>> = (0..meta.chunk_group_count())
            .map(|group| {
                meta.chunk_group_chunks(group)
                    .map(|(_, _, len)| len)
                    .collect()
            })
            .collect();
        assert_eq!(
            runs,
            vec![
                vec![20 * 1024],
                vec![16 * 1024],
                vec![64 * 1024],
                vec![4 * 1024, 8 * 1024]
            ]
        );
        assert_eq!(meta.uncompressed_block_count(), 5 + 4 + 16 + 3);
        assert_eq!(addrs, vec![25, 0, 26, 5, 9]);
        let padded = scatter(&writer);
        for (file, addr) in files.iter().zip(addrs) {
            let offset = addr as usize * EROFS_BLOCK_SIZE as usize;
            assert_eq!(&padded[offset..offset + file.len()], &file[..]);
        }
    }

    #[test]
    fn blob_writer_keeps_a_pack_under_the_minimum_open_for_a_chunk_that_does_not_fit() {
        // Span = chunk size (the minimum a quarter of it): a
        // chunk one block short of the span does not fit behind two 4 KiB
        // files, yet a pack still under the minimum never closes short, so
        // the chunk stands alone first and the pack waits.
        let mut writer = writer(
            4 * TEST_GROUP_MIN_SIZE,
            BlobMetadataCompressor::None,
            BlobLayout::ChunkGroups {
                chunk_group_min_size: TEST_GROUP_MIN_SIZE,
            },
        );
        let tiny = filled(EROFS_BLOCK_SIZE as usize, b'y', Mark::Plain);
        let long = filled(
            (4 * TEST_GROUP_MIN_SIZE - EROFS_BLOCK_SIZE) as usize,
            b'z',
            Mark::Plain,
        );
        let mut addrs = write(&mut writer, &tiny);
        addrs.extend(write(&mut writer, &tiny));
        addrs.extend(write(&mut writer, &long));
        assert_eq!(writer.next_group, 1);
        assert_eq!(
            writer.open_bin.as_ref().map(|bin| bin.lens.clone()),
            Some(vec![EROFS_BLOCK_SIZE, EROFS_BLOCK_SIZE])
        );
        writer.finish().unwrap();
        assert_eq!(resolve(&writer, &mut addrs), vec![31, 32, 0]);
        let meta = writer.blob_metadata().unwrap();
        let runs: Vec<Vec<u32>> = (0..meta.chunk_group_count())
            .map(|group| {
                meta.chunk_group_chunks(group)
                    .map(|(_, _, len)| len)
                    .collect()
            })
            .collect();
        assert_eq!(
            runs,
            vec![
                vec![long.len() as u32],
                vec![EROFS_BLOCK_SIZE, EROFS_BLOCK_SIZE]
            ]
        );
        assert_eq!(meta.lookup_granule(), TEST_GROUP_MIN_SIZE);
        let padded = scatter(&writer);
        assert_eq!(&padded[..long.len()], &long[..]);
        let at = 31 * EROFS_BLOCK_SIZE as usize;
        assert_eq!(&padded[at..at + tiny.len()], &tiny[..]);
    }

    #[test]
    fn blob_writer_sizes_packs_by_the_chunk_group_min_size() {
        let layout = |chunk_group_min_size| BlobLayout::ChunkGroups {
            chunk_group_min_size,
        };
        // The minimum sets the group span (four times it, at least a chunk)
        // and the lookup granule, even when larger than the chunk size.
        for (chunk_group_min_size, span, granule) in [
            (EROFS_BLOCK_SIZE, TEST_CHUNK_SIZE, EROFS_BLOCK_SIZE),
            (TEST_CHUNK_SIZE, 4 * TEST_CHUNK_SIZE, TEST_CHUNK_SIZE),
            (
                DEFAULT_CHUNK_GROUP_MIN_SIZE,
                4 * DEFAULT_CHUNK_GROUP_MIN_SIZE,
                DEFAULT_CHUNK_GROUP_MIN_SIZE,
            ),
        ] {
            let mut writer = writer(
                TEST_CHUNK_SIZE,
                BlobMetadataCompressor::None,
                layout(chunk_group_min_size),
            );
            write(&mut writer, &filled(100, b'p', Mark::Plain));
            writer.finish().unwrap();
            let meta = writer.blob_metadata().unwrap();
            assert_eq!(
                meta.group_span(),
                span,
                "chunk group minimum size {chunk_group_min_size}"
            );
            assert_eq!(
                meta.lookup_granule(),
                granule,
                "chunk group minimum size {chunk_group_min_size}"
            );
        }
        // With the default minimum a pack of one-block files runs to the
        // minimum before any boundary may close it: 512 plain files stay in
        // one open pack, the 513th strict one closes it.
        let mut writer = writer(
            TEST_CHUNK_SIZE,
            BlobMetadataCompressor::None,
            layout(DEFAULT_CHUNK_GROUP_MIN_SIZE),
        );
        let plain = filled(EROFS_BLOCK_SIZE as usize, b'q', Mark::Plain);
        let strict = filled(EROFS_BLOCK_SIZE as usize, b'r', Mark::Strict);
        write(&mut writer, &strict);
        for _ in 1..(DEFAULT_CHUNK_GROUP_MIN_SIZE / EROFS_BLOCK_SIZE) {
            write(&mut writer, &plain);
        }
        assert_eq!(writer.next_group, 0);
        write(&mut writer, &plain);
        assert_eq!(
            writer.next_group, 0,
            "a plain chunk past the minimum closes nothing"
        );
        write(&mut writer, &strict);
        assert_eq!(writer.next_group, 1);
        // Not a power of two, under a block, or over the span the blob meta
        // can record: rejected up front.
        for bad in [3 * 1024, EROFS_BLOCK_SIZE / 2, MAX_CHUNK_GROUP_MIN_SIZE * 2] {
            assert!(BlobWriter::new(
                Vec::new(),
                TEST_CHUNK_SIZE,
                BlobMetadataCompressor::None,
                BlobMetadataDigester::Blake3,
                true,
                layout(bad),
            )
            .is_err());
        }
        assert!(BlobWriter::new(
            Vec::new(),
            TEST_CHUNK_SIZE,
            BlobMetadataCompressor::None,
            BlobMetadataDigester::Blake3,
            true,
            layout(MAX_CHUNK_GROUP_MIN_SIZE),
        )
        .is_ok());
    }

    #[test]
    fn blob_writer_packs_full_chunks_below_the_default_group_minimum() {
        let chunk_size = 256 * 1024;
        let minimum = DEFAULT_CHUNK_GROUP_MIN_SIZE;
        for compressor in [BlobMetadataCompressor::None, BlobMetadataCompressor::Zstd] {
            for (mark, digester, chunks_per_group) in [
                (Mark::Strict, BlobMetadataDigester::Blake3, 8),
                (Mark::Plain, BlobMetadataDigester::Blake3, 32),
                (Mark::Strict, BlobMetadataDigester::None, 32),
            ] {
                let mut writer = BlobWriter::new(
                    Vec::new(),
                    chunk_size,
                    compressor,
                    digester,
                    true,
                    BlobLayout::ChunkGroups {
                        chunk_group_min_size: minimum,
                    },
                )
                .unwrap();
                let data = filled(chunk_size as usize, b'g', mark).repeat(33);
                let tail = filled(123, b't', Mark::Strict);
                let mut addrs = write(&mut writer, &data);
                addrs.extend(write(&mut writer, &tail));
                writer.finish().unwrap();

                let meta = writer.blob_metadata().unwrap();
                assert_eq!(meta.lookup_granule(), minimum);
                assert_eq!(meta.header().lookup_granule_byte_shift(), 21);
                assert_eq!(meta.group_span(), 4 * minimum);
                assert_eq!(meta.chunk_count(), 34);
                assert_eq!(meta.chunk_group_count(), 33 / chunks_per_group + 1);
                for group in meta.chunk_groups() {
                    if group.index() as usize + 1 < meta.chunk_group_count() {
                        assert!(group.uncompressed_size() >= u64::from(minimum));
                        assert!(group.uncompressed_size() <= u64::from(4 * minimum));
                        assert_eq!(group.chunk_count() as usize, chunks_per_group);
                    } else {
                        assert!(group.uncompressed_size() < u64::from(minimum));
                    }
                    for offset in group
                        .uncompressed_range()
                        .step_by(EROFS_BLOCK_SIZE as usize)
                    {
                        assert_eq!(
                            meta.chunk_group_index_of(offset),
                            Some(group.index() as usize)
                        );
                    }
                }
                assert_eq!(
                    resolve(&writer, &mut addrs),
                    (0..34)
                        .map(|index| index * u64::from(chunk_size / EROFS_BLOCK_SIZE))
                        .collect::<Vec<_>>()
                );
                let padded = scatter(&writer);
                assert_eq!(&padded[..data.len()], &data);
                assert_eq!(&padded[data.len()..data.len() + tail.len()], &tail);
            }
        }
    }

    #[test]
    fn blob_writer_stores_uncompressed_when_zstd_saves_too_little() {
        let mut writer = writer(
            TEST_CHUNK_SIZE,
            BlobMetadataCompressor::Zstd,
            BlobLayout::ChunkGroups {
                chunk_group_min_size: TEST_GROUP_MIN_SIZE,
            },
        );
        let noise = pseudo_random_bytes(TEST_CHUNK_SIZE as usize);
        let text = vec![b't'; TEST_CHUNK_SIZE as usize];
        write(&mut writer, &noise);
        write(&mut writer, &text);
        writer.finish().unwrap();
        let meta = writer.blob_metadata().unwrap();
        let groups: Vec<_> = meta.chunk_groups().collect();
        assert_eq!(groups.len(), 2);
        assert!(meta.is_plain(&groups[0]));
        assert_eq!(groups[0].compressed_size(), TEST_CHUNK_SIZE);
        assert!(!meta.is_plain(&groups[1]));
        assert!(groups[1].compressed_size() < TEST_CHUNK_SIZE / 10);
        let padded = scatter(&writer);
        assert_eq!(&padded[..noise.len()], &noise[..]);
        assert_eq!(&padded[TEST_CHUNK_SIZE as usize..], &text[..]);
    }

    #[test]
    fn blob_writer_compresses_packed_groups_and_scatters_back() {
        let mut writer = writer(
            TEST_CHUNK_SIZE,
            BlobMetadataCompressor::Zstd,
            BlobLayout::ChunkGroups {
                chunk_group_min_size: TEST_GROUP_MIN_SIZE,
            },
        );
        let files: Vec<Vec<u8>> = (0..40u8)
            .map(|index| vec![b'a' + index % 26; 1_000 + 500 * index as usize])
            .collect();
        let mut addrs = Vec::new();
        for file in &files {
            addrs.extend(write(&mut writer, file));
        }
        writer.finish().unwrap();
        let addrs = resolve(&writer, &mut addrs);
        let meta = writer.blob_metadata().unwrap();
        assert!(meta.chunk_group_count() > 1);
        assert_eq!(meta.chunk_count(), files.len());
        assert!(meta.chunk_groups().all(|group| !meta.is_plain(&group)));
        let padded = scatter(&writer);
        for (file, addr) in files.iter().zip(addrs) {
            let offset = addr as usize * EROFS_BLOCK_SIZE as usize;
            assert_eq!(&padded[offset..offset + file.len()], &file[..]);
        }
        // Every group's digest derives from its chunks' bytes.
        for group in meta.chunk_groups() {
            let members: Vec<[u8; 32]> = meta
                .chunk_group_chunks(group.index() as usize)
                .map(|(_, offset, len)| {
                    *blake3::hash(&padded[offset as usize..offset as usize + len as usize])
                        .as_bytes()
                })
                .collect();
            assert_eq!(
                meta.digest(group.index() as usize).unwrap(),
                &BlobMetadataDigest::of_group(&members).unwrap()
            );
        }
    }

    #[test]
    fn blob_writer_writes_blob_metadata_file() {
        let dir = tempdir().unwrap();
        let blob_path = dir.path().join("blob.data");
        let meta_path = dir.path().join("blob.meta");
        let mut writer = BlobWriter::new(
            File::create(&blob_path).unwrap(),
            TEST_CHUNK_SIZE,
            BlobMetadataCompressor::None,
            BlobMetadataDigester::None,
            true,
            BlobLayout::ChunkGroups {
                chunk_group_min_size: TEST_GROUP_MIN_SIZE,
            },
        )
        .unwrap();
        writer
            .write_reader_chunks(&mut &[7u8; 5000][..], 5000)
            .unwrap();
        writer.write_blob_metadata(&meta_path).unwrap();
        let meta = BlobMetadata::from_path(&meta_path, true).unwrap();
        assert_eq!(meta.chunk_count(), 1);
        assert_eq!(meta.digest_count(), 0);
        assert_eq!(meta.group_span(), 2 * TEST_CHUNK_SIZE);
        assert_eq!(meta.compressed_end(), 5000);
        // The 5000-byte chunk spans two blocks, and the blob ends there.
        assert_eq!(meta.uncompressed_size(), 2 * EROFS_BLOCK_SIZE as u64);
        assert_eq!(meta.lookup_granule(), TEST_GROUP_MIN_SIZE);
    }

    #[test]
    fn raw_device_writes_padded_chunks_in_place() {
        let mut writer = writer(
            TEST_CHUNK_SIZE,
            BlobMetadataCompressor::None,
            BlobLayout::RawDevice {
                data_alignment: 0,
                data_alignment_threshold: 0,
            },
        );
        let file = vec![b'r'; 5000];
        let mut addrs = write(&mut writer, &file);
        addrs.extend(write(&mut writer, &file));
        writer.finish().unwrap();
        // Addresses are immediate and resolution leaves them alone.
        assert_eq!(resolve(&writer, &mut addrs), vec![0, 2]);
        assert_eq!(writer.total_blocks(), 4);
        assert_eq!(writer.writer.len(), 4 * EROFS_BLOCK_SIZE as usize);
        assert!(writer.blob_metadata().is_err());
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
        z_writer_configured(algorithm, 0, 0, 0)
    }

    fn z_writer_configured(
        algorithm: ZAlgorithm,
        fragment_threshold: u64,
        data_alignment: u32,
        data_alignment_threshold: u64,
    ) -> BlobWriter<Vec<u8>> {
        BlobWriter::new(
            Vec::new(),
            EROFS_BLOCK_SIZE,
            BlobMetadataCompressor::None,
            BlobMetadataDigester::None,
            true,
            BlobLayout::ZErofs {
                algorithm,
                pcluster: 16 * EROFS_BLOCK_SIZE,
                base_blkaddr: Z_BASE,
                fragment_threshold,
                data_alignment,
                data_alignment_threshold,
            },
        )
        .unwrap()
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
    fn z_erofs_zstd_stops_fitting_a_nearly_full_pcluster() {
        let pcluster = 16 * BLOCK;
        let mut source = pseudo_random_bytes(2 * pcluster);
        source[..1280].fill(0);
        source[pcluster..].fill(0);
        let mut compressor = ZCompressor::new(ZAlgorithm::Zstd, pcluster);
        let (take, size, compressed) = compressor.fit_pcluster(&source, true, pcluster, pcluster);
        assert_eq!(take, pcluster);
        assert!((pcluster * 98 / 100..=pcluster).contains(&size));
        assert_eq!(
            zstd::bulk::decompress(&compressed[..size], take).unwrap(),
            source[..take]
        );
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
        let mut writer =
            z_writer_configured(ZAlgorithm::Lz4, 0, 8 * EROFS_BLOCK_SIZE, 2 * BLOCK as u64);
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
        let mut writer = z_writer_configured(ZAlgorithm::Lz4, BLOCK as u64, 0, 0);
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
    fn z_erofs_fragments_recover_from_a_short_read_and_keep_content_in_order() {
        for algorithm in [ZAlgorithm::Lz4, ZAlgorithm::Zstd] {
            let mut writer = z_writer_configured(algorithm, 64 << 10, 0, 0);
            let content = pseudo_random_bytes(64 << 10);
            let mut distinct = content.clone();
            for index in 0..(Z_SEGMENT_SIZE * 2 / content.len()) {
                distinct[..8].copy_from_slice(&(index as u64).to_le_bytes());
                writer
                    .write_reader_z(&mut &distinct[..], distinct.len() as u64)
                    .unwrap();
            }
            let size_before = writer.z_packed.as_ref().unwrap().size;
            assert!(writer
                .write_reader_z(&mut &content[..100], content.len() as u64)
                .is_err());
            assert_eq!(writer.z_packed.as_ref().unwrap().size, size_before);
            let first = writer
                .write_reader_z(&mut &content[..], content.len() as u64)
                .unwrap();
            // Identical content is stored again at its own offset.
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
            let decoded = decode_z_file(&data, &packed.tail, packed_size as usize);
            let mut chunks = decoded.chunks_exact(content.len());
            for index in 0..(Z_SEGMENT_SIZE * 2 / content.len()) {
                distinct[..8].copy_from_slice(&(index as u64).to_le_bytes());
                assert_eq!(chunks.next().unwrap(), &distinct);
            }
            assert_eq!(chunks.next().unwrap(), &content);
            assert_eq!(chunks.next().unwrap(), &content);
            assert_eq!(
                packed_size as usize,
                ((Z_SEGMENT_SIZE * 2 / content.len() + 2) * content.len()).next_multiple_of(BLOCK)
            );
        }
    }

    #[test]
    fn z_erofs_fragments_beyond_the_pipeline_depth_commit_while_packing() {
        let mut writer = z_writer_configured(ZAlgorithm::Lz4, 64 << 10, 0, 0);
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
