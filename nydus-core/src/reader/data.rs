use std::cell::RefCell;
use std::io;
use std::io::Write;

use nydus_format::erofs::{
    cast_ref, ErofsChunkAddr, ErofsChunkIndex, ErofsInode, ZAlgorithm, EROFS_BLOCK_SIZE,
    EROFS_CHUNK_INDEX_SIZE, EROFS_INODE_CHUNK_BASED, EROFS_INODE_COMPRESSED_FULL,
    EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN, EROFS_NULL_ADDR,
    Z_EROFS_ADVISE_FRAGMENT_PCLUSTER, Z_EROFS_FRAGMENT_INODE_FLAG, Z_EROFS_LCLUSTER_INDEX_SIZE,
    Z_EROFS_LCLUSTER_TYPE_HEAD1, Z_EROFS_LCLUSTER_TYPE_NONHEAD, Z_EROFS_LCLUSTER_TYPE_PLAIN,
    Z_EROFS_LI_D0_CBLKCNT, Z_EROFS_LI_LCLUSTER_TYPE_MASK, Z_EROFS_MAP_HEADER_SIZE,
};
use nydus_format::utils::align_up_usize;

use super::z_cache::PclusterKey;
use super::{ErofsReader, RawBlobInfo};

/// Resolve an absolute byte offset in the flattened device to the blob that
/// backs it, returning `(blob_index, offset_within_blob)`. Returns `None` when
/// the address is bootstrap-local (not in any blob's mapped range).
pub(crate) fn locate_flat_blob(blob_layout: &[RawBlobInfo], abs_offset: u64) -> Option<(u16, u64)> {
    let block_size = EROFS_BLOCK_SIZE as u64;
    for info in blob_layout {
        let start = info.mapped_blkaddr * block_size;
        let end = start + info.blocks * block_size;
        if abs_offset >= start && abs_offset < end {
            return Some((info.blob_index, abs_offset - start));
        }
    }
    None
}

/// Where a chunk's data lives, as decided by [`locate_chunk`].
pub(crate) enum ChunkLocation {
    /// Null chunk address: a sparse hole.
    Hole,
    /// The chunk starts at `offset` within blob `index`, either via the legacy
    /// separate-blob layout (non-zero device_id, blob-relative address) or via
    /// the flattened layout (device_id 0 with an absolute address falling in a
    /// blob's mapped range).
    Blob { index: u16, offset: u64 },
    /// The chunk is bootstrap-local: a flattened-layout absolute address that
    /// falls outside every blob's mapped range, resolved against the bootstrap
    /// mmap at absolute byte `offset`.
    Local { offset: u64 },
}

/// Resolve one chunk index entry to the location backing its data. Captures
/// the shared decision (null address → hole, non-zero device_id → legacy
/// blob-relative, otherwise flat-layout lookup) once for every read, write,
/// fetch and range-resolution path.
pub(crate) fn locate_chunk(
    blob_layout: &[RawBlobInfo],
    blkaddr: u64,
    device_id: u16,
) -> io::Result<ChunkLocation> {
    if blkaddr == EROFS_NULL_ADDR {
        return Ok(ChunkLocation::Hole);
    }
    let chunk_addr = blkaddr
        .checked_mul(EROFS_BLOCK_SIZE as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "chunk address overflow"))?;
    if device_id > 0 {
        // Legacy separate-blob layout: blob-relative address.
        return Ok(ChunkLocation::Blob {
            index: device_id,
            offset: chunk_addr,
        });
    }
    // Flattened layout: device_id 0 with an absolute address.
    match locate_flat_blob(blob_layout, chunk_addr) {
        Some((index, offset)) => Ok(ChunkLocation::Blob { index, offset }),
        None => Ok(ChunkLocation::Local { offset: chunk_addr }),
    }
}

/// One chunk-aligned span of a file byte range, as visited by
/// [`for_each_chunk_span`].
pub(crate) struct ChunkSpan {
    /// Chunk index within the inode.
    pub index: usize,
    /// Byte offset of the span within the chunk.
    pub chunk_off: u64,
    /// Span length in bytes.
    pub len: u64,
    /// File position of the span start.
    pub file_pos: u64,
}

/// Walk the file byte range `[offset, offset + len)` chunk by chunk, calling
/// `f` once per span. Stops silently once the range runs past the last chunk;
/// returns the number of bytes covered.
pub(crate) fn for_each_chunk_span<E>(
    offset: u64,
    len: u64,
    chunk_size: u64,
    nchunks: usize,
    mut f: impl FnMut(ChunkSpan) -> Result<(), E>,
) -> Result<u64, E> {
    let mut remaining = len;
    let mut file_pos = offset;
    while remaining > 0 {
        let index = (file_pos / chunk_size) as usize;
        if index >= nchunks {
            break;
        }
        let chunk_off = file_pos % chunk_size;
        let step = remaining.min(chunk_size - chunk_off);
        f(ChunkSpan {
            index,
            chunk_off,
            len: step,
            file_pos,
        })?;
        file_pos += step;
        remaining -= step;
    }
    Ok(len - remaining)
}

impl ErofsReader {
    /// Log2 of the chunk size for a chunk-based inode.
    pub fn chunk_bits(&self, inode: &ErofsInode<'_>) -> u32 {
        self.superblock().blkszbits as u32 + (inode.chunk_format() as u32 & 0x1F)
    }

    /// Chunk size in bytes for a chunk-based inode.
    pub fn chunk_size(&self, inode: &ErofsInode<'_>) -> u64 {
        1u64 << self.chunk_bits(inode)
    }

    fn chunk_index_bytes<'a>(&'a self, nid: u64, inode: &ErofsInode<'_>) -> io::Result<&'a [u8]> {
        if inode.data_layout() != EROFS_INODE_CHUNK_BASED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a chunk-based inode",
            ));
        }
        let chunk_size = self.chunk_size(inode);
        let nchunks = inode.size().div_ceil(chunk_size) as usize;
        let inode_offset = self.nid_to_offset(nid);
        let header_size = inode.header_size() + inode.xattr_size();
        let index_offset = inode_offset
            + align_up_usize(header_size, EROFS_CHUNK_INDEX_SIZE).expect("alignment overflowed");
        let index_total = nchunks * EROFS_CHUNK_INDEX_SIZE;
        self.mmap_slice(index_offset, index_total)
    }

    fn chunk_index_entry_at(index_bytes: &[u8], i: usize) -> &ErofsChunkIndex {
        let off = i * EROFS_CHUNK_INDEX_SIZE;
        cast_ref::<ErofsChunkIndex>(&index_bytes[off..])
    }

    /// The raw inode tail of a z_erofs COMPRESSED_FULL inode: either the
    /// 8-byte whole-file fragment header (bit 63 set, rest = offset in the
    /// packed inode) or the map header, 8 reserved bytes and one full
    /// lcluster index per block of the file.
    pub fn read_z_inode_tail<'a>(
        &'a self,
        nid: u64,
        inode: &ErofsInode<'_>,
    ) -> io::Result<&'a [u8]> {
        if inode.data_layout() != EROFS_INODE_COMPRESSED_FULL {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a z_erofs compressed inode",
            ));
        }
        let inode_offset = self.nid_to_offset(nid);
        let header_size = inode.header_size() + inode.xattr_size();
        let tail_offset =
            inode_offset + align_up_usize(header_size, 8).expect("alignment overflowed");
        let head = self.mmap_slice(tail_offset, Z_EROFS_MAP_HEADER_SIZE)?;
        let head = u64::from_le_bytes(head.try_into().expect("8-byte map header"));
        if inode.size() > 0 && head & Z_EROFS_FRAGMENT_INODE_FLAG != 0 {
            return self.mmap_slice(tail_offset, Z_EROFS_MAP_HEADER_SIZE);
        }
        let lclusters = inode.size().div_ceil(EROFS_BLOCK_SIZE as u64) as usize;
        let len = Z_EROFS_MAP_HEADER_SIZE + 8 + lclusters * Z_EROFS_LCLUSTER_INDEX_SIZE;
        self.mmap_slice(tail_offset, len)
    }

    pub fn read_chunk_index_entries(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
    ) -> io::Result<Vec<ErofsChunkAddr>> {
        if inode.size() == 0 {
            return Ok(Vec::new());
        }

        let chunk_size = self.chunk_size(inode);
        let index_bytes = self.chunk_index_bytes(nid, inode)?;
        let nchunks = inode.size().div_ceil(chunk_size) as usize;
        let mut result = Vec::with_capacity(nchunks);
        for index in 0..nchunks {
            let entry = Self::chunk_index_entry_at(index_bytes, index);
            result.push(ErofsChunkAddr {
                blkaddr: entry.blkaddr(),
                device_id: entry.device_id(),
            });
        }
        Ok(result)
    }

    // ------------------------------------------------------------------
    // Zero-copy write: mmap slices → Writer directly (no intermediate Vec)
    // ------------------------------------------------------------------

    /// Write file data directly to a writer, avoiding intermediate allocation.
    /// Returns the number of bytes written.
    pub fn write_file_data_to(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: u32,
        w: &mut dyn Write,
    ) -> io::Result<usize> {
        if offset >= inode.size() {
            return Ok(0);
        }
        let actual_size = std::cmp::min(size as u64, inode.size() - offset) as usize;
        let layout = inode.data_layout();

        match layout {
            EROFS_INODE_FLAT_PLAIN | EROFS_INODE_FLAT_INLINE => {
                self.write_flat_data_to(nid, inode, offset, actual_size, w)
            }
            EROFS_INODE_CHUNK_BASED => self.write_chunk_data_to(nid, inode, offset, actual_size, w),
            EROFS_INODE_COMPRESSED_FULL => {
                self.write_z_data_to(nid, inode, offset, actual_size, w, 0)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported data layout: {layout}"),
            )),
        }
    }

    fn write_flat_data_to(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: usize,
        w: &mut dyn Write,
    ) -> io::Result<usize> {
        let layout = inode.data_layout();
        if layout == EROFS_INODE_FLAT_INLINE {
            let blocks_size = Self::block_region_size(inode);

            if blocks_size > 0
                && (offset as usize) < blocks_size
                && (offset as usize + size) > blocks_size
            {
                // Read spans block+inline boundary — two writes
                let block_read_size = blocks_size - offset as usize;
                let startblk = inode.startblk();
                let block_offset = (startblk * EROFS_BLOCK_SIZE as u64 + offset) as usize;
                let block_data = self.mmap_slice(block_offset, block_read_size)?;
                w.write_all(block_data)?;

                let inline_read_size = size - block_read_size;
                let inode_offset = self.nid_to_offset(nid);
                let header_size = inode.header_size() + inode.xattr_size();
                let inline_data = self.mmap_slice(inode_offset + header_size, inline_read_size)?;
                w.write_all(inline_data)?;
                return Ok(size);
            }
        }
        // Non-spanning: single mmap slice → writer
        let slice = self.read_flat_data(nid, inode, offset, size)?;
        w.write_all(slice)?;
        Ok(size)
    }

    fn write_chunk_data_to(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: usize,
        w: &mut dyn Write,
    ) -> io::Result<usize> {
        let chunk_size = self.chunk_size(inode);
        let index_bytes = self.chunk_index_bytes(nid, inode)?;
        let nchunks = inode.size().div_ceil(chunk_size) as usize;
        let blob_layout = self.blob_infos()?;

        let written = for_each_chunk_span(
            offset,
            size as u64,
            chunk_size,
            nchunks,
            |span| -> io::Result<()> {
                let chunk_off = span.chunk_off;
                let to_read = span.len as usize;
                let entry = Self::chunk_index_entry_at(index_bytes, span.index);
                match locate_chunk(blob_layout, entry.blkaddr(), entry.device_id())? {
                    ChunkLocation::Hole => {
                        // Hole — write zeros (use small stack buffer to avoid large alloc)
                        let zeros = [0u8; 4096];
                        let mut left = to_read;
                        while left > 0 {
                            let n = std::cmp::min(left, zeros.len());
                            w.write_all(&zeros[..n])?;
                            left -= n;
                        }
                    }
                    ChunkLocation::Blob { index, offset } => {
                        self.write_blob_to(index, offset, chunk_off, to_read, w)?;
                    }
                    ChunkLocation::Local { offset } => {
                        let data_offset = (offset + chunk_off) as usize;
                        let slice = self.mmap_slice(data_offset, to_read)?;
                        w.write_all(slice)?;
                    }
                }
                Ok(())
            },
        )?;

        Ok(written as usize)
    }

    // ------------------------------------------------------------------
    // z_erofs (COMPRESSED_FULL) read: userspace counterpart of the kernel's
    // pcluster decompression, over the blob caches holding the raw
    // (compressed) layer data.
    // ------------------------------------------------------------------

    /// Reads z_erofs ranges through packed fragments and cached LZ4/zstd pclusters.
    fn write_z_data_to(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: usize,
        w: &mut dyn Write,
        depth: u8,
    ) -> io::Result<usize> {
        let tail = self.read_z_inode_tail(nid, inode)?;
        let head = u64::from_le_bytes(tail[..Z_EROFS_MAP_HEADER_SIZE].try_into().unwrap());
        if head & Z_EROFS_FRAGMENT_INODE_FLAG != 0 {
            if depth > 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packed inode is itself a fragment",
                ));
            }
            let packed_nid = self.superblock().packed_nid().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "fragment without packed inode")
            })?;
            let packed = self.inode(packed_nid)?;
            let frag_off = head & !Z_EROFS_FRAGMENT_INODE_FLAG;
            return self.write_z_data_to(
                packed_nid,
                &packed,
                frag_off + offset,
                size,
                w,
                depth + 1,
            );
        }

        let block = EROFS_BLOCK_SIZE as u64;
        let file_size = inode.size();
        let indexes = &tail[Z_EROFS_MAP_HEADER_SIZE + 8..];
        let nlclusters = indexes.len() / Z_EROFS_LCLUSTER_INDEX_SIZE;
        let index_at = |i: usize| -> (u16, u32) {
            let e = &indexes[i * Z_EROFS_LCLUSTER_INDEX_SIZE..][..Z_EROFS_LCLUSTER_INDEX_SIZE];
            let advise = u16::from_le_bytes(e[..2].try_into().unwrap());
            let word = u32::from_le_bytes(e[4..8].try_into().unwrap());
            (advise & Z_EROFS_LI_LCLUSTER_TYPE_MASK, word)
        };
        // Tail fragment: the last extent is served from the packed inode.
        let h_advise = u16::from_le_bytes(tail[4..6].try_into().unwrap());
        let algorithm = ZAlgorithm::from_type(tail[6] & 0x0f).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported z_erofs algorithm {}", tail[6] & 0x0f),
            )
        })?;
        let tail_fragment = if h_advise & Z_EROFS_ADVISE_FRAGMENT_PCLUSTER != 0 {
            let head = (0..nlclusters)
                .rev()
                .find(|&i| index_at(i).0 != Z_EROFS_LCLUSTER_TYPE_NONHEAD)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "tail fragment without head")
                })?;
            let lo = u32::from_le_bytes(tail[..4].try_into().unwrap());
            Some((head, (u64::from(index_at(head).1) << 32) | u64::from(lo)))
        } else {
            None
        };
        let blob_layout = self.blob_infos()?;
        let end = offset + size as u64;

        // Back up to the head of the pcluster covering `offset`.
        let mut i = (offset / block) as usize;
        while index_at(i).0 == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
            let delta0 = index_at(i).1 as u16;
            let distance = if delta0 & Z_EROFS_LI_D0_CBLKCNT != 0 {
                1
            } else {
                usize::from(delta0)
            };
            if distance == 0 || distance > i {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid pcluster head distance",
                ));
            }
            i -= distance;
        }

        thread_local! {
            static Z_BUFS: RefCell<(Vec<u8>, Vec<u8>, Option<zstd::bulk::Decompressor<'static>>)> =
                const { RefCell::new((Vec::new(), Vec::new(), None)) };
        }
        let mut written = 0usize;
        // The tail fragment is the file's last extent; it is read after the
        // scratch buffers are released since it recurses into the packed inode.
        let mut deferred_tail: Option<(u64, u64)> = None;
        Z_BUFS.with(|cell| -> io::Result<()> {
            let mut bufs = cell.borrow_mut();
            let (compressed, decoded, zstd) = &mut *bufs;
            while i < nlclusters {
                let logical_start = i as u64 * block;
                if logical_start >= end {
                    break;
                }
                let (kind, word) = index_at(i);
                let mut j = i + 1;
                while j < nlclusters && index_at(j).0 == Z_EROFS_LCLUSTER_TYPE_NONHEAD {
                    let distance = (index_at(j).1 >> 16) as usize + 1;
                    j = j
                        .checked_add(distance)
                        .filter(|&end| end <= nlclusters)
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid pcluster tail distance",
                            )
                        })?;
                }
                let logical_len = ((j - i) as u64 * block).min(file_size - logical_start) as usize;
                if let Some((head, frag_off)) = tail_fragment {
                    if i == head {
                        let from = offset.max(logical_start) - logical_start;
                        let to = end.min(logical_start + logical_len as u64) - logical_start;
                        if to > from {
                            deferred_tail = Some((frag_off + from, to - from));
                        }
                        break;
                    }
                }
                let phys_blocks = match kind {
                    Z_EROFS_LCLUSTER_TYPE_PLAIN => 1usize,
                    Z_EROFS_LCLUSTER_TYPE_HEAD1 if j - i >= 2 => {
                        let delta0 = index_at(i + 1).1 as u16;
                        if delta0 & Z_EROFS_LI_D0_CBLKCNT == 0 {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "z_erofs pcluster without CBLKCNT",
                            ));
                        }
                        (delta0 & !Z_EROFS_LI_D0_CBLKCNT) as usize
                    }
                    Z_EROFS_LCLUSTER_TYPE_HEAD1 => 1,
                    other => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unsupported z_erofs lcluster type {other}"),
                        ))
                    }
                };
                let phys_len = phys_blocks * EROFS_BLOCK_SIZE as usize;
                let (blob_index, blob_off) = locate_flat_blob(blob_layout, word as u64 * block)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("z_erofs pcluster at block {word} outside every device"),
                        )
                    })?;
                let key = PclusterKey {
                    blob_index,
                    offset: blob_off,
                    physical_len: phys_len,
                    logical_len,
                    algorithm,
                };
                let from = (offset.max(logical_start) - logical_start) as usize;
                let to = (end.min(logical_start + logical_len as u64) - logical_start) as usize;
                if kind == Z_EROFS_LCLUSTER_TYPE_HEAD1 {
                    if let Some(data) = self.z_pclusters.get(key) {
                        w.write_all(&data[from..to])?;
                        written += to - from;
                        i = j;
                        continue;
                    }
                }
                compressed.resize(phys_len, 0);
                self.read_blob_into(blob_index, blob_off, 0, &mut compressed[..phys_len])?;

                let data: &[u8] = if kind == Z_EROFS_LCLUSTER_TYPE_PLAIN {
                    &compressed[..logical_len]
                } else {
                    // ZERO_PADDING: the compressed payload is tail-aligned in
                    // the pcluster and never starts with a zero byte (LZ4
                    // token or zstd magic).
                    let payload_start = compressed[..phys_len]
                        .iter()
                        .position(|b| *b != 0)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "empty z_erofs pcluster")
                        })?;
                    decoded.resize(logical_len, 0);
                    let payload = &compressed[payload_start..phys_len];
                    let n = match algorithm {
                        ZAlgorithm::Lz4 => lz4_flex::block::decompress_into(payload, decoded)
                            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
                        ZAlgorithm::Zstd => {
                            if zstd.is_none() {
                                *zstd = Some(zstd::bulk::Decompressor::new()?);
                            }
                            zstd.as_mut()
                                .expect("initialized above")
                                .decompress_to_buffer(payload, decoded)?
                        }
                    };
                    if n != logical_len {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "z_erofs pcluster decoded to {n} bytes, expected {logical_len}"
                            ),
                        ));
                    }
                    self.z_pclusters.insert(key, decoded);
                    &decoded[..]
                };

                let from = offset.max(logical_start) - logical_start;
                let to = end.min(logical_start + logical_len as u64) - logical_start;
                if to > from {
                    w.write_all(&data[from as usize..to as usize])?;
                    written += (to - from) as usize;
                }
                i = j;
            }
            Ok(())
        })?;
        if let Some((packed_off, len)) = deferred_tail {
            let packed_nid = self.superblock().packed_nid().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tail fragment without packed inode",
                )
            })?;
            let packed = self.inode(packed_nid)?;
            written +=
                self.write_z_data_to(packed_nid, &packed, packed_off, len as usize, w, depth + 1)?;
        }
        Ok(written)
    }

    // ------------------------------------------------------------------
    // File data read
    // ------------------------------------------------------------------

    pub fn read_file_data(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: u32,
    ) -> io::Result<Vec<u8>> {
        if offset >= inode.size() {
            return Ok(Vec::new());
        }
        let actual_size = std::cmp::min(size as u64, inode.size() - offset) as usize;
        let layout = inode.data_layout();

        match layout {
            EROFS_INODE_FLAT_PLAIN | EROFS_INODE_FLAT_INLINE => {
                self.read_flat_data_vec(nid, inode, offset, actual_size)
            }
            EROFS_INODE_CHUNK_BASED => self.read_chunk_data(nid, inode, offset, actual_size),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported data layout: {layout}"),
            )),
        }
    }

    // ------------------------------------------------------------------
    // Chunk data — sync
    // ------------------------------------------------------------------

    fn read_chunk_data(
        &self,
        nid: u64,
        inode: &ErofsInode<'_>,
        offset: u64,
        size: usize,
    ) -> io::Result<Vec<u8>> {
        let chunk_size = self.chunk_size(inode);
        let index_bytes = self.chunk_index_bytes(nid, inode)?;
        let nchunks = inode.size().div_ceil(chunk_size) as usize;
        let blob_layout = self.blob_infos()?;

        let mut result = vec![0u8; size];
        for_each_chunk_span(offset, size as u64, chunk_size, nchunks, |span| {
            let entry = Self::chunk_index_entry_at(index_bytes, span.index);
            let buf_pos = (span.file_pos - offset) as usize;
            self.read_chunk_slice(
                blob_layout,
                entry,
                span.chunk_off,
                &mut result[buf_pos..buf_pos + span.len as usize],
            )
        })?;

        Ok(result)
    }

    /// Resolve one chunk's data into `dst`. Handles holes, the legacy
    /// separate-blob layout (non-zero device_id, blob-relative address) and the
    /// flattened layout (device_id 0 with an absolute address, resolved to a
    /// blob or to bootstrap-local data).
    fn read_chunk_slice(
        &self,
        blob_layout: &[RawBlobInfo],
        entry: &ErofsChunkIndex,
        chunk_off: u64,
        dst: &mut [u8],
    ) -> io::Result<()> {
        match locate_chunk(blob_layout, entry.blkaddr(), entry.device_id())? {
            ChunkLocation::Hole => {
                // Hole — zero the destination explicitly rather than relying on
                // callers to hand in a fresh zeroed buffer.
                dst.fill(0);
                Ok(())
            }
            ChunkLocation::Blob { index, offset } => {
                self.read_blob_into(index, offset, chunk_off, dst)
            }
            ChunkLocation::Local { offset } => {
                let data_offset = (offset + chunk_off) as usize;
                let slice = self.mmap_slice(data_offset, dst.len())?;
                dst.copy_from_slice(slice);
                Ok(())
            }
        }
    }
}
