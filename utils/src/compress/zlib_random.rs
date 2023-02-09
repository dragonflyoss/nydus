// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Generate context information to randomly access gzip/zlib stream.

use std::alloc::{self, Layout};
use std::convert::TryFrom;
use std::io::{Read, Result};
use std::ops::DerefMut;
use std::os::raw::{c_int, c_void};
use std::sync::{Arc, Mutex};
use std::{mem, ptr};

use libz_sys::{
    inflate, inflateEnd, inflateInit2_, inflatePrime, inflateReset, inflateSetDictionary, uInt,
    z_stream, zlibVersion, Z_BLOCK, Z_BUF_ERROR, Z_OK, Z_STREAM_END,
};
use sha2::{Digest, Sha256};

/// Size of inflate dictionary to support random access.
pub const ZRAN_DICT_WIN_SIZE: usize = 1 << 15;
/// Maximum number of random access slices per compression object.
pub const ZRAN_MAX_CI_ENTRIES: usize = 1 << 24;
/// Buffer size for ZRAN reader.
pub const ZRAN_READER_BUF_SIZE: usize = 64 * 1024;

const ZRAN_MIN_COMP_SIZE: u64 = 768 * 1024;
const ZRAN_MAX_COMP_SIZE: u64 = 2048 * 1024;
const ZRAN_MAX_UNCOMP_SIZE: u64 = 2048 * 1024;
const ZLIB_ALIGN: usize = std::mem::align_of::<usize>();

/// Information to retrieve a data chunk from an associated random access slice.
#[derive(Debug, Eq, PartialEq)]
pub struct ZranChunkInfo {
    /// Index into the inflate context array for the associated inflate context.
    pub ci_index: u32,
    /// Offset to get data chunk from the uncompressed content.
    pub ci_offset: u32,
    /// Size of the uncompressed chunk data.
    pub ci_len: u32,
    /// Position in the compressed data stream.
    pub in_pos: u64,
    /// Size of compressed data in input stream.
    pub in_len: u32,
}

/// Context information to decode data from a random access slice.
pub struct ZranContext {
    /// Offset in the original compression data stream.
    pub in_offset: u64,
    /// Offset in the uncompression data stream.
    pub out_offset: u64,
    /// Size of original compressed data.
    pub in_len: u32,
    /// Size of uncompressed data.
    pub out_len: u32,
    /// Optional previous byte in the original compressed data stream, used when `ctx_bits` is non-zero.
    pub ctx_byte: u8,
    /// Bits from previous byte to feeds into the inflate context for random access.
    pub ctx_bits: u8,
    /// Inflate dictionary for random access.
    pub dict: Vec<u8>,
}

impl ZranContext {
    fn new(info: &ZranCompInfo, dict: Vec<u8>) -> Self {
        ZranContext {
            in_offset: info.in_pos,
            out_offset: info.out_pos,
            in_len: 0,
            out_len: 0,
            ctx_byte: info.previous_byte,
            ctx_bits: info.pending_bits,
            dict,
        }
    }
}

/// Gzip/zlib decoder to randomly uncompress Gzip/zlib stream.
pub struct ZranDecoder {
    stream: ZranStream,
}

impl ZranDecoder {
    /// Create a new instance of `ZranDecoder`.
    pub fn new() -> Result<Self> {
        let stream = ZranStream::new(true)?;
        Ok(Self { stream })
    }

    /// Uncompress gzip/zlib compressed data chunk.
    ///
    /// # Arguments
    /// - ctx: context to random access compressed stream.
    /// - dict: use this dictionary instead of `ctx.dict` to decode data
    /// - input: input compressed data stream
    /// - output: buffer to receive uncompressed data
    pub fn uncompress(
        &mut self,
        ctx: &ZranContext,
        dict: Option<&[u8]>,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize> {
        if input.len() != ctx.in_len as usize {
            return Err(einval!("size of input buffer doesn't match"));
        } else if ctx.out_len as usize > output.len() {
            return Err(einval!("buffer to receive decompressed data is too small"));
        }

        self.stream.reset()?;
        if ctx.ctx_bits != 0 {
            let bits = ctx.ctx_bits & 0x7;
            self.stream.set_prime(bits, ctx.ctx_byte)?;
        }
        let dict = dict.unwrap_or(ctx.dict.as_slice());
        self.stream.set_dict(dict)?;

        self.stream.set_next_in(input);
        self.stream.set_next_out(output);
        self.stream.set_avail_out(ctx.out_len as uInt);
        let ret = self.stream.inflate(true);
        match ret {
            Z_OK => {
                let count = self.stream.next_out() as usize - output.as_ptr() as usize;
                if count != ctx.out_len as usize {
                    Err(eio!("failed to decode data from stream, size mismatch"))
                } else {
                    Ok(count)
                }
            }
            _ => Err(eio!("failed to decode data from compressed data stream")),
        }
    }
}

/// Struct to generate random access information for OCIv1 image tarballs.
///
/// `ZranGenerator` generates decompression context information to support random access to the
/// tarball later. It only tracks information related to Tar file content, and ignores all other
/// tar headers and zlib headers when possible. The work flow is:
/// 1) create a `ZranGenerator` object `zran`.
/// 2) create a tar::Archive object from `zran`.
/// 3) walk all entries in the tarball, for each tar regular file:
/// 3.1) get file size and split it into chunks, for each file data chunk
/// 3.2) call zran.begin_data_chunk()
/// 3.3) read file content from the tar Entry object
/// 3.4) call zran.end_data_chunk() to get chunk decompression information
/// 4) call zran.get_compression_info_array() to get all decompression context information for
///    random access later
pub struct ZranGenerator<R> {
    reader: ZranReader<R>,
    min_comp_size: u64,
    max_comp_size: u64,
    max_uncomp_size: u64,
    curr_block_start: u64,
    curr_ci_offset: u64,
    curr_in_offset: u64,
    curr_ci_idx: Option<usize>,
    ci_array: Vec<ZranContext>,
}

impl<R: Read> ZranGenerator<R> {
    /// Create a new instance of `ZranGenerator` from a reader.
    pub fn new(reader: ZranReader<R>) -> Self {
        Self {
            reader,
            min_comp_size: ZRAN_MIN_COMP_SIZE,
            max_comp_size: ZRAN_MAX_COMP_SIZE,
            max_uncomp_size: ZRAN_MAX_UNCOMP_SIZE,
            curr_block_start: 0,
            curr_ci_offset: 0,
            curr_in_offset: 0,
            curr_ci_idx: None,
            ci_array: Vec::new(),
        }
    }

    /// Begin a transaction to read data from the zlib stream.
    ///
    /// # Arguments
    /// - `chunk_size`: size of data to be read from the zlib stream.
    #[allow(clippy::if_same_then_else)]
    pub fn begin_read(&mut self, chunk_size: u64) -> Result<u32> {
        let info = self.reader.get_current_ctx_info();
        let ci_idx = if let Some(idx) = self.curr_ci_idx {
            let ctx = &self.ci_array[idx];
            let comp_size = info.in_pos - ctx.in_offset;
            let uncomp_size = info.out_pos - ctx.out_offset;
            let first = self.is_first_block();
            let enough = !first
                && (comp_size >= self.max_comp_size / 2
                    || uncomp_size + chunk_size >= self.max_uncomp_size);
            if info.stream_switched != 0 || enough {
                // The slice becomes too big after merging current data chunk.
                self.new_ci_entry()?
            } else if !first
                && comp_size > 2 * ctx.in_len as u64
                && ctx.in_len as u64 > self.min_comp_size
            {
                // The gap between current chunk and last chunk is too big.
                self.new_ci_entry()?
            } else {
                idx
            }
        } else {
            self.new_ci_entry()?
        };

        if ci_idx > ZRAN_MAX_CI_ENTRIES {
            Err(einval!("too many compression information entries"))
        } else {
            self.curr_ci_idx = Some(ci_idx);
            self.curr_ci_offset = info.out_pos;
            self.curr_in_offset = info.in_pos;
            Ok(ci_idx as u32)
        }
    }

    /// Mark end of a data read operation and returns information to decode data from the random
    /// access slice.
    pub fn end_read(&mut self) -> Result<ZranChunkInfo> {
        let info = self.reader.get_current_ctx_info();
        if let Some(idx) = self.curr_ci_idx {
            let ctx = &mut self.ci_array[idx];
            let comp_size = info.in_pos - ctx.in_offset;
            let uncomp_size = info.out_pos - ctx.out_offset;
            let ci = ZranChunkInfo {
                ci_index: idx as u32,
                ci_offset: (self.curr_ci_offset - ctx.out_offset) as u32,
                ci_len: (info.out_pos - self.curr_ci_offset) as u32,
                in_pos: self.curr_in_offset,
                in_len: (info.in_pos - self.curr_in_offset) as u32,
            };
            ctx.out_len = uncomp_size as u32;
            ctx.in_len = comp_size as u32;
            Ok(ci)
        } else {
            Err(einval!("invalid compression state"))
        }
    }

    /// Get an immutable reference to the random access context information array.
    pub fn get_compression_ctx_array(&self) -> &[ZranContext] {
        &self.ci_array
    }

    /// Set minimal compressed size to emit an random access slice.
    ///
    /// Please ensure "min_compressed_size * 2 <= max_compressed_size".
    pub fn set_min_compressed_size(&mut self, sz: u64) {
        self.min_comp_size = sz;
    }

    /// Set maximum compressed size to emit an random access slice.
    ///
    /// Please ensure "min_compressed_size * 2 <= max_compressed_size".
    pub fn set_max_compressed_size(&mut self, sz: u64) {
        self.max_comp_size = sz;
    }

    /// Set maximum uncompressed size to emit an random access slice.
    ///
    /// Please ensure "min_compressed_size * 2 < max_compressed_size".
    pub fn set_max_uncompressed_size(&mut self, sz: u64) {
        self.max_uncomp_size = sz;
    }

    fn new_ci_entry(&mut self) -> Result<usize> {
        let info = self.reader.get_block_ctx_info();
        let dict = self.reader.get_block_ctx_dict();
        self.ci_array.push(ZranContext::new(&info, dict));
        self.curr_block_start = info.in_pos;
        Ok(self.ci_array.len() - 1)
    }

    fn is_first_block(&self) -> bool {
        let info = self.reader.get_block_ctx_info();
        info.in_pos == self.curr_block_start
    }
}

impl<R: Read> Read for ZranGenerator<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.reader.read(buf)
    }
}

/// A specialized gzip reader for OCI image tarballs.
///
/// This reader assumes that the compressed file is a tar file, and restricts access patterns.
pub struct ZranReader<R> {
    inner: Arc<Mutex<ZranReaderState<R>>>,
}

impl<R> ZranReader<R> {
    /// Create a `ZranReader` from a reader.
    pub fn new(reader: R) -> Result<Self> {
        let inner = ZranReaderState::new(reader)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Copy data from the buffer into the internal input buffer.
    pub fn set_initial_data(&self, buf: &[u8]) {
        let mut state = self.inner.lock().unwrap();
        assert_eq!(state.stream.avail_in(), 0);
        assert!(buf.len() <= state.input.len());
        let ptr = state.input.as_mut_ptr();
        assert_eq!(state.stream.stream.next_in, ptr);

        state.input[..buf.len()].copy_from_slice(buf);
        state.reader_hash.update(buf);
        state.reader_size += buf.len() as u64;
        state.stream.set_avail_in(buf.len() as u32);
    }

    /// Get size of data read from the reader.
    pub fn get_data_size(&self) -> u64 {
        self.inner.lock().unwrap().reader_size
    }

    /// Get sha256 hash value of data read from the reader.
    pub fn get_data_digest(&self) -> Sha256 {
        self.inner.lock().unwrap().reader_hash.clone()
    }

    /// Get inflate context information for current inflate position.
    fn get_current_ctx_info(&self) -> ZranCompInfo {
        self.inner.lock().unwrap().get_compression_info()
    }

    /// Get inflate context information for current inflate block.
    fn get_block_ctx_info(&self) -> ZranCompInfo {
        self.inner.lock().unwrap().block_ctx_info
    }

    /// Get inflate dictionary for current inflate block.
    fn get_block_ctx_dict(&self) -> Vec<u8> {
        let state = self.inner.lock().unwrap();
        state.block_ctx_dict[..state.block_ctx_dict_size].to_vec()
    }
}

impl<R: Read> Read for ZranReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.inner.lock().unwrap().read(buf)
    }
}

impl<R> Clone for ZranReader<R> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ZranCompInfo {
    in_pos: u64,
    out_pos: u64,
    flags: u32,
    previous_byte: u8,
    pending_bits: u8,
    stream_switched: u8,
}

struct ZranReaderState<R> {
    stream: ZranStream,
    input: Vec<u8>,
    reader: R,
    reader_hash: Sha256,
    reader_size: u64,
    block_ctx_info: ZranCompInfo,
    block_ctx_dict: Vec<u8>,
    block_ctx_dict_size: usize,
    stream_switched: u8,
}

impl<R> ZranReaderState<R> {
    fn new(reader: R) -> Result<Self> {
        let mut stream = ZranStream::new(false)?;
        let input = vec![0u8; ZRAN_READER_BUF_SIZE];
        stream.set_next_in(&input[0..0]);

        Ok(ZranReaderState {
            stream,
            input,
            reader,
            reader_hash: Sha256::new(),
            reader_size: 0,
            block_ctx_info: ZranCompInfo::default(),
            block_ctx_dict: vec![0u8; ZRAN_DICT_WIN_SIZE],
            block_ctx_dict_size: 0,
            stream_switched: 0,
        })
    }

    /// Get decompression information about the stream.
    fn get_compression_info(&mut self) -> ZranCompInfo {
        let stream_switched = self.stream_switched;
        self.stream_switched = 0;
        self.stream
            .get_compression_info(&self.input, stream_switched)
    }

    fn get_compression_dict(&mut self) -> Result<()> {
        self.block_ctx_dict_size = self.stream.get_compression_dict(&mut self.block_ctx_dict)?;
        Ok(())
    }
}

impl<R: Read> Read for ZranReaderState<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stream.set_next_out(buf);
        self.stream.set_avail_out(buf.len() as u32);

        loop {
            // Reload the input buffer when needed.
            if self.stream.avail_in() == 0 {
                if self.stream.stream.next_in > self.input.as_mut_ptr() {
                    self.stream.last_byte = unsafe { *self.stream.stream.next_in.sub(1) };
                }
                let sz = self.reader.read(self.input.as_mut_slice())?;
                if sz == 0 {
                    return Ok(0);
                }
                self.reader_hash.update(&self.input[0..sz]);
                self.reader_size += sz as u64;
                self.stream.set_next_in(&self.input[..sz]);
            }

            match self.stream.inflate(false) {
                Z_STREAM_END => {
                    self.stream.reset()?;
                    self.stream_switched = 1;
                    continue;
                }
                Z_OK => {
                    let count = self.stream.next_out() as usize - buf.as_ptr() as usize;
                    let info = self.get_compression_info();
                    if info.flags & 0x80 != 0 {
                        self.get_compression_dict()?;
                        self.block_ctx_info = info;
                    }
                    if count == 0 {
                        // zlib/gzip compression header, continue for next data block.
                        continue;
                    } else {
                        return Ok(count);
                    }
                }
                Z_BUF_ERROR => {
                    if self.stream.avail_in() == 0 {
                        // Need more input data, continue to feed data into the input buffer.
                        continue;
                    } else {
                        return Err(eio!("failed to decode data from compressed data stream"));
                    }
                }
                e => {
                    return Err(eio!(format!(
                        "failed to decode data from compressed data stream, error code {}",
                        e
                    )));
                }
            }
        }
    }
}

struct ZranStream {
    stream: Box<z_stream>,
    total_in: u64,
    total_out: u64,
    last_byte: u8,
}

impl ZranStream {
    fn new(decode: bool) -> Result<Self> {
        let mut stream = Box::new(z_stream {
            next_in: ptr::null_mut(),
            avail_in: 0,
            total_in: 0,
            next_out: ptr::null_mut(),
            avail_out: 0,
            total_out: 0,
            msg: ptr::null_mut(),
            adler: 0,
            data_type: 0,
            reserved: 0,
            opaque: ptr::null_mut(),
            state: ptr::null_mut(),
            zalloc,
            zfree,
        });
        // windowBits can also be greater than 15 for optional gzip decoding.
        // Add 32 to windowBits to enable zlib and gzip decoding with automatic header detection,
        // or add 16 to decode only the gzip format (the zlib format will return a Z_DATA_ERROR).
        // -15 means raw mode.
        let mode = if decode { -15 } else { 31 };
        let ret = unsafe {
            inflateInit2_(
                stream.deref_mut() as *mut z_stream,
                mode,
                zlibVersion(),
                mem::size_of::<z_stream>() as c_int,
            )
        };
        if ret != Z_OK {
            return Err(einval!("failed to initialize zlib inflate context"));
        }

        Ok(Self {
            stream,
            total_in: 0,
            total_out: 0,
            last_byte: 0,
        })
    }

    fn inflate(&mut self, decode: bool) -> i32 {
        // Z_BLOCK requests that inflate() stop if and when it gets to the next deflate block
        // boundary.  When decoding the zlib or gzip format, this will cause inflate() to return
        // immediately after the header and before the first block.  When doing a raw inflate,
        // inflate() will go ahead and process the first block, and will return when it gets to
        // the end of that block, or when it runs out of data.
        let mode = if decode { 0 } else { Z_BLOCK };
        self.total_in += self.stream.avail_in as u64;
        self.total_out += self.stream.avail_out as u64;
        let ret = unsafe { inflate(self.stream.deref_mut() as *mut z_stream, mode) };
        self.total_in -= self.stream.avail_in as u64;
        self.total_out -= self.stream.avail_out as u64;
        ret
    }

    fn reset(&mut self) -> Result<()> {
        let ret = unsafe { inflateReset(self.stream.deref_mut() as *mut z_stream) };
        if ret != Z_OK {
            return Err(einval!("failed to reset zlib inflate context"));
        }
        Ok(())
    }

    fn get_compression_info(&mut self, buf: &[u8], stream_switched: u8) -> ZranCompInfo {
        let previous_byte = if self.stream.data_type & 0x7 != 0 {
            assert!(self.stream.next_in as usize >= buf.as_ptr() as usize);
            if self.stream.next_in as usize == buf.as_ptr() as usize {
                self.last_byte
            } else {
                unsafe { *self.stream.next_in.sub(1) }
            }
        } else {
            0
        };
        ZranCompInfo {
            in_pos: self.total_in,
            out_pos: self.total_out,
            flags: self.stream.data_type as u32,
            previous_byte,
            pending_bits: self.stream.data_type as u8 & 0x7,
            stream_switched,
        }
    }

    fn get_compression_dict(&mut self, buf: &mut [u8]) -> Result<usize> {
        let mut len: uInt = 0;
        assert_eq!(buf.len(), ZRAN_DICT_WIN_SIZE);

        let ret = unsafe {
            inflateGetDictionary(
                self.stream.deref_mut() as *mut z_stream,
                buf.as_mut_ptr(),
                &mut len as *mut uInt,
            )
        };

        if ret != Z_OK {
            Err(einval!("failed to get inflate dictionary"))
        } else {
            Ok(len as usize)
        }
    }

    fn set_dict(&mut self, dict: &[u8]) -> Result<()> {
        let ret = unsafe {
            inflateSetDictionary(self.stream.deref_mut(), dict.as_ptr(), dict.len() as uInt)
        };
        if ret != Z_OK {
            return Err(einval!("failed to reset zlib inflate context"));
        }
        Ok(())
    }

    fn set_prime(&mut self, bits: u8, prime: u8) -> Result<()> {
        let ret = unsafe {
            inflatePrime(
                self.stream.deref_mut(),
                bits as c_int,
                prime as c_int >> (8 - bits),
            )
        };
        if ret != Z_OK {
            return Err(einval!("failed to reset zlib inflate context"));
        }
        Ok(())
    }

    fn set_next_in(&mut self, buf: &[u8]) {
        self.stream.next_in = buf.as_ptr() as *mut u8;
        self.set_avail_in(buf.len() as u32);
    }

    fn avail_in(&self) -> u32 {
        self.stream.avail_in
    }

    fn set_avail_in(&mut self, avail_in: u32) {
        self.stream.avail_in = avail_in;
    }

    fn next_out(&self) -> *mut u8 {
        self.stream.next_out
    }

    fn set_next_out(&mut self, buf: &mut [u8]) {
        self.stream.next_out = buf.as_mut_ptr();
    }

    fn set_avail_out(&mut self, avail_out: u32) {
        self.stream.avail_out = avail_out;
    }
}

impl Drop for ZranStream {
    fn drop(&mut self) {
        unsafe { inflateEnd(self.stream.deref_mut() as *mut z_stream) };
    }
}

// Code from https://github.com/rust-lang/flate2-rs/blob/main/src/ffi/c.rs with modification.
fn align_up(size: usize, align: usize) -> usize {
    (size + align - 1) & !(align - 1)
}

#[allow(unused)]
extern "C" fn zalloc(_ptr: *mut c_void, items: uInt, item_size: uInt) -> *mut c_void {
    // We need to multiply `items` and `item_size` to get the actual desired
    // allocation size. Since `zfree` doesn't receive a size argument we
    // also need to allocate space for a `usize` as a header so we can store
    // how large the allocation is to deallocate later.
    let size = match items
        .checked_mul(item_size)
        .and_then(|i| usize::try_from(i).ok())
        .map(|size| align_up(size, ZLIB_ALIGN))
        .and_then(|i| i.checked_add(std::mem::size_of::<usize>()))
    {
        Some(i) => i,
        None => return ptr::null_mut(),
    };

    // Make sure the `size` isn't too big to fail `Layout`'s restrictions
    let layout = match Layout::from_size_align(size, ZLIB_ALIGN) {
        Ok(layout) => layout,
        Err(_) => return ptr::null_mut(),
    };

    unsafe {
        // Allocate the data, and if successful store the size we allocated
        // at the beginning and then return an offset pointer.
        let ptr = alloc::alloc(layout) as *mut usize;
        if ptr.is_null() {
            return ptr as *mut c_void;
        }
        *ptr = size;
        ptr.add(1) as *mut c_void
    }
}

#[allow(unused)]
extern "C" fn zfree(_ptr: *mut c_void, address: *mut c_void) {
    unsafe {
        // Move our address being freed back one pointer, read the size we
        // stored in `zalloc`, and then free it using the standard Rust
        // allocator.
        let ptr = (address as *mut usize).offset(-1);
        let size = *ptr;
        let layout = Layout::from_size_align_unchecked(size, ZLIB_ALIGN);
        alloc::dealloc(ptr as *mut u8, layout)
    }
}

extern "system" {
    pub fn inflateGetDictionary(
        strm: *mut z_stream,
        dictionary: *mut u8,
        dictLength: *mut uInt,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom};
    use std::path::PathBuf;
    use tar::{Archive, EntryType};

    #[test]
    fn test_parse_single_gzip_object() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/zran-single-stream.tar.gz");
        let file = OpenOptions::new().read(true).open(&path).unwrap();

        let mut files = 0;
        let mut objects = 0;
        let reader = ZranReader::new(file).unwrap();
        let mut tar = Archive::new(reader);
        let entries = tar.entries().unwrap();
        for entry in entries {
            let entry = entry.unwrap();
            objects += 1;
            if entry.header().entry_type() == EntryType::Regular {
                files += 1;
            }
        }

        assert_eq!(objects, 7);
        assert_eq!(files, 3);
    }

    #[test]
    fn test_parse_first_gzip_object() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/zran-two-streams.tar.gz");
        let file = OpenOptions::new().read(true).open(&path).unwrap();

        let mut files = 0;
        let mut objects = 0;
        let reader = ZranReader::new(file).unwrap();
        let mut tar = Archive::new(reader);

        let entries = tar.entries().unwrap();
        for entry in entries {
            let entry = entry.unwrap();
            objects += 1;
            if entry.header().entry_type() == EntryType::Regular {
                files += 1;
            }
        }

        assert_eq!(objects, 7);
        assert_eq!(files, 3);
    }

    #[test]
    fn test_parse_two_gzip_objects() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/zran-two-streams.tar.gz");
        let file = OpenOptions::new().read(true).open(&path).unwrap();

        let mut files = 0;
        let mut objects = 0;
        let reader = ZranReader::new(file).unwrap();
        let mut tar = Archive::new(reader);
        tar.set_ignore_zeros(true);

        let entries = tar.entries().unwrap();
        for entry in entries {
            let entry = entry.unwrap();
            objects += 1;
            if entry.header().entry_type() == EntryType::Regular {
                files += 1;
            }
        }

        assert_eq!(objects, 10);
        assert_eq!(files, 5);
    }

    #[test]
    fn test_parse_gzip_with_big_zero() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/zran-zero-file.tar.gz");
        let file = OpenOptions::new().read(true).open(&path).unwrap();
        let reader = ZranReader::new(file).unwrap();
        let mut tar = Archive::new(reader.clone());
        let entries = tar.entries().unwrap();

        let mut last: Option<ZranCompInfo> = None;
        for entry in entries {
            let mut entry = entry.unwrap();
            assert_eq!(entry.header().entry_type(), EntryType::Regular);
            loop {
                let mut buf = vec![0u8; 512];
                let sz = entry.read(&mut buf).unwrap();
                if sz == 0 {
                    break;
                }

                let info = reader.get_current_ctx_info();
                if let Some(prev) = last {
                    assert_ne!(prev, info);
                }
                last = Some(info);
            }
        }
    }

    #[test]
    fn test_generate_comp_info() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/zran-two-streams.tar.gz");
        let file = OpenOptions::new().read(true).open(&path).unwrap();

        let reader = ZranReader::new(file).unwrap();
        let mut tar = Archive::new(reader.clone());
        tar.set_ignore_zeros(true);
        let mut generator = ZranGenerator::new(reader);
        generator.set_min_compressed_size(1024);
        generator.set_max_compressed_size(2048);
        generator.set_max_uncompressed_size(4096);

        let entries = tar.entries().unwrap();
        for entry in entries {
            let mut entry = entry.unwrap();
            if entry.header().entry_type() == EntryType::Regular {
                loop {
                    let _start = generator.begin_read(512).unwrap();
                    let mut buf = vec![0u8; 512];
                    let sz = entry.read(&mut buf).unwrap();
                    if sz == 0 {
                        break;
                    }
                    let _info = generator.end_read().unwrap();
                }
            }
        }

        let ctx = generator.get_compression_ctx_array();
        assert_eq!(ctx.len(), 3);
    }

    #[test]
    fn test_zran_decoder() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/zran/zran-two-streams.tar.gz");
        let file = OpenOptions::new().read(true).open(&path).unwrap();

        let reader = ZranReader::new(file).unwrap();
        let mut tar = Archive::new(reader.clone());
        tar.set_ignore_zeros(true);
        let mut generator = ZranGenerator::new(reader);
        generator.set_min_compressed_size(1024);
        generator.set_max_compressed_size(2048);
        generator.set_max_uncompressed_size(4096);

        let entries = tar.entries().unwrap();
        for entry in entries {
            let mut entry = entry.unwrap();
            if entry.header().entry_type() == EntryType::Regular {
                loop {
                    let _start = generator.begin_read(512).unwrap();
                    let mut buf = vec![0u8; 512];
                    let sz = entry.read(&mut buf).unwrap();
                    let _info = generator.end_read().unwrap();
                    if sz == 0 {
                        break;
                    }
                }
            }
        }

        let ctx_array = generator.get_compression_ctx_array();
        assert_eq!(ctx_array.len(), 3);
        for ctx in ctx_array.iter().take(3) {
            let mut c_buf = vec![0u8; ctx.in_len as usize];
            let mut file = OpenOptions::new().read(true).open(&path).unwrap();
            file.seek(SeekFrom::Start(ctx.in_offset)).unwrap();
            file.read_exact(&mut c_buf).unwrap();

            let mut d_buf = vec![0u8; ctx.out_len as usize];
            let mut decoder = ZranDecoder::new().unwrap();
            decoder.uncompress(ctx, None, &c_buf, &mut d_buf).unwrap();
        }
    }
}
