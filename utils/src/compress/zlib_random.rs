// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::alloc::{self, Layout};
use std::convert::TryFrom;
use std::io::{Read, Result};
use std::ops::DerefMut;
use std::os::raw::{c_char, c_int, c_void};
use std::sync::{Arc, Mutex};
use std::{mem, ptr};

use libz_sys::{
    inflate, inflateEnd, inflateInit2_, inflateReset, uInt, z_stream, Z_BLOCK, Z_BUF_ERROR, Z_OK,
    Z_STREAM_END,
};

const ZLIB_ALIGN: usize = std::mem::align_of::<usize>();
const ZLIB_VERSION: &'static str = "1.2.8\0";
const ZRAN_READER_BUF_SIZE: usize = 256 * 1024;

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

struct ZranReaderState<R> {
    stream: ZranStream,
    input: Vec<u8>,
    reader: R,
    stream_switched: u8,
}

impl<R> ZranReaderState<R> {
    fn new(reader: R) -> Result<Self> {
        let mut stream = ZranStream::new()?;
        let mut input = vec![0u8; ZRAN_READER_BUF_SIZE];
        stream.set_next_in(&mut input);
        stream.set_avail_in(0);

        Ok(ZranReaderState {
            stream,
            input,
            reader,
            stream_switched: 0,
        })
    }
}

impl<R: Read> Read for ZranReaderState<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stream.set_next_out(buf);
        self.stream.set_avail_out(buf.len() as u32);

        loop {
            // Reload the input buffer when needed.
            if self.stream.avail_in() == 0 {
                let sz = self.reader.read(self.input.as_mut_slice())?;
                if sz == 0 {
                    return Ok(0);
                }
                self.stream.set_next_in(&self.input);
                self.stream.set_avail_in(sz as u32);
            }

            match self.stream.inflate() {
                Z_STREAM_END => {
                    self.stream.reset()?;
                    self.stream_switched = 1;
                    continue;
                }
                Z_OK => {
                    let count = self.stream.next_out() as usize - buf.as_ptr() as usize;
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
                _ => {
                    return Err(eio!("failed to decode data from compressed data stream"));
                }
            }
        }
    }
}

struct ZranStream {
    stream: Box<z_stream>,
    total_in: u64,
    total_out: u64,
}

impl ZranStream {
    fn new() -> Result<Self> {
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
        let ret = unsafe {
            // windowBits can also be greater than 15 for optional gzip decoding.
            // Add 32 to windowBits to enable zlib and gzip decoding with automatic header detection,
            // or add 16 to decode only the gzip format (the zlib format will return a Z_DATA_ERROR).
            inflateInit2_(
                stream.deref_mut() as *mut z_stream,
                31,
                ZLIB_VERSION.as_ptr() as *const c_char,
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
        })
    }

    fn inflate(&mut self) -> i32 {
        // Z_BLOCK requests that inflate() stop if and when it gets to the next deflate block
        // boundary.  When decoding the zlib or gzip format, this will cause inflate() to return
        // immediately after the header and before the first block.  When doing a raw inflate,
        // inflate() will go ahead and process the first block, and will return when it gets to
        // the end of that block, or when it runs out of data.
        self.total_in += self.stream.avail_in as u64;
        self.total_out += self.stream.avail_out as u64;
        let ret = unsafe { inflate(self.stream.deref_mut() as *mut z_stream, Z_BLOCK) };
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

    fn set_next_in(&mut self, buf: &[u8]) {
        self.stream.next_in = buf.as_ptr() as *mut u8;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
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
}
