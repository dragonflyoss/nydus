use std::io::Result;

use libc::{c_uint, c_void};
use std::ffi::CStr;
use zstd_sys::{
    ZSTD_compress, ZSTD_compressBound, ZSTD_decompress, ZSTD_defaultCLevel, ZSTD_getErrorName,
    ZSTD_isError,
};

pub(super) fn zstd_compress(src: &[u8]) -> Result<Vec<u8>> {
    let compress_bound = unsafe { ZSTD_compressBound(src.len()) };

    if src.len() > (i32::max_value() as usize) || compress_bound == 0 {
        return Err(einval!("compression input data is too big"));
    }

    let mut dst_buf = Vec::with_capacity(compress_bound as usize);
    let cmp_size = unsafe {
        ZSTD_compress(
            dst_buf.as_mut_ptr() as *mut c_void,
            compress_bound,
            src.as_ptr() as *const c_void,
            src.len(),
            ZSTD_defaultCLevel(),
        )
    };

    let error_code: c_uint = unsafe { ZSTD_isError(cmp_size) };
    if error_code > 0 {
        let char_ptr = unsafe { ZSTD_getErrorName(cmp_size) };
        let c_str = unsafe { CStr::from_ptr(char_ptr) }.to_str().unwrap();
        return Err(eio!(format!("compression failed {}", c_str)));
    }

    assert!(cmp_size <= dst_buf.capacity());
    unsafe { dst_buf.set_len(cmp_size) };

    Ok(dst_buf)
}

pub(super) fn zstd_decompress(src: &[u8], dst: &mut [u8]) -> Result<usize> {
    if dst.len() >= std::i32::MAX as usize {
        return Err(einval!("the destination buffer is big than i32::MAX"));
    }

    let dec_bytes = unsafe {
        ZSTD_decompress(
            dst.as_mut_ptr() as *mut c_void,
            dst.len(),
            src.as_ptr() as *const c_void,
            src.len(),
        )
    };

    let error_code: c_uint = unsafe { ZSTD_isError(dec_bytes) };
    if error_code > 0 {
        let char_ptr = unsafe { ZSTD_getErrorName(dec_bytes) };
        let c_str = unsafe { CStr::from_ptr(char_ptr) }.to_str().unwrap();
        return Err(eio!(format!("decompression failed {}", c_str)));
    }

    Ok(dec_bytes as usize)
}
