//! Bindings for the zran library.

use std::ffi::c_void;
use std::ffi::CString;
use std::ops::Range;
use std::os::raw::c_char;
use std::os::raw::c_int;
use std::os::raw::c_uchar;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::ptr;

// TODO(tianqian.zyf): Provide more error info
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("generate index error: {0}")]
    GenerateIndexError(std::io::Error),
    #[error("null index")]
    NullIndexError,
    #[error("convert index to blob failed")]
    IndexToBlobError,
    #[error("extra data from file failed")]
    ExtractDataError,
    #[error("invalid index point")]
    InvalidIndexPoint,
    #[error("failed to get point range for offset({0}, {1})")]
    GetPointRangeFailed(u64, u64),
}

type Result<T> = std::result::Result<T, Error>;

const WINSIZE: usize = 32768;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct gzip_index_point {
    g_out: u64,                   /* corresponding offset in uncompressed data */
    g_in: u64,                    /* offset in input file of first full byte */
    g_bits: u8,                   /* number of bits (1-7) from byte at in - 1, or 0 */
    g_window: [c_uchar; WINSIZE], /* preceding 32K of uncompressed data */
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct gzip_index {
    g_have: c_int,                 /* number of list entries filled in */
    g_size: c_int,                 /* number of list entries allocated */
    g_list: *mut gzip_index_point, /* allocated list */
    g_span_size: u64,
}

// TODO(tianqian.zyf): There are quite a few functions that can be completely rewritten in rust
extern "C" {
    fn generate_index(filepath: *const c_char, span: u64, index: *mut *mut gzip_index) -> c_int;
    /* Get the index number of the point in the gzip index where
       the uncompressed offset is present
    */
    fn pt_index_from_ucmp_offset(index: *const gzip_index, off: u64) -> c_int;
    fn extract_data_from_buffer(
        d: *const c_void,
        datalen: u64,
        index: *mut gzip_index,
        offset: u64,
        buffer: *mut c_void,
        len: u64,
        first_point_index: c_int,
    ) -> c_int;

    fn extract_data(
        file: *const c_char,
        index: *mut gzip_index,
        off: u64,
        buf: *mut c_void,
        len: c_int,
    ) -> c_int;

    fn has_bits(index: *const gzip_index, point_index: c_int) -> c_int;

    fn get_ucomp_off(index: *const gzip_index, point_index: c_int) -> u64;
    fn get_comp_off(index: *const gzip_index, point_index: c_int) -> u64;

    /* Given a file's uncompressed start and end offset, returns the spans which
        contains those offsets
    */
    fn span_indices_for_file(
        index: *mut gzip_index,
        start: u64,
        end: u64,
        index_start: *mut c_void,
        index_end: *mut c_void,
    ) -> c_int;

    /* Subroutines to convert index to/from a binary blob */

    /* Get size of blob given an index */
    // fn get_blob_size(index: *const gzip_index) -> c_uint;

    /* Converts index to blob
       Returns the size of the buffer on success
       This function assumes that the buffer is large enough already
       to hold the entire index
    */
    fn index_to_blob(index: *const gzip_index, buf: *mut c_void) -> c_int;

    fn blob_to_index(buf: *const c_void) -> *mut gzip_index;

    fn free_index(index: *const gzip_index);
}

#[derive(Debug)]
pub struct GzipIndex(*mut gzip_index);

impl Drop for GzipIndex {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // Safe given that we checked the pointer for non-null and it should always be of the
            // correct type.
            unsafe {
                free_index(self.0);
            }
        }
    }
}

impl GzipIndex {
    fn new_with_blob(blob: &[u8]) -> Result<GzipIndex> {
        let index;
        unsafe {
            index = blob_to_index(blob.as_ptr() as *const c_void);
            if index.is_null() {
                return Err(Error::GenerateIndexError(std::io::Error::last_os_error()));
            }
        }

        Ok(GzipIndex(index))
    }

    fn new(file: &Path, span: u64) -> Result<GzipIndex> {
        let mut response: *mut gzip_index = ptr::null_mut();
        let path_str_c = CString::new(file.as_os_str().as_bytes()).unwrap();
        unsafe {
            //let GzipIndex
            let ret = generate_index(path_str_c.as_ptr(), span, &mut response);
            if ret < 0 {
                return Err(Error::GenerateIndexError(std::io::Error::last_os_error()));
            }

            if response.is_null() {
                return Err(Error::NullIndexError);
            }
        }

        Ok(GzipIndex(response))
    }

    fn index_to_blob(&self) -> Result<Vec<u8>> {
        let blob_size = self.get_blob_size();
        let mut bytes_data = vec![0; blob_size as usize];

        unsafe {
            let ret = index_to_blob(self.0, bytes_data.as_mut_ptr() as *mut c_void);
            if ret < 0 {
                return Err(Error::IndexToBlobError);
            }
        }
        Ok(bytes_data)
    }

    fn get_blob_size(&self) -> usize {
        let size;
        unsafe {
            size = (*self.0).g_size as usize;
        }
        /*
            The buffer will be tightly packed. The layout of the buffer is:
            -   4 bytes, number of span entries
            -   8 bytes, size of span
            -   for each entry (except span 0)
                -  8 bytes, compressed offset
                -  8 bytes, uncompressed offset
                -  1 byte, bits
                -  32768 bytes, window
                -  8 bytes magic
        */
        (((2 << 14) + 17) * (size - 1) + 12 + 8) as usize
    }

    fn extract_data_from_file(
        &self,
        file: &Path,
        ucompressed_offet: u64,
        ucompressed_size: u32,
    ) -> Result<Vec<u8>> {
        let mut bytes_data = vec![0; ucompressed_size as usize];

        let path_str_c = CString::new(file.as_os_str().as_bytes()).unwrap();
        unsafe {
            let ret = extract_data(
                path_str_c.as_ptr(),
                self.0,
                ucompressed_offet,
                bytes_data.as_mut_ptr() as *mut c_void,
                ucompressed_size as i32,
            );

            if ret < 0 {
                return Err(Error::ExtractDataError);
            }
        }

        Ok(bytes_data)
    }

    fn has_point(&self, point: u32) -> bool {
        unsafe {
            if has_bits(self.0 as *const gzip_index, point as i32) < 0 {
                return false;
            }
        }
        true
    }

    fn get_point_index(&self, uncompressed_offset: u64) -> Result<u32> {
        let point_index;
        unsafe {
            point_index =
                pt_index_from_ucmp_offset(self.0 as *const gzip_index, uncompressed_offset);
            if point_index < 0 {
                return Err(Error::InvalidIndexPoint);
            }
        }

        debug_assert!(self.has_point(point_index as u32));

        Ok(point_index as u32)
    }

    fn get_ucompressed_offset(&self, point_index: u32) -> u64 {
        debug_assert!(self.has_point(point_index));

        unsafe { get_ucomp_off(self.0 as *const gzip_index, point_index as i32) }
    }

    fn get_compressed_offset(&self, point_index: u32) -> u64 {
        debug_assert!(self.has_point(point_index));

        unsafe { get_comp_off(self.0 as *const gzip_index, point_index as i32) }
    }

    fn get_point_range(
        &self,
        uncompressed_offset_start: u64,
        uncompressed_offset_end: u64,
    ) -> Result<Range<u32>> {
        let mut start: u32 = 0;
        let mut end: u32 = 0;
        unsafe {
            let ret = span_indices_for_file(
                self.0,
                uncompressed_offset_start,
                uncompressed_offset_end,
                &mut start as *mut u32 as *mut c_void,
                &mut end as *mut u32 as *mut c_void,
            );
            if ret < 0 {
                return Err(Error::GetPointRangeFailed(
                    uncompressed_offset_start,
                    uncompressed_offset_end,
                ));
            }
        }
        Ok(Range { start, end })
    }

    fn extract_data_from_buffer(
        &self,
        compressed_buf: &[u8],
        start_uncompressed_offset: u64,
        uncompress_size: u64,
        first_point_index: u32,
    ) -> Result<Vec<u8>> {
        let mut buffer = vec![0; uncompress_size as usize];

        unsafe {
            let ret = extract_data_from_buffer(
                compressed_buf.as_ptr() as *const c_void,
                compressed_buf.len() as u64,
                self.0,
                start_uncompressed_offset,
                buffer.as_mut_ptr() as *mut c_void,
                uncompress_size,
                first_point_index as i32, // We should replace i32 to u32
            );
            if ret < 0 {
                return Err(Error::ExtractDataError);
            }
        }
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::File,
        io::{Read, Seek, SeekFrom},
        path::PathBuf,
        str::FromStr,
    };

    const DEFAULT_GZ_FILE: &str = "syslog.4.gz";

    fn get_tests_file(filename: &str) -> PathBuf {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push(format!("testdata/{}", filename));
        d
    }
    fn tests_file_info() -> Vec<(&'static str, usize)> {
        // file name, uncompressed size
        return vec![(DEFAULT_GZ_FILE, 28325777)];
    }

    fn generate_span_sizes(file_size: u64) -> Vec<u64> {
        let mut span_sizes = Vec::with_capacity(10);
        span_sizes.push(0);
        span_sizes.push(1);
        span_sizes.push(file_size / 8);
        span_sizes.push(file_size / 4);
        span_sizes.push(file_size / 2);
        span_sizes.push(file_size);
        span_sizes.push(file_size + 1);
        span_sizes
    }

    #[test]
    fn test_basic() {
        for file_info in tests_file_info() {
            let spans = generate_span_sizes(file_info.1 as u64);
            for span in spans {
                let index = GzipIndex::new(get_tests_file(file_info.0).as_path(), span).unwrap();
                let blob = index.index_to_blob().unwrap();
                assert_eq!(blob.len(), index.get_blob_size());
                let index2 = GzipIndex::new_with_blob(&blob).unwrap();
                let blob2 = index2.index_to_blob().unwrap();
                assert_eq!(blob, blob2);
                assert_eq!(index2.get_blob_size(), index.get_blob_size());
            }
        }
    }

    #[test]
    #[should_panic]
    fn test_file_not_found() {
        let index = GzipIndex::new(get_tests_file("exist").as_path(), 1).unwrap();
        let blob = index.index_to_blob().unwrap();
        assert_eq!(blob.len(), index.get_blob_size());
    }

    #[test]
    #[should_panic]
    fn test_invalid_blob() {
        let index = GzipIndex::new(get_tests_file(DEFAULT_GZ_FILE).as_path(), 1).unwrap();
        let blob = index.index_to_blob().unwrap();
        assert_eq!(blob.len(), index.get_blob_size());
        let index2 = GzipIndex::new_with_blob(&blob[2..]).unwrap();
        let blob2 = index2.index_to_blob().unwrap();
        assert_eq!(blob, blob2);
    }
    #[test]
    fn test_point_index() {
        let span_size = 1024 * 1024;
        let index = GzipIndex::new(get_tests_file(DEFAULT_GZ_FILE).as_path(), span_size).unwrap();
        let point_index_start = index.get_point_index(0).unwrap();
        let point_index_end = index.get_point_index(span_size).unwrap();
        assert_eq!(point_index_start, point_index_end);
        let next_point_index = index.get_point_index(span_size * 2).unwrap();
        assert_eq!(point_index_start, next_point_index - 1);
    }

    #[test]
    fn test_extract_data_from_file() {
        let span_size = 1024 * 1024;
        let test_cases = vec![
            // gzip file、uncompressed_offset、uncompressed_size、uncompressed_content
            (DEFAULT_GZ_FILE, 0, 3, "Aug"),
            (DEFAULT_GZ_FILE, 41, 7, "rsyslog"),
            (DEFAULT_GZ_FILE, 6372170, 4, "\\\"\"\n"),
        ];

        for test_case in test_cases {
            let index = GzipIndex::new(get_tests_file(test_case.0).as_path(), span_size).unwrap();
            let data = index
                .extract_data_from_file(
                    get_tests_file(test_case.0).as_path(),
                    test_case.1,
                    test_case.2,
                )
                .unwrap();
            let s = String::from_utf8(data).expect("Found invalid UTF-8");
            assert_eq!(String::from_str(test_case.3).unwrap(), s);
        }
    }

    #[test]
    fn test_get_point_range() {
        let span_size = 1024 * 1024;
        let index = GzipIndex::new(get_tests_file(DEFAULT_GZ_FILE).as_path(), span_size).unwrap();
        let range = index.get_point_range(0, span_size * 2).unwrap();
        assert_eq!(range.start, 0);
        assert_eq!(range.end, 1);
    }

    #[test]
    fn test_get_ucompressed_offset() {
        let span_size = 1024 * 1024;
        let index = GzipIndex::new(get_tests_file(DEFAULT_GZ_FILE).as_path(), span_size).unwrap();
        let offset = index.get_ucompressed_offset(0);
        assert_eq!(offset, 0);
        let next_offset = index.get_ucompressed_offset(1);
        // span size is just an estimate of the gzip split point, not the exact size
        assert!(next_offset > span_size && next_offset <= span_size * 2);
    }

    #[test]
    fn test_get_compressed_offset() {
        let span_size = 1024 * 1024;
        let index = GzipIndex::new(get_tests_file(DEFAULT_GZ_FILE).as_path(), span_size).unwrap();
        let offset = index.get_compressed_offset(0);
        // 10 bytes gzip header
        assert_eq!(offset, 10);
        let next_offset = index.get_compressed_offset(1);
        assert!(next_offset > 10 && next_offset <= span_size);
    }

    #[test]
    fn test_extract_data_from_buffer() {
        let span_size = 1024 * 1024;

        let test_cases = vec![
            // gzip file、uncompressed_offset、uncompressed_size、uncompressed_content
            (DEFAULT_GZ_FILE, 0, 3, "Aug"),
            (DEFAULT_GZ_FILE, 41, 7, "rsyslog"),
            //(DEFAULT_GZ_FILE, 6372170, 4, "\\\"\"\n"),
        ];

        for test_case in test_cases {
            let index = GzipIndex::new(get_tests_file(test_case.0).as_path(), span_size).unwrap();
            let point_range = index
                .get_point_range(test_case.1, test_case.1 + test_case.2)
                .unwrap();

            let compressed_start = index.get_compressed_offset(point_range.start);
            let compressed_end = index.get_compressed_offset(point_range.end + 1);

            let compressed_size = compressed_end - compressed_start;

            let mut file = File::open(get_tests_file(test_case.0)).unwrap();
            file.seek(SeekFrom::Start(compressed_start)).unwrap();
            let mut compressed_buf = vec![0; compressed_size as usize];
            file.read_exact(&mut compressed_buf).unwrap();

            let data = index
                .extract_data_from_buffer(
                    &compressed_buf,
                    test_case.1,
                    test_case.2,
                    point_range.start,
                )
                .unwrap();
            let s = String::from_utf8(data).expect("Found invalid UTF-8");
            assert_eq!(String::from_str(test_case.3).unwrap(), s);
        }
    }
}
