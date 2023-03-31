// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::Result;
use std::mem::size_of;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

/// Struct to manage memory range mapped from file objects.
///
/// It maps a region from a file into current process by using libc::mmap().
/// Then it provides safe interfaces to access the memory mapped region.
pub struct FileMapState {
    base: *const u8,
    end: *const u8,
    size: usize,
    fd: RawFd,
}

// Safe to Send/Sync because the underlying data structures are readonly
unsafe impl Send for FileMapState {}
unsafe impl Sync for FileMapState {}

impl Default for FileMapState {
    fn default() -> Self {
        FileMapState {
            fd: -1,
            base: std::ptr::null(),
            end: std::ptr::null(),
            size: 0,
        }
    }
}

impl Drop for FileMapState {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe { libc::munmap(self.base as *mut u8 as *mut libc::c_void, self.size) };
            self.base = std::ptr::null();
            self.end = std::ptr::null();
            self.size = 0;
        }
        if self.fd >= 0 {
            let _ = nix::unistd::close(self.fd);
            self.fd = -1;
        }
    }
}

impl FileMapState {
    /// Memory map a region of the file object into current process.
    ///
    /// It takes ownership of the file object and will close it when the returned object is dropped.
    pub fn new(file: File, offset: libc::off_t, size: usize, writable: bool) -> Result<Self> {
        let prot = if writable {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                prot,
                libc::MAP_NORESERVE | libc::MAP_SHARED,
                file.as_raw_fd(),
                offset,
            )
        } as *const u8;
        if base as *mut core::ffi::c_void == libc::MAP_FAILED {
            return Err(last_error!(
                "failed to memory map file region into current process"
            ));
        } else if base.is_null() {
            return Err(last_error!(
                "failed to memory map file region into current process"
            ));
        }
        // Safe because the mmap area should covered the range [start, end)
        let end = unsafe { base.add(size) };

        Ok(Self {
            fd: file.into_raw_fd(),
            base,
            end,
            size,
        })
    }

    /// Get size of mapped region.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Cast a subregion of the mapped area to an object reference.
    pub fn get_ref<T>(&self, offset: usize) -> Result<&T> {
        let start = self.base.wrapping_add(offset);
        let end = start.wrapping_add(size_of::<T>());

        if start > end
            || start < self.base
            || end < self.base
            || end > self.end
            || start as usize & (std::mem::align_of::<T>() - 1) != 0
        {
            return Err(einval!("invalid mmap offset"));
        }

        Ok(unsafe { &*(start as *const T) })
    }

    /// Cast a subregion of the mapped area to an mutable object reference.
    pub fn get_mut<T>(&mut self, offset: usize) -> Result<&mut T> {
        let start = self.base.wrapping_add(offset);
        let end = start.wrapping_add(size_of::<T>());

        if start > end
            || start < self.base
            || end < self.base
            || end > self.end
            || start as usize & (std::mem::align_of::<T>() - 1) != 0
        {
            return Err(einval!("invalid mmap offset"));
        }

        Ok(unsafe { &mut *(start as *const T as *mut T) })
    }

    /// Get an immutable slice of 'T' at 'offset' with 'count' entries.
    pub fn get_slice<T>(&self, offset: usize, count: usize) -> Result<&[T]> {
        let start = self.base.wrapping_add(offset);
        if count.checked_mul(size_of::<T>()).is_none() {
            bail_einval!("count 0x{count:x} to validate_slice() is too big");
        }
        let size = count * size_of::<T>();
        if size.checked_add(start as usize).is_none() {
            bail_einval!(
                "invalid parameter to validate_slice(), offset 0x{offset:x}, count 0x{count:x}"
            );
        }
        let end = start.wrapping_add(size);
        if start > end || start < self.base || end < self.base || end > self.end {
            bail_einval!(
                "invalid range in validate_slice, base 0x{:p}, start 0x{start:p}, end 0x{end:p}",
                self.base
            );
        }
        Ok(unsafe { std::slice::from_raw_parts(start as *const T, count) })
    }

    /// Get a mutable slice of 'T' at 'offset' with 'count' entries.
    pub fn get_slice_mut<T>(&mut self, offset: usize, count: usize) -> Result<&mut [T]> {
        let start = self.base.wrapping_add(offset);
        if count.checked_mul(size_of::<T>()).is_none() {
            bail_einval!("count 0x{count:x} to validate_slice() is too big");
        }
        let size = count * size_of::<T>();
        if size.checked_add(start as usize).is_none() {
            bail_einval!(
                "invalid parameter to validate_slice(), offset 0x{offset:x}, count 0x{count:x}"
            );
        }
        let end = start.wrapping_add(size);
        if start > end || start < self.base || end < self.base || end > self.end {
            bail_einval!(
                "invalid range in validate_slice, base 0x{:p}, start 0x{start:p}, end 0x{end:p}",
                self.base
            );
        }
        Ok(unsafe { std::slice::from_raw_parts_mut(start as *mut T, count) })
    }

    /// Check whether the range [offset, offset + size) is valid and return the start address.
    pub fn validate_range(&self, offset: usize, size: usize) -> Result<*const u8> {
        let start = self.base.wrapping_add(offset);
        let end = start.wrapping_add(size);

        if start > end || start < self.base || end < self.base || end > self.end {
            return Err(einval!("invalid range"));
        }

        Ok(start)
    }

    /// Add `offset` to the base pointer.
    ///
    /// # Safety
    /// The caller should ensure that `offset` is within range.
    pub unsafe fn offset(&self, offset: usize) -> *const u8 {
        self.base.wrapping_add(offset)
    }

    /// Sync mapped file data into disk.
    pub fn sync_data(&self) -> Result<()> {
        let file = unsafe { File::from_raw_fd(self.fd) };
        let result = file.sync_data();
        std::mem::forget(file);
        result
    }
}

/// Duplicate a file object by `libc::dup()`.
pub fn clone_file(fd: RawFd) -> Result<File> {
    unsafe {
        let fd = libc::dup(fd);
        if fd < 0 {
            return Err(last_error!("failed to dup bootstrap file fd"));
        }
        Ok(File::from_raw_fd(fd))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::path::PathBuf;

    #[test]
    fn create_file_map_object() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/bootstrap/rafs-v5.boot");
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(&path)
            .unwrap();
        let map = FileMapState::new(file, 0, 4096, false).unwrap();

        let magic = map.get_ref::<u32>(0).unwrap();
        assert_eq!(u32::from_le(*magic), 0x52414653);

        map.get_ref::<u32>(4096).unwrap_err();
        let _ = map.get_ref::<u32>(4092).unwrap();
        let _ = map.get_ref::<u32>(0).unwrap();
        map.validate_range(4096, 1).unwrap_err();
        let _ = map.validate_range(4095, 1).unwrap();
        let _ = map.validate_range(0, 1).unwrap();
        drop(map);
    }

    #[test]
    fn create_default_file_map_object() {
        let map = FileMapState::default();
        drop(map);
    }
}
