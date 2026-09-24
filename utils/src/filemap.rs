// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::Result;
use std::mem::size_of;
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::ptr::NonNull;
use std::sync::Arc;

/// Struct to manage memory range mapped from file objects.
///
/// It maps a region from a file into current process by using libc::mmap().
/// Typed access requires the caller to uphold the mapped type and aliasing contracts.
pub struct FileMapState {
    base: *const u8,
    size: usize,
    fd: RawFd,
    writable: bool,
}

// Typed access is unsafe and requires callers to synchronize writes to shared mappings.
unsafe impl Send for FileMapState {}
unsafe impl Sync for FileMapState {}

impl Default for FileMapState {
    fn default() -> Self {
        FileMapState {
            fd: -1,
            writable: false,
            base: std::ptr::null(),
            size: 0,
        }
    }
}

impl Drop for FileMapState {
    fn drop(&mut self) {
        if !self.base.is_null() {
            unsafe { libc::munmap(self.base as *mut u8 as *mut libc::c_void, self.size) };
            self.base = std::ptr::null();
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
        if size == 0 || size > isize::MAX as usize {
            return Err(einval!("invalid mmap size"));
        }
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
        Ok(Self {
            fd: file.into_raw_fd(),
            writable,
            base,
            size,
        })
    }

    /// Get size of mapped region.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Cast a subregion of the mapped area to an object reference.
    ///
    /// # Safety
    /// The mapped bytes must represent a valid T and remain unchanged while borrowed, except
    /// through T's interior mutability. The backing file must not be truncated while mapped.
    pub unsafe fn get_ref<T>(&self, offset: usize) -> Result<&T> {
        let start = self.typed_range::<T>(offset, 1)?;
        Ok(unsafe { &*start })
    }

    /// Cast a subregion of the mapped area to a mutable object reference.
    ///
    /// # Safety
    /// The mapped bytes must represent a valid T, with exclusive access to the borrowed range.
    /// The backing file must not be truncated while mapped.
    pub unsafe fn get_mut<T>(&mut self, offset: usize) -> Result<&mut T> {
        if !self.writable {
            return Err(einval!("mapping is read-only"));
        }
        let start = self.typed_range::<T>(offset, 1)?;
        Ok(unsafe { &mut *start.cast_mut() })
    }

    /// Get an immutable slice of T at offset with count entries.
    ///
    /// # Safety
    /// Each element must be a valid T and remain unchanged while borrowed, except through T's
    /// interior mutability. The backing file must not be truncated while mapped.
    pub unsafe fn get_slice<T>(&self, offset: usize, count: usize) -> Result<&[T]> {
        let start = self.typed_range::<T>(offset, count)?;
        Ok(unsafe { std::slice::from_raw_parts(start, count) })
    }

    /// Get a mutable slice of T at offset with count entries.
    ///
    /// # Safety
    /// Each element must be a valid T, with exclusive access to the borrowed range.
    /// The backing file must not be truncated while mapped.
    pub unsafe fn get_slice_mut<T>(&mut self, offset: usize, count: usize) -> Result<&mut [T]> {
        if !self.writable {
            return Err(einval!("mapping is read-only"));
        }
        let start = self.typed_range::<T>(offset, count)?;
        Ok(unsafe { std::slice::from_raw_parts_mut(start.cast_mut(), count) })
    }

    fn typed_range<T>(&self, offset: usize, count: usize) -> Result<*const T> {
        let size = count
            .checked_mul(size_of::<T>())
            .ok_or_else(|| einval!("mapped type size overflow"))?;
        if size == 0 {
            if offset > self.size {
                return Err(einval!("invalid range"));
            }
            return Ok(NonNull::<T>::dangling().as_ptr());
        }
        let start = self.validate_range(offset, size)?;
        if !start.cast::<T>().is_aligned() {
            return Err(einval!("unaligned mmap offset"));
        }
        Ok(start.cast())
    }

    /// Check whether the range [offset, offset + size) is valid and return the start address.
    pub fn validate_range(&self, offset: usize, size: usize) -> Result<*const u8> {
        if self.base.is_null()
            || offset
                .checked_add(size)
                .filter(|end| *end <= self.size)
                .is_none()
        {
            return Err(einval!("invalid range"));
        }
        Ok(self.base.wrapping_add(offset))
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
        if self.fd < 0 {
            return Err(einval!("mapping has no file"));
        }
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

/// An immutable `[T]` view into a `FileMapState`, which stays mapped for as long as the view
/// exists.
pub struct MappedSlice<T> {
    ptr: *const T,
    len: usize,
    _map: Arc<FileMapState>,
}

impl<T> MappedSlice<T> {
    /// Create a view of `len` entries of `T` at `offset` in `map`.
    ///
    /// # Safety
    /// Every bit pattern of the mapped bytes must be a valid `T`. Nothing may write to the mapped
    /// range or truncate the backing file while the view exists.
    pub unsafe fn new(map: Arc<FileMapState>, offset: usize, len: usize) -> Result<Self> {
        let size = len
            .checked_mul(size_of::<T>())
            .ok_or_else(|| einval!("mapped slice size overflow"))?;
        let start = map.validate_range(offset, size)?;
        let ptr = if size == 0 {
            NonNull::<T>::dangling().as_ptr().cast_const()
        } else if start.cast::<T>().is_aligned() {
            start.cast::<T>()
        } else {
            return Err(einval!("unaligned mmap offset"));
        };
        Ok(Self {
            ptr,
            len,
            _map: map,
        })
    }
}

impl<T> Clone for MappedSlice<T> {
    fn clone(&self) -> Self {
        Self {
            ptr: self.ptr,
            len: self.len,
            _map: self._map.clone(),
        }
    }
}

impl<T> Deref for MappedSlice<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        // Safe because `new` checked the range against the mapping, which `_map` keeps alive.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

// Sharing the view is as safe as sharing a `&[T]`.
unsafe impl<T: Sync> Send for MappedSlice<T> {}
unsafe impl<T: Sync> Sync for MappedSlice<T> {}

/// A table of entries that is either built in memory or viewed in a mapped file.
#[derive(Clone)]
pub enum MappedOrOwned<T> {
    Owned(Vec<T>),
    Mapped(MappedSlice<T>),
}

impl<T: Clone> MappedOrOwned<T> {
    /// Get the entries as a vector, copying them out of the mapping first if needed.
    pub fn to_mut(&mut self) -> &mut Vec<T> {
        if let MappedOrOwned::Mapped(slice) = self {
            *self = MappedOrOwned::Owned(slice.to_vec());
        }
        match self {
            MappedOrOwned::Owned(v) => v,
            MappedOrOwned::Mapped(_) => unreachable!(),
        }
    }
}

impl<T> Default for MappedOrOwned<T> {
    fn default() -> Self {
        MappedOrOwned::Owned(Vec::new())
    }
}

impl<T> From<Vec<T>> for MappedOrOwned<T> {
    fn from(v: Vec<T>) -> Self {
        MappedOrOwned::Owned(v)
    }
}

impl<T> Deref for MappedOrOwned<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        match self {
            MappedOrOwned::Owned(v) => v,
            MappedOrOwned::Mapped(s) => s,
        }
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn mapped_slice_checks_range_and_alignment() {
        let temp = TempFile::new().unwrap();
        temp.as_file()
            .write_all(&[1u8, 0, 0, 0, 2, 0, 0, 0])
            .unwrap();
        let map =
            Arc::new(FileMapState::new(temp.as_file().try_clone().unwrap(), 0, 8, false).unwrap());
        unsafe {
            let view = MappedSlice::<u32>::new(map.clone(), 0, 2).unwrap();
            assert_eq!(u32::from_le(view[1]), 2);
            assert!(MappedSlice::<u32>::new(map.clone(), 1, 1).is_err());
            assert!(MappedSlice::<u32>::new(map.clone(), 4, 2).is_err());
            assert!(MappedSlice::<u32>::new(map.clone(), 0, usize::MAX).is_err());
            assert!(MappedSlice::<u32>::new(map.clone(), 8, 0)
                .unwrap()
                .is_empty());
            assert!(MappedSlice::<u32>::new(map.clone(), 9, 0).is_err());
            drop(map);
            assert_eq!(u32::from_le(view[0]), 1);
        }
    }

    #[test]
    fn create_file_map_object() {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let path = PathBuf::from(root_dir).join("../tests/texture/bootstrap/rafs-v5.boot");
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .unwrap();
        let map = FileMapState::new(file, 0, 4096, false).unwrap();

        let magic = unsafe { map.get_ref::<u32>(0) }.unwrap();
        assert_eq!(u32::from_le(*magic), 0x52414653);

        unsafe { map.get_ref::<u32>(4096) }.unwrap_err();
        let _ = unsafe { map.get_ref::<u32>(4092) }.unwrap();
        let _ = unsafe { map.get_ref::<u32>(0) }.unwrap();
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

    #[test]
    fn test_file_map_error() {
        let temp = TempFile::new().unwrap();
        temp.as_file().set_len(4096).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();
        assert!(FileMapState::new(file, 0, 4096, true).is_err());

        let temp = TempFile::new().unwrap();
        temp.as_file().set_len(4096).unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(temp.as_path())
            .unwrap();
        let mut map = FileMapState::new(file, 0, 4096, false).unwrap();
        assert!(unsafe { map.get_slice::<usize>(0, usize::MAX) }.is_err());
        assert!(unsafe { map.get_slice::<usize>(usize::MAX, 1) }.is_err());
        assert!(unsafe { map.get_slice::<usize>(4096, 4096) }.is_err());
        assert!(unsafe { map.get_slice::<usize>(0, 128) }.is_ok());
        assert!(unsafe { map.get_slice::<usize>(0, 0) }.is_ok());

        assert!(unsafe { map.get_slice_mut::<usize>(0, usize::MAX) }.is_err());
        assert!(unsafe { map.get_slice_mut::<usize>(usize::MAX, 1) }.is_err());
        assert!(unsafe { map.get_slice_mut::<usize>(4096, 4096) }.is_err());
        assert!(unsafe { map.get_slice_mut::<usize>(0, 128) }.is_err());
    }

    #[test]
    fn typed_mapping_checks_alignment_permissions_and_empty_state() {
        let temp = TempFile::new().unwrap();
        temp.as_file().set_len(4096).unwrap();
        let mut map =
            FileMapState::new(temp.as_file().try_clone().unwrap(), 0, 4096, true).unwrap();
        unsafe {
            assert!(map.get_ref::<u32>(1).is_err());
            assert!(map.get_mut::<u32>(1).is_err());
            assert!(map.get_slice::<u32>(1, 1).is_err());
            assert!(map.get_slice_mut::<u32>(1, 1).is_err());
            assert!(map.get_ref::<u64>(4092).is_err());
            *map.get_mut::<u32>(4).unwrap() = 42;
            assert_eq!(*map.get_ref::<u32>(4).unwrap(), 42);
        }
        map.sync_data().unwrap();
        drop(map);
        let mut map =
            FileMapState::new(temp.as_file().try_clone().unwrap(), 0, 4096, false).unwrap();
        unsafe {
            assert_eq!(*map.get_ref::<u32>(4).unwrap(), 42);
            assert!(map.get_mut::<u32>(4).is_err());
            assert!(map.get_slice_mut::<u8>(0, 1).is_err());
        }
        let mut empty = FileMapState::default();
        unsafe {
            assert!(empty.get_ref::<()>(0).is_ok());
            assert!(empty.get_slice::<u8>(0, 0).is_ok());
            assert!(empty.get_slice::<u8>(1, 0).is_err());
            assert!(empty.get_ref::<u8>(0).is_err());
            assert!(empty.get_mut::<()>(0).is_err());
        }
        assert!(empty.sync_data().is_err());
        assert!(empty.validate_range(0, 0).is_err());
        assert!(FileMapState::new(temp.as_file().try_clone().unwrap(), 0, 0, false).is_err());
    }
}
