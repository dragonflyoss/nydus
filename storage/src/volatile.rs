//! Volatile memory slice helpers owned by the storage crate.

use std::io;

use std::marker::PhantomData;

/// A raw writable memory region used by storage read paths.
#[derive(Clone, Copy)]
pub struct VolatileSlice<'a> {
    ptr: *mut u8,
    len: usize,
    phantom: PhantomData<&'a mut [u8]>,
}

impl<'a> VolatileSlice<'a> {
    /// Create a volatile slice from a raw pointer and length.
    ///
    /// # Safety
    ///
    /// The caller must ensure `ptr..ptr+len` is valid for writes for the lifetime `'a`.
    pub unsafe fn from_raw_ptr(ptr: *mut u8, len: usize) -> Self {
        Self {
            ptr,
            len,
            phantom: PhantomData,
        }
    }

    /// Get the raw pointer backing the slice.
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Get the length of the slice.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check whether the slice is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Read chunk data into volatile memory slices.
pub trait BlobIoRead {
    fn read_vectored_at_volatile(
        &mut self,
        buffers: &[VolatileSlice<'_>],
        offset: u64,
    ) -> io::Result<usize>;

    fn read_at_volatile(&mut self, slice: VolatileSlice<'_>, offset: u64) -> io::Result<usize> {
        let buffers = [slice];
        self.read_vectored_at_volatile(&buffers, offset)
    }
}

/// Write chunk data from a volatile reader into a runtime-specific writer.
pub trait BlobIoWrite {
    fn write_from(
        &mut self,
        reader: &mut dyn BlobIoRead,
        size: usize,
        offset: u64,
    ) -> io::Result<usize>;
}
