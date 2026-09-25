// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Checked;
static WATCH: AtomicBool = AtomicBool::new(false);
static PTR: AtomicUsize = AtomicUsize::new(0);
static ALLOC_SIZE: AtomicUsize = AtomicUsize::new(0);
static ALLOC_ALIGN: AtomicUsize = AtomicUsize::new(0);
static FREE_SIZE: AtomicUsize = AtomicUsize::new(0);
static FREE_ALIGN: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Checked {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if WATCH.load(Ordering::SeqCst) && layout.align() == 4096 {
            PTR.store(ptr as usize, Ordering::SeqCst);
            ALLOC_SIZE.store(layout.size(), Ordering::SeqCst);
            ALLOC_ALIGN.store(layout.align(), Ordering::SeqCst);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr as usize == PTR.load(Ordering::SeqCst) {
            FREE_SIZE.store(layout.size(), Ordering::SeqCst);
            FREE_ALIGN.store(layout.align(), Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Checked = Checked;

#[test]
fn allocation_and_deallocation_use_the_same_layout() {
    PTR.store(0, Ordering::SeqCst);
    ALLOC_SIZE.store(0, Ordering::SeqCst);
    ALLOC_ALIGN.store(0, Ordering::SeqCst);
    FREE_SIZE.store(0, Ordering::SeqCst);
    FREE_ALIGN.store(0, Ordering::SeqCst);
    WATCH.store(true, Ordering::SeqCst);
    let mut bytes = nydus_storage::utils::alloc_buf(512);
    WATCH.store(false, Ordering::SeqCst);
    assert_eq!(PTR.load(Ordering::SeqCst), bytes.as_ptr() as usize);
    bytes.fill(0);
    drop(bytes);
    let allocated = (
        ALLOC_SIZE.load(Ordering::SeqCst),
        ALLOC_ALIGN.load(Ordering::SeqCst),
    );
    let freed = (
        FREE_SIZE.load(Ordering::SeqCst),
        FREE_ALIGN.load(Ordering::SeqCst),
    );
    assert_eq!(allocated, (4096, 4096));
    assert_eq!(
        allocated, freed,
        "allocation and deallocation layouts differ"
    );
}
