// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use nydus_storage::cache::state::PendingRange;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn pending_ranges_can_be_constructed_by_external_maps() {
    let range = PendingRange::new(vec![1, 2]);
    assert_eq!(&*range, &[1, 2]);

    let released = AtomicUsize::new(0);
    let result = catch_unwind(AssertUnwindSafe(|| {
        let range = PendingRange::with_cleanup(vec![1, 2], || {
            released.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(&*range, &[1, 2]);
        panic!("producer failed");
    }));
    assert!(result.is_err());
    assert_eq!(released.load(Ordering::SeqCst), 1);
}
