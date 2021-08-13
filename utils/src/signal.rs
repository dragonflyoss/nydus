// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use nix::sys::signal;

pub fn register_signal_handler(sig: signal::Signal, handler: extern "C" fn(libc::c_int)) {
    let sa = signal::SigAction::new(
        signal::SigHandler::Handler(handler),
        signal::SaFlags::empty(),
        signal::SigSet::empty(),
    );

    unsafe {
        // Signal registration fails, just panic since nydusd won't work properly.
        signal::sigaction(sig, &sa).unwrap();
    }
}
