// Copyright (C) 2022 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::future::Future;

/// An adapter to support both tokio current-thread Runtime and tokio-uring Runtime.
pub enum Runtime {
    /// Tokio current thread Runtime.
    Tokio(tokio::runtime::Runtime),
    /// Tokio-uring Runtime.
    #[cfg(target_os = "linux")]
    Uring,
}

impl Runtime {
    /// Create a new instance of async Runtime.
    ///
    /// A `tokio-uring::Runtime` is create if io-uring is available, otherwise a tokio current
    /// thread Runtime will be created.
    ///
    /// # Panic
    /// Panic if failed to create the Runtime object.
    pub fn new() -> Self {
        /*
        let uring = tokio_uring::start(async { tokio_uring::fs::File::open("/proc/self/mounts").await });
        if uring.is_ok() {
            return Runtime::Uring;
        }
         */

        // Create tokio runtime if io-uring is not supported.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("utils: failed to create tokio runtime for current thread");
        Runtime::Tokio(rt)
    }

    /// Run a future to completion.
    pub fn block_on<F: Future>(&self, f: F) -> F::Output {
        match self {
            Runtime::Tokio(rt) => rt.block_on(f),
            // Due to limitation of tokio_uring API, the runtime object is created on-demand.
            // TODO: expose tokio-uring Runtime object.
            #[cfg(target_os = "linux")]
            Runtime::Uring => tokio_uring::start(f),
        }
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Runtime::new()
    }
}

std::thread_local! {
    static CURRENT_RUNTIME: Runtime = Runtime::new();
}

/// Run a callback with the default `Runtime` object.
pub fn with_runtime<F, R>(f: F) -> R
where
    F: FnOnce(&Runtime) -> R,
{
    CURRENT_RUNTIME.with(f)
}

/// Run a future to completion with the default `Runtime` object.
pub fn block_on<F: Future>(f: F) -> F::Output {
    CURRENT_RUNTIME.with(|rt| rt.block_on(f))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_runtime() {
        let res = with_runtime(|rt| rt.block_on(async { 1 }));
        assert_eq!(res, 1);

        let res = with_runtime(|rt| rt.block_on(async { 3 }));
        assert_eq!(res, 3);
    }

    #[test]
    fn test_block_on() {
        let res = block_on(async { 1 });
        assert_eq!(res, 1);

        let res = block_on(async { 3 });
        assert_eq!(res, 3);
    }
}
