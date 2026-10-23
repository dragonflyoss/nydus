//! The notifier of an in-flight fill: one reader owns the fetch of a chunk
//! group window, every other reader of the same chunk groups waits for its
//! result instead of fetching too.

use std::collections::HashMap;
use std::io;
use std::ops::Range;
use std::sync::{Arc, Condvar, Mutex};

/// The result of a fill, replayed to its waiters.
#[derive(Clone)]
enum FillResult {
    /// The fill succeeded.
    Success,

    /// The fill failed; the error is replayed to every waiter.
    Failure {
        /// The kind of the error.
        kind: io::ErrorKind,

        /// The message of the error.
        message: Arc<str>,
    },
}

/// The notifier of one in-flight fill: the owner publishes its result, every
/// other reader of the same chunk groups waits for it.
pub(super) struct ChunkGroupNotifier {
    /// The result, `None` until the owner publishes it.
    result: Mutex<Option<FillResult>>,

    /// Wakes the waiters once the result is published.
    done: Condvar,
}

/// Implements the chunk group notifier.
impl ChunkGroupNotifier {
    /// Creates a notifier whose result is pending.
    pub(super) fn new() -> Self {
        Self {
            result: Mutex::new(None),
            done: Condvar::new(),
        }
    }

    /// Notifies every waiter of `result`. Idempotent: a result already
    /// published, by the owner or its guard, stays.
    pub(super) fn notify(&self, result: &io::Result<()>) {
        let mut guard = self.result.lock().unwrap();
        if guard.is_some() {
            return;
        }

        *guard = Some(match result {
            Ok(()) => FillResult::Success,
            Err(err) => FillResult::Failure {
                kind: err.kind(),
                message: Arc::from(err.to_string()),
            },
        });
        self.done.notify_all();
    }

    /// Waits for the result.
    pub(super) fn wait(&self) -> io::Result<()> {
        let mut result = self.result.lock().unwrap();
        while result.is_none() {
            result = self.done.wait(result).unwrap();
        }

        match result.as_ref().unwrap() {
            FillResult::Success => Ok(()),
            FillResult::Failure { kind, message } => {
                Err(io::Error::new(*kind, message.to_string()))
            }
        }
    }
}

/// The guard of a fill's owner: notifies the waiters of a failure and frees
/// the in-flight chunk groups when dropped, so a panic in the fill never
/// leaves the waiters waiting forever.
pub(super) struct OwnerGuard<'a> {
    /// The notifier of the fill the owner runs.
    pub(super) notifier: Arc<ChunkGroupNotifier>,

    /// The chunk groups the owner registered as in flight: every chunk
    /// group of its window.
    pub(super) chunk_groups: Range<usize>,

    /// The notifiers of the in-flight fills of the cache.
    pub(super) notifiers: &'a Mutex<HashMap<usize, Arc<ChunkGroupNotifier>>>,
}

/// Implements the release of the owner's fill.
impl Drop for OwnerGuard<'_> {
    fn drop(&mut self) {
        self.notifier.notify(&Err(io::Error::other(
            "chunk group fill owner panicked or was abandoned",
        )));
        let mut notifiers = self.notifiers.lock().unwrap();
        for index in self.chunk_groups.clone() {
            notifiers.remove(&index);
        }
    }
}
