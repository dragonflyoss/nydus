//! The in-process fill in flight: one reader leads the fetch of a chunk
//! group window, every other reader of the same chunk groups waits for its
//! result instead of fetching too.

use std::collections::HashMap;
use std::io;
use std::ops::Range;
use std::sync::{Arc, Condvar, Mutex};

/// The outcome of an in-process fill, published to its followers.
#[derive(Clone)]
enum FlightResult {
    /// The fill succeeded.
    Success,

    /// The fill failed; the error is replayed to every follower.
    Failure {
        /// The kind of the error.
        kind: io::ErrorKind,

        /// The message of the error.
        message: Arc<str>,
    },
}

/// One in-process fill in progress: the leader publishes its result, every
/// other reader of the same chunk groups waits for it.
pub(super) struct Flight {
    /// The result, `None` until the leader publishes it.
    result: Mutex<Option<FlightResult>>,

    /// Wakes the followers once the result is published.
    done: Condvar,
}

/// Implements the flight.
impl Flight {
    /// Creates a flight whose result is pending.
    pub(super) fn new() -> Self {
        Self {
            result: Mutex::new(None),
            done: Condvar::new(),
        }
    }

    /// Publishes `result` to every follower. Idempotent: a result already
    /// published, by the leader or its guard, stays.
    pub(super) fn complete(&self, result: &io::Result<()>) {
        let mut guard = self.result.lock().unwrap();
        if guard.is_some() {
            return;
        }

        *guard = Some(match result {
            Ok(()) => FlightResult::Success,
            Err(err) => FlightResult::Failure {
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
            FlightResult::Success => Ok(()),
            FlightResult::Failure { kind, message } => {
                Err(io::Error::new(*kind, message.to_string()))
            }
        }
    }
}

/// The guard of a fill's leader: publishes a failure to the followers and
/// frees the in-flight slots when dropped, so a panic in the fill never
/// leaves the followers waiting forever.
pub(super) struct LeaderGuard<'a> {
    /// The flight the leader runs.
    pub(super) flight: Arc<Flight>,

    /// The in-flight keys the leader registered: every chunk group of its
    /// window.
    pub(super) keys: Range<usize>,

    /// The in-flight fills of the cache.
    pub(super) inflight: &'a Mutex<HashMap<usize, Arc<Flight>>>,
}

/// Implements the release of the leader's flight.
impl Drop for LeaderGuard<'_> {
    fn drop(&mut self) {
        self.flight.complete(&Err(io::Error::other(
            "chunk group leader panicked or was abandoned",
        )));
        let mut inflight = self.inflight.lock().unwrap();
        for key in self.keys.clone() {
            inflight.remove(&key);
        }
    }
}
