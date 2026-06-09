//! Global backend pauser used to temporarily halt all backend network reads.
//!
//! This is a lightweight cooperative mechanism: callers block in
//! [`Pauser::wait_if_paused`] before issuing a network request. A management
//! plane (or rate-limit handler) can call [`Pauser::pause_for`] to stall all
//! backend traffic for a while, e.g. to back off after a burst of `429`
//! responses. No HTTP/management trigger is wired up yet — only the internal
//! API and the global instance are provided.

use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;

/// Process-wide pauser shared by all backends.
pub static BACKEND_PAUSER: Lazy<Pauser> = Lazy::new(Pauser::new);

#[derive(Default)]
struct PauserState {
    /// Instant until which backend reads should be paused, if any.
    paused_until: Option<Instant>,
}

pub struct Pauser {
    state: Mutex<PauserState>,
    cvar: Condvar,
}

impl Pauser {
    fn new() -> Self {
        Self {
            state: Mutex::new(PauserState::default()),
            cvar: Condvar::new(),
        }
    }

    /// Pause backend reads for the given duration (extends an existing pause).
    pub fn pause_for(&self, duration: Duration) {
        let until = Instant::now() + duration;
        let mut state = self.state.lock().unwrap();
        match state.paused_until {
            Some(existing) if existing >= until => {}
            _ => state.paused_until = Some(until),
        }
    }

    /// Clear any active pause and wake all waiters.
    pub fn clear(&self) {
        let mut state = self.state.lock().unwrap();
        state.paused_until = None;
        self.cvar.notify_all();
    }

    /// Block the calling thread until the active pause (if any) elapses.
    pub fn wait_if_paused(&self) {
        let mut state = self.state.lock().unwrap();
        while let Some(until) = state.paused_until {
            let now = Instant::now();
            if until <= now {
                state.paused_until = None;
                break;
            }
            let (guard, _) = self.cvar.wait_timeout(state, until - now).unwrap();
            state = guard;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_returns_immediately_when_not_paused() {
        let pauser = Pauser::new();
        let start = Instant::now();
        pauser.wait_if_paused();
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[test]
    fn wait_blocks_until_pause_elapses() {
        let pauser = Pauser::new();
        pauser.pause_for(Duration::from_millis(80));
        let start = Instant::now();
        pauser.wait_if_paused();
        assert!(start.elapsed() >= Duration::from_millis(60));
    }

    #[test]
    fn clear_wakes_waiter_early() {
        use std::sync::Arc;
        use std::thread;

        let pauser = Arc::new(Pauser::new());
        pauser.pause_for(Duration::from_secs(10));
        let p = pauser.clone();
        let handle = thread::spawn(move || {
            let start = Instant::now();
            p.wait_if_paused();
            start.elapsed()
        });
        thread::sleep(Duration::from_millis(50));
        pauser.clear();
        let elapsed = handle.join().unwrap();
        assert!(elapsed < Duration::from_secs(5));
    }
}
