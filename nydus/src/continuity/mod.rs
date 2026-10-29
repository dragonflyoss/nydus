//! Frontend-independent service continuity: hot upgrade and crash failover.
//!
//! One native resource (a FUSE mount, an NBD device, ...) has exactly one
//! serving process at any time. A starting process selects one of three paths:
//!
//! - **Fresh**: no predecessor and no resource; create it.
//! - **Upgrade**: a live predecessor hands its session over.
//! - **Recovery**: the predecessor crashed; adopt what it left behind.
//!
//! # Three rules
//!
//! 1. **Owner before activation.** The `.owner` flock is the only proof of
//!    ownership. Every path ends `set_owner` → (`recover`) → `activate`.
//! 2. **Fallible work before the point of no return.** Records, resources and
//!    session IDs are checked before `HANDOFF_BEGIN`; in [`Mode::Transfer`]
//!    the successor is fully built before READY. Afterwards only the owner
//!    wait and the frontend's own activation can fail.
//! 3. **Release is signalled by the lock, not by exit.** Normal handoff waits
//!    for `.owner`, not process exit. An ambiguous verdict requires confirmed
//!    exit first. Frontends hold the owner until their native readers stop.
//!
//! # Handoff
//!
//! ```text
//! successor (client.rs)                      predecessor (server.rs)
//!   HTTP upgrade + INFO           ───────▶   authenticate (SO_PEERCRED, pidfd)
//!                                 ◀───────   INFO { identity, session_id }
//!   check record / resource
//!   HANDOFF_BEGIN { identity }    ───────▶   begin_handoff → prepare (reversible)
//!   Transfer: receive bundle      ◀───────   HANDOFF_TRANSFER + Transfer
//!             open (inactive)
//!             READY               ───────▶   mark_released → release → unlink socket
//!                                 ◀───────   COMMITTED
//!   Kernel:                       ◀───────   mark_released → release → RELEASED
//!   wait .owner → set_owner → activate
//! ```
//!
//! Before READY any failure yields ABORT and `resume` on the predecessor.
//! After READY only COMMITTED or ABORT are accepted; an ambiguous verdict
//! makes the successor terminate the predecessor through its pidfd and
//! confirm exit before continuing.
//!
//! # Modes
//!
//! Each frontend declares one fixed [`Identity::MODE`]:
//!
//! | | [`Mode::Transfer`] | [`Mode::Kernel`] |
//! |---|---|---|
//! | Handoff | opaque [`wire::Transfer`] over the control socket | predecessor releases at `HANDOFF_BEGIN` |
//! | Rollback | until READY | none |
//! | Crash protection | a Recovery Holder retains the transfer until serving ends the session; needs a session ID | the kernel keeps the resource; always |
//! | Example | FUSE | NBD |
//!
//! # Reading order
//!
//! `handoff/protocol.rs` (the messages) → [`handoff::SessionControl`]
//! (predecessor contract) → [`Identity`] and [`SessionLifecycle`] below →
//! [`startup::Frontend`] (successor contract) → [`startup::Startup::start`]
//! (path selection). [`wire`], [`ownership`], `peer.rs` and `holder.rs` are
//! leaf utilities and can be read on demand.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nydus_error::{Error, Result};
use serde::{de::DeserializeOwned, Serialize};

pub mod handoff;
pub(crate) mod holder;
pub mod ownership;
pub(crate) mod peer;
pub mod startup;
#[cfg(test)]
pub(crate) mod test_support;
pub mod wire;

pub const CONTROL_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
pub const HANDOFF_TIMEOUT: Duration = Duration::from_secs(30);

/// How a frontend hands over a live session and recovers a crashed one; fixed per frontend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// The predecessor sends an opaque [`wire::Transfer`] and can still resume until READY.
    /// A Recovery Holder retains a copy for crash failover.
    Transfer,
    /// The predecessor irreversibly releases the resource, which the kernel keeps for the
    /// successor to reopen. No transfer crosses the control connection.
    Kernel,
}

/// The frontend's wire identity; serialization remains frontend-owned.
pub trait Identity:
    Clone + std::fmt::Debug + Serialize + DeserializeOwned + Send + Sync + 'static
{
    const CONTROL: crate::api_server::ControlProtocol;
    const MODE: Mode;

    fn pid(&self) -> u32;
    fn version(&self) -> &str;
    fn check(&self, peer: &Self) -> Result<()>;

    /// Whether a crash leaves the session recoverable. A transfer session is protected
    /// only when it has a Holder session ID.
    fn protected(session_id: Option<uuid::Uuid>) -> bool {
        Self::MODE == Mode::Kernel || session_id.is_some()
    }

    fn check_pid(&self, authenticated: u32) -> Result<()> {
        if self.pid() != authenticated {
            return Err(Error::Protocol(format!(
                "peer pid mismatch: declared {}, authenticated {}",
                self.pid(),
                authenticated
            )));
        }
        Ok(())
    }
}

pub(crate) fn lock_exclusive(file: &File) -> std::io::Result<()> {
    // SAFETY: file keeps the descriptor alive; closing it releases the lock.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Phase {
    #[default]
    Serving,
    HandoffInFlight,
    Released,
    ShuttingDown,
}

/// Serializes handoff with teardown; released ownership cannot be reclaimed.
#[derive(Clone, Default)]
pub struct SessionLifecycle {
    phase: Arc<Mutex<Phase>>,
}

impl SessionLifecycle {
    fn phase(&self) -> Phase {
        *self.phase.lock().unwrap()
    }

    fn transition(&self, from: Phase, to: Phase) -> bool {
        let mut phase = self.phase.lock().unwrap();
        if *phase != from {
            return false;
        }
        *phase = to;
        true
    }

    pub(crate) fn begin_handoff(&self) -> Result<()> {
        let mut phase = self.phase.lock().unwrap();
        let message = match *phase {
            Phase::Serving => {
                *phase = Phase::HandoffInFlight;
                return Ok(());
            }
            Phase::HandoffInFlight => "another handoff is already in flight",
            Phase::Released => "this instance released its session",
            Phase::ShuttingDown => "the instance is shutting down",
        };
        Err(Error::Runtime(message.into()))
    }

    pub(crate) fn mark_released(&self) -> Result<()> {
        if !self.transition(Phase::HandoffInFlight, Phase::Released) {
            return Err(Error::Runtime("no handoff is in flight to release".into()));
        }
        Ok(())
    }

    pub(crate) fn abort_handoff(&self) -> bool {
        self.transition(Phase::HandoffInFlight, Phase::Serving)
    }

    pub fn begin_teardown(&self) {
        loop {
            match self.phase() {
                Phase::Serving => {
                    if self.transition(Phase::Serving, Phase::ShuttingDown) {
                        return;
                    }
                }
                Phase::HandoffInFlight => std::thread::sleep(Duration::from_millis(50)),
                Phase::Released | Phase::ShuttingDown => return,
            }
        }
    }

    pub fn is_released(&self) -> bool {
        self.phase() == Phase::Released
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn teardown_blocks_until_the_handoff_resolves_and_release_is_final() {
        for released in [true, false] {
            let lifecycle = SessionLifecycle::default();
            lifecycle.begin_handoff().unwrap();
            let teardown = lifecycle.clone();
            let (done_tx, done_rx) = mpsc::channel();
            let thread = std::thread::spawn(move || {
                teardown.begin_teardown();
                done_tx.send(()).unwrap();
            });
            assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
            if released {
                lifecycle.mark_released().unwrap();
                assert!(!lifecycle.abort_handoff());
            } else {
                assert!(lifecycle.abort_handoff());
            }
            done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            thread.join().unwrap();
            assert_eq!(lifecycle.is_released(), released);
            assert!(lifecycle.begin_handoff().is_err());
        }
    }
}
