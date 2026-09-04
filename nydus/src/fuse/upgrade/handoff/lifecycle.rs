//! Tracks live-session ownership and coordinates pause, transfer, cutover, and
//! teardown.

use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;

use super::super::transfer::{FuseInitState, SessionProtection, SessionTransfer};
use super::super::wire::ProtocolDeadline;
use super::identity::InstanceInfo;

/// Maximum wall-clock time for reaching READY. This is an operational
/// fail-safe for a path that normally completes in milliseconds, not a FUSE
/// protocol requirement.
pub(in crate::fuse) const HANDOFF_TIMEOUT: Duration = Duration::from_secs(30);

/// One shared deadline covering a whole handoff transaction, from
/// `HANDOFF_BEGIN` through `READY`.
pub(super) fn handoff_deadline() -> ProtocolDeadline {
    ProtocolDeadline::after(HANDOFF_TIMEOUT, "fuse handoff transaction")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum LifecyclePhase {
    Serving,
    HandoffInFlight,
    HandedOff,
    ShuttingDown,
}

impl LifecyclePhase {
    fn from_raw(raw: u8) -> Self {
        match raw {
            value if value == Self::Serving as u8 => Self::Serving,
            value if value == Self::HandoffInFlight as u8 => Self::HandoffInFlight,
            value if value == Self::HandedOff as u8 => Self::HandedOff,
            value if value == Self::ShuttingDown as u8 => Self::ShuttingDown,
            _ => unreachable!("session lifecycle is only mutated through SessionLifecycle"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::fuse) enum SessionOrigin {
    Fresh,
    Adopted,
}

#[derive(Clone)]
pub(in crate::fuse) struct SessionLifecycle {
    phase: Arc<AtomicU8>,
}

impl SessionLifecycle {
    fn new() -> Self {
        Self {
            phase: Arc::new(AtomicU8::new(LifecyclePhase::Serving as u8)),
        }
    }

    fn phase(&self) -> LifecyclePhase {
        LifecyclePhase::from_raw(self.phase.load(Ordering::SeqCst))
    }

    fn begin_handoff(&self) -> std::result::Result<(), &'static str> {
        self.phase
            .compare_exchange(
                LifecyclePhase::Serving as u8,
                LifecyclePhase::HandoffInFlight as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map(|_| ())
            .map_err(|actual| match LifecyclePhase::from_raw(actual) {
                LifecyclePhase::HandedOff => "the session was already handed off",
                LifecyclePhase::ShuttingDown => "the instance is shutting down",
                LifecyclePhase::Serving => {
                    unreachable!("compare_exchange cannot fail with the expected state")
                }
                LifecyclePhase::HandoffInFlight => "another handoff is already in flight",
            })
    }

    fn commit_handoff(&self) {
        self.phase
            .compare_exchange(
                LifecyclePhase::HandoffInFlight as u8,
                LifecyclePhase::HandedOff as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .expect("READY cutover must retain coordinator ownership");
    }

    fn abort_handoff(&self) -> bool {
        self.phase
            .compare_exchange(
                LifecyclePhase::HandoffInFlight as u8,
                LifecyclePhase::Serving as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    pub(in crate::fuse) fn claim_for_teardown(&self) {
        loop {
            match self.phase.compare_exchange(
                LifecyclePhase::Serving as u8,
                LifecyclePhase::ShuttingDown as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(actual) => match LifecyclePhase::from_raw(actual) {
                    LifecyclePhase::HandedOff | LifecyclePhase::ShuttingDown => return,
                    LifecyclePhase::HandoffInFlight => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    LifecyclePhase::Serving => {
                        unreachable!("compare_exchange cannot fail with the expected state")
                    }
                },
            }
        }
    }

    pub(in crate::fuse) fn is_handed_off(&self) -> bool {
        self.phase() == LifecyclePhase::HandedOff
    }

    #[cfg(test)]
    pub(in crate::fuse) fn in_flight_for_test() -> Self {
        Self {
            phase: Arc::new(AtomicU8::new(LifecyclePhase::HandoffInFlight as u8)),
        }
    }

    #[cfg(test)]
    pub(in crate::fuse) fn resolve_for_test(&self, handed_off: bool) {
        let phase = if handed_off {
            LifecyclePhase::HandedOff
        } else {
            LifecyclePhase::Serving
        };
        self.phase.store(phase as u8, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(in crate::fuse) fn is_shutting_down(&self) -> bool {
        self.phase() == LifecyclePhase::ShuttingDown
    }
}

/// A cloneable handle over everything a continuity handoff needs from the
/// live session: the worker pauser, a duplicate of the `/dev/fuse` fd, the
/// negotiated FUSE INIT state, the mount disarmer, and the session's
/// protection kind. `FuseService` owns one; `ControlServer` and the Recovery
/// Holder client drive the handoff protocol through clones of it.
#[derive(Clone)]
pub struct SessionRuntimeHandle {
    pauser: fuser::SessionPauser,
    fuse_fd: Arc<OwnedFd>,
    init_state: FuseInitState,
    disarmer: fuser::MountDisarmer,
    lifecycle: SessionLifecycle,
    protection: SessionProtection,
}

impl SessionRuntimeHandle {
    pub(in crate::fuse) fn new(
        pauser: fuser::SessionPauser,
        fuse_fd: OwnedFd,
        init_state: FuseInitState,
        disarmer: fuser::MountDisarmer,
        protection: SessionProtection,
    ) -> Self {
        Self {
            pauser,
            fuse_fd: Arc::new(fuse_fd),
            init_state,
            disarmer,
            lifecycle: SessionLifecycle::new(),
            protection,
        }
    }

    pub(in crate::fuse) fn resume(&self) {
        self.pauser.resume();
    }

    pub(in crate::fuse) fn exit(&self) {
        self.pauser.exit();
    }

    pub(in crate::fuse) fn is_paused(&self) -> bool {
        self.pauser.is_paused()
    }

    pub(in crate::fuse) fn disarm_mount(&self) {
        self.disarmer.disarm();
    }

    pub(in crate::fuse) fn fuse_fd_owner(&self) -> Arc<OwnedFd> {
        Arc::clone(&self.fuse_fd)
    }

    pub(in crate::fuse) fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle.clone()
    }

    pub(super) fn session_id(&self) -> Option<Uuid> {
        self.protection.session_id()
    }

    pub(in crate::fuse::upgrade) fn session_transfer(
        &self,
        info: &InstanceInfo,
    ) -> std::result::Result<SessionTransfer, String> {
        self.protection
            .capture_transfer(info, &self.init_state, self.fuse_fd.as_fd())
    }

    pub(super) fn handoff_begin(
        &self,
        timeout: Duration,
        info: &InstanceInfo,
    ) -> std::result::Result<SessionTransfer, String> {
        self.protection.supports_handoff()?;
        if let Err(message) = self.lifecycle.begin_handoff() {
            return Err(message.to_string());
        }
        if let Err(err) = self.pauser.pause(timeout) {
            self.lifecycle.abort_handoff();
            return Err(format!("failed to pause fuse workers: {err}"));
        }

        let result = self.session_transfer(info);
        if result.is_err() {
            self.handoff_abort();
        }
        result
    }

    pub(super) fn handoff_cutover(&self) {
        self.lifecycle.commit_handoff();
        self.disarm_mount();
        self.exit();
    }

    pub(super) fn handoff_abort(&self) {
        if self.lifecycle.abort_handoff() {
            self.resume();
        } else {
            self.exit();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuse::upgrade::test_support::parked_runtime_handle;

    #[test]
    fn handoff_begin_rejects_standalone_and_transfers_failover_sessions() {
        let info = InstanceInfo::new("/mnt", &[0x11; 32]);

        let (standalone, background, _kernel) = parked_runtime_handle(None);
        // Resuming leaves a deterministically live, running session for
        // `handoff_begin` to pause again exactly as it would for a real
        // serving predecessor.
        background.pauser().resume();
        let standalone_error = standalone
            .handoff_begin(Duration::from_secs(1), &info)
            .err()
            .expect("Standalone Session hot upgrade must be rejected");
        assert!(standalone_error.contains("Standalone Session"));
        background.pauser().exit();
        background.join().unwrap();

        let failover_session_id = Uuid::from_u128(7);
        let (failover, background, _kernel) = parked_runtime_handle(Some(failover_session_id));
        background.pauser().resume();
        let transfer = failover
            .handoff_begin(Duration::from_secs(1), &info)
            .unwrap();
        drop(transfer);
        failover.handoff_abort();
        background.pauser().exit();
        background.join().unwrap();
    }
}
