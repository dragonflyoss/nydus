use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use nydus_error::{Context, Error, Result};
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use tracing::{error, info, warn};

use super::fs::ErofsFs;
use super::mount::{connection_dead, finish_session, mount_dev_of};
#[cfg(test)]
use super::upgrade::SessionLifecycle;
use super::upgrade::{
    validate_fuse_connection, FuseInitState, SessionOrigin, SessionProtection,
    SessionRuntimeHandle, SessionTransfer, HANDOFF_TIMEOUT,
};

/// Mask over the termination signals ([`TERM_SIGNALS`] plus `SIGHUP`) that the
/// mount lifecycle handles via `sigwait` instead of asynchronous handlers.
pub struct TermSignalMask {
    mask: libc::sigset_t,
    restore_on_drop: bool,
}

impl TermSignalMask {
    fn new() -> Result<Self> {
        let mut mask = unsafe { MaybeUninit::<libc::sigset_t>::zeroed().assume_init() };
        let empty_ret = unsafe { libc::sigemptyset(&mut mask) };
        if empty_ret != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to initialize signal mask");
        }
        for signal in termination_signals() {
            let add_ret = unsafe { libc::sigaddset(&mut mask, *signal) };
            if add_ret != 0 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("failed to add signal {signal} to mask"));
            }
        }

        Ok(Self {
            mask,
            restore_on_drop: false,
        })
    }

    /// Blocks the termination signals on the calling thread (and every thread
    /// it spawns afterwards), returning a guard that restores the previous
    /// mask on drop.
    pub fn block() -> Result<Self> {
        let mut mask = Self::new()?;

        let mask_ret =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &mask.mask, std::ptr::null_mut()) };
        if mask_ret != 0 {
            return Err(std::io::Error::from_raw_os_error(mask_ret))
                .context("failed to block termination signals");
        }

        mask.restore_on_drop = true;
        Ok(mask)
    }

    fn wait(&self) -> Result<i32> {
        let mut signal = 0;
        let wait_ret = unsafe { libc::sigwait(&self.mask, &mut signal) };
        if wait_ret != 0 {
            return Err(std::io::Error::from_raw_os_error(wait_ret))
                .context("failed to wait for termination signal");
        }
        Ok(signal)
    }
}

fn termination_signals() -> impl Iterator<Item = &'static libc::c_int> {
    TERM_SIGNALS.iter().chain(std::iter::once(&SIGHUP))
}

impl Drop for TermSignalMask {
    fn drop(&mut self) {
        if self.restore_on_drop {
            let _ = unsafe {
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &self.mask, std::ptr::null_mut())
            };
        }
    }
}

/// A FUSE filesystem served on background threads.
///
/// The service knows whether it created the kernel mount itself (a fresh
/// [`FuseService::mount`]) or adopted a live connection from a predecessor
/// (`FuseService::adopt`), and records its mount's device identity. Teardown
/// needs both: after an fd handoff the device never changes, so only the
/// lifecycle can tell the two processes apart; while only the device can
/// tell this session's mount apart from an unrelated filesystem later
/// mounted at the same path.
pub struct FuseService {
    session: fuser::BackgroundSession,
    mountpoint: PathBuf,
    handle: SessionRuntimeHandle,
    origin: SessionOrigin,
    /// The `major:minor` of the mount this session serves, captured when it
    /// started; teardown unmounts by path only while the path still reports
    /// this device.
    mount_dev: Option<String>,
}

impl FuseService {
    /// Mounts `fs` at `mountpoint` and starts serving it in the background.
    pub fn mount(fs: ErofsFs, mountpoint: &Path, config: &fuser::Config) -> Result<Self> {
        let session = fuser::Session::new(fs, mountpoint, config).context("mount failed")?;
        Self::start(
            session,
            mountpoint,
            SessionOrigin::Fresh,
            None,
            SessionProtection::Standalone,
        )
    }

    /// Mounts a Failover-Protected Session with workers parked until the
    /// Recovery Holder has retained its Session Transfer.
    pub fn mount_failover(fs: ErofsFs, mountpoint: &Path, config: &fuser::Config) -> Result<Self> {
        let protection = SessionProtection::fresh_failover()
            .context("failed to create the FUSE inflight journal")?;
        let session = fuser::Session::new(fs, mountpoint, config).context("mount failed")?;
        Self::start(
            session,
            mountpoint,
            SessionOrigin::Fresh,
            Some(HANDOFF_TIMEOUT),
            protection,
        )
    }

    /// Adopts a live Session Transfer with workers parked.
    pub fn adopt(
        fs: ErofsFs,
        mountpoint: &Path,
        config: &fuser::Config,
        transfer: SessionTransfer,
        timeout: Duration,
    ) -> Result<Self> {
        Self::adopt_transfer(fs, mountpoint, config, transfer, timeout)
            .map(|(session, _session_id)| session)
            .context("failed to adopt fuse session")
    }

    /// Restores a retained FUSE Session and resumes it after fuser has
    /// reconciled requests left by the previous daemon incarnation.
    pub fn recover(
        fs: ErofsFs,
        mountpoint: &Path,
        config: &fuser::Config,
        transfer: SessionTransfer,
    ) -> Result<Self> {
        let (session, session_id) =
            Self::adopt_transfer(fs, mountpoint, config, transfer, HANDOFF_TIMEOUT)
                .context("failed to adopt recovered fuse session")?;

        let outcome = match session.recover_inflight() {
            Ok(outcome) => outcome,
            Err(err) => {
                return match session.abort_adoption() {
                    Ok(()) => Err(err).context("failed to recover retained FUSE requests"),
                    Err(cleanup) => Err(Error::Runtime(format!(
                        "{}; failed to stand down the recovery successor: {}",
                        err.report(),
                        cleanup.report()
                    ))),
                }
            }
        };
        session.start_serving();
        let (recovery_mode, errored_request_count) = match outcome {
            fuser::InflightRecovery::Resent => ("resent", 0),
            fuser::InflightRecovery::ErroredOut(count) => ("errored_out", count),
        };
        info!(
            session_id = %session_id,
            recovery_mode,
            errored_request_count,
            "fuse: crash recovery complete; workers resumed"
        );
        Ok(session)
    }

    /// Imports a [`SessionTransfer`] into a paused, failover-protected
    /// session. Adoption of an already-initialized FUSE connection belongs to
    /// `FuseService`, so both the hot-handoff and crash-recovery paths reach
    /// the transfer's internals through this one place, and neither has to
    /// know how metadata, descriptor, and failover state are packed.
    fn adopt_transfer(
        fs: ErofsFs,
        mountpoint: &Path,
        config: &fuser::Config,
        transfer: SessionTransfer,
        timeout: Duration,
    ) -> Result<(Self, uuid::Uuid)> {
        let (metadata, fuse_fd, protection) = transfer.into_adoption();
        if Path::new(&metadata.mountpoint) != mountpoint {
            return Err(Error::InvalidParameter(format!(
                "session transfer mountpoint mismatch: transfer uses {}, adoption requested {}",
                metadata.mountpoint,
                mountpoint.display()
            )));
        }
        let session = Self::prepare_adopt(
            fs,
            mountpoint,
            config,
            fuse_fd,
            &metadata.fuse_session_state,
            protection,
            timeout,
        )?;
        Ok((session, metadata.session_id))
    }

    /// Prepares a live fuse session handed over by a predecessor without
    /// reading any request from it.
    fn prepare_adopt(
        fs: ErofsFs,
        mountpoint: &Path,
        config: &fuser::Config,
        fd: OwnedFd,
        state: &FuseInitState,
        protection: SessionProtection,
        timeout: Duration,
    ) -> Result<Self> {
        validate_fuse_connection(fd.as_fd()).context("invalid handed-over FUSE connection")?;
        let session = fuser::Session::from_initialized_fd(
            fs,
            fd,
            config.acl,
            config.clone(),
            fuser::Version(state.proto_major, state.proto_minor),
            fuser::InitFlags::from_bits_retain(state.negotiated_init_flags),
            fuser::InitFlags::from_bits_retain(state.kernel_init_flags),
        )
        .context("failed to build a session on the handed-over fd")?;
        Self::start(
            session,
            mountpoint,
            SessionOrigin::Adopted,
            Some(timeout),
            protection,
        )
    }

    fn start(
        mut session: fuser::Session<ErofsFs>,
        mountpoint: &Path,
        origin: SessionOrigin,
        park_timeout: Option<Duration>,
        protection: SessionProtection,
    ) -> Result<Self> {
        if let Some(journal) = protection.journal() {
            session.set_inflight_journal(journal.clone());
        }
        // Dup the fd and read the negotiated version and init flags before
        // spawn consumes the session; all of them are needed to hand off to
        // a successor later.
        let fuse_fd = session
            .as_fd()
            .try_clone_to_owned()
            .context("failed to dup the fuse fd")?;
        let fuser::Version(proto_major, proto_minor) = session
            .proto_version()
            .ok_or_else(|| Error::Runtime("fuse session has no negotiated version".to_string()))?;
        let init_state = FuseInitState {
            proto_major,
            proto_minor,
            negotiated_init_flags: session.negotiated_init_flags().bits(),
            kernel_init_flags: session.kernel_init_flags().bits(),
        };
        let session = match park_timeout {
            Some(timeout) => session
                .spawn_paused(timeout)
                .context("failed to prepare paused fuse workers")?,
            None => session.spawn().context("spawn failed")?,
        };
        let handle = SessionRuntimeHandle::new(
            session.pauser(),
            fuse_fd,
            init_state,
            session.mount_disarmer(),
            protection,
        );
        let mount_dev = mount_dev_of(mountpoint).ok().flatten();
        if mount_dev.is_none() {
            warn!(
                "failed to record the mount device of {}; teardown will not unmount it",
                mountpoint.display()
            );
        }
        Ok(Self {
            session,
            mountpoint: mountpoint.to_path_buf(),
            handle,
            origin,
            mount_dev,
        })
    }

    /// A handle for controlling the live session while
    /// [`FuseService::serve`] runs.
    pub fn runtime_handle(&self) -> SessionRuntimeHandle {
        self.handle.clone()
    }

    fn recover_inflight(&self) -> Result<fuser::InflightRecovery> {
        recover_parked_session(&self.session)
    }

    /// Releases workers deliberately parked during Failover-Protected Session
    /// startup or recovery preparation.
    pub fn start_serving(&self) {
        self.handle.resume();
    }

    /// Aborts adoption without unmounting the retained kernel mount.
    pub fn abort_adoption(self) -> Result<()> {
        if self.origin != SessionOrigin::Adopted {
            return Err(Error::Runtime(
                "abort_adoption is only valid for an adopted FUSE session".to_string(),
            ));
        }
        self.handle.disarm_mount();
        self.handle.exit();
        self.session
            .join()
            .context("failed to join the stopped fuse successor")
    }

    /// Stops a session that never became reachable through the mountpoint or
    /// its control socket, so a retry can attempt the same mountpoint again.
    ///
    /// This is for a fresh mount whose startup failed before publication
    /// (a lost Holder acknowledgement, a control-socket bind failure): the
    /// mount belongs to no one else yet, so teardown actively unmounts it
    /// instead of leaving it for an adopted-session join. Adopted (recovered
    /// or handed-off) sessions must keep using [`FuseService::abort_adoption`],
    /// which disarms unmount to preserve the retained kernel mount.
    pub fn shutdown_unpublished(self) -> Result<()> {
        if self.origin != SessionOrigin::Fresh {
            return Err(Error::Runtime(
                "shutdown_unpublished called on an adopted session; use abort_adoption instead"
                    .to_string(),
            ));
        }
        let FuseService {
            session,
            mountpoint,
            handle,
            origin,
            mount_dev,
        } = self;
        if handle.is_paused() {
            handle.exit();
        }
        let teardown = handle.lifecycle().is_handed_off();
        finish_session(session, &mountpoint, origin, teardown, mount_dev.as_deref())
            .context("failed to stop unpublished FUSE session")
    }

    /// Serves until the session ends on its own or a termination signal
    /// arrives, then tears the mount down and returns the session's join
    /// result. The caller is expected to have blocked the termination signals
    /// with [`TermSignalMask::block`] before spawning any threads.
    pub fn serve(self) -> Result<std::io::Result<()>> {
        let FuseService {
            session: bg,
            mountpoint,
            handle,
            origin,
            mount_dev,
        } = self;

        let wait_signals = TermSignalMask::new()?;
        let lifecycle = handle.lifecycle();
        let fuse_fd = handle.fuse_fd_owner();
        let (unmount_tx, unmount_rx) = mpsc::channel::<i32>();
        let (result_tx, result_rx) = mpsc::channel::<std::io::Result<()>>();

        std::thread::Builder::new()
            .name("nydus_fuse_controller".to_string())
            .spawn(move || {
                let mut bg = Some(bg);

                // Every exit path claims the lifecycle before teardown. Even
                // for a dead connection the claim is needed: without it, a
                // handoff could start against the dying session in this same
                // instant and its cutover would tell a successor to serve a
                // corpse. `claim_for_teardown` returns immediately once the
                // session was handed off.
                let teardown = |session: fuser::BackgroundSession| {
                    lifecycle.claim_for_teardown();
                    finish_session(
                        session,
                        &mountpoint,
                        origin,
                        lifecycle.is_handed_off(),
                        mount_dev.as_deref(),
                    )
                };
                // The session is over when it was handed to a successor
                // (cutover releases the workers to exit) or when the kernel
                // connection ended on its own (external unmount, abort):
                // fuser exposes no thread-liveness probe, but a dead
                // connection raises POLLERR on every dup of its fd.
                let session_ended = |bg: &Option<fuser::BackgroundSession>| {
                    lifecycle.is_handed_off()
                        || connection_dead(fuse_fd.as_fd())
                        || bg.as_ref().is_some_and(|s| s.is_finished())
                };

                loop {
                    if bg.is_some() && session_ended(&bg) {
                        let session = bg.take().expect("background session already taken");
                        let _ = result_tx.send(teardown(session));
                        return;
                    }

                    match unmount_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(signal) => {
                            let session = bg.take().expect("background session already taken");
                            let result = teardown(session);
                            if let Err(err) = &result {
                                error!(
                                    "failed to unmount after receiving signal {}: {:?}",
                                    signal, err
                                );
                            }
                            let _ = result_tx.send(result);
                            return;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            let session = bg.take().expect("background session already taken");
                            let _ = result_tx.send(teardown(session));
                            return;
                        }
                    }
                }
            })
            .context("failed to spawn fuse controller thread")?;

        std::thread::Builder::new()
            .name("nydus_fuse_signal".to_string())
            .spawn(move || {
                // The first termination signal hands the shutdown to the
                // controller thread; a second signal while that graceful
                // shutdown is in progress (e.g. a wedged unmount keeping the
                // join blocked) forces exit rather than requiring SIGKILL.
                let mut unmount_tx = Some(unmount_tx);
                loop {
                    match wait_signals.wait() {
                        Ok(signal) => match unmount_tx.take() {
                            Some(tx) => {
                                info!("received signal {signal}, stopping nydus fuse session");
                                let _ = tx.send(signal);
                            }
                            None => {
                                warn!("received second signal {signal}, forcing immediate exit");
                                std::process::exit(130);
                            }
                        },
                        Err(err) => {
                            error!("signal wait error: {}", err);
                            return;
                        }
                    }
                }
            })
            .context("failed to spawn signal thread")?;

        result_rx.recv().map_err(|err| {
            Error::Runtime(format!("failed to receive fuse controller result: {err}"))
        })
    }
}

fn recover_parked_session(session: &fuser::BackgroundSession) -> Result<fuser::InflightRecovery> {
    let journal = session.inflight_journal().ok_or_else(|| {
        Error::Runtime("recovery session has no inflight journal attached".to_string())
    })?;
    session
        .notifier()
        .recover_inflight(journal, fuser::Errno::EIO)
        .context("failed to recover inflight FUSE requests")
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use super::*;

    struct EmptyFilesystem;

    impl fuser::Filesystem for EmptyFilesystem {}

    fn parked_session(
        journal: fuser::InflightJournal,
        kernel_flags: fuser::InitFlags,
    ) -> (fuser::BackgroundSession, UnixStream) {
        let (daemon, kernel) = UnixStream::pair().unwrap();
        let mut session = fuser::Session::from_initialized_fd(
            EmptyFilesystem,
            OwnedFd::from(daemon),
            fuser::SessionACL::All,
            fuser::Config::default(),
            fuser::Version(7, 31),
            fuser::InitFlags::empty(),
            kernel_flags,
        )
        .unwrap();
        session.set_inflight_journal(journal);
        let background = session.spawn_paused(Duration::from_secs(5)).unwrap();
        (background, kernel)
    }

    #[test]
    fn inflight_recovery_failure_keeps_workers_parked_and_journal_reusable() {
        let journal = fuser::InflightJournal::create().unwrap();
        let (failed, kernel) = parked_session(journal.clone(), fuser::InitFlags::FUSE_HAS_RESEND);
        let pauser = failed.pauser();
        drop(kernel);

        assert!(recover_parked_session(&failed).is_err());
        assert!(pauser.is_paused());
        pauser.exit();
        let _ = failed.join();

        let (retry, kernel) = parked_session(journal.clone(), fuser::InitFlags::empty());
        assert_eq!(
            recover_parked_session(&retry).unwrap(),
            fuser::InflightRecovery::ErroredOut(0)
        );
        assert!(retry.pauser().is_paused());
        assert!(journal.pending_requests().unwrap().is_empty());
        retry.pauser().exit();
        retry.join().unwrap();
        drop(kernel);
    }

    #[test]
    fn teardown_waits_for_the_handoff_coordinator_to_resolve() {
        for handed_off in [true, false] {
            let lifecycle = SessionLifecycle::in_flight_for_test();
            let claim = lifecycle.clone();
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                claim.claim_for_teardown();
                done_tx.send(()).unwrap();
            });

            assert!(
                done_rx.recv_timeout(Duration::from_millis(100)).is_err(),
                "teardown stole an in-flight handoff"
            );
            lifecycle.resolve_for_test(handed_off);
            done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            thread.join().unwrap();
            assert_eq!(lifecycle.is_handed_off(), handed_off);
            assert_eq!(lifecycle.is_shutting_down(), !handed_off);
        }
    }

    /// A stub `FuseService` over a plain fd (no real kernel mount) with the
    /// given origin, for exercising ownership-state logic without a
    /// real FUSE mount.
    fn stub_service(origin: SessionOrigin) -> (FuseService, UnixStream) {
        let (daemon, kernel) = UnixStream::pair().unwrap();
        let session = fuser::Session::from_initialized_fd(
            EmptyFilesystem,
            OwnedFd::from(daemon),
            fuser::SessionACL::All,
            fuser::Config::default(),
            fuser::Version(7, 31),
            fuser::InitFlags::empty(),
            fuser::InitFlags::empty(),
        )
        .unwrap();
        let fuse_fd = session.as_fd().try_clone_to_owned().unwrap();
        // Mirrors `FuseService::start`: a fresh (non-adopted) session spawns
        // its worker loop actively so a dead connection unblocks `join` on
        // its own, while an adopted session is parked until explicitly
        // resumed or exited.
        let background = if origin == SessionOrigin::Adopted {
            session.spawn_paused(Duration::from_secs(5)).unwrap()
        } else {
            session.spawn().unwrap()
        };
        let handle = SessionRuntimeHandle::new(
            background.pauser(),
            fuse_fd,
            FuseInitState {
                proto_major: 7,
                proto_minor: 31,
                negotiated_init_flags: 0,
                kernel_init_flags: 0,
            },
            background.mount_disarmer(),
            SessionProtection::Standalone,
        );
        let service = FuseService {
            session: background,
            mountpoint: PathBuf::from("/nonexistent-shutdown-unpublished-stub"),
            handle,
            origin,
            mount_dev: None,
        };
        (service, kernel)
    }

    #[test]
    fn shutdown_unpublished_rejects_an_adopted_session() {
        let (service, kernel) = stub_service(SessionOrigin::Adopted);
        let err = service
            .shutdown_unpublished()
            .expect_err("an adopted session must not be torn down as unpublished");
        assert!(
            err.to_string().contains("adopted"),
            "unexpected rejection message: {err}"
        );
        drop(kernel);
    }

    #[test]
    fn shutdown_unpublished_stops_a_fresh_session_without_a_real_mount() {
        // Dead connection: the mount is gone and the workers exit on their own.
        let (service, kernel) = stub_service(SessionOrigin::Fresh);
        drop(kernel);
        service.shutdown_unpublished().unwrap();

        // Externally detached mount with a live connection: nothing is
        // mounted at the stub's mountpoint, so teardown must not unmount by
        // path; it has to exit the still-blocked workers and join them.
        let (service, kernel) = stub_service(SessionOrigin::Fresh);
        service.shutdown_unpublished().unwrap();
        drop(kernel);
    }
}
