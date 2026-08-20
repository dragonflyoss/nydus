use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use nydus_error::{Context, Error, Result};
use signal_hook::consts::{signal::SIGHUP, TERM_SIGNALS};
use tracing::{error, info, warn};

use super::fs::ErofsFs;
use super::mount::{finish_session, mount_dev_of};

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

/// A FUSE filesystem mounted and served on background threads, remembering
/// which mount it created so teardown never unmounts a successor's mount.
pub struct FuseService {
    session: fuser::BackgroundSession,
    mountpoint: PathBuf,
}

impl FuseService {
    /// Mounts `fs` at `mountpoint` and starts serving it in the background.
    pub fn mount(fs: ErofsFs, mountpoint: &Path, config: &fuser::Config) -> Result<Self> {
        let session = fuser::Session::new(fs, mountpoint, config)
            .with_context(|| format!("failed to mount fuse session: {}", mountpoint.display()))?;
        let session = session.spawn().context("failed to spawn fuse session")?;
        Ok(Self {
            session,
            mountpoint: mountpoint.to_path_buf(),
        })
    }

    /// Serves until the session ends on its own or a termination signal
    /// arrives, then tears the mount down and returns the session's join
    /// result. The caller is expected to have blocked the termination signals
    /// with [`TermSignalMask::block`] before spawning any threads.
    pub fn serve(self) -> Result<std::io::Result<()>> {
        let FuseService {
            session: bg,
            mountpoint,
        } = self;

        let wait_signals = TermSignalMask::new()?;
        // Captured before anything can replace the mount, so the teardown below
        // can tell our own mount apart from a successor's at the same path.
        let our_dev = mount_dev_of(&mountpoint)
            .with_context(|| format!("failed to read mount device of {}", mountpoint.display()))?;
        let (unmount_tx, unmount_rx) = mpsc::channel::<i32>();
        let (result_tx, result_rx) = mpsc::channel::<std::io::Result<()>>();

        std::thread::Builder::new()
            .name("nydus_fuse_controller".to_string())
            .spawn(move || {
                let mut bg = Some(bg);

                loop {
                    if bg.as_ref().is_some_and(|bg| bg.guard.is_finished()) {
                        let session = bg.take().expect("background session already taken");
                        let result = finish_session(session, &mountpoint, our_dev.clone());
                        let _ = result_tx.send(result);
                        return;
                    }

                    match unmount_rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(signal) => {
                            let session = bg.take().expect("background session already taken");
                            let result = finish_session(session, &mountpoint, our_dev.clone());
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
                            let result = finish_session(session, &mountpoint, our_dev.clone());
                            let _ = result_tx.send(result);
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
