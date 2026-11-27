//! systemd service notification for a daemon started as a `Type=notify`
//! unit: the sd_notify(3) datagram protocol and the sd_watchdog_enabled(3)
//! keep-alive, over std alone.

use nydus_error::{Context, Error, Result};
use std::env;
use std::ffi::OsStr;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tracing::{info, warn};

/// The environment variable naming the notification socket of the service
/// manager.
const NOTIFY_SOCKET: &str = "NOTIFY_SOCKET";

/// The environment variable carrying the watchdog timeout in microseconds.
const WATCHDOG_USEC: &str = "WATCHDOG_USEC";

/// The environment variable naming the process the watchdog timeout applies
/// to.
const WATCHDOG_PID: &str = "WATCHDOG_PID";

/// The state reporting that the service finished starting up.
const READY: &str = "READY=1";

/// The state reporting that the service began shutting down.
const STOPPING: &str = "STOPPING=1";

/// The state resetting the watchdog timer of the service.
const WATCHDOG: &str = "WATCHDOG=1";

/// Reports service state to the service manager that started the process.
///
/// Every state is one datagram to the `NOTIFY_SOCKET` address, refer to
/// https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html.
/// Without that address every method is a no-op. A state that cannot be sent
/// is logged and dropped: reporting never fails the daemon, and a send waits
/// only for room in the service manager's receive queue, as sd_notify(3)
/// does.
#[derive(Clone, Debug)]
pub struct Notifier {
    /// The notification socket, `None` when no service manager listens.
    address: Option<SocketAddr>,

    /// The interval between watchdog keep-alives, `None` when the watchdog is
    /// not enabled for this process.
    watchdog_interval: Option<Duration>,
}

/// Implements the service state notifications.
impl Notifier {
    /// Creates a notifier from explicit values.
    pub fn new(address: Option<SocketAddr>, watchdog_interval: Option<Duration>) -> Self {
        Self {
            address,
            watchdog_interval,
        }
    }

    /// Creates a notifier from the environment the service manager set up:
    /// `NOTIFY_SOCKET` for the address, `WATCHDOG_USEC` and `WATCHDOG_PID`
    /// for the watchdog.
    pub fn from_env() -> Self {
        let address = env::var_os(NOTIFY_SOCKET).and_then(|socket| {
            socket_address(&socket)
                .inspect_err(|err| warn!("ignoring {}: {}", NOTIFY_SOCKET, err.report()))
                .ok()
        });
        let watchdog_interval = watchdog_interval(
            env::var(WATCHDOG_USEC).ok().as_deref(),
            env::var(WATCHDOG_PID).ok().as_deref(),
            process::id(),
        );
        Self::new(address, watchdog_interval)
    }

    /// Reports that the service finished starting up.
    pub fn ready(&self) {
        self.notify(READY);
    }

    /// Reports that the service began shutting down.
    pub fn stopping(&self) {
        self.notify(STOPPING);
    }

    /// Starts the watchdog keep-alive thread when the service manager enabled
    /// the watchdog for this process, and returns the guard that stops it.
    ///
    /// `WATCHDOG=1` is sent once before returning and then once per interval
    /// by a thread that shares nothing with the request path. The keep-alive
    /// therefore proves only that the process exists and its threads still
    /// get scheduled: a stopped, frozen or starved process misses it. It does
    /// not prove that requests make progress: a worker blocked in a read, a
    /// parked session or an unreachable backend never stops it. That is
    /// deliberate. The service manager answers a missed keep-alive by killing
    /// the daemon, and a session without crash recovery loses its mount to
    /// that kill, so a slow backend must not look like a hung process.
    ///
    /// # Errors
    ///
    /// Fails when the thread cannot be spawned. The service manager enforces
    /// the watchdog whether or not a thread keeps it alive, so the caller
    /// spawns it before there is a session to lose and treats the failure as
    /// a failed start.
    pub fn spawn_watchdog(&self) -> Result<Option<Watchdog>> {
        let (Some(interval), Some(_)) = (self.watchdog_interval, &self.address) else {
            return Ok(None);
        };
        self.notify(WATCHDOG);
        let stop = Arc::new(AtomicBool::new(false));
        let thread = thread::Builder::new()
            .name("nydus_watchdog".to_string())
            .spawn({
                let notifier = self.clone();
                let stop = stop.clone();
                move || loop {
                    thread::park_timeout(interval);
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    notifier.notify(WATCHDOG);
                }
            })
            .context("failed to spawn the watchdog thread")?;
        info!(
            "started the service watchdog keep-alive every {:?}",
            interval
        );
        Ok(Some(Watchdog {
            stop,
            thread: Some(thread),
        }))
    }

    /// Sends one state datagram, logging a failure instead of returning it.
    fn notify(&self, state: &str) {
        let Some(address) = &self.address else {
            return;
        };
        let sent = UnixDatagram::unbound()
            .and_then(|socket| socket.send_to_addr(state.as_bytes(), address));
        if let Err(err) = sent {
            warn!("failed to notify the service manager of {}: {}", state, err);
        }
    }
}

/// The watchdog keep-alive thread, stopped and joined on drop.
pub struct Watchdog {
    /// The flag telling the thread to stop.
    stop: Arc<AtomicBool>,

    /// The handle of the thread, taken on drop.
    thread: Option<JoinHandle<()>>,
}

/// Implements the stop of the keep-alive thread.
impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.thread().unpark();
            if thread.join().is_err() {
                warn!("watchdog thread panicked");
            }
        }
    }
}

/// Parses a `NOTIFY_SOCKET` value: an absolute path, or `@` followed by a
/// name in the abstract namespace.
fn socket_address(socket: &OsStr) -> Result<SocketAddr> {
    let bytes = socket.as_bytes();
    let address = match bytes.first() {
        Some(b'/') => SocketAddr::from_pathname(socket),
        Some(b'@') => SocketAddr::from_abstract_name(&bytes[1..]),
        _ => {
            return Err(Error::Unsupported(format!(
                "notification socket {} is neither an absolute path nor an abstract name",
                socket.to_string_lossy()
            )))
        }
    };
    address.with_context(|| format!("invalid notification socket {}", socket.to_string_lossy()))
}

/// Returns the interval between watchdog keep-alives, half the timeout the
/// service manager enforces, or `None` when the watchdog is not enabled for
/// the process `pid`.
///
/// Follows sd_watchdog_enabled(3): `WATCHDOG_USEC` holds a non-zero count of
/// microseconds, and applies when `WATCHDOG_PID` is unset or names `pid`.
fn watchdog_interval(
    watchdog_usec: Option<&str>,
    watchdog_pid: Option<&str>,
    pid: u32,
) -> Option<Duration> {
    let usec = watchdog_usec?
        .parse::<u64>()
        .ok()
        .filter(|usec| *usec != 0 && *usec != u64::MAX)?;
    if watchdog_pid.is_some_and(|watchdog_pid| watchdog_pid.parse() != Ok(pid)) {
        return None;
    }
    Some(Duration::from_micros(usec) / 2)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;
    use std::path::Path;
    use tempfile::tempdir;

    const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);

    fn listen(dir: &Path, watchdog_interval: Option<Duration>) -> (UnixDatagram, Notifier) {
        let path = dir.join("notify.sock");
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver.set_read_timeout(Some(RECEIVE_TIMEOUT)).unwrap();
        let address = SocketAddr::from_pathname(&path).unwrap();
        (receiver, Notifier::new(Some(address), watchdog_interval))
    }

    fn receive(receiver: &UnixDatagram) -> String {
        let mut buffer = [0; 64];
        let len = receiver.recv(&mut buffer).unwrap();
        String::from_utf8_lossy(&buffer[..len]).into_owned()
    }

    #[test]
    fn notifier_without_a_socket_is_a_noop() {
        let test_cases = vec![None, Some(Duration::from_millis(10))];

        for watchdog_interval in test_cases {
            let notifier = Notifier::new(None, watchdog_interval);
            notifier.ready();
            notifier.stopping();
            assert!(notifier.spawn_watchdog().unwrap().is_none());
        }
    }

    #[test]
    fn notifier_sends_each_state_as_one_datagram() {
        let test_cases: Vec<(fn(&Notifier), &str)> = vec![
            (Notifier::ready, "READY=1"),
            (Notifier::stopping, "STOPPING=1"),
        ];

        for (notify, expected) in test_cases {
            let dir = tempdir().unwrap();
            let (receiver, notifier) = listen(dir.path(), None);
            notify(&notifier);
            assert_eq!(receive(&receiver), expected);
        }
    }

    #[test]
    fn notifier_survives_a_socket_nobody_listens_on() {
        let dir = tempdir().unwrap();
        let address = SocketAddr::from_pathname(dir.path().join("absent.sock")).unwrap();
        let notifier = Notifier::new(Some(address), Some(Duration::from_millis(10)));
        notifier.ready();
        notifier.stopping();
        drop(notifier.spawn_watchdog().unwrap().unwrap());
    }

    #[test]
    fn watchdog_is_disabled_without_an_interval() {
        let dir = tempdir().unwrap();
        let (_receiver, notifier) = listen(dir.path(), None);
        assert!(notifier.spawn_watchdog().unwrap().is_none());
    }

    #[test]
    fn watchdog_pings_every_interval() {
        let dir = tempdir().unwrap();
        let (receiver, notifier) = listen(dir.path(), Some(Duration::from_millis(10)));
        let _watchdog = notifier.spawn_watchdog().unwrap().unwrap();
        for _ in 0..3 {
            assert_eq!(receive(&receiver), "WATCHDOG=1");
        }
    }

    #[test]
    fn watchdog_stops_pinging_when_dropped() {
        let test_cases = vec![Duration::from_millis(10), Duration::from_secs(3600)];

        for interval in test_cases {
            let dir = tempdir().unwrap();
            let (receiver, notifier) = listen(dir.path(), Some(interval));
            let watchdog = notifier.spawn_watchdog().unwrap().unwrap();
            assert_eq!(receive(&receiver), "WATCHDOG=1");
            drop(watchdog);
            receiver.set_nonblocking(true).unwrap();
            while receiver.recv(&mut [0; 64]).is_ok() {}
            receiver.set_nonblocking(false).unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            assert!(receiver.recv(&mut [0; 64]).is_err());
        }
    }

    #[test]
    fn socket_address_accepts_paths_and_abstract_names() {
        let test_cases: Vec<(&str, fn(Result<SocketAddr>))> = vec![
            ("/run/systemd/notify", |address| {
                let address = address.unwrap();
                assert_eq!(
                    address.as_pathname(),
                    Some(Path::new("/run/systemd/notify"))
                );
            }),
            ("@nydus/notify", |address| {
                let address = address.unwrap();
                assert_eq!(address.as_abstract_name(), Some(b"nydus/notify".as_slice()));
            }),
            ("run/notify", |address| {
                assert!(matches!(address, Err(Error::Unsupported(_))));
            }),
            ("", |address| {
                assert!(matches!(address, Err(Error::Unsupported(_))));
            }),
            ("/run/\0notify", |address| assert!(address.is_err())),
        ];

        for (socket, assert_fn) in test_cases {
            assert_fn(socket_address(OsStr::new(socket)));
        }
    }

    #[test]
    fn notifier_reaches_an_abstract_socket() {
        let name = format!("nydus-systemd-test-{}", process::id());
        let receiver =
            UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(&name).unwrap()).unwrap();
        receiver.set_read_timeout(Some(RECEIVE_TIMEOUT)).unwrap();
        let address = socket_address(OsStr::new(&format!("@{name}"))).unwrap();
        Notifier::new(Some(address), None).ready();
        assert_eq!(receive(&receiver), "READY=1");
    }

    #[test]
    fn watchdog_interval_is_half_the_timeout_for_this_process() {
        let test_cases = vec![
            (None, None, None),
            (None, Some("42"), None),
            (Some("30000000"), None, Some(Duration::from_secs(15))),
            (Some("30000000"), Some("42"), Some(Duration::from_secs(15))),
            (
                Some("1000000"),
                Some("42"),
                Some(Duration::from_millis(500)),
            ),
            (Some("30000000"), Some("43"), None),
            (Some("30000000"), Some("init"), None),
            (Some("0"), None, None),
            (Some("18446744073709551615"), None, None),
            (Some("30s"), None, None),
            (Some(""), None, None),
        ];

        for (watchdog_usec, watchdog_pid, expected) in test_cases {
            assert_eq!(watchdog_interval(watchdog_usec, watchdog_pid, 42), expected);
        }
    }
}
