//! Exactly-once ownership and submission of fanotify permission responses.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tracing::{error, warn};

use super::core::Response;

const FAN_ALLOW: u32 = 0x01;
const FAN_DENY: u32 = 0x02;

/// Kernel `struct fanotify_response`.
#[repr(C)]
#[derive(Clone, Copy)]
struct FanotifyResponse {
    fd: i32,
    response: u32,
}

const RESPONSE_SIZE: usize = std::mem::size_of::<FanotifyResponse>();

/// Injectable response sink used by the real fanotify fd and unit tests.
pub trait ResponseWriter: Send + Sync {
    fn write_response(&self, event_fd: RawFd, decision: Response) -> io::Result<usize>;
}

/// `ResponseWriter` backed by the live fanotify group fd.
///
/// Holds an `Arc<OwnedFd>` shared with the `AsyncFd` that drives the event
/// loop, so the descriptor stays alive as long as any `PendingPermission`
/// (which holds the writer via `Arc<dyn ResponseWriter>`) exists. The fd
/// lifetime is therefore structural — independent of local drop order in the
/// service — and no `unsafe impl Send/Sync` is needed.
pub struct FdResponseWriter {
    fan: Arc<OwnedFd>,
}

impl FdResponseWriter {
    pub fn new(fan: Arc<OwnedFd>) -> Self {
        Self { fan }
    }
}

impl ResponseWriter for FdResponseWriter {
    fn write_response(&self, event_fd: RawFd, decision: Response) -> io::Result<usize> {
        let response = FanotifyResponse {
            fd: event_fd,
            response: match decision {
                Response::Allow => FAN_ALLOW,
                Response::Deny => FAN_DENY,
            },
        };
        let written = unsafe {
            libc::write(
                self.fan.as_raw_fd(),
                &response as *const FanotifyResponse as *const libc::c_void,
                RESPONSE_SIZE,
            )
        };
        if written < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(written as usize)
        }
    }
}

/// The sole owner of one permission event fd and its terminal decision.
///
/// A decision may be selected once. The fd is released only after one complete
/// response is successfully written. Dropping an unresolved value logs an
/// invariant violation, makes one best-effort deny submission, then closes the fd.
pub struct PendingPermission {
    event_fd: Option<OwnedFd>,
    writer: Arc<dyn ResponseWriter>,
    decision: Option<Response>,
    submitted: bool,
}

impl PendingPermission {
    pub fn new(event_fd: OwnedFd, writer: Arc<dyn ResponseWriter>) -> Self {
        Self {
            event_fd: Some(event_fd),
            writer,
            decision: None,
            submitted: false,
        }
    }

    pub fn event_fd(&self) -> RawFd {
        self.event_fd
            .as_ref()
            .expect("pending permission must retain its event fd")
            .as_raw_fd()
    }

    pub fn decide(&mut self, decision: Response) -> Result<()> {
        if self.decision.is_some() || self.submitted {
            return Err(anyhow!("permission event already has a terminal decision"));
        }
        self.decision = Some(decision);
        Ok(())
    }

    /// Attempt to submit the selected decision.
    ///
    /// EINTR is retried internally. `Ok(false)` means EAGAIN and preserves both
    /// the decision and fd for a later writable retry. ENOENT is treated as
    /// success (the event was already answered by the kernel). Any other error
    /// is fatal.
    pub fn try_submit(&mut self) -> Result<bool> {
        if self.submitted {
            return Err(anyhow!("permission response was already submitted"));
        }
        let decision = self
            .decision
            .ok_or_else(|| anyhow!("permission response has no terminal decision"))?;
        let event_fd = self.event_fd();

        loop {
            match self.writer.write_response(event_fd, decision) {
                Ok(RESPONSE_SIZE) => {
                    self.submitted = true;
                    self.event_fd.take();
                    return Ok(true);
                }
                Ok(written) => {
                    return Err(anyhow!(
                        "short fanotify response write for fd={event_fd}: {written}/{RESPONSE_SIZE}"
                    ));
                }
                Err(err) if err.raw_os_error() == Some(libc::EINTR) => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(false),
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                    // The event was already answered by the kernel (timeout, duplicate
                    // response, etc.). Treat as success: the reader is unblocked and
                    // there is nothing left to do.
                    self.submitted = true;
                    self.event_fd.take();
                    return Ok(true);
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to write fanotify response for fd={event_fd}")
                    });
                }
            }
        }
    }

    pub fn decision(&self) -> Option<Response> {
        self.decision
    }
}

impl Drop for PendingPermission {
    fn drop(&mut self) {
        let Some(event_fd) = self.event_fd.as_ref().map(AsRawFd::as_raw_fd) else {
            return;
        };

        let decision = self.decision.unwrap_or(Response::Deny);
        error!(
            "fanotify permission fd={event_fd} dropped before response submission; attempting {decision:?}"
        );
        loop {
            match self.writer.write_response(event_fd, decision) {
                Ok(RESPONSE_SIZE) => break,
                Ok(written) => {
                    warn!(
                        "best-effort fanotify response for fd={event_fd} was short: {written}/{RESPONSE_SIZE}"
                    );
                    break;
                }
                Err(err) if err.raw_os_error() == Some(libc::EINTR) => continue,
                Err(err) => {
                    warn!("best-effort fanotify deny failed for fd={event_fd}: {err}");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::sync::Mutex;

    use super::*;

    enum WriteResult {
        Written(usize),
        Error(i32),
    }

    #[derive(Default)]
    struct MockWriter {
        results: Mutex<VecDeque<WriteResult>>,
        decisions: Mutex<Vec<Response>>,
    }

    impl MockWriter {
        fn scripted(results: impl IntoIterator<Item = WriteResult>) -> Arc<Self> {
            Arc::new(Self {
                results: Mutex::new(results.into_iter().collect()),
                decisions: Mutex::new(Vec::new()),
            })
        }
    }

    impl ResponseWriter for MockWriter {
        fn write_response(&self, _event_fd: RawFd, decision: Response) -> io::Result<usize> {
            self.decisions.lock().unwrap().push(decision);
            match self.results.lock().unwrap().pop_front() {
                Some(WriteResult::Written(size)) => Ok(size),
                Some(WriteResult::Error(errno)) => Err(io::Error::from_raw_os_error(errno)),
                None => Ok(RESPONSE_SIZE),
            }
        }
    }

    fn event_fd() -> OwnedFd {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        assert!(fd >= 0, "eventfd failed: {}", io::Error::last_os_error());
        // SAFETY: eventfd returned a fresh, owned descriptor.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    fn pending(writer: Arc<MockWriter>) -> PendingPermission {
        PendingPermission::new(event_fd(), writer)
    }

    #[test]
    fn submits_allow_and_deny() {
        for decision in [Response::Allow, Response::Deny] {
            let writer = MockWriter::scripted([]);
            let mut event = pending(writer.clone());
            event.decide(decision).unwrap();
            assert!(event.try_submit().unwrap());
            assert_eq!(*writer.decisions.lock().unwrap(), vec![decision]);
        }
    }

    #[test]
    fn retries_eintr() {
        let writer = MockWriter::scripted([
            WriteResult::Error(libc::EINTR),
            WriteResult::Written(RESPONSE_SIZE),
        ]);
        let mut event = pending(writer.clone());
        event.decide(Response::Allow).unwrap();
        assert!(event.try_submit().unwrap());
        assert_eq!(writer.decisions.lock().unwrap().len(), 2);
    }

    #[test]
    fn preserves_decision_across_eagain() {
        let writer = MockWriter::scripted([
            WriteResult::Error(libc::EAGAIN),
            WriteResult::Written(RESPONSE_SIZE),
        ]);
        let mut event = pending(writer.clone());
        event.decide(Response::Deny).unwrap();
        assert!(!event.try_submit().unwrap());
        assert_eq!(event.decision(), Some(Response::Deny));
        assert!(event.try_submit().unwrap());
        assert_eq!(
            *writer.decisions.lock().unwrap(),
            vec![Response::Deny, Response::Deny]
        );
    }

    #[test]
    fn short_and_permanent_writes_fail() {
        for result in [
            WriteResult::Written(RESPONSE_SIZE - 1),
            WriteResult::Error(libc::EIO),
        ] {
            let writer = MockWriter::scripted([result, WriteResult::Written(RESPONSE_SIZE)]);
            let mut event = pending(writer);
            event.decide(Response::Allow).unwrap();
            assert!(event.try_submit().is_err());
            // Drop uses the second scripted result for the required best effort.
        }
    }

    #[test]
    fn rejects_duplicate_decision_and_submission() {
        let writer = MockWriter::scripted([]);
        let mut event = pending(writer);
        event.decide(Response::Allow).unwrap();
        assert!(event.decide(Response::Deny).is_err());
        assert!(event.try_submit().unwrap());
        assert!(event.try_submit().is_err());
    }

    #[test]
    fn drop_without_decision_best_effort_denies() {
        let writer = MockWriter::scripted([]);
        drop(pending(writer.clone()));
        assert_eq!(*writer.decisions.lock().unwrap(), vec![Response::Deny]);
    }
}
