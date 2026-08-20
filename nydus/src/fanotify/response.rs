//! Exactly-once ownership and submission of fanotify permission responses.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;

/// What to answer the kernel with for one event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response {
    Allow,
    Deny,
}

use nydus_error::{Context, Error, Result};
use tracing::{error, warn};

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
    fn write_response(&self, event_fd: RawFd, response: Response) -> io::Result<usize>;
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
    fn write_response(&self, event_fd: RawFd, response: Response) -> io::Result<usize> {
        let response = FanotifyResponse {
            fd: event_fd,
            response: match response {
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

/// The sole owner of one permission event fd and its terminal response.
///
/// A response may be selected once. The fd is released only after one complete
/// response is successfully written. Dropping an unresolved value logs an
/// invariant violation, makes one best-effort deny submission, then closes the fd.
pub struct PendingPermission {
    event_fd: Option<OwnedFd>,
    writer: Arc<dyn ResponseWriter>,
    response: Option<Response>,
    submitted: bool,
}

impl PendingPermission {
    pub fn new(event_fd: OwnedFd, writer: Arc<dyn ResponseWriter>) -> Self {
        Self {
            event_fd: Some(event_fd),
            writer,
            response: None,
            submitted: false,
        }
    }

    pub fn event_fd(&self) -> RawFd {
        self.event_fd
            .as_ref()
            .expect("pending permission must retain its event fd")
            .as_raw_fd()
    }

    pub fn decide(&mut self, response: Response) -> Result<()> {
        if self.response.is_some() || self.submitted {
            return Err(Error::Runtime(
                "permission event already has a terminal response".to_string(),
            ));
        }
        self.response = Some(response);
        Ok(())
    }

    /// Attempt to submit the selected response.
    ///
    /// EINTR is retried internally. `Ok(false)` means EAGAIN and preserves both
    /// the response and fd for a later writable retry. ENOENT is treated as
    /// success (the event was already answered by the kernel). Any other error
    /// is fatal.
    pub fn try_submit(&mut self) -> Result<bool> {
        if self.submitted {
            return Err(Error::Runtime(
                "permission response was already submitted".to_string(),
            ));
        }
        let response = self.response.ok_or_else(|| {
            Error::Runtime("permission response has no terminal response".to_string())
        })?;
        let event_fd = self.event_fd();

        loop {
            match self.writer.write_response(event_fd, response) {
                Ok(RESPONSE_SIZE) => {
                    self.submitted = true;
                    self.event_fd.take();
                    return Ok(true);
                }
                Ok(written) => {
                    return Err(Error::Runtime(format!(
                        "short fanotify response write for fd={event_fd}: {written}/{RESPONSE_SIZE}"
                    )));
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

    pub fn response(&self) -> Option<Response> {
        self.response
    }
}

impl Drop for PendingPermission {
    fn drop(&mut self) {
        let Some(event_fd) = self.event_fd.as_ref().map(AsRawFd::as_raw_fd) else {
            return;
        };

        let response = self.response.unwrap_or(Response::Deny);
        error!(
            "fanotify permission fd={event_fd} dropped before response submission (attempting {response:?})"
        );
        loop {
            match self.writer.write_response(event_fd, response) {
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
        fn write_response(&self, _event_fd: RawFd, response: Response) -> io::Result<usize> {
            self.decisions.lock().unwrap().push(response);
            match self.results.lock().unwrap().pop_front() {
                Some(WriteResult::Written(size)) => Ok(size),
                Some(WriteResult::Error(errno)) => Err(io::Error::from_raw_os_error(errno)),
                None => Ok(RESPONSE_SIZE),
            }
        }
    }

    fn pending(writer: Arc<MockWriter>) -> PendingPermission {
        PendingPermission::new(crate::fanotify::service::create_eventfd().unwrap(), writer)
    }

    #[test]
    fn submits_allow_and_deny() {
        for response in [Response::Allow, Response::Deny] {
            let writer = MockWriter::scripted([]);
            let mut event = pending(writer.clone());
            event.decide(response).unwrap();
            assert!(event.try_submit().unwrap());
            assert_eq!(*writer.decisions.lock().unwrap(), vec![response]);
        }
    }

    #[test]
    fn retries_write_after_eintr() {
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
        assert_eq!(event.response(), Some(Response::Deny));
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
