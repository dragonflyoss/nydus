//! Minimal frontends for exercising the framework without FUSE or NBD.
//!
//! `TestInfo<KERNEL>` selects the mode: `false` behaves like FUSE
//! ([`Mode::Transfer`]), `true` like NBD ([`Mode::Kernel`]). `TestSession`
//! and the `TestFrontend` in `startup.rs` push one word per framework callback
//! into a shared `events` list, so tests assert ordering by comparing lists.

use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nydus_core::{Metrics, OndemandRecorder};
use nydus_error::{Error, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::continuity::handoff::SessionControl;
use crate::continuity::ownership::SessionOwner;
use crate::continuity::wire::{ProtocolDeadline, Transfer};
use crate::continuity::{Identity, Mode, SessionLifecycle};

/// A test identity whose mode is selected by `KERNEL`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TestInfo<const KERNEL: bool> {
    pub(crate) pid: u32,
    pub(crate) resource: String,
}

pub(crate) type LiveInfo = TestInfo<false>;
pub(crate) type KernelInfo = TestInfo<true>;

impl<const KERNEL: bool> TestInfo<KERNEL> {
    pub(crate) fn new() -> Self {
        Self {
            pid: std::process::id(),
            resource: "test-resource".into(),
        }
    }
}

impl<const KERNEL: bool> Identity for TestInfo<KERNEL> {
    const CONTROL: crate::api_server::ControlProtocol = crate::api_server::ControlProtocol {
        path: "/resource/control",
        token: "nydus-resource-control/1",
    };
    const MODE: Mode = if KERNEL { Mode::Kernel } else { Mode::Transfer };
    fn pid(&self) -> u32 {
        self.pid
    }
    fn version(&self) -> &str {
        "test"
    }
    fn check(&self, peer: &Self) -> Result<()> {
        if self.resource != peer.resource {
            return Err(Error::InvalidParameter("resource mismatch".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub(crate) struct TestSession<const KERNEL: bool> {
    pub(crate) lifecycle: SessionLifecycle,
    pub(crate) session_id: Option<Uuid>,
    pub(crate) events: Arc<Mutex<Vec<&'static str>>>,
    pub(crate) owner: Arc<Mutex<Option<SessionOwner>>>,
    pub(crate) fail_release: bool,
}

impl<const KERNEL: bool> SessionControl for TestSession<KERNEL> {
    type Identity = TestInfo<KERNEL>;
    fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle.clone()
    }
    fn session_id(&self) -> Option<Uuid> {
        self.session_id
    }
    fn prepare(&self, _info: &TestInfo<KERNEL>, _timeout: Duration) -> Result<Option<Transfer>> {
        self.events.lock().unwrap().push("prepare");
        if KERNEL {
            return Ok(None);
        }
        Ok(Some(Transfer {
            metadata: b"native state".to_vec(),
            fds: (0..1 + usize::from(self.session_id.is_some()))
                .map(|_| tempfile::tempfile().unwrap().into())
                .collect(),
        }))
    }
    fn resume(&self) {
        self.events.lock().unwrap().push("resume");
    }
    fn release(&self) -> Result<()> {
        assert!(self.lifecycle.is_released());
        self.events.lock().unwrap().push("release");
        if self.fail_release {
            return Err(Error::Runtime("native release failed".into()));
        }
        self.owner.lock().unwrap().take();
        Ok(())
    }
}

pub(crate) fn metrics() -> Arc<Metrics> {
    Arc::new(Metrics::new())
}

pub(crate) fn ondemand() -> Arc<OndemandRecorder> {
    Arc::new(OndemandRecorder::default())
}

pub(crate) fn test_deadline() -> ProtocolDeadline {
    ProtocolDeadline::after(Duration::from_secs(5), "continuity unit test")
}

pub(crate) fn assert_peer_closed(mut peer: UnixStream) {
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
}

pub(crate) fn assert_cloexec<'a>(fds: impl IntoIterator<Item = BorrowedFd<'a>>) {
    for fd in fds {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags, -1);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
}
