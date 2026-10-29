mod client;
mod protocol;
mod server;

use std::time::Duration;

use nydus_error::Result;
use uuid::Uuid;

use super::wire::Transfer;
use super::{Identity, SessionLifecycle};

pub(crate) use client::{probe, Handoff};
pub(crate) use server::ControlServer;

/// The predecessor side of a handoff. Preparation must remain reversible; release need not.
pub trait SessionControl: Clone + Send + Sync + 'static {
    type Identity: Identity;

    fn lifecycle(&self) -> SessionLifecycle;
    fn session_id(&self) -> Option<Uuid>;
    /// Parks the session without crossing the rollback boundary. [`super::Mode::Transfer`]
    /// frontends return their transfer; [`super::Mode::Kernel`] frontends return `None`.
    fn prepare(&self, info: &Self::Identity, timeout: Duration) -> Result<Option<Transfer>>;
    fn resume(&self);
    /// Runs after ownership becomes irreversible; an error must not revive the old reader.
    /// The frontend keeps its owner until native readers stop, since successors wait on
    /// the owner rather than on process exit. It must not exit the process itself.
    fn release(&self) -> Result<()>;
}
