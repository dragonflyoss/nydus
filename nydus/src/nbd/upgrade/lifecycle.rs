use nydus_error::{Context, Error, Result};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};
use uuid::Uuid;

use super::identity::InstanceInfo;
use super::ownership::{kernel_resource, OwnerRecord};
use crate::continuity::handoff::SessionControl;
use crate::continuity::wire::Transfer;
use crate::continuity::SessionLifecycle;
use crate::mount::table::mount_entry_of;
use crate::mount::unmount;
use crate::nbd::netlink;
use crate::nbd::service::{combine, NbdService, NbdSession, POLL_INTERVAL};

/// How this daemon obtained its session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Origin {
    /// The session this daemon created.
    Fresh,

    /// The session this daemon took over from a predecessor.
    Adopted,
}

/// The control a live NBD daemon exposes to its successor.
#[derive(Clone)]
pub(super) struct NbdControl {
    /// The state shared with the workers.
    pub(super) service: Arc<NbdService>,

    /// The handoff and teardown lifecycle.
    pub(super) lifecycle: SessionLifecycle,

    /// The record of the served session.
    pub(super) record: OwnerRecord,
}

/// Implements the NBD session control.
impl SessionControl for NbdControl {
    /// The identity of an NBD daemon.
    type Identity = InstanceInfo;

    /// Returns the handoff and teardown lifecycle.
    fn lifecycle(&self) -> SessionLifecycle {
        self.lifecycle.clone()
    }

    /// Returns the identity of the served session.
    fn session_id(&self) -> Option<Uuid> {
        Some(self.record.session_id)
    }

    /// Parks the workers and returns their connections with the record of the session.
    ///
    /// The kernel keeps queueing requests on the parked connections, so the pause must end
    /// before the kernel gives up on them: it may take at most half the request timeout.
    fn prepare(&self, _info: &InstanceInfo, timeout: Duration) -> Result<Option<Transfer>> {
        let limit = Duration::from_secs(self.record.options.timeout_secs) / 2;
        let fds = self.service.pause(timeout.min(limit))?;
        if fds.is_empty() {
            return Err(Error::Runtime(format!(
                "{} has no live connection to hand over; retry once they are reattached",
                self.record.device
            )));
        }
        let metadata =
            serde_json::to_vec(&self.record).context("failed to encode the NBD session record")?;
        Ok(Some(Transfer { metadata, fds }))
    }

    /// Lets the parked workers serve again after a handoff that did not complete.
    fn resume(&self) {
        if let Err(err) = self.service.resume() {
            warn!(
                "nbd: failed to resume serving after a handoff: {}",
                err.report()
            );
        }
    }

    /// Leaves the connections to the successor that took them over and gives up ownership.
    fn release(&self) -> Result<()> {
        self.service.release()?;
        info!("nbd: handed all connections to the successor");
        Ok(())
    }
}

/// The NBD session this daemon serves.
pub(super) struct NativeSession {
    /// The workers.
    pub(super) pool: NbdSession,

    /// The control exposed to a successor.
    pub(super) control: NbdControl,

    /// The resolved device node, which a fresh session mounts.
    pub(super) node: String,

    /// The `major:minor` of the device.
    pub(super) mount_dev: String,

    /// How this daemon obtained the session.
    pub(super) origin: Origin,
}

/// Implements the served NBD session.
impl NativeSession {
    /// Wraps a pool whose connections the kernel accepted.
    pub(super) fn new(
        pool: NbdSession,
        record: OwnerRecord,
        node: String,
        mount_dev: String,
        origin: Origin,
    ) -> Self {
        let control = NbdControl {
            service: pool.service.clone(),
            lifecycle: SessionLifecycle::default(),
            record,
        };
        Self {
            pool,
            control,
            node,
            mount_dev,
            origin,
        }
    }

    /// Marks the record as describing a disconnected session.
    ///
    /// A device that is still open, usually by a mounted filesystem, keeps the kernel
    /// reporting the capacity and backend identity of the session, which a restart would
    /// otherwise take for a session to recover.
    ///
    /// A successor peeks at the record without the lifetime lock before a handoff, so it can
    /// race this write; that is harmless, because an owner tearing down refuses the handoff.
    fn retire_record(&self) -> Result<()> {
        let record = OwnerRecord {
            session_id: Uuid::nil(),
            ..self.control.record.clone()
        };
        let mut owner = self.control.service.owner.lock().unwrap();
        owner.as_mut().map_or(Ok(()), |owner| owner.write(&record))
    }

    /// Unmounts the filesystem, then disconnects the session if the kernel still holds the
    /// recorded one.
    fn teardown(&self) -> Result<()> {
        let record = &self.control.record;
        let connected = match kernel_resource(Path::new("/sys/block"), self.pool.index)? {
            None => false,
            Some(resource) if resource == record.resource() => true,
            Some(_) => {
                return Err(Error::Runtime(format!(
                    "the kernel session on {} is not the recorded one; refusing native teardown",
                    record.device
                )))
            }
        };

        // Unmount while the workers still serve: the unmount's own reads need a live device.
        // A filesystem still in use keeps the session for a restart to recover, instead of
        // disconnecting it under the mount.
        let unmounted = match &record.mountpoint {
            Some(path) => match mount_entry_of(path)? {
                Some((device, kind)) if device == self.mount_dev && kind == "erofs" => {
                    unmount(path, || {}).map_err(|err| {
                        err.context(format!(
                            "kept the NBD session on {0}; restart nydus with the same device, image and mountpoint to recover it; to discard it, unmount its filesystem and run `nbd-client -d {0}`",
                            record.device
                        ))
                    })?;
                    Ok(())
                }
                Some(_) => Err(Error::Runtime(format!(
                    "NBD mountpoint {} was replaced; refusing to unmount it",
                    path.display()
                ))),
                None => Ok(()),
            },
            None => Ok(()),
        };
        let disconnected = if connected {
            netlink::disconnect_device(self.pool.index).and_then(|()| self.retire_record())
        } else {
            Ok(())
        };
        combine(unmounted, disconnected)
    }

    /// Tears the session down and stops the workers, unless the session was released.
    pub(super) fn shutdown(&mut self) -> Result<()> {
        self.control.lifecycle.begin_teardown();
        if self.control.lifecycle.is_released() {
            return self.pool.detach();
        }
        let native = self.teardown();
        combine(native, self.pool.cancel())
    }

    /// Stops the workers after a failure, keeping the kernel session for a replacement daemon.
    fn abandon(&mut self, err: Error) -> Result<()> {
        self.control.lifecycle.begin_teardown();
        if self.control.lifecycle.is_released() {
            warn!(
                "nbd: ignoring a failure after the session was released: {}",
                err.report()
            );
            return self.pool.detach();
        }
        let stopped = self.pool.cancel();
        let err = err.context(format!(
            "the NBD session can no longer be served; restart nydus with the same device, image and mountpoint to recover the retained session; to discard it, unmount its filesystem and run `nbd-client -d {}`",
            self.control.record.device,
        ));
        combine(Err(err), stopped)
    }

    /// Serves until `stop` is set by a termination signal, a kernel disconnect, a failure or
    /// a release.
    pub(super) fn serve(mut self, stop: Arc<AtomicBool>) -> Result<()> {
        loop {
            // Repair before reading the disconnect flag: a worker sets it before it exits, so
            // the connections a kernel disconnect closes are seen together with the request.
            // Only a worker failure fails the repair; a failed reattachment is retried.
            let repaired = self.pool.repair();
            let signalled = stop.swap(false, Ordering::AcqRel);
            if signalled || self.pool.disconnect_requested() {
                self.control.lifecycle.begin_teardown();
                if !self.control.lifecycle.is_released() {
                    if !signalled {
                        info!("nbd: the kernel disconnected the session; shutting down");
                    }
                    break self.shutdown();
                }
            }
            if let Err(err) = repaired {
                break self.abandon(err);
            }
            if self.pool.is_released() {
                info!("nbd: session released; exiting without disconnecting the successor");
                break self.pool.detach();
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::continuity::ownership::SessionOwner;
    use crate::nbd::service::tests::{test_pool, test_session};
    use crate::nbd::upgrade::ownership::tests::test_record;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    #[test]
    fn failed_workers_preserve_the_record_and_release_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("owner");
        let (_, record) = test_record();
        let mut owner = SessionOwner::acquire(&base, true).unwrap();
        owner.write(&record).unwrap();
        let mut pool = test_session(dir.path(), test_pool());
        *pool.service.owner.lock().unwrap() = Some(owner);
        let mut kernels = pool.start(2).unwrap();
        UnixStream::from(kernels.remove(0).0)
            .write_all(&[0; 28])
            .unwrap();

        let session = NativeSession::new(
            pool,
            record.clone(),
            "/dev/nbd0".into(),
            "0:0".into(),
            Origin::Fresh,
        );
        let stop = Arc::new(AtomicBool::new(false));
        let message = session.serve(stop).unwrap_err().report().to_string();
        assert!(message.contains("restart nydus with the same device, image and mountpoint"));
        assert!(message.contains(&format!("nbd-client -d {}", record.device)));
        let mut owner = SessionOwner::acquire(&base, false).unwrap();
        assert_eq!(owner.read::<OwnerRecord>().unwrap(), record);
    }

    #[test]
    fn a_handoff_carries_the_record_with_every_live_connection() {
        let dir = tempfile::tempdir().unwrap();
        let (info, record) = test_record();
        let mut pool = test_session(dir.path(), test_pool());
        let control = NbdControl {
            service: pool.service.clone(),
            lifecycle: SessionLifecycle::default(),
            record: record.clone(),
        };
        let timeout = Duration::from_secs(2);

        let err = control.prepare(&info, timeout).err().unwrap();
        assert!(err.report().to_string().contains("no live connection"));
        control.resume();

        let _kernels = pool.start(2).unwrap();
        let transfer = control.prepare(&info, timeout).unwrap().unwrap();
        assert_eq!(transfer.fds.len(), 2);
        let carried: OwnerRecord = serde_json::from_slice(&transfer.metadata).unwrap();
        assert_eq!(carried, record);
        control.resume();
        pool.cancel().unwrap();
    }

    #[test]
    fn a_disconnected_session_is_not_taken_for_one_to_recover() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("owner");
        let (info, record) = test_record();
        let mut owner = SessionOwner::acquire(&base, true).unwrap();
        owner.write(&record).unwrap();
        let pool = test_session(dir.path(), test_pool());
        *pool.service.owner.lock().unwrap() = Some(owner);
        let session = NativeSession::new(
            pool,
            record.clone(),
            "/dev/nbd0".into(),
            "0:0".into(),
            Origin::Fresh,
        );

        session.retire_record().unwrap();
        drop(session);
        let mut owner = SessionOwner::acquire(&base, false).unwrap();
        let retired = owner.read::<OwnerRecord>().unwrap();
        let err = retired.validate(&info, &record.resource()).unwrap_err();
        assert!(err.report().to_string().contains("was disconnected"));
    }
}
