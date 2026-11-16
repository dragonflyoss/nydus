use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use uuid::Uuid;

use super::lifecycle::SessionRuntimeHandle;
use super::transfer::{FuseInitState, SessionProtection};

pub(super) fn empty_filesystem() -> crate::fuse::ErofsFs {
    use nydus_core::build::bootstrap::render_bootstrap;
    use nydus_core::build::inode::{build_tree, resolve_chunk_addrs};
    use nydus_format::erofs::EROFS_BLOCK_SIZE;

    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    std::fs::create_dir(&source).unwrap();
    let mut writer =
        crate::build::plain_blob_writer(tempfile::tempfile().unwrap(), EROFS_BLOCK_SIZE);
    let mut inodes =
        build_tree(&source, &mut writer, EROFS_BLOCK_SIZE, &Default::default()).unwrap();
    writer.finish().unwrap();
    resolve_chunk_addrs(&mut inodes, &writer).unwrap();
    let bootstrap = dir.path().join("bootstrap");
    std::fs::write(
        &bootstrap,
        render_bootstrap(&mut inodes, 0, &[], &[0; 16]).unwrap(),
    )
    .unwrap();
    let reader = nydus_core::ErofsReader::open_metadata_only(&bootstrap).unwrap();
    crate::fuse::ErofsFs::new(std::sync::Arc::new(reader)).unwrap()
}

pub(in crate::fuse) struct EmptyFilesystem;

impl fuser::Filesystem for EmptyFilesystem {}

/// An initialized 7.31 session over a socketpair; the other end plays the kernel.
pub(in crate::fuse) fn empty_session(
    kernel_flags: fuser::InitFlags,
) -> (fuser::Session<EmptyFilesystem>, UnixStream) {
    let (daemon, kernel) = UnixStream::pair().unwrap();
    let session = fuser::Session::from_initialized_fd(
        EmptyFilesystem,
        OwnedFd::from(daemon),
        fuser::SessionACL::All,
        fuser::Config::default(),
        fuser::InitState {
            proto_version: fuser::Version(7, 31),
            negotiated: fuser::InitFlags::empty(),
            kernel_capabilities: kernel_flags,
        },
    )
    .unwrap();
    (session, kernel)
}

pub(in crate::fuse) fn fuse_init_state() -> FuseInitState {
    FuseInitState {
        proto_major: 7,
        proto_minor: 31,
        negotiated_init_flags: 0,
        kernel_init_flags: 0,
    }
}

/// Returns the runtime handle of a parked session, protected with a journal when
/// `session_id` is set.
pub(super) fn parked_runtime_handle(
    session_id: Option<Uuid>,
) -> (SessionRuntimeHandle, fuser::BackgroundSession, UnixStream) {
    let (mut session, kernel) = empty_session(fuser::InitFlags::empty());
    let (devices, protection) = match session_id {
        None => (
            vec![session.as_fd().try_clone_to_owned().unwrap()],
            SessionProtection::Standalone,
        ),
        Some(session_id) => {
            let journal = session.create_inflight_journal().unwrap();
            let protection = SessionProtection::Failover {
                session_id,
                journal: journal.map(std::sync::Arc::new),
            };
            (session.try_clone_fds().unwrap(), protection)
        }
    };
    let background = session.spawn_paused(Duration::from_secs(5)).unwrap();
    let handle = SessionRuntimeHandle::new(
        background.pauser(),
        devices,
        fuse_init_state(),
        protection,
        std::sync::Arc::new(std::sync::Mutex::new(None)),
    );
    (handle, background, kernel)
}
