//! FUSE frontend for nydus images: the [`ErofsFs`] filesystem
//! implementation, the [`FuseService`] mount/serve lifecycle, and the
//! hot-upgrade handoff machinery in [`upgrade`].

pub mod fs;
pub mod mount;
pub mod service;
pub mod upgrade;

pub use fs::ErofsFs;
pub use service::{FuseService, TermSignalMask};
