//! EROFS-oriented image tooling on top of [`nydus_core`]: image inspection
//! and unpack, plus optional FUSE / NBD / ublk / fanotify / userfaultfd
//! frontends.

pub mod check;
#[cfg(feature = "fanotify")]
pub mod fanotify;
#[cfg(feature = "fuse")]
pub mod fuse;
#[cfg(feature = "nbd")]
pub mod nbd;
#[cfg(feature = "ublk")]
pub mod ublk;
#[cfg(feature = "uffd")]
pub mod uffd;
pub mod unpack;

#[cfg(feature = "fuse")]
pub use fuse::ErofsFs;
