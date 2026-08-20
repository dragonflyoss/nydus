//! EROFS-oriented image tooling on top of [`nydus_core`]: image inspection
//! and export, plus optional FUSE / NBD / ublk / fanotify / userfaultfd
//! frontends.

#![warn(unreachable_pub)]

use std::path::PathBuf;

pub mod build;
pub mod check;
pub mod export;
#[cfg(feature = "fanotify")]
pub mod fanotify;
#[cfg(feature = "fuse")]
pub mod fuse;
#[cfg(any(feature = "fanotify", feature = "nbd"))]
pub mod mount;
#[cfg(feature = "nbd")]
pub mod nbd;
pub mod optimize;
#[cfg(any(
    feature = "fanotify",
    feature = "nbd",
    feature = "ublk",
    feature = "uffd"
))]
pub mod signal;
#[cfg(feature = "ublk")]
pub mod ublk;
#[cfg(feature = "uffd")]
pub mod uffd;

#[cfg(feature = "fuse")]
pub use fuse::ErofsFs;

pub use nydus_error as error;
pub use nydus_error::{Error, Result};

/// Parse a `unix:///path/to.sock` address into its socket path.
///
/// The path is taken literally after the scheme prefix — no percent-decoding
/// or normalization, matching the convention for unix socket addresses.
pub fn parse_unix_address(address: &str) -> Result<PathBuf> {
    let path = address.strip_prefix("unix://").ok_or_else(|| {
        Error::InvalidParameter(format!("address must start with unix:// (got {address})"))
    })?;
    if path.is_empty() {
        return Err(Error::InvalidParameter(
            "unix socket path is empty".to_string(),
        ));
    }
    Ok(PathBuf::from(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unix_address_extracts_the_socket_path() {
        let path = parse_unix_address("unix:///run/nydus/api.sock").unwrap();
        assert_eq!(path, PathBuf::from("/run/nydus/api.sock"));
    }

    #[test]
    fn parse_unix_address_rejects_a_missing_scheme() {
        let err = parse_unix_address("/run/nydus/api.sock").unwrap_err();
        assert!(err.to_string().contains("must start with unix://"));
    }

    #[test]
    fn parse_unix_address_rejects_an_empty_path() {
        let err = parse_unix_address("unix://").unwrap_err();
        assert!(err.to_string().contains("unix socket path is empty"));
    }
}
