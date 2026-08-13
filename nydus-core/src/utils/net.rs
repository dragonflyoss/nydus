use std::path::PathBuf;

use crate::error::{Error, Result};

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
