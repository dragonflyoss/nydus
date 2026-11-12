//! The debug-safe wrappers that keep secret configuration values out of
//! printed output.

use serde::Deserialize;
use std::fmt;

/// The placeholder printed in place of redacted secret material.
const REDACTED: &str = "[REDACTED]";

/// The debug-safe wrapper around a secret configuration string, such as a
/// credential. It has no `Display` and its `Debug` output is redacted, so the
/// structs that hold one keep their derived `Debug`.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct RedactedString(String);

/// Implements the redacted string.
impl RedactedString {
    /// Returns the secret value, marking where it leaves the wrapper.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// Implements the redacted debug output of the string.
impl fmt::Debug for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}
