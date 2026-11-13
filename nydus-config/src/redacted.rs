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

/// Implements the conversion from an owned string.
impl From<String> for RedactedString {
    /// Wraps the owned string as a redacted string.
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Implements the conversion from a string slice.
impl From<&str> for RedactedString {
    /// Copies the string slice into a redacted string.
    fn from(value: &str) -> Self {
        Self::from(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_wraps_strings_and_keeps_debug_redacted() {
        let test_cases: Vec<Option<RedactedString>> = vec![
            Some("my-token".into()),
            Some(String::from("my-token").into()),
        ];

        for redacted in test_cases {
            assert_eq!(
                redacted.as_ref().map(RedactedString::expose),
                Some("my-token")
            );
            assert_eq!(format!("{redacted:?}"), "Some([REDACTED])");
        }
    }
}
