//! The format-layer error type.
//!
//! On-disk format parsing is consumed by both of nydus's error planes: the
//! data plane wraps [`Error`] into `io::Error` (`InvalidData`) so the
//! errno-carrying read path stays uniform, and the control plane converts it
//! into the project-wide error (`Error::InvalidImage` and friends) via a
//! `From` impl there. Keeping the format error local to this crate lets both
//! planes share one parser without the data plane ever naming the
//! control-plane error type.
//!
//! The shape deliberately mirrors the project-wide error: `Io` is transparent
//! so bare `?` keeps the OS errno, `Display` prints only the outermost layer,
//! and [`Context`] wraps with a message while keeping the source chain.

use std::fmt;
use std::io;

/// The result type for format-layer operations.
pub type Result<T> = std::result::Result<T, Error>;

/// The error type for parsing and writing nydus on-disk structures.
///
/// Marked `#[non_exhaustive]`: new variants may be added without a semver
/// break, so downstream matches need a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The error for IO operations. Kept transparent so the OS errno survives
    /// into the data plane's `io::Error` wrapping.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// The error when on-disk image data is malformed or inconsistent.
    #[error("{0}")]
    InvalidImage(String),

    /// The error when an argument violates a documented requirement.
    #[error("{0}")]
    InvalidParameter(String),

    /// The error when an offset, range, or size computation overflows.
    #[error("{0}")]
    Overflow(String),

    /// The error when a feature, type, or version is not supported.
    #[error("{0}")]
    Unsupported(String),

    /// The error wrapped with additional context by [`Context`]. Display
    /// prints only the context; the wrapped error stays reachable through
    /// `source()`.
    #[error("{context}")]
    Context {
        /// Human-readable description of the failed operation.
        context: String,
        /// The underlying error.
        source: Box<Error>,
    },
}

mod private {
    /// Seals [`Context`](super::Context); the blanket impl below is the only
    /// one intended.
    pub trait Sealed {}

    impl<T, E: Into<super::Error>> Sealed for std::result::Result<T, E> {}
}

/// Extension trait that wraps an error with context, keeping the original
/// error as the source of the returned [`Error::Context`].
///
/// Sealed: implemented for `Result<T, E>` where `E: Into<Error>` and
/// not implementable outside this crate.
pub trait Context<T>: private::Sealed {
    /// Wraps the error with `context`.
    fn context<C: fmt::Display>(self, context: C) -> Result<T>;

    /// Wraps the error with the context computed by `f`, evaluated only on
    /// the error path.
    fn with_context<C: fmt::Display, F: FnOnce() -> C>(self, f: F) -> Result<T>;
}

impl<T, E: Into<Error>> Context<T> for std::result::Result<T, E> {
    fn context<C: fmt::Display>(self, context: C) -> Result<T> {
        self.map_err(|err| Error::Context {
            context: context.to_string(),
            source: Box::new(err.into()),
        })
    }

    fn with_context<C: fmt::Display, F: FnOnce() -> C>(self, f: F) -> Result<T> {
        self.map_err(|err| Error::Context {
            context: f().to_string(),
            source: Box::new(err.into()),
        })
    }
}
