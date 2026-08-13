//! Project-wide error and result types for nydus.
//!
//! This crate is the control-plane error contract, mirroring the role of
//! `nydus-error` in nydus v2 and `rustc_errors`/`linkerd-error`-style
//! dedicated error crates. The data-plane crates (`nydus-backend`,
//! `nydus-storage`) never depend on it.
//!
//! Nydus splits errors along two planes:
//!
//! - The data plane (`storage`, `fs`, and the FUSE/fanotify/NBD/UFFD read
//!   paths) keeps [`std::io::Result`]: those errors must carry an OS errno so
//!   the service edges can answer the kernel with a meaningful POSIX code.
//! - Everything else (image building, config parsing, CLI, service setup)
//!   returns [`Result`] with the project-wide [`Error`] defined here.
//!
//! [`Error`] wraps `io::Error` transparently, so data-plane failures cross
//! into the control plane with a plain `?`. Use [`Context`] to attach
//! human-readable context while keeping the source chain intact.
//!
//! Following the std guidance that an error exposes its cause either through
//! `source()` or through `Display` but not both, `Display` prints only the
//! outermost layer. Print edges (logs, `eprintln!`) must format errors with
//! [`Error::report`] to keep the whole cause chain on one line.

use std::fmt;
use std::io;

/// The result type used across nydus, with the project-wide [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// The error type for nydus operations.
///
/// Marked `#[non_exhaustive]`: new variants may be added without a semver
/// break, so downstream matches need a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The error for IO operations. Kept transparent so the OS errno survives
    /// for the service edges that map errors back to POSIX codes.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// The error for JSON serialization or deserialization.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// The error for YAML deserialization.
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),

    /// The error when on-disk image data is malformed or inconsistent
    /// (EROFS metadata, nydus footer, blob meta, chunk table, ...).
    #[error("{0}")]
    InvalidImage(String),

    /// The error when a configuration file or backend config is invalid.
    #[error("{0}")]
    InvalidConfig(String),

    /// The error when an argument or CLI flag violates a documented
    /// requirement (alignment, power-of-two sizes, conflicting flags, ...).
    #[error("{0}")]
    InvalidParameter(String),

    /// The error when an offset, range, or size computation overflows.
    #[error("{0}")]
    Overflow(String),

    /// The error when a path, blob, or job cannot be found.
    #[error("{0}")]
    NotFound(String),

    /// The error when a feature, type, or version is not supported.
    #[error("{0}")]
    Unsupported(String),

    /// The error when a storage backend or remote endpoint misbehaves.
    #[error("{0}")]
    Backend(String),

    /// The error when a wire protocol message is malformed (UFFD, NBD,
    /// fanotify event payloads).
    #[error("{0}")]
    Protocol(String),

    /// The error when runtime plumbing fails (thread panicked, channel
    /// closed, socket reader exited, event queue overflow).
    #[error("{0}")]
    Runtime(String),

    /// The error wrapped with additional context by [`Context`]. Display
    /// prints only the context; the wrapped error stays reachable through
    /// `source()`, and print edges use [`Error::report`] for the full chain.
    #[error("{context}")]
    Context {
        /// Human-readable description of the failed operation.
        context: String,
        /// The underlying error.
        source: Box<Error>,
    },
}

impl Error {
    /// Wraps this error with additional context, mirroring
    /// [`Context::context`] for already-materialized errors.
    pub fn context<C: fmt::Display>(self, context: C) -> Self {
        Error::Context {
            context: context.to_string(),
            source: Box::new(self),
        }
    }

    /// Returns the underlying [`io::Error`] beneath any [`Error::Context`]
    /// wrappers, if this error started as an IO failure. Service edges use
    /// this to recover the OS errno.
    pub fn io_error(&self) -> Option<&io::Error> {
        let mut err = self;
        loop {
            match err {
                Error::Io(io_err) => return Some(io_err),
                Error::Context { source, .. } => err = source,
                _ => return None,
            }
        }
    }

    /// Returns an adapter that prints this error and every `source()` beneath
    /// it as one `": "`-separated line, like `std::error::Report`.
    ///
    /// `Display` on [`Error`] prints only the outermost layer, so a plain
    /// `{err}` in a log line silently drops the cause chain — print edges
    /// format errors as `err.report()` instead.
    pub fn report(&self) -> impl fmt::Display + '_ {
        struct Report<'a>(&'a Error);

        impl fmt::Display for Report<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                use std::error::Error as _;

                write!(f, "{}", self.0)?;
                let mut source = self.0.source();
                while let Some(cause) = source {
                    write!(f, ": {cause}")?;
                    source = cause.source();
                }
                Ok(())
            }
        }

        Report(self)
    }
}

/// Converts a format-layer error into the project-wide error, so control-plane
/// code crosses the boundary with a plain `?`. Each variant maps to its
/// project-wide counterpart and `Context` chains are rebuilt recursively, so
/// the printed chain text is unchanged. The data plane never uses this: it
/// wraps [`nydus_format::Error`] into `io::Error` instead.
impl From<nydus_format::Error> for Error {
    fn from(err: nydus_format::Error) -> Self {
        use nydus_format::Error as FormatError;
        match err {
            FormatError::Io(source) => Error::Io(source),
            FormatError::InvalidImage(msg) => Error::InvalidImage(msg),
            FormatError::InvalidParameter(msg) => Error::InvalidParameter(msg),
            FormatError::Overflow(msg) => Error::Overflow(msg),
            FormatError::Unsupported(msg) => Error::Unsupported(msg),
            FormatError::Context { context, source } => Error::from(*source).context(context),
            other => Error::InvalidImage(other.to_string()),
        }
    }
}

mod private {
    /// Seals [`Context`](super::Context) so new methods can be added without
    /// a semver break; the blanket impl below is the only one intended. The
    /// `Into<Error>` bound mirrors the `Context` impl exactly, so no other
    /// impl is possible outside this crate.
    pub trait Sealed {}

    impl<T, E: Into<super::Error>> Sealed for std::result::Result<T, E> {}
}

/// Extension trait that wraps an error with context, keeping the original
/// error as the source of the returned [`Error::Context`].
///
/// Sealed: implemented for `Result<T, E>` where `E: Into<Error>` and not
/// implementable outside this crate.
pub trait Context<T>: private::Sealed {
    /// Wraps the error with `context`.
    fn context<C: fmt::Display>(self, context: C) -> Result<T>;

    /// Wraps the error with the context computed by `f`, evaluated only on
    /// the error path. Use this when building the message is not free
    /// (e.g. `format!`).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_prints_only_the_outermost_layer() {
        let root: Result<()> = Err(io::Error::other("inner error").into());
        let err = root
            .context("failed to open blob")
            .context("mount failed")
            .unwrap_err();
        assert_eq!(err.to_string(), "mount failed");
    }

    #[test]
    fn report_prints_the_context_chain() {
        let root: Result<()> = Err(io::Error::other("inner error").into());
        let err = root
            .context("failed to open blob")
            .context("mount failed")
            .unwrap_err();
        assert_eq!(
            err.report().to_string(),
            "mount failed: failed to open blob: inner error"
        );
    }

    #[test]
    fn report_on_an_unwrapped_error_prints_a_single_message() {
        let err = Error::InvalidImage("bad superblock".to_string());
        assert_eq!(err.report().to_string(), "bad superblock");
    }

    #[test]
    fn with_context_is_lazy_on_the_ok_path() {
        let mut called = false;
        let ok: Result<u32> = Ok(7);
        let value = ok
            .with_context(|| {
                called = true;
                "must not run on the ok path"
            })
            .unwrap();
        assert_eq!(value, 7);
        assert!(!called);
    }

    #[test]
    fn io_error_is_recovered_through_context_wrappers() {
        let root: Result<()> = Err(io::Error::from_raw_os_error(libc::ENOENT).into());
        let err = root.context("failed to stat mountpoint").unwrap_err();
        assert_eq!(
            err.io_error().and_then(|io_err| io_err.raw_os_error()),
            Some(libc::ENOENT)
        );

        let err = Error::InvalidImage("bad superblock".to_string());
        assert!(err.io_error().is_none());
    }

    #[test]
    fn source_chain_is_preserved() {
        let err: Error = io::Error::other("inner error").into();
        let err = Err::<(), _>(err).context("outer context").unwrap_err();
        let source = std::error::Error::source(&err).expect("context must keep its source");
        assert_eq!(source.to_string(), "inner error");
    }
}
