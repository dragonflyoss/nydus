//! Nydus-private blob sidecar formats.
//!
//! These are nydus's own on-disk formats layered next to the EROFS data —
//! the `.blob.meta` sidecar ([`meta`]) and the trailing blob footer
//! ([`footer`]) — not part of the EROFS metadata format itself.

pub mod footer;
pub mod meta;

pub use footer::*;
pub use meta::*;
