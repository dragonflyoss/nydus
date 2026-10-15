//! The load-shedding policy of the registry's Dragonfly reads: what a read
//! does with the answer the SDK hands back once its own retries are spent.
//! An on-demand read falls back to the origin on any failure, a prefetch read
//! is deferred to the storage layer's delayed reschedule instead.

use super::response::Response;
use super::{RegistryError, RegistryResult};
use crate::ReadKind;

/// What a read does with the result of its Dragonfly request.
pub(super) enum Action {
    /// Hands the answer to the caller: a success, a redirect, the `401` auth
    /// handshake, or a definitive `4xx` such as `403` or `404` that no retry
    /// or fallback would change.
    Serve(Response),

    /// Gives up on Dragonfly and reads from the origin through the fallback
    /// throttle.
    Fallback(RegistryError),

    /// Fails the read without touching the origin, marked for the storage
    /// layer to reschedule the blob's prefetch hours later.
    Defer(RegistryError),
}

/// Implements the action.
impl Action {
    /// Decides what a read of `kind` does with the result of its Dragonfly
    /// request.
    ///
    /// A retryable answer is folded into its error first, a dfdaemon `507`
    /// among them since another seed peer may have room, while a dfdaemon
    /// `422` is definitive and served as is. Prefetch reads never touch the
    /// origin, so a Dragonfly outage degrades prefetch instead of flooding the
    /// registry, while on-demand reads fall back on every failure the SDK's
    /// retries did not cure.
    pub(super) async fn decide(kind: ReadKind, result: RegistryResult<Response>) -> Self {
        let err = match result {
            Ok(response) if response.is_retryable() => response.into_registry_error().await,
            Ok(response) => return Self::Serve(response),
            Err(err) => err,
        };

        match kind {
            ReadKind::Prefetch => Self::Defer(RegistryError::PrefetchDeferred(Box::new(err))),
            ReadKind::OnDemand => Self::Fallback(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Protocol;
    use reqwest::header::HeaderMap;
    use reqwest::StatusCode;
    use std::io;

    #[tokio::test]
    async fn decide_serves_definitive_answers_for_both_read_kinds() {
        let test_cases = vec![
            StatusCode::OK,
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::UNPROCESSABLE_ENTITY,
        ];

        for kind in [ReadKind::OnDemand, ReadKind::Prefetch] {
            for &status in &test_cases {
                let response = Response {
                    status,
                    headers: HeaderMap::new(),
                    reader: Box::new(io::Cursor::new(Vec::new())),
                    protocol: Protocol::Dragonfly,
                };
                assert!(
                    matches!(
                        Action::decide(kind, Ok(response)).await,
                        Action::Serve(served) if served.status == status
                    ),
                    "kind={kind:?} status={status}"
                );
            }
        }
    }

    #[tokio::test]
    async fn decide_defers_prefetch_and_falls_back_ondemand_on_failures() {
        let test_cases = vec![
            Some(StatusCode::TOO_MANY_REQUESTS),
            Some(StatusCode::SERVICE_UNAVAILABLE),
            Some(StatusCode::INSUFFICIENT_STORAGE),
            Some(StatusCode::REQUEST_TIMEOUT),
            None,
        ];

        for kind in [ReadKind::OnDemand, ReadKind::Prefetch] {
            for &status in &test_cases {
                let result = match status {
                    Some(status) => Ok(Response {
                        status,
                        headers: HeaderMap::new(),
                        reader: Box::new(io::Cursor::new(Vec::new())),
                        protocol: Protocol::Dragonfly,
                    }),
                    None => Err(RegistryError::Io(io::Error::other("connection reset"))),
                };
                let action = Action::decide(kind, result).await;
                match kind {
                    ReadKind::OnDemand => {
                        assert!(matches!(action, Action::Fallback(_)), "status={status:?}")
                    }
                    ReadKind::Prefetch => assert!(
                        matches!(action, Action::Defer(RegistryError::PrefetchDeferred(_))),
                        "status={status:?}"
                    ),
                }
            }
        }
    }
}
