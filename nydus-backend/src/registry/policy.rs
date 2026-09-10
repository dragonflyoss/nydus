//! The load-shedding policy of the registry's Dragonfly reads: what a read
//! does with the answer the SDK hands back once its own retries are spent.
//! An on-demand read falls back to the origin on any failure, a prefetch read
//! is deferred to the storage layer's delayed reschedule instead.

use reqwest::StatusCode;

use super::response::{status_error, Response};
use super::{RegistryError, RegistryResult};
use crate::ReadKind;

/// What a read does with the outcome of its Dragonfly request.
pub(super) enum Action {
    /// Hand the answer to the caller: a success, a redirect, the `401` auth
    /// handshake, or a definitive `4xx` such as `403` or `404` that no retry
    /// or fallback would change.
    Serve(Response),
    /// Give up on Dragonfly and read from the origin through the fallback
    /// throttle.
    Fallback(RegistryError),
    /// Fail the read without touching the origin, marked for the storage
    /// layer to reschedule the blob's prefetch hours later.
    Defer(RegistryError),
}

/// Fold a transient answer into its error: `429`, `5xx` and `408` become
/// [`RegistryError::UnexpectedStatus`], a dfdaemon `507` among them since
/// another seed peer may have room. Every other status passes through,
/// including a dfdaemon `422` that no retry or fallback would change.
pub(super) async fn classify(response: Response) -> RegistryResult<Response> {
    match response.status {
        status
            if status.is_server_error()
                || status == StatusCode::REQUEST_TIMEOUT
                || status == StatusCode::TOO_MANY_REQUESTS =>
        {
            Err(status_error(response).await)
        }
        _ => Ok(response),
    }
}

/// Decide what a read of `kind` does with the outcome of its Dragonfly
/// request. Prefetch reads never touch the origin, so a Dragonfly outage
/// degrades prefetch instead of flooding the registry, while on-demand reads
/// fall back on every failure the SDK's retries did not cure.
pub(super) async fn decide(kind: ReadKind, outcome: RegistryResult<Response>) -> Action {
    let outcome = match outcome {
        Ok(response) => classify(response).await,
        Err(err) => Err(err),
    };
    match outcome {
        Ok(response) => Action::Serve(response),
        Err(err) => match kind {
            ReadKind::Prefetch => Action::Defer(RegistryError::PrefetchDeferred(Box::new(err))),
            ReadKind::OnDemand => Action::Fallback(err),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::RUNTIME;
    use crate::Protocol;
    use reqwest::header::HeaderMap;
    use std::io;

    fn response(status: StatusCode) -> Response {
        Response {
            status,
            headers: HeaderMap::new(),
            reader: Box::new(std::io::Cursor::new(Vec::new())),
            protocol: Protocol::Dragonfly,
        }
    }

    fn transport_error() -> RegistryError {
        RegistryError::Io(io::Error::other("connection reset"))
    }

    #[test]
    fn classify_folds_transient_answers_into_errors() {
        for status in [
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::INSUFFICIENT_STORAGE,
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_MANY_REQUESTS,
        ] {
            assert!(
                matches!(
                    RUNTIME.block_on(classify(response(status))),
                    Err(RegistryError::UnexpectedStatus(got, _)) if got == status
                ),
                "status={status}"
            );
        }
        for status in [
            StatusCode::OK,
            StatusCode::PARTIAL_CONTENT,
            StatusCode::TEMPORARY_REDIRECT,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
            StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            assert_eq!(
                RUNTIME.block_on(classify(response(status))).unwrap().status,
                status
            );
        }
    }

    #[test]
    fn decide_serves_definitive_answers_for_both_read_kinds() {
        for kind in [ReadKind::OnDemand, ReadKind::Prefetch] {
            for status in [
                StatusCode::OK,
                StatusCode::TEMPORARY_REDIRECT,
                StatusCode::UNAUTHORIZED,
                StatusCode::FORBIDDEN,
                StatusCode::NOT_FOUND,
                StatusCode::UNPROCESSABLE_ENTITY,
            ] {
                assert!(
                    matches!(
                        RUNTIME.block_on(decide(kind, Ok(response(status)))),
                        Action::Serve(r) if r.status == status
                    ),
                    "kind={kind:?} status={status}"
                );
            }
        }
    }

    #[test]
    fn decide_defers_prefetch_and_falls_back_ondemand_on_failures() {
        let failures: [fn() -> RegistryResult<Response>; 5] = [
            || Ok(response(StatusCode::TOO_MANY_REQUESTS)),
            || Ok(response(StatusCode::SERVICE_UNAVAILABLE)),
            || Ok(response(StatusCode::INSUFFICIENT_STORAGE)),
            || Ok(response(StatusCode::REQUEST_TIMEOUT)),
            || Err(transport_error()),
        ];
        for failure in failures {
            assert!(matches!(
                RUNTIME.block_on(decide(ReadKind::Prefetch, failure())),
                Action::Defer(RegistryError::PrefetchDeferred(_))
            ));
            assert!(matches!(
                RUNTIME.block_on(decide(ReadKind::OnDemand, failure())),
                Action::Fallback(_)
            ));
        }
    }
}
