use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use nydus_error::{Context, Error, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::peer::authenticate_peer;
use super::wire::{connect_until, read_frame_until, write_frame_until, ProtocolDeadline, Transfer};

const HOLDER_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Fetch {},
    Retain { session_id: Uuid },
    Release { session_id: Uuid },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Response {
    Empty {},
    Transfer {},
    Retained {},
    Released {},
    Error { message: String },
}

fn connect(path: &Path, deadline: ProtocolDeadline) -> Result<UnixStream> {
    let stream = connect_until(path, deadline).with_context(|| {
        format!(
            "failed to connect Recovery Holder socket {}",
            path.display()
        )
    })?;
    authenticate_peer(&stream).with_context(|| {
        format!(
            "failed to authenticate Recovery Holder socket {}",
            path.display()
        )
    })?;
    Ok(stream)
}

/// Retains `session_id`'s prepared resource bundle; success requires an explicit
/// acknowledgement.
pub(crate) fn retain(path: &Path, session_id: Uuid, transfer: &Transfer) -> Result<()> {
    let deadline = ProtocolDeadline::after(HOLDER_TIMEOUT, "Recovery Holder transaction");
    let mut stream = connect(path, deadline)?;
    write_frame_until(&mut stream, deadline, &Command::Retain { session_id })?;
    transfer.send(&mut stream, deadline)?;
    match read_frame_until(&mut stream, deadline)? {
        Some(Response::Retained {}) => Ok(()),
        Some(Response::Error { message }) => Err(Error::Runtime(format!(
            "Recovery Holder rejected Session Transfer: {message}"
        ))),
        Some(response) => Err(Error::Protocol(format!(
            "unexpected Recovery Holder retention response: {response:?}"
        ))),
        None => Err(Error::Protocol(
            "Recovery Holder closed before acknowledging Session Transfer retention".into(),
        )),
    }
}

/// Drops `session_id`'s retained bundle. An empty Holder also acknowledges, so a
/// retry is safe; a Holder retaining another session refuses.
pub(crate) fn release(path: &Path, session_id: Uuid) -> Result<()> {
    let deadline = ProtocolDeadline::after(HOLDER_TIMEOUT, "Recovery Holder transaction");
    let mut stream = connect(path, deadline)?;
    write_frame_until(&mut stream, deadline, &Command::Release { session_id })?;
    match read_frame_until(&mut stream, deadline)? {
        Some(Response::Released {}) => Ok(()),
        Some(Response::Error { message }) => Err(Error::Runtime(format!(
            "Recovery Holder rejected session release: {message}"
        ))),
        Some(response) => Err(Error::Protocol(format!(
            "unexpected Recovery Holder release response: {response:?}"
        ))),
        None => Err(Error::Protocol(
            "Recovery Holder closed before acknowledging session release".into(),
        )),
    }
}

/// Fetches descriptor copies without consuming the Holder's originals.
/// Only an explicit `empty` response returns `None`; the frontend validates the bundle.
pub(crate) fn fetch(path: &Path) -> Result<Option<Transfer>> {
    let deadline = ProtocolDeadline::after(HOLDER_TIMEOUT, "Recovery Holder transaction");
    let mut stream = connect(path, deadline)?;
    write_frame_until(&mut stream, deadline, &Command::Fetch {})?;
    match read_frame_until(&mut stream, deadline)? {
        Some(Response::Empty {}) => Ok(None),
        Some(Response::Transfer {}) => Transfer::receive(&mut stream, deadline)
            .map(Some)
            .context("failed to receive session transfer"),
        Some(Response::Error { message }) => Err(Error::Runtime(format!(
            "Recovery Holder rejected Session Transfer fetch: {message}"
        ))),
        Some(response) => Err(Error::Protocol(format!(
            "unexpected Recovery Holder fetch response: {response:?}"
        ))),
        None => Err(Error::Protocol(
            "Recovery Holder closed before responding to Session Transfer fetch".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;
    use crate::continuity::test_support::test_deadline;
    use crate::continuity::wire::write_raw_frame_until;

    fn exchange<T>(
        request: impl FnOnce(&Path) -> Result<T>,
        respond: impl FnOnce(&mut UnixStream) + Send + 'static,
    ) -> Result<T> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("holder.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let holder = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            respond(&mut stream);
        });
        let result = request(&path);
        holder.join().unwrap();
        result
    }

    #[test]
    fn fetch_distinguishes_empty_from_rejection_and_interruption() {
        for response in [
            None,
            Some(r#"{"type":"empty"}"#),
            Some(r#"{"type":"error","message":"unavailable"}"#),
            Some(r#"{"type":"retained"}"#),
            Some(r#"{"type":"unknown"}"#),
            Some(r#"{"type":"empty","unexpected":true}"#),
            Some(r#"{"type":"empty"#),
            Some(r#"{"type":"transfer"}"#),
        ] {
            let result = exchange(fetch, move |stream| {
                assert!(matches!(
                    read_frame_until(stream, test_deadline()).unwrap(),
                    Some(Command::Fetch {})
                ));
                if let Some(response) = response {
                    write_raw_frame_until(stream, test_deadline(), response.as_bytes()).unwrap();
                }
            });
            if response == Some(r#"{"type":"empty"}"#) {
                assert!(result.unwrap().is_none());
            } else {
                assert!(result.is_err(), "{response:?}");
            }
        }
        // Absent and unlistened sockets are interruptions, never `empty`.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("holder.sock");
        assert!(fetch(&path).is_err());
        drop(UnixListener::bind(&path).unwrap());
        assert!(fetch(&path).is_err());
    }

    #[test]
    fn retain_requires_acknowledgement_of_the_complete_bundle() {
        let transfer = Transfer {
            metadata: br#"{"opaque":true}"#.to_vec(),
            fds: vec![
                tempfile::tempfile().unwrap().into(),
                tempfile::tempfile().unwrap().into(),
            ],
        };
        for response in [
            Some(Response::Retained {}),
            Some(Response::Empty {}),
            Some(Response::Transfer {}),
            Some(Response::Error {
                message: "unavailable".into(),
            }),
            None,
        ] {
            let accepted = matches!(response, Some(Response::Retained {}));
            let result = exchange(
                |path| retain(path, Uuid::from_u128(1), &transfer),
                move |stream| {
                    assert!(matches!(
                        read_frame_until(stream, test_deadline()).unwrap(),
                        Some(Command::Retain { session_id }) if session_id == Uuid::from_u128(1)
                    ));
                    let received = Transfer::receive(stream, test_deadline()).unwrap();
                    assert_eq!(received.metadata, br#"{"opaque":true}"#);
                    if let Some(response) = response {
                        write_frame_until(stream, test_deadline(), &response).unwrap();
                    }
                },
            );
            assert_eq!(result.is_ok(), accepted);
        }
    }

    #[test]
    fn release_requires_an_explicit_acknowledgement() {
        for response in [
            Some(Response::Released {}),
            Some(Response::Retained {}),
            Some(Response::Error {
                message: "another session is retained".into(),
            }),
            None,
        ] {
            let accepted = matches!(response, Some(Response::Released {}));
            let result = exchange(
                |path| release(path, Uuid::from_u128(1)),
                move |stream| {
                    let request: serde_json::Value =
                        read_frame_until(stream, test_deadline()).unwrap().unwrap();
                    assert_eq!(
                        request,
                        serde_json::json!({"type":"release","session_id":Uuid::from_u128(1)})
                    );
                    if let Some(response) = response {
                        write_frame_until(stream, test_deadline(), &response).unwrap();
                    }
                },
            );
            assert_eq!(result.is_ok(), accepted);
        }
    }
}
