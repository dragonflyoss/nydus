//! Control frames exchanged after the HTTP upgrade.
//!
//! The envelope (`"type"` tag, snake_case variants, explicit `null` for an
//! absent `session_id`) is frozen: another nydus version parses it, and the
//! Go E2E harness implements it independently. Frontend-specific additions go
//! into the identity `I`, not here; an envelope change requires a new
//! `ControlProtocol` token.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request<I> {
    Info {},
    HandoffBegin { peer: I },
    Ready {},
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Response<I> {
    Info { info: I, session_id: Option<Uuid> },
    HandoffTransfer {},
    Committed {},
    Abort { message: String },
    Error { message: String },
    Released {},
}
