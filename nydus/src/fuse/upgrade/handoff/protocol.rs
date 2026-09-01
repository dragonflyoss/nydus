use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::identity::InstanceInfo;

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::fuse::upgrade) enum Request {
    Info {},
    HandoffBegin { peer: InstanceInfo },
    Ready {},
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Response {
    Info {
        info: InstanceInfo,
        session_id: Option<Uuid>,
    },
    HandoffTransfer {},
    Abort {
        message: String,
    },
    Error {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cutover_messages_use_ready_and_abort_wire_names() {
        assert_eq!(
            serde_json::to_value(Request::Ready {}).unwrap()["type"],
            "ready"
        );
        assert_eq!(
            serde_json::to_value(Response::Abort {
                message: "stop".to_string(),
            })
            .unwrap()["type"],
            "abort"
        );
    }
}
