use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::fuse) struct FuseInitState {
    pub(in crate::fuse) proto_major: u32,
    pub(in crate::fuse) proto_minor: u32,
    pub(in crate::fuse) negotiated_init_flags: u64,
    pub(in crate::fuse) kernel_init_flags: u64,
}

impl FuseInitState {
    pub(super) fn validate(&self) -> std::result::Result<(), String> {
        if self.proto_major != 7 || self.proto_minor < 6 {
            return Err(format!(
                "fuse continuity state has unsupported FUSE protocol version {}.{}",
                self.proto_major, self.proto_minor
            ));
        }
        if self.negotiated_init_flags & !self.kernel_init_flags != 0 {
            return Err(
                "fuse continuity state negotiated FUSE flags absent from kernel capabilities"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_state() -> FuseInitState {
        FuseInitState {
            proto_major: 7,
            proto_minor: 31,
            negotiated_init_flags: 0,
            kernel_init_flags: 0,
        }
    }

    #[test]
    fn session_state_accepts_a_negotiated_session_and_rejects_incompatible_fuse_state() {
        assert!(session_state().validate().is_ok());

        let mut unsupported_major = session_state();
        unsupported_major.proto_major = 8;
        assert!(unsupported_major.validate().is_err());

        let mut unsupported_minor = session_state();
        unsupported_minor.proto_minor = 5;
        assert!(unsupported_minor.validate().is_err());

        let mut unsupported_flags = session_state();
        unsupported_flags.negotiated_init_flags = 0b10;
        unsupported_flags.kernel_init_flags = 0b01;
        assert!(unsupported_flags.validate().is_err());
    }
}
