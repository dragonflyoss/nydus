//! NBD wire-protocol framing: a pure, kernel-independent parser and encoder.
//!
//! The layout mirrors the Network Block Device protocol: a 28-byte request
//! header (`magic | type | handle | offset | len`, all big-endian) and a
//! 16-byte reply header (`magic | error | handle`). This module only turns
//! bytes into typed [`Request`]s and typed replies back into bytes — no
//! syscalls, no sockets, no `/dev/nbdX` — so it is fully unit-tested
//! independently of kernel support, matching the split used by the fanotify
//! `event`/`response` modules.
//!
//! Keeping the framing here leaves [`super::service`] free to deal only with
//! the ioctl handshake, the socket pair, and the control loop.

/// Request magic. A header whose first four bytes differ is rejected with
/// [`ParseError::BadMagic`].
pub const NBD_REQUEST_MAGIC: u32 = 0x2560_9513;
/// Reply magic, written into every reply header.
pub const NBD_REPLY_MAGIC: u32 = 0x6744_6698;

/// Fixed request-header length in bytes.
pub const NBD_REQUEST_HEADER_SIZE: usize = 28;
/// Fixed reply-header length in bytes.
pub const NBD_REPLY_HEADER_SIZE: usize = 16;

/// `NBD_CMD_READ` — the only command a read-only daemon serves with data.
pub const NBD_CMD_READ: u32 = 0;
/// `NBD_CMD_WRITE` — never legitimate here (the device is read-only); it
/// carries a data payload, so the service drops the session rather than
/// replying and desyncing on the unconsumed payload.
pub const NBD_CMD_WRITE: u32 = 1;
/// `NBD_CMD_DISC` — the kernel is tearing down the session; the loop exits.
pub const NBD_CMD_DISC: u32 = 2;

/// Reply error code: success, data follows the header.
pub const NBD_OK: u32 = 0;
/// Reply error code: an I/O failure filled the buffer only partially.
pub const NBD_EIO: u32 = 5;
/// Reply error code: the request was malformed (bad alignment, bad type).
pub const NBD_EINVAL: u32 = 22;

/// Block size in bytes reported to the NBD driver and enforced as the
/// alignment unit for read offsets and lengths. Equals the EROFS block size,
/// so cache-fetch preconditions are always satisfied for a valid request.
pub const NBD_BLOCK_SIZE: u64 = nydus_format::erofs::EROFS_BLOCK_SIZE as u64;

/// Why a request header could not be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ParseError {
    /// The buffer is shorter than [`NBD_REQUEST_HEADER_SIZE`].
    #[error("request header is too short")]
    ShortBuffer,
    /// The magic field did not match [`NBD_REQUEST_MAGIC`].
    #[error("invalid request magic {got:#x}")]
    BadMagic { got: u32 },
}

/// A parsed NBD request header.
///
/// Field names mirror the protocol field names so the worker can log them
/// directly. The raw `ty` is preserved (rather than collapsed into an enum) so
/// an unsupported command can be reported by its numeric type, matching the
/// kernel's own diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request {
    pub ty: u32,
    pub handle: u64,
    pub offset: u64,
    pub len: u32,
}

impl Request {
    /// Parse a 28-byte request header, validating the magic. The fixed-size
    /// conversion up front enforces the length precondition and makes the
    /// per-field `try_into().unwrap()`s infallible.
    pub fn parse(header: &[u8]) -> Result<Self, ParseError> {
        let header: &[u8; NBD_REQUEST_HEADER_SIZE] =
            header.try_into().map_err(|_| ParseError::ShortBuffer)?;
        let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
        if magic != NBD_REQUEST_MAGIC {
            return Err(ParseError::BadMagic { got: magic });
        }
        Ok(Self {
            ty: u32::from_be_bytes(header[4..8].try_into().unwrap()),
            handle: u64::from_be_bytes(header[8..16].try_into().unwrap()),
            offset: u64::from_be_bytes(header[16..24].try_into().unwrap()),
            len: u32::from_be_bytes(header[24..28].try_into().unwrap()),
        })
    }

    /// True when this is a read command the daemon serves with data.
    pub fn is_read(&self) -> bool {
        self.ty == NBD_CMD_READ
    }

    /// True when the kernel signalled session disconnect.
    pub fn is_disc(&self) -> bool {
        self.ty == NBD_CMD_DISC
    }

    /// True when the offset and length are whole-block aligned, the
    /// precondition for [`super::core::NbdCore::read_at`].
    pub fn is_block_aligned(&self) -> bool {
        self.offset % NBD_BLOCK_SIZE == 0 && (self.len as u64) % NBD_BLOCK_SIZE == 0
    }
}

/// Encode a reply header (`magic | error | handle`) into a 16-byte array.
/// The caller writes any data payload immediately after.
pub fn encode_reply(code: u32, handle: u64) -> [u8; NBD_REPLY_HEADER_SIZE] {
    let mut out = [0u8; NBD_REPLY_HEADER_SIZE];
    out[0..4].copy_from_slice(&NBD_REPLY_MAGIC.to_be_bytes());
    out[4..8].copy_from_slice(&code.to_be_bytes());
    out[8..16].copy_from_slice(&handle.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_request(
        magic: u32,
        ty: u32,
        handle: u64,
        offset: u64,
        len: u32,
    ) -> [u8; NBD_REQUEST_HEADER_SIZE] {
        let mut buf = [0u8; NBD_REQUEST_HEADER_SIZE];
        buf[0..4].copy_from_slice(&magic.to_be_bytes());
        buf[4..8].copy_from_slice(&ty.to_be_bytes());
        buf[8..16].copy_from_slice(&handle.to_be_bytes());
        buf[16..24].copy_from_slice(&offset.to_be_bytes());
        buf[24..28].copy_from_slice(&len.to_be_bytes());
        buf
    }

    #[test]
    fn reply_header_is_well_formed() {
        // A reply header is 4-byte magic, 4-byte error, 8-byte handle.
        assert_eq!(NBD_REPLY_HEADER_SIZE, 16);
        assert_eq!(NBD_REPLY_MAGIC, 0x67446698);
    }

    #[test]
    fn parses_valid_read_request() {
        let buf = encode_request(NBD_REQUEST_MAGIC, NBD_CMD_READ, 0xDEADBEEF, 4096, 8192);
        let req = Request::parse(&buf).unwrap();
        assert_eq!(req.ty, NBD_CMD_READ);
        assert_eq!(req.handle, 0xDEADBEEF);
        assert_eq!(req.offset, 4096);
        assert_eq!(req.len, 8192);
        assert!(req.is_read());
        assert!(!req.is_disc());
        assert!(req.is_block_aligned());
    }

    #[test]
    fn detects_disconnect_command() {
        let buf = encode_request(NBD_REQUEST_MAGIC, NBD_CMD_DISC, 0, 0, 0);
        let req = Request::parse(&buf).unwrap();
        assert!(req.is_disc());
        assert!(!req.is_read());
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = encode_request(0xDEADBEEF, NBD_CMD_READ, 0, 0, 0);
        assert_eq!(
            Request::parse(&buf),
            Err(ParseError::BadMagic { got: 0xDEADBEEF })
        );
    }

    #[test]
    fn rejects_short_buffer() {
        let short = [0u8; NBD_REQUEST_HEADER_SIZE - 1];
        assert_eq!(Request::parse(&short), Err(ParseError::ShortBuffer));
    }

    #[test]
    fn flags_unaligned_read() {
        // offset 100 and len 50 are not 4096-aligned.
        let buf = encode_request(NBD_REQUEST_MAGIC, NBD_CMD_READ, 1, 100, 50);
        let req = Request::parse(&buf).unwrap();
        assert!(!req.is_block_aligned());
    }

    #[test]
    fn encode_reply_roundtrips_fields() {
        let out = encode_reply(NBD_EIO, 0x1234);
        assert_eq!(
            u32::from_be_bytes(out[0..4].try_into().unwrap()),
            NBD_REPLY_MAGIC
        );
        assert_eq!(u32::from_be_bytes(out[4..8].try_into().unwrap()), NBD_EIO);
        assert_eq!(u64::from_be_bytes(out[8..16].try_into().unwrap()), 0x1234);
    }
}
