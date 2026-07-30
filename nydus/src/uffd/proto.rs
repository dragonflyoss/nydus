//! External userfaultfd backend protocol definitions.
//!
//! Wire format: 16-byte little-endian header followed by typed payload. File
//! descriptors are passed with SCM_RIGHTS and are not counted in payload length.

use std::io::{self, Write};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use crate::FdRange;
use anyhow::{anyhow, bail, Context, Result};
use sendfd::{RecvWithFd, SendWithFd};
use tokio::io::unix::AsyncFd;
use tracing::warn;

pub const UFFD_PROTOCOL_VERSION: u16 = 1;

pub const COMMAND_HANDSHAKE: u16 = 0x0a;
pub const COMMAND_ADD_REGION: u16 = 0x0b;
pub const COMMAND_REMOVE_REGION: u16 = 0x0c;

pub const COMMAND_STAT: u16 = 0x20;
pub const COMMAND_FETCH: u16 = 0x21;
pub const COMMAND_PROBE: u16 = 0x22;

pub const STATUS_OK: u16 = 1;
pub const STATUS_ERROR: u16 = 2;

pub const REPLY_LEGACY: u16 = 0;
pub const REPLY_FD_RANGES: u16 = 1;
pub const REPLY_STAT: u16 = 0x20;

pub const FD_RANGES_FLAG_MORE: u16 = 1 << 0;

pub const HANDSHAKE_FLAG_MANAGED: u8 = 1 << 0;
pub const HANDSHAKE_FLAG_PREFAULT: u8 = 1 << 1;
pub const HANDSHAKE_FLAG_ACK_REQUIRED: u8 = 1 << 2;
pub const HANDSHAKE_FLAG_BACKING_FDS: u8 = 1 << 3;

pub const UFFD_MODE_MISSING: u8 = 1 << 0;
pub const UFFD_MODE_WP: u8 = 1 << 1;
pub const UFFD_MODE_WP_ASYNC: u8 = 1 << 2;

pub const HEADER_SIZE: usize = 16;
pub const REGION_SIZE: usize = 48;
pub const RANGE_SIZE: usize = 24;
pub const FETCH_REQUEST_SIZE: usize = 16;
pub const STAT_RESPONSE_SIZE: usize = size_of::<u64>() + 2 * size_of::<u32>();

const MAX_RANGES_PER_MSG: usize = 16;
const MAX_RECV_FDS: usize = 64;
const MAX_PAYLOAD_SIZE: usize = 64 * 1024;

pub(crate) type Frame = (RequestHeader, Vec<u8>, Vec<OwnedFd>);

#[derive(Debug, Clone, Copy)]
pub struct RequestHeader {
    pub command: u16,
    pub command_headers: [u8; 6],
    pub len: u64,
}

impl RequestHeader {
    pub fn new(command: u16, payload_len: u64) -> Self {
        Self {
            command,
            command_headers: [0; 6],
            len: payload_len,
        }
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..2].copy_from_slice(&self.command.to_le_bytes());
        buf[2..8].copy_from_slice(&self.command_headers);
        buf[8..16].copy_from_slice(&self.len.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8; HEADER_SIZE]) -> Self {
        Self {
            command: u16::from_le_bytes(buf[0..2].try_into().unwrap()),
            command_headers: buf[2..8].try_into().unwrap(),
            len: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ResponseHeader {
    pub status: u16,
    pub reply_type: u16,
    pub reply_headers: [u8; 4],
    pub len: u64,
}

impl ResponseHeader {
    pub fn new(status: u16, reply_type: u16, payload_len: u64) -> Self {
        Self {
            status,
            reply_type,
            reply_headers: [0; 4],
            len: payload_len,
        }
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..2].copy_from_slice(&self.status.to_le_bytes());
        buf[2..4].copy_from_slice(&self.reply_type.to_le_bytes());
        buf[4..8].copy_from_slice(&self.reply_headers);
        buf[8..16].copy_from_slice(&self.len.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8; HEADER_SIZE]) -> Self {
        Self {
            status: u16::from_le_bytes(buf[0..2].try_into().unwrap()),
            reply_type: u16::from_le_bytes(buf[2..4].try_into().unwrap()),
            reply_headers: buf[4..8].try_into().unwrap(),
            len: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmaRegion {
    pub virt_addr: u64,
    pub size: u64,
    pub offset: u64,
    pub fault_size: u64,
    pub prot: i32,
    pub flags: i32,
    pub backing_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobRange {
    pub device_offset: u64,
    pub blob_offset: u64,
    pub len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRange {
    pub offset: u64,
    pub len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatResponse {
    pub size: u64,
    pub block_size: u32,
    pub flags: u32,
}

#[derive(Debug)]
pub enum Request {
    Handshake {
        flags: u8,
        regions: Vec<VmaRegion>,
        uffd: OwnedFd,
    },
    Stat,
    Fetch(DeviceRange),
    Probe,
}

pub type ResolvedRange = FdRange;

#[derive(Clone)]
pub struct ProtoConn {
    stream: Arc<AsyncFd<UnixStream>>,
}

impl ProtoConn {
    pub fn new(stream: UnixStream) -> Result<Self> {
        Ok(Self {
            stream: Arc::new(
                AsyncFd::new(stream)
                    .context("failed to register UFFD protocol socket with tokio")?,
            ),
        })
    }

    pub async fn recv(&self) -> Result<Option<Request>> {
        loop {
            let Some((header, payload, mut fds)) = self.recv_frame().await? else {
                return Ok(None);
            };
            let request = match header.command {
                COMMAND_HANDSHAKE => {
                    let version =
                        u16::from_le_bytes(header.command_headers[0..2].try_into().unwrap());
                    let flags = header.command_headers[2];
                    let region_count =
                        u16::from_le_bytes(header.command_headers[4..6].try_into().unwrap());
                    let regions = decode_handshake(region_count, &payload)
                        .ok_or_else(|| anyhow!("invalid HANDSHAKE payload"))?;
                    if version != UFFD_PROTOCOL_VERSION {
                        bail!("unsupported UFFD protocol version {version}");
                    }
                    let expected_fds = 1 + if flags & HANDSHAKE_FLAG_BACKING_FDS != 0 {
                        usize::from(region_count)
                    } else {
                        0
                    };
                    if fds.len() != expected_fds {
                        bail!(
                            "HANDSHAKE must carry {expected_fds} file descriptor(s), received {}",
                            fds.len()
                        );
                    }
                    Request::Handshake {
                        flags,
                        regions,
                        uffd: fds.remove(0),
                    }
                }
                COMMAND_STAT => {
                    validate_empty_request(&payload, &fds, "STAT")?;
                    Request::Stat
                }
                COMMAND_FETCH => {
                    validate_no_fds(&fds, "FETCH")?;
                    let request = decode_fetch_request(&payload)
                        .ok_or_else(|| anyhow!("invalid FETCH payload"))?;
                    Request::Fetch(DeviceRange {
                        offset: request.offset,
                        len: request.len,
                    })
                }
                COMMAND_PROBE => {
                    validate_empty_request(&payload, &fds, "PROBE")?;
                    Request::Probe
                }
                other => {
                    warn!("nydus uffd ignored command 0x{other:04x}");
                    continue;
                }
            };
            return Ok(Some(request));
        }
    }

    async fn recv_frame(&self) -> Result<Option<Frame>> {
        let mut header_buf = [0u8; HEADER_SIZE];
        let mut raw_fds = [0i32; MAX_RECV_FDS];
        let (read, fd_count) = recv_with_fd(&self.stream, &mut header_buf, &mut raw_fds).await?;
        let fds = raw_fds[..fd_count]
            .iter()
            .map(|fd| unsafe { OwnedFd::from_raw_fd(*fd) })
            .collect::<Vec<_>>();
        if read == 0 {
            return Ok(None);
        }
        if read < HEADER_SIZE {
            recv_exact(&self.stream, &mut header_buf[read..]).await?;
        }

        let header = RequestHeader::from_bytes(&header_buf);
        let payload_len = usize::try_from(header.len).context("invalid UFFD payload length")?;
        if payload_len > MAX_PAYLOAD_SIZE {
            bail!("UFFD payload length {payload_len} exceeds limit {MAX_PAYLOAD_SIZE}");
        }
        let mut payload = vec![0u8; payload_len];
        if !payload.is_empty() {
            recv_exact(&self.stream, &mut payload).await?;
        }
        Ok(Some((header, payload, fds)))
    }

    pub async fn send_ranges(&self, ranges: &[ResolvedRange]) -> Result<()> {
        if ranges.is_empty() {
            return send_with_fd(&self.stream, &encode_range_response(&[], false), &[]).await;
        }

        let mut chunks = ranges.chunks(MAX_RANGES_PER_MSG).peekable();
        while let Some(chunk) = chunks.next() {
            let wire_ranges = chunk
                .iter()
                .map(|range| (range.source_offset, range.offset, range.len))
                .collect::<Vec<_>>();
            let fds = chunk.iter().map(|range| range.fd).collect::<Vec<_>>();
            send_with_fd(
                &self.stream,
                &encode_range_response(&wire_ranges, chunks.peek().is_some()),
                &fds,
            )
            .await?;
        }
        Ok(())
    }

    pub async fn send_ack(&self) -> Result<()> {
        send_with_fd(&self.stream, &encode_ack_response(), &[]).await
    }

    pub async fn send_stat(&self, size: u64, block_size: u32, flags: u32) -> Result<()> {
        send_with_fd(
            &self.stream,
            &encode_stat_response(size, block_size, flags),
            &[],
        )
        .await
    }
}

pub fn encode_handshake(ver: u16, flags: u8, uffd_modes: u8, regions: &[VmaRegion]) -> Vec<u8> {
    let region_count = regions.len() as u16;
    let payload_len = regions.len() * REGION_SIZE;
    let mut header = RequestHeader::new(COMMAND_HANDSHAKE, payload_len as u64);
    header.command_headers[0..2].copy_from_slice(&ver.to_le_bytes());
    header.command_headers[2] = flags;
    header.command_headers[3] = uffd_modes;
    header.command_headers[4..6].copy_from_slice(&region_count.to_le_bytes());
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload_len);
    buf.extend_from_slice(&header.to_bytes());
    for r in regions {
        encode_region(&mut buf, r);
    }
    buf
}

fn encode_region(buf: &mut Vec<u8>, region: &VmaRegion) {
    buf.extend_from_slice(&region.virt_addr.to_le_bytes());
    buf.extend_from_slice(&region.size.to_le_bytes());
    buf.extend_from_slice(&region.offset.to_le_bytes());
    buf.extend_from_slice(&region.fault_size.to_le_bytes());
    buf.extend_from_slice(&region.prot.to_le_bytes());
    buf.extend_from_slice(&region.flags.to_le_bytes());
    buf.extend_from_slice(&region.backing_offset.to_le_bytes());
}

pub fn decode_handshake(region_count: u16, payload: &[u8]) -> Option<Vec<VmaRegion>> {
    let region_count = region_count as usize;
    let expected_len = region_count * REGION_SIZE;
    if payload.len() != expected_len {
        return None;
    }
    let mut regions = Vec::with_capacity(region_count);
    let mut off = 0;
    for _ in 0..region_count {
        regions.push(VmaRegion {
            virt_addr: u64::from_le_bytes(payload[off..off + 8].try_into().unwrap()),
            size: u64::from_le_bytes(payload[off + 8..off + 16].try_into().unwrap()),
            offset: u64::from_le_bytes(payload[off + 16..off + 24].try_into().unwrap()),
            fault_size: u64::from_le_bytes(payload[off + 24..off + 32].try_into().unwrap()),
            prot: i32::from_le_bytes(payload[off + 32..off + 36].try_into().unwrap()),
            flags: i32::from_le_bytes(payload[off + 36..off + 40].try_into().unwrap()),
            backing_offset: u64::from_le_bytes(payload[off + 40..off + 48].try_into().unwrap()),
        });
        off += REGION_SIZE;
    }
    Some(regions)
}

pub fn encode_ack_response() -> Vec<u8> {
    ResponseHeader::new(STATUS_OK, REPLY_LEGACY, 0)
        .to_bytes()
        .to_vec()
}

pub fn encode_range_response(ranges: &[(u64, u64, u64)], more: bool) -> Vec<u8> {
    let payload_len = ranges.len() * RANGE_SIZE;
    let mut header = ResponseHeader::new(STATUS_OK, REPLY_FD_RANGES, payload_len as u64);
    let flags = if more { FD_RANGES_FLAG_MORE } else { 0 };
    let fd_count = ranges.len() as u16;
    header.reply_headers[0..2].copy_from_slice(&flags.to_le_bytes());
    header.reply_headers[2..4].copy_from_slice(&fd_count.to_le_bytes());
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload_len);
    buf.extend_from_slice(&header.to_bytes());
    for &(device_offset, blob_offset, len) in ranges {
        buf.extend_from_slice(&device_offset.to_le_bytes());
        buf.extend_from_slice(&blob_offset.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
    }
    buf
}

pub fn decode_range_response(payload: &[u8]) -> Option<Vec<BlobRange>> {
    if !payload.len().is_multiple_of(RANGE_SIZE) {
        return None;
    }
    let mut ranges = Vec::with_capacity(payload.len() / RANGE_SIZE);
    for entry in payload.chunks_exact(RANGE_SIZE) {
        ranges.push(BlobRange {
            device_offset: u64::from_le_bytes(entry[0..8].try_into().unwrap()),
            blob_offset: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
            len: u64::from_le_bytes(entry[16..24].try_into().unwrap()),
        });
    }
    Some(ranges)
}

pub fn encode_stat_request() -> Vec<u8> {
    RequestHeader::new(COMMAND_STAT, 0).to_bytes().to_vec()
}

pub fn encode_stat_response(size: u64, block_size: u32, flags: u32) -> Vec<u8> {
    let header = ResponseHeader::new(STATUS_OK, REPLY_STAT, STAT_RESPONSE_SIZE as u64);
    let mut buf = Vec::with_capacity(HEADER_SIZE + STAT_RESPONSE_SIZE);
    buf.extend_from_slice(&header.to_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
    buf.extend_from_slice(&block_size.to_le_bytes());
    buf.extend_from_slice(&flags.to_le_bytes());
    buf
}

pub fn decode_stat_response(payload: &[u8]) -> Option<StatResponse> {
    if payload.len() != STAT_RESPONSE_SIZE {
        return None;
    }
    Some(StatResponse {
        size: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        block_size: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
        flags: u32::from_le_bytes(payload[12..16].try_into().unwrap()),
    })
}

pub fn encode_fetch_request(offset: u64, len: u64) -> Vec<u8> {
    encode_range_request(COMMAND_FETCH, offset, len)
}

fn encode_range_request(command: u16, offset: u64, len: u64) -> Vec<u8> {
    let header = RequestHeader::new(command, FETCH_REQUEST_SIZE as u64);
    let mut buf = Vec::with_capacity(HEADER_SIZE + FETCH_REQUEST_SIZE);
    buf.extend_from_slice(&header.to_bytes());
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(&len.to_le_bytes());
    buf
}

pub fn decode_fetch_request(payload: &[u8]) -> Option<DeviceRange> {
    if payload.len() != FETCH_REQUEST_SIZE {
        return None;
    }
    Some(DeviceRange {
        offset: u64::from_le_bytes(payload[0..8].try_into().unwrap()),
        len: u64::from_le_bytes(payload[8..16].try_into().unwrap()),
    })
}

pub fn encode_probe_request() -> Vec<u8> {
    RequestHeader::new(COMMAND_PROBE, 0).to_bytes().to_vec()
}

fn validate_no_fds(fds: &[OwnedFd], name: &str) -> Result<()> {
    if !fds.is_empty() {
        bail!("{name} request must not carry file descriptors");
    }
    Ok(())
}

fn validate_empty_request(payload: &[u8], fds: &[OwnedFd], name: &str) -> Result<()> {
    validate_no_fds(fds, name)?;
    if !payload.is_empty() {
        bail!("{name} request must have an empty payload");
    }
    Ok(())
}

async fn recv_with_fd(
    stream: &AsyncFd<UnixStream>,
    buf: &mut [u8],
    fds: &mut [RawFd],
) -> Result<(usize, usize)> {
    loop {
        let mut guard = stream
            .readable()
            .await
            .context("failed to wait for UFFD protocol socket readability")?;
        match stream.get_ref().recv_with_fd(buf, fds) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
            result => return result.context("recv_with_fd failed"),
        }
    }
}

async fn recv_exact(stream: &AsyncFd<UnixStream>, buf: &mut [u8]) -> Result<()> {
    let fd = stream.get_ref().as_raw_fd();
    let mut offset = 0;
    while offset < buf.len() {
        let mut guard = stream
            .readable()
            .await
            .context("failed to wait for UFFD protocol socket readability")?;
        let read = unsafe {
            libc::recv(
                fd,
                buf[offset..].as_mut_ptr() as *mut libc::c_void,
                buf.len() - offset,
                0,
            )
        };
        if read < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                guard.clear_ready();
                continue;
            }
            return Err(err).context("recv failed");
        }
        if read == 0 {
            bail!("peer closed while reading UFFD protocol message");
        }
        offset += read as usize;
    }
    Ok(())
}

async fn send_with_fd(stream: &AsyncFd<UnixStream>, data: &[u8], fds: &[RawFd]) -> Result<()> {
    let mut sent = 0;
    while sent < data.len() {
        let mut guard = stream
            .writable()
            .await
            .context("failed to wait for UFFD protocol socket writability")?;
        let result = if sent == 0 {
            stream.get_ref().send_with_fd(data, fds)
        } else {
            let mut socket = stream.get_ref();
            socket.write(&data[sent..])
        };
        match result {
            Ok(0) => bail!("short send_with_fd"),
            Ok(written) => sent += written,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => guard.clear_ready(),
            Err(err) => return Err(err).context("send_with_fd failed"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;

    use super::*;

    fn proto_pair() -> (ProtoConn, UnixStream) {
        let (server, client) = UnixStream::pair().unwrap();
        server.set_nonblocking(true).unwrap();
        (ProtoConn::new(server).unwrap(), client)
    }

    #[test]
    fn protocol_number_layout() {
        assert_eq!(COMMAND_HANDSHAKE, 0x0a);
        assert_eq!(COMMAND_ADD_REGION, 0x0b);
        assert_eq!(COMMAND_REMOVE_REGION, 0x0c);
        assert_eq!(COMMAND_STAT, 0x20);
        assert_eq!(COMMAND_FETCH, 0x21);
        assert_eq!(COMMAND_PROBE, 0x22);

        assert_eq!(REPLY_LEGACY, 0);
        assert_eq!(REPLY_FD_RANGES, 1);
        assert_eq!(REPLY_STAT, 0x20);
    }

    #[test]
    fn ack_response_wire_layout() {
        let buf = encode_ack_response();
        let header = ResponseHeader::from_bytes(&buf.try_into().unwrap());
        assert_eq!(header.status, STATUS_OK);
        assert_eq!(header.reply_type, REPLY_LEGACY);
        assert_eq!(header.reply_headers, [0; 4]);
        assert_eq!(header.len, 0);
    }

    #[test]
    fn range_response_roundtrip() {
        let buf = encode_range_response(&[(0, 4096, 8192)], false);
        let hdr = ResponseHeader::from_bytes(&buf[..HEADER_SIZE].try_into().unwrap());
        assert_eq!(hdr.status, STATUS_OK);
        assert_eq!(hdr.reply_type, REPLY_FD_RANGES);
        let flags = u16::from_le_bytes(hdr.reply_headers[0..2].try_into().unwrap());
        let fd_count = u16::from_le_bytes(hdr.reply_headers[2..4].try_into().unwrap());
        assert_eq!(flags, 0);
        assert_eq!(fd_count, 1);
        assert_eq!(hdr.len as usize, RANGE_SIZE);
        let ranges = decode_range_response(&buf[HEADER_SIZE..]).unwrap();
        assert_eq!(ranges[0].device_offset, 0);
        assert_eq!(ranges[0].blob_offset, 4096);
        assert_eq!(ranges[0].len, 8192);
    }

    #[test]
    fn stat_response_roundtrip() {
        let buf = encode_stat_response(0x20_0000, 4096, 1);
        let hdr = ResponseHeader::from_bytes(&buf[..HEADER_SIZE].try_into().unwrap());
        assert_eq!(hdr.status, STATUS_OK);
        assert_eq!(hdr.reply_type, REPLY_STAT);
        assert_eq!(hdr.reply_headers, [0; 4]);
        assert_eq!(hdr.len as usize, STAT_RESPONSE_SIZE);
        assert_eq!(
            decode_stat_response(&buf[HEADER_SIZE..]),
            Some(StatResponse {
                size: 0x20_0000,
                block_size: 4096,
                flags: 1,
            })
        );
    }

    #[test]
    fn fetch_request_roundtrip() {
        let buf = encode_fetch_request(0x1234_0000, 0x20_0000);
        let hdr = RequestHeader::from_bytes(&buf[..HEADER_SIZE].try_into().unwrap());
        assert_eq!(hdr.command, COMMAND_FETCH);
        assert_eq!(hdr.command_headers, [0; 6]);
        assert_eq!(hdr.len as usize, FETCH_REQUEST_SIZE);
        assert_eq!(
            decode_fetch_request(&buf[HEADER_SIZE..]),
            Some(DeviceRange {
                offset: 0x1234_0000,
                len: 0x20_0000,
            })
        );
        assert_eq!(decode_fetch_request(&buf[HEADER_SIZE..buf.len() - 1]), None);
    }

    #[tokio::test]
    async fn proto_conn_decodes_typed_requests() {
        let (proto, client) = proto_pair();
        client.send_with_fd(&encode_stat_request(), &[]).unwrap();
        assert!(matches!(proto.recv().await.unwrap(), Some(Request::Stat)));

        client
            .send_with_fd(&encode_fetch_request(0x4000, 0x8000), &[])
            .unwrap();
        assert!(matches!(
            proto.recv().await.unwrap(),
            Some(Request::Fetch(DeviceRange {
                offset: 0x4000,
                len: 0x8000
            }))
        ));

        client.send_with_fd(&encode_probe_request(), &[]).unwrap();
        assert!(matches!(proto.recv().await.unwrap(), Some(Request::Probe)));
    }

    #[tokio::test]
    async fn proto_conn_owns_handshake_fd() {
        let (proto, client) = proto_pair();
        let file = File::open("/dev/null").unwrap();
        let region = VmaRegion {
            virt_addr: 0x1000,
            size: 0x2000,
            offset: 0x3000,
            fault_size: 0x1000,
            prot: 1,
            flags: 2,
            backing_offset: 0x4000,
        };
        let backing = File::open("/dev/zero").unwrap();
        let flags = HANDSHAKE_FLAG_MANAGED | HANDSHAKE_FLAG_PREFAULT | HANDSHAKE_FLAG_ACK_REQUIRED;
        let mut handshake = encode_handshake(
            UFFD_PROTOCOL_VERSION,
            flags,
            UFFD_MODE_MISSING,
            std::slice::from_ref(&region),
        );
        handshake[4] |= HANDSHAKE_FLAG_BACKING_FDS | (1 << 7);
        handshake[5] |= 1 << 7;
        let header = RequestHeader::from_bytes(&handshake[..HEADER_SIZE].try_into().unwrap());
        assert_eq!(header.command, COMMAND_HANDSHAKE);
        assert_eq!(
            header.command_headers[2] & HANDSHAKE_FLAG_MANAGED,
            HANDSHAKE_FLAG_MANAGED
        );
        assert_eq!(
            header.command_headers[2] & HANDSHAKE_FLAG_ACK_REQUIRED,
            HANDSHAKE_FLAG_ACK_REQUIRED
        );
        assert_eq!(
            header.command_headers[3] & UFFD_MODE_MISSING,
            UFFD_MODE_MISSING
        );
        assert_eq!(header.len as usize, REGION_SIZE);
        client
            .send_with_fd(&handshake, &[file.as_raw_fd(), backing.as_raw_fd()])
            .unwrap();
        drop(file);
        drop(backing);

        let Some(Request::Handshake {
            flags,
            regions,
            uffd,
        }) = proto.recv().await.unwrap()
        else {
            panic!("expected HANDSHAKE request");
        };
        assert_eq!(flags & HANDSHAKE_FLAG_MANAGED, HANDSHAKE_FLAG_MANAGED);
        assert_eq!(flags & HANDSHAKE_FLAG_PREFAULT, HANDSHAKE_FLAG_PREFAULT);
        assert_eq!(
            flags & HANDSHAKE_FLAG_ACK_REQUIRED,
            HANDSHAKE_FLAG_ACK_REQUIRED
        );
        assert_eq!(regions, vec![region]);
        assert!(unsafe { libc::fcntl(uffd.as_raw_fd(), libc::F_GETFD) } >= 0);
    }

    #[tokio::test]
    async fn proto_conn_rejects_invalid_handshake_fd_counts() {
        let handshake = encode_handshake(UFFD_PROTOCOL_VERSION, 0, UFFD_MODE_MISSING, &[]);

        let (proto, client) = proto_pair();
        client.send_with_fd(&handshake, &[]).unwrap();
        let err = proto.recv().await.unwrap_err();
        assert!(format!("{err:#}").contains("must carry 1 file descriptor(s), received 0"));

        let (proto, client) = proto_pair();
        let first = File::open("/dev/null").unwrap();
        let second = File::open("/dev/null").unwrap();
        client
            .send_with_fd(&handshake, &[first.as_raw_fd(), second.as_raw_fd()])
            .unwrap();
        let err = proto.recv().await.unwrap_err();
        assert!(format!("{err:#}").contains("must carry 1 file descriptor(s), received 2"));
    }

    #[tokio::test]
    async fn proto_conn_supports_concurrent_receive_and_send() {
        let (proto, mut client) = proto_pair();
        let receiver = proto.clone();
        let receive_task = tokio::spawn(async move { receiver.recv().await });
        tokio::task::yield_now().await;

        proto.send_stat(0x20_0000, 4096, 0).await.unwrap();
        let mut header_buf = [0u8; HEADER_SIZE];
        let mut raw_fds = [0i32; MAX_RECV_FDS];
        let (read, fd_count) = client.recv_with_fd(&mut header_buf, &mut raw_fds).unwrap();
        assert_eq!(read, HEADER_SIZE);
        assert_eq!(fd_count, 0);
        let header = ResponseHeader::from_bytes(&header_buf);
        assert_eq!(header.reply_type, REPLY_STAT);
        let mut payload = vec![0u8; header.len as usize];
        client.read_exact(&mut payload).unwrap();
        assert_eq!(decode_stat_response(&payload).unwrap().size, 0x20_0000);

        client.send_with_fd(&encode_stat_request(), &[]).unwrap();
        assert!(matches!(
            receive_task.await.unwrap().unwrap(),
            Some(Request::Stat)
        ));
    }

    #[tokio::test]
    async fn proto_conn_rejects_oversized_payload() {
        let (proto, client) = proto_pair();
        let header = RequestHeader::new(COMMAND_FETCH, (MAX_PAYLOAD_SIZE + 1) as u64);
        client.send_with_fd(&header.to_bytes(), &[]).unwrap();
        let err = proto.recv().await.unwrap_err();
        assert!(format!("{err:#}").contains("exceeds limit"));
    }

    #[tokio::test]
    async fn proto_conn_rejects_unexpected_fds() {
        let (proto, client) = proto_pair();
        let file = File::open("/dev/null").unwrap();
        client
            .send_with_fd(&encode_stat_request(), &[file.as_raw_fd()])
            .unwrap();
        let err = proto.recv().await.unwrap_err();
        assert!(format!("{err:#}").contains("must not carry file descriptors"));
    }

    #[tokio::test]
    async fn proto_conn_batches_ranges_with_matching_fds() {
        let (proto, mut client) = proto_pair();
        let file = File::open("/dev/zero").unwrap();
        let ranges = (0..17)
            .map(|index| ResolvedRange {
                fd: file.as_raw_fd(),
                offset: index * 4096,
                len: 4096,
                source_offset: index * 4096,
            })
            .collect::<Vec<_>>();
        proto.send_ranges(&ranges).await.unwrap();

        for (expected_count, expected_flags) in [(16, FD_RANGES_FLAG_MORE), (1, 0)] {
            let mut header_buf = [0u8; HEADER_SIZE];
            let mut raw_fds = [0i32; MAX_RECV_FDS];
            let (read, fd_count) = client.recv_with_fd(&mut header_buf, &mut raw_fds).unwrap();
            assert_eq!(read, HEADER_SIZE);
            assert_eq!(fd_count, expected_count);
            let received_fds = raw_fds[..fd_count]
                .iter()
                .map(|fd| unsafe { OwnedFd::from_raw_fd(*fd) })
                .collect::<Vec<_>>();
            let header = ResponseHeader::from_bytes(&header_buf);
            assert_eq!(header.reply_type, REPLY_FD_RANGES);
            let flags = u16::from_le_bytes(header.reply_headers[0..2].try_into().unwrap());
            let fd_count = u16::from_le_bytes(header.reply_headers[2..4].try_into().unwrap());
            assert_eq!(flags, expected_flags);
            assert_eq!(fd_count as usize, expected_count);
            let mut payload = vec![0u8; header.len as usize];
            client.read_exact(&mut payload).unwrap();
            assert_eq!(
                decode_range_response(&payload).unwrap().len(),
                expected_count
            );
            assert_eq!(received_fds.len(), expected_count);
        }
    }

    #[tokio::test]
    async fn proto_conn_sends_final_empty_range_batch() {
        let (proto, mut client) = proto_pair();
        proto.send_ranges(&[]).await.unwrap();

        let mut header_buf = [0u8; HEADER_SIZE];
        let mut raw_fds = [0i32; MAX_RECV_FDS];
        let (read, fd_count) = client.recv_with_fd(&mut header_buf, &mut raw_fds).unwrap();
        assert_eq!(read, HEADER_SIZE);
        assert_eq!(fd_count, 0);
        let header = ResponseHeader::from_bytes(&header_buf);
        assert_eq!(header.reply_type, REPLY_FD_RANGES);
        let flags = u16::from_le_bytes(header.reply_headers[0..2].try_into().unwrap());
        let fd_count = u16::from_le_bytes(header.reply_headers[2..4].try_into().unwrap());
        assert_eq!(flags, 0);
        assert_eq!(fd_count, 0);
        let mut payload = vec![0u8; header.len as usize];
        client.read_exact(&mut payload).unwrap();
        assert!(decode_range_response(&payload).unwrap().is_empty());
    }
}
