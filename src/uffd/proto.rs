//! Nydus-compatible binary UFFD protocol definitions.
//!
//! Wire format: 20-byte little-endian header followed by typed payload. File
//! descriptors are passed with SCM_RIGHTS and are not counted in payload length.

use std::io::{self, Write};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use sendfd::{RecvWithFd, SendWithFd};
use tokio::io::unix::AsyncFd;
use tracing::warn;

pub const UFFD_MAGIC: u32 = 0x5546_4644;
pub const UFFD_PROTOCOL_VERSION: u16 = 1;

pub const MSG_HANDSHAKE: u16 = 0x01;
pub const MSG_STAT_REQUEST: u16 = 0x02;
pub const MSG_FETCH_REQUEST: u16 = 0x03;
pub const MSG_PROBE_REQUEST: u16 = 0x04;

pub const MSG_PAGE_RESPONSE: u16 = 0x81;
pub const MSG_STAT_RESPONSE: u16 = 0x82;

pub const PAGE_RESPONSE_FLAG_NEXT: u16 = 1 << 0;

pub const HANDSHAKE_FLAG_COPY: u8 = 0x01;
pub const HANDSHAKE_FLAG_PREFAULT: u8 = 0x02;

pub const HEADER_SIZE: usize = 20;
pub const REGION_SIZE: usize = 40;
pub const RANGE_SIZE: usize = 24;
pub const FETCH_REQUEST_SIZE: usize = 16;
pub const STAT_RESPONSE_SIZE: usize = size_of::<u64>() + 2 * size_of::<u32>();

const HANDSHAKE_PREFIX_SIZE: usize = size_of::<u16>() + 2 * size_of::<u8>();
const RANGE_COUNT_SIZE: usize = size_of::<u32>();
const MAX_RANGES_PER_MSG: usize = 16;
const MAX_RECV_FDS: usize = 32;
const MAX_PAYLOAD_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub magic: u32,
    pub flags: u16,
    pub msg_type: u16,
    pub cookie: u64,
    pub len: u32,
}

impl Header {
    pub fn new(msg_type: u16, payload_len: u32) -> Self {
        Self {
            magic: UFFD_MAGIC,
            flags: 0,
            msg_type,
            cookie: 0,
            len: payload_len,
        }
    }

    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.flags.to_le_bytes());
        buf[6..8].copy_from_slice(&self.msg_type.to_le_bytes());
        buf[8..16].copy_from_slice(&self.cookie.to_le_bytes());
        buf[16..20].copy_from_slice(&self.len.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8; HEADER_SIZE]) -> Self {
        Self {
            magic: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            flags: u16::from_le_bytes(buf[4..6].try_into().unwrap()),
            msg_type: u16::from_le_bytes(buf[6..8].try_into().unwrap()),
            cookie: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            len: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum FaultPolicy {
    #[default]
    Zerocopy = 0,
    Copy = 1,
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq)]
pub struct VmaRegion {
    pub base_host_virt_addr: u64,
    pub size: u64,
    pub offset: u64,
    pub page_size: u64,
    pub prot: i32,
    pub flags: i32,
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
        policy: FaultPolicy,
        prefault: bool,
        regions: Vec<VmaRegion>,
        uffd: OwnedFd,
    },
    Stat,
    Fetch(DeviceRange),
    Probe,
}

#[derive(Clone, Copy, Debug)]
pub struct ResolvedRange {
    pub fd: RawFd,
    pub device_offset: u64,
    pub file_offset: u64,
    pub len: u64,
}

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
            let Some((msg_type, payload, mut fds)) = self.recv_frame().await? else {
                return Ok(None);
            };
            let request = match msg_type {
                MSG_HANDSHAKE => {
                    let (version, policy, prefault, regions) = decode_handshake(&payload)
                        .ok_or_else(|| anyhow!("invalid HANDSHAKE payload"))?;
                    if version != UFFD_PROTOCOL_VERSION {
                        bail!("unsupported UFFD protocol version {version}");
                    }
                    if fds.len() != 1 {
                        bail!(
                            "HANDSHAKE must carry exactly one userfaultfd, received {}",
                            fds.len()
                        );
                    }
                    Request::Handshake {
                        policy,
                        prefault,
                        regions,
                        uffd: fds.pop().expect("validated HANDSHAKE fd count"),
                    }
                }
                MSG_STAT_REQUEST => {
                    validate_empty_request(&payload, &fds, "STAT")?;
                    Request::Stat
                }
                MSG_FETCH_REQUEST => {
                    validate_no_fds(&fds, "FETCH")?;
                    let request = decode_fetch_request(&payload)
                        .ok_or_else(|| anyhow!("invalid FETCH payload"))?;
                    Request::Fetch(DeviceRange {
                        offset: request.offset,
                        len: request.len,
                    })
                }
                MSG_PROBE_REQUEST => {
                    validate_empty_request(&payload, &fds, "PROBE")?;
                    Request::Probe
                }
                other => {
                    warn!("lepton uffd ignored message type 0x{other:04x}");
                    continue;
                }
            };
            return Ok(Some(request));
        }
    }

    async fn recv_frame(&self) -> Result<Option<(u16, Vec<u8>, Vec<OwnedFd>)>> {
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

        let header = Header::from_bytes(&header_buf);
        if header.magic != UFFD_MAGIC {
            bail!("invalid UFFD magic 0x{:08x}", header.magic);
        }
        let payload_len = usize::try_from(header.len).context("invalid UFFD payload length")?;
        if payload_len > MAX_PAYLOAD_SIZE {
            bail!("UFFD payload length {payload_len} exceeds limit {MAX_PAYLOAD_SIZE}");
        }
        let mut payload = vec![0u8; payload_len];
        if !payload.is_empty() {
            recv_exact(&self.stream, &mut payload).await?;
        }
        Ok(Some((header.msg_type, payload, fds)))
    }

    pub async fn send_ranges(&self, ranges: &[ResolvedRange]) -> Result<()> {
        if ranges.is_empty() {
            return send_with_fd(&self.stream, &encode_page_response(&[], false), &[]).await;
        }

        let mut chunks = ranges.chunks(MAX_RANGES_PER_MSG).peekable();
        while let Some(chunk) = chunks.next() {
            let wire_ranges = chunk
                .iter()
                .map(|range| (range.device_offset, range.file_offset, range.len))
                .collect::<Vec<_>>();
            let fds = chunk.iter().map(|range| range.fd).collect::<Vec<_>>();
            send_with_fd(
                &self.stream,
                &encode_page_response(&wire_ranges, chunks.peek().is_some()),
                &fds,
            )
            .await?;
        }
        Ok(())
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

pub fn encode_handshake(
    ver: u16,
    policy: FaultPolicy,
    enable_prefault: bool,
    regions: &[VmaRegion],
) -> Vec<u8> {
    let payload_len = HANDSHAKE_PREFIX_SIZE + regions.len() * REGION_SIZE;
    let header = Header::new(MSG_HANDSHAKE, payload_len as u32);
    let mut flags = 0u8;
    if policy == FaultPolicy::Copy {
        flags |= HANDSHAKE_FLAG_COPY;
    }
    if enable_prefault {
        flags |= HANDSHAKE_FLAG_PREFAULT;
    }

    let mut buf = Vec::with_capacity(HEADER_SIZE + payload_len);
    buf.extend_from_slice(&header.to_bytes());
    buf.extend_from_slice(&ver.to_le_bytes());
    buf.push(flags);
    buf.push(regions.len() as u8);
    for r in regions {
        buf.extend_from_slice(&r.base_host_virt_addr.to_le_bytes());
        buf.extend_from_slice(&r.size.to_le_bytes());
        buf.extend_from_slice(&r.offset.to_le_bytes());
        buf.extend_from_slice(&r.page_size.to_le_bytes());
        buf.extend_from_slice(&r.prot.to_le_bytes());
        buf.extend_from_slice(&r.flags.to_le_bytes());
    }
    buf
}

pub fn decode_handshake(payload: &[u8]) -> Option<(u16, FaultPolicy, bool, Vec<VmaRegion>)> {
    if payload.len() < HANDSHAKE_PREFIX_SIZE {
        return None;
    }
    let ver = u16::from_le_bytes(payload[0..2].try_into().unwrap());
    let flags = payload[2];
    let region_count = payload[3] as usize;
    let expected_len = HANDSHAKE_PREFIX_SIZE + region_count * REGION_SIZE;
    if payload.len() != expected_len {
        return None;
    }
    let policy = if flags & HANDSHAKE_FLAG_COPY != 0 {
        FaultPolicy::Copy
    } else {
        FaultPolicy::Zerocopy
    };
    let enable_prefault = flags & HANDSHAKE_FLAG_PREFAULT != 0;
    let mut regions = Vec::with_capacity(region_count);
    let mut off = HANDSHAKE_PREFIX_SIZE;
    for _ in 0..region_count {
        regions.push(VmaRegion {
            base_host_virt_addr: u64::from_le_bytes(payload[off..off + 8].try_into().unwrap()),
            size: u64::from_le_bytes(payload[off + 8..off + 16].try_into().unwrap()),
            offset: u64::from_le_bytes(payload[off + 16..off + 24].try_into().unwrap()),
            page_size: u64::from_le_bytes(payload[off + 24..off + 32].try_into().unwrap()),
            prot: i32::from_le_bytes(payload[off + 32..off + 36].try_into().unwrap()),
            flags: i32::from_le_bytes(payload[off + 36..off + 40].try_into().unwrap()),
        });
        off += REGION_SIZE;
    }
    Some((ver, policy, enable_prefault, regions))
}

pub fn encode_page_response(ranges: &[(u64, u64, u64)], next: bool) -> Vec<u8> {
    let payload_len = RANGE_COUNT_SIZE + ranges.len() * RANGE_SIZE;
    let mut header = Header::new(MSG_PAGE_RESPONSE, payload_len as u32);
    if next {
        header.flags |= PAGE_RESPONSE_FLAG_NEXT;
    }
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload_len);
    buf.extend_from_slice(&header.to_bytes());
    buf.extend_from_slice(&(ranges.len() as u32).to_le_bytes());
    for &(device_offset, blob_offset, len) in ranges {
        buf.extend_from_slice(&device_offset.to_le_bytes());
        buf.extend_from_slice(&blob_offset.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
    }
    buf
}

pub fn decode_page_response(payload: &[u8]) -> Option<Vec<BlobRange>> {
    if payload.len() < RANGE_COUNT_SIZE {
        return None;
    }
    let range_count = u32::from_le_bytes(payload[..RANGE_COUNT_SIZE].try_into().unwrap()) as usize;
    let expected_len = RANGE_COUNT_SIZE + range_count * RANGE_SIZE;
    if payload.len() != expected_len {
        return None;
    }
    let mut ranges = Vec::with_capacity(range_count);
    let mut off = RANGE_COUNT_SIZE;
    for _ in 0..range_count {
        ranges.push(BlobRange {
            device_offset: u64::from_le_bytes(payload[off..off + 8].try_into().unwrap()),
            blob_offset: u64::from_le_bytes(payload[off + 8..off + 16].try_into().unwrap()),
            len: u64::from_le_bytes(payload[off + 16..off + 24].try_into().unwrap()),
        });
        off += RANGE_SIZE;
    }
    Some(ranges)
}

pub fn encode_stat_request() -> Vec<u8> {
    Header::new(MSG_STAT_REQUEST, 0).to_bytes().to_vec()
}

pub fn encode_stat_response(size: u64, block_size: u32, flags: u32) -> Vec<u8> {
    let header = Header::new(MSG_STAT_RESPONSE, STAT_RESPONSE_SIZE as u32);
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
    let header = Header::new(MSG_FETCH_REQUEST, FETCH_REQUEST_SIZE as u32);
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
    Header::new(MSG_PROBE_REQUEST, 0).to_bytes().to_vec()
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
    fn stat_response_roundtrip() {
        let buf = encode_stat_response(0x20_0000, 4096, 1);
        let hdr = Header::from_bytes(&buf[..HEADER_SIZE].try_into().unwrap());
        assert_eq!(hdr.msg_type, MSG_STAT_RESPONSE);
        assert_eq!(MSG_STAT_RESPONSE, 0x82);
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
    fn page_response_roundtrip() {
        let buf = encode_page_response(&[(0, 4096, 8192)], false);
        let hdr = Header::from_bytes(&buf[..HEADER_SIZE].try_into().unwrap());
        assert_eq!(hdr.magic, UFFD_MAGIC);
        assert_eq!(hdr.msg_type, MSG_PAGE_RESPONSE);
        assert_eq!(hdr.flags, 0);
        let ranges = decode_page_response(&buf[HEADER_SIZE..]).unwrap();
        assert_eq!(ranges[0].device_offset, 0);
        assert_eq!(ranges[0].blob_offset, 4096);
        assert_eq!(ranges[0].len, 8192);
    }

    #[test]
    fn fetch_request_roundtrip() {
        let buf = encode_fetch_request(0x1234_0000, 0x20_0000);
        let hdr = Header::from_bytes(&buf[..HEADER_SIZE].try_into().unwrap());
        assert_eq!(hdr.msg_type, MSG_FETCH_REQUEST);
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
        let mut stat = Header::from_bytes(&encode_stat_request().try_into().unwrap());
        stat.flags = 1;
        stat.cookie = 2;
        client.send_with_fd(&stat.to_bytes(), &[]).unwrap();
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
            base_host_virt_addr: 0x1000,
            size: 0x2000,
            offset: 0x3000,
            page_size: 0x1000,
            prot: 1,
            flags: 2,
        };
        client
            .send_with_fd(
                &encode_handshake(
                    UFFD_PROTOCOL_VERSION,
                    FaultPolicy::Copy,
                    true,
                    std::slice::from_ref(&region),
                ),
                &[file.as_raw_fd()],
            )
            .unwrap();
        drop(file);

        let Some(Request::Handshake {
            policy,
            prefault,
            regions,
            uffd,
        }) = proto.recv().await.unwrap()
        else {
            panic!("expected HANDSHAKE request");
        };
        assert_eq!(policy, FaultPolicy::Copy);
        assert!(prefault);
        assert_eq!(regions, vec![region]);
        assert!(unsafe { libc::fcntl(uffd.as_raw_fd(), libc::F_GETFD) } >= 0);
    }

    #[tokio::test]
    async fn proto_conn_rejects_invalid_handshake_fd_counts() {
        let handshake = encode_handshake(UFFD_PROTOCOL_VERSION, FaultPolicy::Zerocopy, false, &[]);

        let (proto, client) = proto_pair();
        client.send_with_fd(&handshake, &[]).unwrap();
        let err = proto.recv().await.unwrap_err();
        assert!(format!("{err:#}").contains("exactly one userfaultfd, received 0"));

        let (proto, client) = proto_pair();
        let first = File::open("/dev/null").unwrap();
        let second = File::open("/dev/null").unwrap();
        client
            .send_with_fd(&handshake, &[first.as_raw_fd(), second.as_raw_fd()])
            .unwrap();
        let err = proto.recv().await.unwrap_err();
        assert!(format!("{err:#}").contains("exactly one userfaultfd, received 2"));
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
        let header = Header::from_bytes(&header_buf);
        assert_eq!(header.msg_type, MSG_STAT_RESPONSE);
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
        let header = Header::new(MSG_FETCH_REQUEST, (MAX_PAYLOAD_SIZE + 1) as u32);
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
                device_offset: index * 4096,
                file_offset: index * 4096,
                len: 4096,
            })
            .collect::<Vec<_>>();
        proto.send_ranges(&ranges).await.unwrap();

        for (expected_count, expected_flags) in [(16, PAGE_RESPONSE_FLAG_NEXT), (1, 0)] {
            let mut header_buf = [0u8; HEADER_SIZE];
            let mut raw_fds = [0i32; MAX_RECV_FDS];
            let (read, fd_count) = client.recv_with_fd(&mut header_buf, &mut raw_fds).unwrap();
            assert_eq!(read, HEADER_SIZE);
            assert_eq!(fd_count, expected_count);
            let received_fds = raw_fds[..fd_count]
                .iter()
                .map(|fd| unsafe { OwnedFd::from_raw_fd(*fd) })
                .collect::<Vec<_>>();
            let header = Header::from_bytes(&header_buf);
            assert_eq!(header.msg_type, MSG_PAGE_RESPONSE);
            assert_eq!(header.flags, expected_flags);
            let mut payload = vec![0u8; header.len as usize];
            client.read_exact(&mut payload).unwrap();
            assert_eq!(
                decode_page_response(&payload).unwrap().len(),
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
        let header = Header::from_bytes(&header_buf);
        assert_eq!(header.msg_type, MSG_PAGE_RESPONSE);
        assert_eq!(header.flags, 0);
        let mut payload = vec![0u8; header.len as usize];
        client.read_exact(&mut payload).unwrap();
        assert!(decode_page_response(&payload).unwrap().is_empty());
    }
}
