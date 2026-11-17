use neli::consts::genl::{CtrlAttr, CtrlCmd};
use neli::consts::nl::{GenlId, NlmF};
use neli::consts::socket::NlFamily;
use neli::err::SocketError;
use neli::genl::{AttrTypeBuilder, Genlmsghdr, GenlmsghdrBuilder, Nlattr, NlattrBuilder};
use neli::nl::{NlPayload, NlmsghdrBuilder};
use neli::socket::synchronous::NlSocketHandle;
use neli::types::{Buffer, GenlBuffer};
use neli::utils::Groups;
use neli::{Size, ToBytes};
use nydus_error::{Context, Error, Result};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::{Duration, Instant};

use super::proto::NBD_BLOCK_SIZE;
use super::service::{NbdOptions, POLL_INTERVAL};

/// How long one netlink command may wait for its reply.
///
/// The kernel runs a command inside the sending call, so this bounds a lost reply, not a
/// command blocked in the kernel.
pub(crate) const NETLINK_TIMEOUT: Duration = Duration::from_secs(10);

/// How long CONNECT retries a device the kernel briefly reports in use.
const CONNECT_BUSY_TIMEOUT: Duration = Duration::from_secs(2);

/// The generic netlink command that creates an NBD session.
const NBD_CMD_CONNECT: u8 = 1;
/// The generic netlink command that tears down an NBD session.
const NBD_CMD_DISCONNECT: u8 = 2;
/// The generic netlink command that attaches sockets to the dead slots of a session.
const NBD_CMD_RECONFIGURE: u8 = 3;
/// The attribute carrying the `/dev/nbdN` index.
const NBD_ATTR_INDEX: u16 = 1;
/// The attribute carrying the device capacity in bytes.
const NBD_ATTR_SIZE_BYTES: u16 = 2;
/// The attribute carrying the logical block size in bytes.
const NBD_ATTR_BLOCK_SIZE_BYTES: u16 = 3;
/// The attribute carrying the per-request timeout in seconds.
const NBD_ATTR_TIMEOUT: u16 = 4;
/// The attribute carrying the export flags.
const NBD_ATTR_SERVER_FLAGS: u16 = 5;
/// The nested attribute listing the connection sockets.
const NBD_ATTR_SOCKETS: u16 = 7;
/// The attribute carrying how long new I/O waits for a reconnect, in seconds.
const NBD_ATTR_DEAD_CONN_TIMEOUT: u16 = 8;
/// The attribute carrying the session identity shown in sysfs `backend`.
const NBD_ATTR_BACKEND_IDENTIFIER: u16 = 10;
/// The nested attribute wrapping one socket of the list.
const NBD_SOCK_ITEM: u16 = 1;
/// The attribute carrying one socket descriptor.
const NBD_SOCK_FD: u16 = 1;

/// The server flag telling the kernel that the other flags are valid.
const NBD_FLAG_HAS_FLAGS: u64 = 0x1;
/// The server flag making the device read-only.
const NBD_FLAG_READ_ONLY: u64 = 0x2;
/// The server flag letting the kernel use several connections at once.
const NBD_FLAG_CAN_MULTI_CONN: u64 = 0x100;

/// The attributes of one generic netlink request.
type Attrs = GenlBuffer<u16, Buffer>;

/// Creates a session on `/dev/nbd<index>` with one socket per connection.
///
/// The capacity is committed before the call returns.
pub(crate) fn connect_device(
    index: u32,
    size: u64,
    options: &NbdOptions,
    backend: &str,
    sockets: &[BorrowedFd<'_>],
) -> Result<()> {
    if sockets.len() != options.connections {
        return Err(Error::InvalidParameter(
            "NBD CONNECT needs one socket per connection".into(),
        ));
    }
    let mut attrs = connection_attrs(index, options, backend, sockets)?;
    attrs.push(attr(NBD_ATTR_SIZE_BYTES, size)?);
    attrs.push(attr(NBD_ATTR_BLOCK_SIZE_BYTES, NBD_BLOCK_SIZE)?);
    attrs.push(attr(
        NBD_ATTR_SERVER_FLAGS,
        NBD_FLAG_HAS_FLAGS | NBD_FLAG_READ_ONLY | NBD_FLAG_CAN_MULTI_CONN,
    )?);

    // Opening a configless device, as udev does to probe one just torn down, briefly makes
    // the kernel report it in use.
    let deadline = Instant::now() + CONNECT_BUSY_TIMEOUT;
    loop {
        match transact(NBD_CMD_CONNECT, attrs.clone()) {
            Err(err) if is_busy(&err) && Instant::now() < deadline => {
                std::thread::sleep(POLL_INTERVAL)
            }
            result => {
                return result
                    .with_context(|| format!("NBD_CMD_CONNECT for /dev/nbd{index} failed"))
            }
        }
    }
}

/// Returns whether the kernel reported the device in use.
fn is_busy(err: &Error) -> bool {
    err.io_error()
        .is_some_and(|err| err.raw_os_error() == Some(libc::EBUSY))
}

/// Attaches sockets to the dead slots of the session on `/dev/nbd<index>`.
///
/// The ACK alone does not prove acceptance: the kernel silently ignores sockets when no slot is dead.
pub(crate) fn reconfigure_device(
    index: u32,
    options: &NbdOptions,
    backend: &str,
    sockets: &[BorrowedFd<'_>],
) -> Result<()> {
    let attrs = connection_attrs(index, options, backend, sockets)?;
    transact(NBD_CMD_RECONFIGURE, attrs)
        .with_context(|| format!("NBD_CMD_RECONFIGURE for /dev/nbd{index} failed"))
}

/// Tears down the session on `/dev/nbd<index>`.
pub(crate) fn disconnect_device(index: u32) -> Result<()> {
    let attrs = [attr(NBD_ATTR_INDEX, index)?].into_iter().collect();
    transact(NBD_CMD_DISCONNECT, attrs)
        .with_context(|| format!("NBD_CMD_DISCONNECT for /dev/nbd{index} failed"))
}

/// Encodes the index, timeouts, backend identity and sockets shared by CONNECT and RECONFIGURE.
fn connection_attrs(
    index: u32,
    options: &NbdOptions,
    backend: &str,
    sockets: &[BorrowedFd<'_>],
) -> Result<Attrs> {
    options.validate()?;

    // Accept fewer sockets than connections: RECONFIGURE replaces only the slots a previous
    // attempt left dead.
    if sockets.is_empty()
        || sockets.len() > options.connections
        || backend.is_empty()
        || backend.as_bytes().contains(&0)
    {
        return Err(Error::InvalidParameter(
            "invalid NBD backend or connection count".into(),
        ));
    }
    let mut list = attr(NBD_ATTR_SOCKETS, Buffer::new())?;
    for fd in sockets {
        let fd = u32::try_from(fd.as_raw_fd())
            .map_err(|_| Error::InvalidParameter("invalid NBD socket descriptor".into()))?;
        let item = attr(NBD_SOCK_ITEM, Buffer::new())?
            .nest(&attr(NBD_SOCK_FD, fd)?)
            .map_err(netlink_error)?;
        list = list.nest(&item).map_err(netlink_error)?;
    }
    Ok([
        attr(NBD_ATTR_TIMEOUT, options.timeout_secs)?,
        attr(NBD_ATTR_DEAD_CONN_TIMEOUT, options.dead_conn_timeout_secs)?,
        attr(NBD_ATTR_INDEX, index)?,
        attr(NBD_ATTR_BACKEND_IDENTIFIER, backend)?,
        list,
    ]
    .into_iter()
    .collect())
}

/// Builds one netlink attribute.
fn attr(kind: u16, payload: impl Size + ToBytes) -> Result<Nlattr<u16, Buffer>> {
    let kind = AttrTypeBuilder::default()
        .nla_type(kind)
        .build()
        .map_err(netlink_error)?;
    NlattrBuilder::default()
        .nla_type(kind)
        .nla_payload(payload)
        .build()
        .map_err(netlink_error)
}

/// Resolves the nbd generic netlink family and sends one acknowledged command to it.
fn transact(command: u8, attrs: Attrs) -> Result<()> {
    let deadline = Instant::now() + NETLINK_TIMEOUT;
    let socket = NlSocketHandle::connect(NlFamily::Generic, Some(0), Groups::empty())
        .map_err(|err| socket_error(err, "failed to open netlink socket"))?;
    let name = [attr(CtrlAttr::FamilyName.into(), "nbd")?]
        .into_iter()
        .collect();
    let family = request(
        &socket,
        GenlId::Ctrl.into(),
        CtrlCmd::Getfamily.into(),
        name,
        deadline,
    )
    .and_then(|reply| {
        reply
            .ok_or_else(|| Error::Protocol("GETFAMILY reply has no payload".into()))?
            .attrs()
            .get_attr_handle()
            .get_attr_payload_as::<u16>(CtrlAttr::FamilyId.into())
            .map_err(netlink_error)
    })
    .context("failed to resolve the nbd netlink family; load the nbd kernel module")?;
    request(&socket, family, command, attrs, deadline)?;
    Ok(())
}

/// Sends one request and returns the payload of its acknowledged reply.
fn request(
    socket: &NlSocketHandle,
    family: u16,
    command: u8,
    attrs: Attrs,
    deadline: Instant,
) -> Result<Option<Genlmsghdr<u8, u16>>> {
    let header = GenlmsghdrBuilder::default()
        .cmd(command)
        .version(1)
        .attrs(attrs)
        .build()
        .map_err(netlink_error)?;
    let message = NlmsghdrBuilder::default()
        .nl_type(family)
        .nl_flags(NlmF::REQUEST | NlmF::ACK)
        .nl_seq(u32::from(command))
        .nl_payload(NlPayload::Payload(header))
        .build()
        .map_err(netlink_error)?;
    set_deadline(socket, libc::SO_SNDTIMEO, deadline)?;
    socket
        .send(&message)
        .map_err(|err| socket_error(err, "failed to send netlink request"))?;
    let mut payload = None;
    loop {
        set_deadline(socket, libc::SO_RCVTIMEO, deadline)?;
        let (replies, _) = socket
            .recv_all::<u16, Genlmsghdr<u8, u16>>()
            .map_err(|err| socket_error(err, "failed to receive netlink reply"))?;
        for reply in replies {
            if reply.nl_seq() != message.nl_seq() {
                continue;
            }
            match reply.nl_payload() {
                NlPayload::Ack(_) => return Ok(payload),
                NlPayload::Err(err) => {
                    return Err(io::Error::from_raw_os_error(-*err.error()))
                        .context("kernel rejected NBD netlink request")
                }
                NlPayload::Payload(body) => payload = Some(body.clone()),
                _ => {}
            }
        }
    }
}

/// Bounds the next send or receive by the remaining time before the deadline.
fn set_deadline(socket: &NlSocketHandle, option: libc::c_int, deadline: Instant) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "NBD netlink deadline expired"))?;
    let tv = libc::timeval {
        tv_sec: remaining
            .as_secs()
            .try_into()
            .map_err(|_| Error::Overflow("netlink timeout overflow".into()))?,
        tv_usec: remaining.subsec_micros().max(1).into(),
    };

    // SAFETY: tv is live and correctly sized for the selected socket timeout.
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of_val(&tv) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error()).context("failed to set netlink deadline");
    }
    Ok(())
}

/// Converts a netlink socket failure, reporting an expired socket timeout as a timeout.
fn socket_error(err: SocketError, context: &'static str) -> Error {
    let err = match err {
        SocketError::Io(err) if err.kind() == io::ErrorKind::WouldBlock => Error::from(
            io::Error::new(io::ErrorKind::TimedOut, "NBD netlink deadline expired"),
        ),
        SocketError::Io(err) => Error::from(io::Error::new(err.kind(), err.to_string())),
        err => netlink_error(err),
    };
    err.context(context)
}

/// Converts a netlink encoding or decoding failure.
fn netlink_error(err: impl std::fmt::Display) -> Error {
    Error::Protocol(format!("invalid netlink message: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn connection_attributes_nest_one_descriptor_per_socket() {
        let (one, two) = UnixStream::pair().unwrap();
        let options = NbdOptions {
            connections: 2,
            timeout_secs: 15,
            dead_conn_timeout_secs: 60,
        };
        let attrs = connection_attrs(3, &options, "session", &[one.as_fd(), two.as_fd()]).unwrap();
        let handle = attrs.get_attr_handle();
        assert_eq!(
            handle.get_attr_payload_as::<u32>(NBD_ATTR_INDEX).unwrap(),
            3
        );
        assert_eq!(
            handle
                .get_attr_payload_as_with_len::<String>(NBD_ATTR_BACKEND_IDENTIFIER)
                .unwrap(),
            "session"
        );
        let sockets = handle
            .get_nested_attributes::<u16>(NBD_ATTR_SOCKETS)
            .unwrap();
        let fds = sockets
            .iter()
            .map(|item| {
                item.get_attr_handle::<u16>()
                    .unwrap()
                    .get_attr_payload_as::<u32>(NBD_SOCK_FD)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(fds, [one.as_raw_fd() as u32, two.as_raw_fd() as u32]);
        let test_cases = vec![vec![], vec![one.as_fd(), two.as_fd(), one.as_fd()]];

        for sockets in test_cases {
            assert!(connection_attrs(3, &options, "session", &sockets).is_err());
        }
        assert!(connection_attrs(3, &options, "session", &[one.as_fd()]).is_ok());
    }
}
