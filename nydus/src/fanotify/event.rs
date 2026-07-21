//! Fanotify pre-content event ABI and a pure, kernel-independent parser.
//!
//! The layout mirrors `<linux/fanotify.h>`: a fixed `fanotify_event_metadata`
//! header optionally followed by info records. For pre-content events the kernel
//! appends a `FAN_EVENT_INFO_TYPE_RANGE` record carrying the `{offset, count}`
//! the reader is about to access.
//!
//! Everything here is pure byte parsing with no syscalls, so it is fully
//! unit-tested independently of kernel support.

use std::os::fd::RawFd;
use std::ptr::read_unaligned;

/// Read-pre-content event mask bit (Linux 6.15+).
pub const FAN_PRE_ACCESS: u64 = 0x0010_0000;
/// Sentinel `fd` on a queue-overflow event: no file descriptor is attached.
pub const FAN_NOFD: RawFd = -1;
/// Expected `vers` field of the metadata header.
pub const FANOTIFY_METADATA_VERSION: u8 = 3;
/// Info-record type carrying `{offset, count}` (Linux 6.15+).
const FAN_EVENT_INFO_TYPE_RANGE: u8 = 6;

/// Fixed event metadata header. Must match `struct fanotify_event_metadata`.
#[repr(C)]
#[derive(Clone, Copy)]
struct EventMetadata {
    event_len: u32,
    vers: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

/// Info-record header. Must match `struct fanotify_event_info_header`.
#[repr(C)]
#[derive(Clone, Copy)]
struct InfoHeader {
    info_type: u8,
    pad: u8,
    len: u16,
}

// The RANGE record trails the header with `{ __u32 pad; __u64 offset; __u64 count; }`,
// i.e. offset sits 8 bytes past the record start and count 16 bytes past.
const RANGE_RECORD_MIN_LEN: usize = 24;
const RANGE_OFFSET_FIELD: usize = 8;
const RANGE_COUNT_FIELD: usize = 16;

/// The `{offset, count}` byte range the accessing reader is about to touch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Range {
    pub offset: u64,
    pub count: u64,
}

/// A parsed pre-content event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreContentEvent {
    pub fd: RawFd,
    pub pid: i32,
    pub mask: u64,
    pub range: Option<Range>,
}

impl PreContentEvent {
    /// True for a queue-overflow marker: no fd, nothing to answer or close.
    pub fn is_overflow(&self) -> bool {
        self.fd == FAN_NOFD
    }

    /// True when this event carries the read-pre-content mask bit.
    pub fn is_pre_access(&self) -> bool {
        self.mask & FAN_PRE_ACCESS != 0
    }
}

/// The specific reason an event batch or record failed validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseErrorKind {
    TruncatedMetadata,
    InvalidVersion { version: u8 },
    MetadataTooShort { len: usize },
    MetadataOutOfBounds { len: usize, event_len: usize },
    EventTooShort { len: usize },
    EventOutOfBounds { len: usize },
    InfoHeaderTruncated,
    InfoRecordTooShort { len: usize },
    InfoRecordOutOfBounds { len: usize },
    RangeRecordTooShort { len: usize },
    DuplicateRange,
    MissingRange,
    RangeCountZero,
    RangeOverflow,
}

/// A parser error. `event_fd` is present only when the metadata version
/// matched — i.e. the header layout is trusted, so the fd field is a real
/// descriptor the service may deny and close.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseError {
    pub offset: usize,
    pub kind: ParseErrorKind,
    event_fd: Option<RawFd>,
}

impl ParseError {
    fn new(offset: usize, kind: ParseErrorKind, event_fd: Option<RawFd>) -> Self {
        Self {
            offset,
            kind,
            event_fd,
        }
    }

    pub fn event_fd(&self) -> Option<RawFd> {
        self.event_fd.filter(|fd| *fd != FAN_NOFD)
    }

    /// Whether the batch can keep being parsed past this error.
    ///
    /// `true` for errors that fire only **after** the event's length has been
    /// validated: the next event's boundary (`offset + event_len`) is then
    /// known, so this one unusable event can be denied and skipped without
    /// abandoning the rest of the batch. `false` for structural corruption
    /// (truncated header, bad version, bogus/out-of-bounds `event_len`) where
    /// the boundary is untrustworthy and the batch must stop. New variants
    /// default to non-recoverable — the conservative choice.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self.kind,
            ParseErrorKind::MetadataTooShort { .. }
                | ParseErrorKind::MetadataOutOfBounds { .. }
                | ParseErrorKind::InfoHeaderTruncated
                | ParseErrorKind::InfoRecordTooShort { .. }
                | ParseErrorKind::InfoRecordOutOfBounds { .. }
                | ParseErrorKind::RangeRecordTooShort { .. }
                | ParseErrorKind::DuplicateRange
                | ParseErrorKind::MissingRange
                | ParseErrorKind::RangeCountZero
                | ParseErrorKind::RangeOverflow
        )
    }
}

/// Iterator over events packed into one `read(2)` buffer from a fanotify fd.
///
/// A malformed event is reported instead of being silently dropped.
///
/// Recoverable errors (where the event's length has been validated so the next
/// event boundary is known) are yielded and the iterator **continues** past them.
/// Non-recoverable errors (structural corruption such as a bad version or
/// truncated header) stop the iterator — the rest of the batch is untrusted.
pub struct EventIter<'a> {
    buf: &'a [u8],
    off: usize,
    done: bool,
}

impl<'a> EventIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            off: 0,
            done: false,
        }
    }
}

impl Iterator for EventIter<'_> {
    type Item = Result<PreContentEvent, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        if self.off == self.buf.len() {
            self.done = true;
            return None;
        }

        let meta_size = std::mem::size_of::<EventMetadata>();
        let meta_end = match self.off.checked_add(meta_size) {
            Some(end) => end,
            None => {
                self.done = true;
                return Some(Err(ParseError::new(
                    self.off,
                    ParseErrorKind::TruncatedMetadata,
                    None,
                )));
            }
        };
        if meta_end > self.buf.len() {
            self.done = true;
            return Some(Err(ParseError::new(
                self.off,
                ParseErrorKind::TruncatedMetadata,
                None,
            )));
        }

        // SAFETY: the complete metadata header is in the buffer; it may be
        // unaligned because the buffer starts at an arbitrary byte address.
        let meta: EventMetadata =
            unsafe { read_unaligned(self.buf.as_ptr().add(self.off) as *const EventMetadata) };
        let event_offset = self.off;
        let event_len = meta.event_len as usize;
        let result = self.parse_event(meta, event_offset, event_len, meta_size);
        match &result {
            Ok(_) => {
                self.off = event_offset
                    .checked_add(event_len)
                    .expect("successful event parsing checked event length");
            }
            Err(err) if err.is_recoverable() => {
                // The error fired after `event_len` was validated, so the next
                // event's boundary is known: skip this one and keep parsing.
                self.off = event_offset
                    .checked_add(event_len)
                    .expect("recoverable parse error implies a validated event length");
            }
            Err(_) => {
                // Structural corruption: the remaining bytes cannot be trusted
                // as event boundaries, so stop.
                self.done = true;
            }
        }
        Some(result)
    }
}

impl EventIter<'_> {
    fn parse_event(
        &self,
        meta: EventMetadata,
        event_offset: usize,
        event_len: usize,
        meta_size: usize,
    ) -> Result<PreContentEvent, ParseError> {
        if meta.vers != FANOTIFY_METADATA_VERSION {
            // A version mismatch means the header layout itself is untrusted,
            // so the fd field may be garbage: exposing it would let the service
            // close an arbitrary (possibly its own) descriptor. Withhold it.
            return Err(ParseError::new(
                event_offset,
                ParseErrorKind::InvalidVersion { version: meta.vers },
                None,
            ));
        }
        let event_fd = Some(meta.fd);
        if event_len < meta_size {
            return Err(ParseError::new(
                event_offset,
                ParseErrorKind::EventTooShort { len: event_len },
                event_fd,
            ));
        }
        let event_end = event_offset.checked_add(event_len).ok_or_else(|| {
            ParseError::new(
                event_offset,
                ParseErrorKind::EventOutOfBounds { len: event_len },
                event_fd,
            )
        })?;
        if event_end > self.buf.len() {
            return Err(ParseError::new(
                event_offset,
                ParseErrorKind::EventOutOfBounds { len: event_len },
                event_fd,
            ));
        }

        let metadata_len = meta.metadata_len as usize;
        if metadata_len < meta_size {
            return Err(ParseError::new(
                event_offset,
                ParseErrorKind::MetadataTooShort { len: metadata_len },
                event_fd,
            ));
        }
        if metadata_len > event_len {
            return Err(ParseError::new(
                event_offset,
                ParseErrorKind::MetadataOutOfBounds {
                    len: metadata_len,
                    event_len,
                },
                event_fd,
            ));
        }

        // FAN_Q_OVERFLOW has no event fd or RANGE record. The service treats it
        // as a fatal health event rather than as a permission event.
        if meta.fd == FAN_NOFD {
            return Ok(PreContentEvent {
                fd: meta.fd,
                pid: meta.pid,
                mask: meta.mask,
                range: None,
            });
        }

        let event = &self.buf[event_offset..event_end];
        let range = parse_range(event, metadata_len, event_fd)?;
        Ok(PreContentEvent {
            fd: meta.fd,
            pid: meta.pid,
            mask: meta.mask,
            range: Some(range),
        })
    }
}

/// Walk the info records trailing the fixed metadata and return the single RANGE.
fn parse_range(
    event: &[u8],
    metadata_len: usize,
    event_fd: Option<RawFd>,
) -> Result<Range, ParseError> {
    let hdr_size = std::mem::size_of::<InfoHeader>();
    let mut ioff = metadata_len;
    let mut range = None;

    while ioff < event.len() {
        let hdr_end = ioff
            .checked_add(hdr_size)
            .ok_or_else(|| ParseError::new(ioff, ParseErrorKind::InfoHeaderTruncated, event_fd))?;
        if hdr_end > event.len() {
            return Err(ParseError::new(
                ioff,
                ParseErrorKind::InfoHeaderTruncated,
                event_fd,
            ));
        }
        // SAFETY: the complete info header is in the event; it may be unaligned.
        let hdr: InfoHeader =
            unsafe { read_unaligned(event.as_ptr().add(ioff) as *const InfoHeader) };
        let hlen = hdr.len as usize;
        if hlen < hdr_size {
            return Err(ParseError::new(
                ioff,
                ParseErrorKind::InfoRecordTooShort { len: hlen },
                event_fd,
            ));
        }
        let info_end = ioff.checked_add(hlen).ok_or_else(|| {
            ParseError::new(
                ioff,
                ParseErrorKind::InfoRecordOutOfBounds { len: hlen },
                event_fd,
            )
        })?;
        if info_end > event.len() {
            return Err(ParseError::new(
                ioff,
                ParseErrorKind::InfoRecordOutOfBounds { len: hlen },
                event_fd,
            ));
        }

        if hdr.info_type == FAN_EVENT_INFO_TYPE_RANGE {
            if hlen < RANGE_RECORD_MIN_LEN {
                return Err(ParseError::new(
                    ioff,
                    ParseErrorKind::RangeRecordTooShort { len: hlen },
                    event_fd,
                ));
            }
            if range.is_some() {
                return Err(ParseError::new(
                    ioff,
                    ParseErrorKind::DuplicateRange,
                    event_fd,
                ));
            }
            // SAFETY: hlen >= RANGE_RECORD_MIN_LEN and info_end is in bounds.
            let base = event.as_ptr();
            let offset =
                unsafe { read_unaligned(base.add(ioff + RANGE_OFFSET_FIELD) as *const u64) };
            let count = unsafe { read_unaligned(base.add(ioff + RANGE_COUNT_FIELD) as *const u64) };
            if count == 0 {
                return Err(ParseError::new(
                    ioff,
                    ParseErrorKind::RangeCountZero,
                    event_fd,
                ));
            }
            if offset.checked_add(count).is_none() {
                return Err(ParseError::new(
                    ioff,
                    ParseErrorKind::RangeOverflow,
                    event_fd,
                ));
            }
            range = Some(Range { offset, count });
        }
        ioff = info_end;
    }

    range.ok_or_else(|| ParseError::new(metadata_len, ParseErrorKind::MissingRange, event_fd))
}

#[cfg(test)]
mod tests {
    use super::*;

    const META_LEN: u16 = std::mem::size_of::<EventMetadata>() as u16;

    fn make_event(fd: i32, pid: i32, mask: u64, range: Option<(u64, u64)>) -> Vec<u8> {
        let mut body = Vec::new();
        if let Some((offset, count)) = range {
            body.push(FAN_EVENT_INFO_TYPE_RANGE);
            body.push(0);
            body.extend_from_slice(&24u16.to_ne_bytes());
            body.extend_from_slice(&0u32.to_ne_bytes());
            body.extend_from_slice(&offset.to_ne_bytes());
            body.extend_from_slice(&count.to_ne_bytes());
        }
        let event_len = META_LEN as u32 + body.len() as u32;

        let mut out = Vec::new();
        out.extend_from_slice(&event_len.to_ne_bytes());
        out.push(FANOTIFY_METADATA_VERSION);
        out.push(0);
        out.extend_from_slice(&META_LEN.to_ne_bytes());
        out.extend_from_slice(&mask.to_ne_bytes());
        out.extend_from_slice(&fd.to_ne_bytes());
        out.extend_from_slice(&pid.to_ne_bytes());
        out.extend_from_slice(&body);
        out
    }

    fn parse_one(bytes: &[u8]) -> Result<PreContentEvent, ParseError> {
        EventIter::new(bytes).next().expect("one parser result")
    }

    #[test]
    fn parses_event_with_range_record() {
        let ev = parse_one(&make_event(7, 1234, FAN_PRE_ACCESS, Some((4096, 8192)))).unwrap();
        assert_eq!(ev.fd, 7);
        assert_eq!(ev.pid, 1234);
        assert!(ev.is_pre_access());
        assert!(!ev.is_overflow());
        assert_eq!(
            ev.range,
            Some(Range {
                offset: 4096,
                count: 8192
            })
        );
    }

    #[test]
    fn missing_range_is_reported() {
        let err = parse_one(&make_event(7, 1, FAN_PRE_ACCESS, None)).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::MissingRange);
        assert_eq!(err.event_fd(), Some(7));
    }

    #[test]
    fn iterates_multiple_packed_events() {
        let mut bytes = make_event(3, 10, FAN_PRE_ACCESS, Some((0, 4096)));
        bytes.extend(make_event(4, 11, FAN_PRE_ACCESS, Some((4096, 4096))));
        let events: Vec<_> = EventIter::new(&bytes).collect::<Result<_, _>>().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].fd, 3);
        assert_eq!(events[1].fd, 4);
    }

    #[test]
    fn overflow_event_is_flagged() {
        let ev = parse_one(&make_event(FAN_NOFD, 0, 0, None)).unwrap();
        assert!(ev.is_overflow());
        assert_eq!(ev.range, None);
    }

    #[test]
    fn wrong_version_withholds_untrusted_fd() {
        let mut bytes = make_event(9, 2, FAN_PRE_ACCESS, Some((0, 4096)));
        bytes[4] = FANOTIFY_METADATA_VERSION + 1;
        let err = parse_one(&bytes).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::InvalidVersion { version: 4 });
        // The layout is untrusted, so the fd field must not be exposed for a
        // deny+close — it could be an arbitrary descriptor number.
        assert_eq!(err.event_fd(), None);
    }

    #[test]
    fn short_metadata_is_rejected() {
        let mut bytes = make_event(9, 2, FAN_PRE_ACCESS, Some((0, 4096)));
        bytes[6..8].copy_from_slice(&8u16.to_ne_bytes());
        let err = parse_one(&bytes).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::MetadataTooShort { len: 8 });
    }

    #[test]
    fn metadata_beyond_event_is_rejected() {
        let mut bytes = make_event(9, 2, FAN_PRE_ACCESS, Some((0, 4096)));
        let event_len = u16::from_ne_bytes([bytes[0], bytes[1]]) as usize;
        bytes[6..8].copy_from_slice(&((event_len + 1) as u16).to_ne_bytes());
        let err = parse_one(&bytes).unwrap_err();
        assert_eq!(
            err.kind,
            ParseErrorKind::MetadataOutOfBounds {
                len: event_len + 1,
                event_len
            }
        );
    }

    #[test]
    fn zero_count_and_range_overflow_are_rejected() {
        for (offset, count, expected) in [
            (0, 0, ParseErrorKind::RangeCountZero),
            (u64::MAX - 1, 2, ParseErrorKind::RangeOverflow),
        ] {
            let err =
                parse_one(&make_event(9, 2, FAN_PRE_ACCESS, Some((offset, count)))).unwrap_err();
            assert_eq!(err.kind, expected);
        }
    }

    #[test]
    fn duplicate_range_is_rejected() {
        let mut bytes = make_event(9, 2, FAN_PRE_ACCESS, Some((0, 4096)));
        bytes.extend_from_slice(&[FAN_EVENT_INFO_TYPE_RANGE, 0, 24, 0]);
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(&4096u64.to_ne_bytes());
        bytes.extend_from_slice(&4096u64.to_ne_bytes());
        let event_len = bytes.len() as u32;
        bytes[0..4].copy_from_slice(&event_len.to_ne_bytes());
        let err = parse_one(&bytes).unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::DuplicateRange);
    }

    #[test]
    fn malformed_second_packed_event_is_reported() {
        let mut bytes = make_event(3, 10, FAN_PRE_ACCESS, Some((0, 4096)));
        let second_offset = bytes.len();
        bytes.extend(make_event(4, 11, FAN_PRE_ACCESS, Some((4096, 4096))));
        bytes[second_offset + 4] = 0;
        let mut iter = EventIter::new(&bytes);
        assert!(iter.next().unwrap().is_ok());
        let err = iter.next().unwrap().unwrap_err();
        // A bad version is structural: the boundary is untrusted, so iteration
        // stops (fail-closed) and the untrusted fd field is withheld.
        assert_eq!(err.kind, ParseErrorKind::InvalidVersion { version: 0 });
        assert!(!err.is_recoverable());
        assert_eq!(err.event_fd(), None);
        assert!(iter.next().is_none());
    }

    #[test]
    fn recoverable_error_is_skipped_and_iteration_continues() {
        // [good, missing-range (recoverable), good]: the middle event has a
        // valid length but no RANGE record, so it is reportable-and-skippable —
        // the third event must still be parsed.
        let mut bytes = make_event(3, 10, FAN_PRE_ACCESS, Some((0, 4096)));
        bytes.extend(make_event(4, 11, FAN_PRE_ACCESS, None));
        bytes.extend(make_event(5, 12, FAN_PRE_ACCESS, Some((4096, 4096))));
        let mut iter = EventIter::new(&bytes);

        assert_eq!(iter.next().unwrap().unwrap().fd, 3);
        let err = iter.next().unwrap().unwrap_err();
        assert_eq!(err.kind, ParseErrorKind::MissingRange);
        assert!(err.is_recoverable());
        assert_eq!(err.event_fd(), Some(4));
        // Continues past the recoverable error to the third event.
        assert_eq!(iter.next().unwrap().unwrap().fd, 5);
        assert!(iter.next().is_none());
    }

    #[test]
    fn truncated_event_is_reported() {
        let mut bytes = make_event(9, 2, FAN_PRE_ACCESS, Some((0, 4096)));
        bytes.truncate(bytes.len() - 4);
        let err = parse_one(&bytes).unwrap_err();
        assert!(matches!(err.kind, ParseErrorKind::EventOutOfBounds { .. }));
        assert_eq!(err.event_fd(), Some(9));
    }

    #[test]
    fn trailing_partial_metadata_is_reported() {
        let mut bytes = make_event(3, 10, FAN_PRE_ACCESS, Some((0, 4096)));
        bytes.extend_from_slice(&[1, 2, 3]);
        let mut iter = EventIter::new(&bytes);
        assert!(iter.next().unwrap().is_ok());
        assert_eq!(
            iter.next().unwrap().unwrap_err().kind,
            ParseErrorKind::TruncatedMetadata
        );
    }
}
