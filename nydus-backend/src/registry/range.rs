//! The `Range` and `Content-Range` of a blob `GET`, refer to RFC 9110 Section
//! 14.

use std::fmt;
use std::io;
use std::ops::{self, RangeInclusive};
use std::str::FromStr;

/// The byte range of the `Range` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Range {
    /// The bytes from first to last, inclusive.
    Bounded(RangeInclusive<u64>),

    /// The last bytes, this many of them.
    Suffix(u64),
}

/// Implements the requested byte range.
impl Range {
    /// Returns the satisfiable range in a blob `complete_length` long, refer
    /// to RFC 9110 Section 14.1.2.
    pub(crate) fn satisfiable_range(&self, complete_length: u64) -> RangeInclusive<u64> {
        let last = complete_length.saturating_sub(1);
        match self {
            Range::Bounded(range) => *range.start()..=(*range.end()).min(last),
            Range::Suffix(length) => complete_length.saturating_sub(*length)..=last,
        }
    }
}

/// Implements TryFrom for a range of blob bytes that excludes its end.
impl TryFrom<ops::Range<u64>> for Range {
    type Error = io::Error;

    /// Converts `start..end` to the bytes from `start` to `end - 1`, rejecting
    /// an empty range.
    fn try_from(range: ops::Range<u64>) -> io::Result<Self> {
        if range.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("empty blob range {}..{}", range.start, range.end),
            ));
        }

        Ok(Range::Bounded(range.start..=range.end - 1))
    }
}

/// Implements Display as the `Range` header value.
impl fmt::Display for Range {
    /// Formats the range as `bytes=first-last` or `bytes=-length`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Range::Bounded(range) => write!(f, "bytes={}-{}", range.start(), range.end()),
            Range::Suffix(length) => write!(f, "bytes=-{length}"),
        }
    }
}

/// Implements FromStr for the `Range` header value.
impl FromStr for Range {
    type Err = io::Error;

    /// Parses `bytes=first-last` or `bytes=-length` of digits alone.
    fn from_str(value: &str) -> io::Result<Self> {
        value
            .strip_prefix("bytes=")
            .filter(|range_set| {
                range_set
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'-')
            })
            .and_then(|range_set| match range_set.split_once('-')? {
                ("", length) => Some(Range::Suffix(length.parse().ok()?)),
                (first, last) => Some(Range::Bounded(first.parse().ok()?..=last.parse().ok()?)),
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid Range {value}"))
            })
    }
}

/// The byte range of the `Content-Range` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContentRange {
    /// The bytes the body holds, inclusive.
    pub(crate) range: RangeInclusive<u64>,

    /// The length of the whole blob.
    pub(crate) complete_length: u64,
}

/// Implements Display as the `Content-Range` header value.
impl fmt::Display for ContentRange {
    /// Formats the range as `bytes first-last/complete-length`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bytes {}-{}/{}",
            self.range.start(),
            self.range.end(),
            self.complete_length
        )
    }
}

/// Implements FromStr for the `Content-Range` header value.
impl FromStr for ContentRange {
    type Err = io::Error;

    /// Parses `bytes first-last/complete-length` of digits alone, rejecting a
    /// `*` length and invalid ranges, refer to RFC 9110 Section 14.4.
    fn from_str(value: &str) -> io::Result<Self> {
        value
            .strip_prefix("bytes ")
            .filter(|range_resp| {
                range_resp
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'-' | b'/'))
            })
            .and_then(|range_resp| {
                let (incl_range, complete_length) = range_resp.split_once('/')?;
                let (first, last) = incl_range.split_once('-')?;
                let first = first.parse().ok()?;
                let last = last.parse().ok()?;
                let complete_length = complete_length.parse().ok()?;

                (first <= last && last < complete_length).then_some(ContentRange {
                    range: first..=last,
                    complete_length,
                })
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid Content-Range {value}"),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_to_string_formats_the_range_header() {
        let test_cases = vec![
            (Range::Bounded(0..=0), "bytes=0-0"),
            (Range::Bounded(2..=5), "bytes=2-5"),
            (Range::Suffix(64), "bytes=-64"),
        ];

        for (range, expected) in test_cases {
            assert_eq!(range.to_string(), expected);
        }
    }

    #[test]
    fn range_try_from_converts_a_range_excluding_its_end() {
        let test_cases = vec![
            (0..1, Some(Range::Bounded(0..=0))),
            (2..6, Some(Range::Bounded(2..=5))),
            (3..3, None),
            (ops::Range { start: 6, end: 2 }, None),
        ];

        for (range, expected) in test_cases {
            assert_eq!(Range::try_from(range).ok(), expected);
        }
    }

    #[test]
    fn range_from_str_parses_a_bounded_or_suffix_range() {
        let test_cases = vec![
            ("bytes=0-0", Some(Range::Bounded(0..=0))),
            ("bytes=2-5", Some(Range::Bounded(2..=5))),
            ("bytes=-64", Some(Range::Suffix(64))),
            ("bytes=2-", None),
            ("bytes=-", None),
            ("bytes=2-5,6-7", None),
            ("bytes=x-5", None),
            ("bytes=2-x", None),
            ("bytes=+2-5", None),
            ("bytes=2-+5", None),
            ("bytes=2", None),
            ("items=2-5", None),
        ];

        for (header, expected) in test_cases {
            assert_eq!(header.parse::<Range>().ok(), expected);
        }
    }

    #[test]
    fn satisfiable_range_resolves_against_the_complete_length() {
        let test_cases = vec![
            (Range::Bounded(2..=5), 8, 2..=5),
            (Range::Bounded(2..=9), 8, 2..=7),
            (Range::Bounded(0..=0), 1, 0..=0),
            (Range::Suffix(4), 8, 4..=7),
            (Range::Suffix(8), 8, 0..=7),
            (Range::Suffix(9), 8, 0..=7),
        ];

        for (range, complete_length, expected) in test_cases {
            assert_eq!(range.satisfiable_range(complete_length), expected);
        }
    }

    #[test]
    fn content_range_from_str_parses_only_a_valid_satisfied_range() {
        let test_cases = vec![
            ("bytes 2-5/8", Some((2..=5, 8))),
            ("bytes 0-7/8", Some((0..=7, 8))),
            ("bytes 0-0/1", Some((0..=0, 1))),
            (
                "bytes 18446744073709551614-18446744073709551614/18446744073709551615",
                Some((u64::MAX - 1..=u64::MAX - 1, u64::MAX)),
            ),
            ("bytes 2-5/*", None),
            ("bytes */8", None),
            ("items 2-5/8", None),
            ("bytes 2/8", None),
            ("bytes x-5/8", None),
            ("bytes 2-x/8", None),
            ("bytes 2-5/x", None),
            ("bytes +2-5/8", None),
            ("bytes 2-5/+8", None),
            ("bytes 2-5/8/9", None),
            ("bytes 5-2/8", None),
            ("bytes 2-5/5", None),
            ("bytes 2-5/0", None),
            ("bytes 2-5/18446744073709551616", None),
        ];

        for (header, expected) in test_cases {
            let content_range = header
                .parse::<ContentRange>()
                .ok()
                .map(|content_range| (content_range.range, content_range.complete_length));
            assert_eq!(content_range, expected);
        }
    }
}
