//! The byte ranges of a blob `GET`: the one a read asks for in `Range`, and
//! the one an answer names in `Content-Range`, refer to RFC 9110 Section 14.

use std::fmt;
use std::io;
use std::ops::RangeInclusive;
use std::str::FromStr;

/// The byte range a blob `GET` asks for, sent as the `Range` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GetRange {
    /// The bytes from the first to the last, both included.
    Bounded(RangeInclusive<u64>),

    /// The last bytes of a blob of unknown size, this many of them.
    Suffix(u64),
}

/// Implements the requested byte range.
impl GetRange {
    /// Returns the bytes the range selects of a blob `complete_length` long:
    /// a suffix counts back from the end, and a range past the end stops at
    /// the last byte, refer to RFC 9110 Section 14.1.2.
    pub(crate) fn to_range(&self, complete_length: u64) -> RangeInclusive<u64> {
        let last = complete_length.saturating_sub(1);
        match self {
            GetRange::Bounded(range) => *range.start()..=(*range.end()).min(last),
            GetRange::Suffix(length) => complete_length.saturating_sub(*length)..=last,
        }
    }
}

/// Implements Display as the `Range` header value.
impl fmt::Display for GetRange {
    /// Formats the range as `bytes=first-last` or `bytes=-length`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GetRange::Bounded(range) => write!(f, "bytes={}-{}", range.start(), range.end()),
            GetRange::Suffix(length) => write!(f, "bytes=-{length}"),
        }
    }
}

/// Implements FromStr for the `Range` header value.
impl FromStr for GetRange {
    type Err = io::Error;

    /// Parses `bytes=first-last` or `bytes=-length`, the two forms the range
    /// is formatted as.
    fn from_str(value: &str) -> io::Result<Self> {
        value
            .strip_prefix("bytes=")
            .and_then(|spec| spec.split_once('-'))
            .and_then(|(first, last)| match first {
                "" => Some(GetRange::Suffix(last.parse().ok()?)),
                first => Some(GetRange::Bounded(first.parse().ok()?..=last.parse().ok()?)),
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid Range {value}"))
            })
    }
}

/// The byte range an answer carries, read from the `Content-Range` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContentRange {
    /// The bytes the body holds, both ends included.
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

    /// Parses `bytes first-last/complete-length`, rejecting an unknown `*`
    /// length and the invalid ranges a recipient must not recombine: a last
    /// byte before the first, or a complete length not past the last, refer
    /// to RFC 9110 Section 14.4.
    fn from_str(value: &str) -> io::Result<Self> {
        value
            .strip_prefix("bytes ")
            .and_then(|spec| {
                let (range, complete_length) = spec.split_once('/')?;
                let (first, last) = range.split_once('-')?;
                Some((
                    first.parse::<u64>().ok()?,
                    last.parse::<u64>().ok()?,
                    complete_length.parse::<u64>().ok()?,
                ))
            })
            .filter(|(first, last, complete_length)| first <= last && last < complete_length)
            .map(|(first, last, complete_length)| ContentRange {
                range: first..=last,
                complete_length,
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
    fn get_range_to_string_formats_the_range_header() {
        let test_cases = vec![
            (GetRange::Bounded(0..=0), "bytes=0-0"),
            (GetRange::Bounded(2..=5), "bytes=2-5"),
            (GetRange::Suffix(64), "bytes=-64"),
        ];

        for (range, expected) in test_cases {
            assert_eq!(range.to_string(), expected);
        }
    }

    #[test]
    fn get_range_from_str_parses_a_bounded_or_suffix_range() {
        let test_cases = vec![
            ("bytes=0-0", Some(GetRange::Bounded(0..=0))),
            ("bytes=2-5", Some(GetRange::Bounded(2..=5))),
            ("bytes=-64", Some(GetRange::Suffix(64))),
            ("bytes=2-", None),
            ("bytes=-", None),
            ("bytes=2-5,6-7", None),
            ("bytes=x-5", None),
            ("bytes=2-x", None),
            ("bytes=2", None),
            ("items=2-5", None),
        ];

        for (value, expected) in test_cases {
            assert_eq!(value.parse::<GetRange>().ok(), expected, "{value}");
        }
    }

    #[test]
    fn get_range_to_range_resolves_against_the_complete_length() {
        let test_cases = vec![
            (GetRange::Bounded(2..=5), 8, 2..=5),
            (GetRange::Bounded(2..=9), 8, 2..=7),
            (GetRange::Bounded(0..=0), 1, 0..=0),
            (GetRange::Suffix(4), 8, 4..=7),
            (GetRange::Suffix(8), 8, 0..=7),
            (GetRange::Suffix(9), 8, 0..=7),
        ];

        for (range, complete_length, expected) in test_cases {
            assert_eq!(range.to_range(complete_length), expected, "{range}");
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
            ("bytes 2-5/8/9", None),
            ("bytes 5-2/8", None),
            ("bytes 2-5/5", None),
            ("bytes 2-5/0", None),
            ("bytes 2-5/18446744073709551616", None),
        ];

        for (value, expected) in test_cases {
            let content_range = value
                .parse::<ContentRange>()
                .ok()
                .map(|content_range| (content_range.range, content_range.complete_length));
            assert_eq!(content_range, expected, "{value}");
        }
    }
}
