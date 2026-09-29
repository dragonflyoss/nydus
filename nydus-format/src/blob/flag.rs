//! The frozen prefix shared by the blob meta and the blob footer,
//! `magic[0..8] + feature_compat[8..12] + feature_incompat[12..16] +
//! crc32[16..20]`. There is no version field. Compatibility is decided by
//! the feature words alone, EROFS-style. Unknown `feature_compat` bits are
//! ignored, unknown `feature_incompat` bits reject the record, so an
//! incompatible change sets a new incompat bit.

use crate::error::{Error, Result};

/// A `feature_incompat` word, the raw on-disk word verbatim. Every bit is
/// an incompatible feature and an unknown bit rejects the record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeatureFlags(u32);

/// Builds, queries and checks a feature word.
impl FeatureFlags {
    /// A word with no feature bits set.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Wrap a raw on-disk word. Nothing is rejected here, unknown incompat
    /// bits are caught by [`Self::validate_incompat`].
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// The raw on-disk word.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether every bit of `bits` is set.
    pub const fn contains(self, bits: u32) -> bool {
        self.0 & bits == bits
    }

    /// Set or clear every bit of `bits` per `value` (`bitflags::Flags::set`
    /// semantics).
    pub fn set(&mut self, bits: u32, value: bool) {
        if value {
            self.0 |= bits;
        } else {
            self.0 &= !bits;
        }
    }

    /// Reject a word carrying bits outside `supported`.
    pub fn validate_incompat(self, supported: u32) -> Result<()> {
        let unknown_incompat = self.0 & !supported;
        if unknown_incompat != 0 {
            return Err(Error::Unsupported(format!(
                "unsupported incompat flags {unknown_incompat:#x} (image is newer than this reader)"
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bits_keeps_the_bits() {
        assert_eq!(FeatureFlags::empty().bits(), 0);
        assert_eq!(FeatureFlags::from_bits(0xdead_beef).bits(), 0xdead_beef);
    }

    #[test]
    fn contains_requires_every_bit() {
        let flags = FeatureFlags::from_bits(0b011);

        let test_cases = vec![(0b001, true), (0b011, true), (0b100, false), (0b101, false)];

        for (bits, expected) in test_cases {
            assert_eq!(flags.contains(bits), expected);
        }
    }

    #[test]
    fn set_changes_only_the_given_bits() {
        let mut flags = FeatureFlags::from_bits(0x8000_0000);

        let test_cases = vec![
            (0b001, true, 0x8000_0001),
            (0b110, true, 0x8000_0007),
            (0b010, false, 0x8000_0005),
            (0b010, false, 0x8000_0005),
        ];

        for (bits, value, expected) in test_cases {
            flags.set(bits, value);
            assert_eq!(flags.bits(), expected);
        }
    }

    #[test]
    fn validate_incompat_rejects_unknown_bits() {
        let test_cases = vec![
            (0, 0b1, Ok(())),
            (0b1, 0b1, Ok(())),
            (
                0b10,
                0b1,
                Err("unsupported incompat flags 0x2 (image is newer than this reader)"),
            ),
            (
                0x8000_0001,
                0b1,
                Err("unsupported incompat flags 0x80000000 (image is newer than this reader)"),
            ),
            (
                0b111,
                0b001,
                Err("unsupported incompat flags 0x6 (image is newer than this reader)"),
            ),
        ];

        for (bits, supported, expected) in test_cases {
            assert_eq!(
                FeatureFlags::from_bits(bits)
                    .validate_incompat(supported)
                    .map_err(|err| err.to_string()),
                expected.map_err(String::from)
            );
        }
    }
}
