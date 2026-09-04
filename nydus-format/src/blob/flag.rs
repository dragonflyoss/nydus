//! Conventions shared by the nydus on-disk record formats (blob meta, blob
//! footer): a `magic + version + flags` header prefix where `flags` is split
//! EROFS-style — the low 16 bits are incompatible features (unknown bits
//! reject the file), the high 16 bits are compatible features (unknown bits
//! are ignored) — and a crc32c computed over the record with the crc field
//! zeroed.

use crate::error::{Error, Result};

/// A format `flags` word, split EROFS-style into the incompatible low half
/// (unknown bits reject the file) and the compatible high half (unknown bits
/// are ignored). Wraps the raw on-disk word verbatim, so compat bits written
/// by a newer writer survive a round trip through this reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeatureFlags(u32);

impl FeatureFlags {
    /// The incompatible (reject-when-unknown) half of the word.
    pub const INCOMPAT_MASK: u32 = 0x0000_FFFF;

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

    /// Reject a word whose incompat half carries bits outside `supported`.
    pub fn validate_incompat(self, supported: u32) -> Result<()> {
        let unknown_incompat = self.0 & Self::INCOMPAT_MASK & !supported;
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
    fn raw_bits_round_trip_verbatim() {
        assert_eq!(FeatureFlags::from_bits(0xdead_beef).bits(), 0xdead_beef);
    }

    #[test]
    fn contains_requires_every_bit() {
        let flags = FeatureFlags::from_bits(0b011);

        assert!(flags.contains(0b001));
        assert!(flags.contains(0b011));
        assert!(!flags.contains(0b100));
        assert!(!flags.contains(0b101));
    }

    #[test]
    fn set_sets_or_clears_only_the_given_bits() {
        let mut flags = FeatureFlags::from_bits(0x8000_0000);

        flags.set(0b001, true);
        flags.set(0b110, true);
        assert_eq!(flags.bits(), 0x8000_0007);

        flags.set(0b010, false);
        assert_eq!(flags.bits(), 0x8000_0005);

        flags.set(0b010, false);
        assert_eq!(flags.bits(), 0x8000_0005);
    }

    #[test]
    fn incompat_validation_follows_the_split_word_rules() {
        let supported = 0b1;
        let cases: [(&str, u32, Option<&str>); 4] = [
            ("empty word", 0, None),
            ("supported incompat bit", 0b1, None),
            ("unknown compat bits are ignored", 0xffff_0001, None),
            (
                "unknown incompat bit",
                0b10,
                Some("unsupported incompat flags"),
            ),
        ];

        for (case, bits, expected) in cases {
            let result = FeatureFlags::from_bits(bits).validate_incompat(supported);
            match expected {
                None => assert!(result.is_ok(), "{case}"),
                Some(message) => {
                    let err = result.unwrap_err();
                    assert!(err.to_string().contains(message), "{case}: {err}");
                }
            }
        }
    }

    #[test]
    fn the_rejection_names_only_the_unknown_bits() {
        let err = FeatureFlags::from_bits(0b111)
            .validate_incompat(0b001)
            .unwrap_err();

        assert!(err.to_string().contains("0x6"), "{err}");
    }
}
