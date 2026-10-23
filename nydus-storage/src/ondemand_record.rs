//! The ondemand record: every chunk group a workload's on-demand reads
//! touched, in first-access order.
//!
//! The caches append each chunk group once, at its first access, as a
//! `(blob_index, chunk_group_index)` pair to the [`OndemandRecord`] they
//! were opened with. The record is served as JSON by the apiserver's
//! `/trace` endpoint and feeds `nydus optimize`, which copies exactly those
//! chunk groups into an ondemand blob the runtime prefetches first. Prefetch
//! reads are not recorded.

use std::io;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// One chunk group access of the ondemand record.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct OndemandEntry {
    /// The blob's device index in the merged image, 1-based for the
    /// external blobs; device 0 is the bootstrap itself and never produces
    /// chunk reads.
    pub blob_index: u16,

    /// The index of the accessed chunk group in the blob's blob meta.
    pub chunk_group_index: u32,
}

/// The ondemand record of a workload, `{"version":1,"patterns":[...]}`,
/// shared by the image's caches, which append to it as they are read.
///
/// The explicit version lets fields be added, or the entry shape change,
/// without breaking consumers, and keeps the record self-describing wherever
/// it travels: files, HTTP bodies, embedding hosts.
#[derive(Debug, Serialize, Deserialize)]
pub struct OndemandRecord {
    /// The format version of the record, [`OndemandRecord::VERSION`].
    version: u32,

    /// The chunk groups accessed, in first-access order.
    #[serde(rename = "patterns")]
    entries: Mutex<Vec<OndemandEntry>>,
}

/// Implements the default record: the current version, no entries.
impl Default for OndemandRecord {
    fn default() -> Self {
        Self {
            version: Self::VERSION,
            entries: Mutex::new(Vec::new()),
        }
    }
}

/// Implements the ondemand record.
impl OndemandRecord {
    /// The version of the serialized record, bumped on incompatible changes.
    pub const VERSION: u32 = 1;

    /// Parses a record from the JSON [`to_json`](Self::to_json) wrote,
    /// failing with [`io::ErrorKind::Unsupported`] on another version.
    pub fn from_json(json: &[u8]) -> io::Result<Self> {
        let record: Self = serde_json::from_slice(json)?;
        if record.version != Self::VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported ondemand record version {}", record.version),
            ));
        }

        Ok(record)
    }

    /// Appends `entry`. The caches push each chunk group once, at its first
    /// access, so the record stays bounded by the image's chunk groups.
    pub fn push(&self, entry: OndemandEntry) {
        self.entries.lock().unwrap().push(entry);
    }

    /// Returns a copy of the entries recorded so far.
    pub fn entries(&self) -> Vec<OndemandEntry> {
        self.entries.lock().unwrap().clone()
    }

    /// Serializes the record as JSON, such as
    /// `{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":4}]}`.
    pub fn to_json(&self) -> io::Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_keeps_first_access_order() {
        let record = OndemandRecord::default();
        record.push(OndemandEntry {
            blob_index: 9001,
            chunk_group_index: 7,
        });
        record.push(OndemandEntry {
            blob_index: 9002,
            chunk_group_index: 4,
        });
        record.push(OndemandEntry {
            blob_index: 9002,
            chunk_group_index: 5,
        });

        assert_eq!(
            record.entries(),
            vec![
                OndemandEntry {
                    blob_index: 9001,
                    chunk_group_index: 7,
                },
                OndemandEntry {
                    blob_index: 9002,
                    chunk_group_index: 4,
                },
                OndemandEntry {
                    blob_index: 9002,
                    chunk_group_index: 5,
                },
            ]
        );
    }

    #[test]
    fn to_json_round_trips_through_from_json() {
        let record = OndemandRecord::default();
        assert_eq!(record.to_json().unwrap(), "{\"version\":1,\"patterns\":[]}");

        record.push(OndemandEntry {
            blob_index: 1,
            chunk_group_index: 4,
        });
        record.push(OndemandEntry {
            blob_index: 2,
            chunk_group_index: 7,
        });
        let json = record.to_json().unwrap();
        assert_eq!(
            json,
            "{\"version\":1,\"patterns\":[{\"blob_index\":1,\"chunk_group_index\":4},{\"blob_index\":2,\"chunk_group_index\":7}]}"
        );
        assert_eq!(
            OndemandRecord::from_json(json.as_bytes())
                .unwrap()
                .entries(),
            record.entries()
        );
    }

    #[test]
    fn from_json_rejects_another_version_and_a_record_without_one() {
        let test_cases = vec![
            (
                &br#"{"version":2,"patterns":[]}"#[..],
                io::ErrorKind::Unsupported,
            ),
            (&br#"{"patterns":[]}"#[..], io::ErrorKind::InvalidData),
            (&b"not json"[..], io::ErrorKind::InvalidData),
        ];

        for (json, expected) in test_cases {
            assert_eq!(
                OndemandRecord::from_json(json).unwrap_err().kind(),
                expected
            );
        }
    }
}
