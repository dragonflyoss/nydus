//! On-demand access tracing at chunk group granularity.
//!
//! Every chunk group an on-demand read touches is recorded once, at its
//! first access, as a `(blob_index, chunk_group_index)` pair into the
//! [`TraceRecorder`] the image's caches were opened with. The ordered list
//! is served as JSON by the apiserver's `/trace` endpoint and feeds `nydus
//! optimize`, which copies exactly those groups into an ondemand blob the
//! runtime prefetches first. Prefetch reads are not recorded.

use std::collections::HashSet;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// The version of the serialized trace document, bumped on incompatible
/// changes.
pub const TRACE_DOCUMENT_VERSION: u32 = 1;

/// One chunk group access of the on-demand trace.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TraceEntry {
    /// The blob's device index in the merged image, 1-based for the
    /// external blobs; device 0 is the bootstrap itself and never produces
    /// chunk reads.
    pub blob_index: u16,

    /// The index of the accessed chunk group in the blob's blob meta.
    pub chunk_group_index: u32,
}

/// The serialized trace document, `{"version":1,"patterns":[...]}`.
///
/// The explicit version lets fields be added, or the pattern shape change,
/// without breaking consumers, and keeps the document self-describing
/// wherever it travels: files, HTTP bodies, embedding hosts.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceDocument {
    /// The format version of the document, [`TRACE_DOCUMENT_VERSION`].
    pub version: u32,

    /// The chunk groups accessed, in first-access order.
    #[serde(rename = "patterns")]
    pub entries: Vec<TraceEntry>,
}

/// Implements the default trace document: the current version, no entries.
impl Default for TraceDocument {
    fn default() -> Self {
        Self {
            version: TRACE_DOCUMENT_VERSION,
            entries: Vec::new(),
        }
    }
}

/// The accesses recorded so far.
#[derive(Default)]
struct TraceState {
    /// The entries in first-access order.
    entries: Vec<TraceEntry>,

    /// The entries recorded, so a chunk group is appended once.
    seen: HashSet<TraceEntry>,
}

/// The recorder of an image's on-demand chunk group accesses.
#[derive(Default)]
pub struct TraceRecorder {
    /// The accesses recorded so far.
    state: Mutex<TraceState>,
}

/// Implements the trace recorder.
impl TraceRecorder {
    /// Records an on-demand access to chunk group `chunk_group_index` of
    /// blob `blob_index`, appended at its first access and ignored after.
    pub fn record_chunk_group_access(&self, blob_index: u16, chunk_group_index: u32) {
        let entry = TraceEntry {
            blob_index,
            chunk_group_index,
        };
        let mut state = self.state.lock().unwrap();
        if state.seen.insert(entry) {
            state.entries.push(entry);
        }
    }

    /// Returns a snapshot of the trace collected so far.
    pub fn snapshot(&self) -> TraceDocument {
        TraceDocument {
            version: TRACE_DOCUMENT_VERSION,
            entries: self.state.lock().unwrap().entries.clone(),
        }
    }

    /// Serializes the trace collected so far as JSON, such as
    /// `{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":4}]}`.
    pub fn encode_json(&self) -> String {
        serde_json::to_string(&self.snapshot()).expect("a trace document is plain data")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_chunk_group_access_keeps_first_access_order_and_dedups() {
        let recorder = TraceRecorder::default();
        recorder.record_chunk_group_access(9001, 7);
        recorder.record_chunk_group_access(9002, 4);
        recorder.record_chunk_group_access(9001, 7);
        recorder.record_chunk_group_access(9002, 5);

        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.version, TRACE_DOCUMENT_VERSION);
        assert_eq!(
            snapshot.entries,
            vec![
                TraceEntry {
                    blob_index: 9001,
                    chunk_group_index: 7,
                },
                TraceEntry {
                    blob_index: 9002,
                    chunk_group_index: 4,
                },
                TraceEntry {
                    blob_index: 9002,
                    chunk_group_index: 5,
                },
            ]
        );
    }

    #[test]
    fn encode_json_writes_the_versioned_document() {
        let recorder = TraceRecorder::default();
        assert_eq!(recorder.encode_json(), "{\"version\":1,\"patterns\":[]}");

        recorder.record_chunk_group_access(1, 4);
        recorder.record_chunk_group_access(1, 4);
        recorder.record_chunk_group_access(2, 7);
        assert_eq!(
            recorder.encode_json(),
            "{\"version\":1,\"patterns\":[{\"blob_index\":1,\"chunk_group_index\":4},{\"blob_index\":2,\"chunk_group_index\":7}]}"
        );
    }
}
