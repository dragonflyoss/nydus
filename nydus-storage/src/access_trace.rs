//! Chunk-group-level on-demand access tracing.
//!
//! Records, in first-access order, every chunk group touched by an
//! on-demand (FUSE) read as a `(blob_index, chunk_group_index)` pair. The
//! resulting ordered list is exposed as JSON by the apiserver's `/trace`
//! endpoint and feeds `nydus optimize`, which copies exactly those groups
//! into an ondemand blob the runtime prefetches first. Prefetch reads are
//! not recorded.
//!
//! Each group is recorded once, at the position of its first on-demand
//! access, so the trace stays bounded and reflects the access pattern rather
//! than raw repeat counts.

use std::collections::HashSet;
use std::sync::LazyLock;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Version of the serialized trace document, bumped on incompatible changes.
pub const TRACE_DOCUMENT_VERSION: u32 = 1;

/// A single chunk group access in the on-demand trace.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TraceEntry {
    /// Device/blob index in the merged image (external blobs are 1-based;
    /// device 0 is the primary bootstrap image and never produces chunk
    /// reads).
    pub blob_index: u32,
    /// The accessed chunk group's index within that blob's blob meta.
    pub chunk_group_index: u32,
}

/// The serialized trace document: `{"version":1,"patterns":[...]}`. The
/// explicit format version lets future fields be added (or the pattern shape
/// change) without breaking consumers, and keeps the document self-describing
/// wherever it travels (files, HTTP bodies, embedding hosts).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceDocument {
    pub version: u32,
    /// Serialized as `patterns`.
    #[serde(rename = "patterns")]
    pub entries: Vec<TraceEntry>,
}

impl Default for TraceDocument {
    fn default() -> Self {
        Self {
            version: TRACE_DOCUMENT_VERSION,
            entries: Vec::new(),
        }
    }
}

#[derive(Default)]
struct TraceState {
    entries: Vec<TraceEntry>,
    seen: HashSet<TraceEntry>,
}

#[derive(Default)]
pub struct TraceRecorder {
    state: Mutex<TraceState>,
}

impl TraceRecorder {
    /// Record an on-demand access to chunk group `chunk_group_index` of
    /// `blob_index`. The first access to a given group is appended in
    /// order; later accesses are ignored.
    pub fn record_chunk_group_access(&self, blob_index: u32, chunk_group_index: u32) {
        let entry = TraceEntry {
            blob_index,
            chunk_group_index,
        };
        let mut state = self.state.lock().unwrap();
        if state.seen.insert(entry) {
            state.entries.push(entry);
        }
    }

    /// Return a stable snapshot of the trace collected so far.
    pub fn snapshot(&self) -> TraceDocument {
        let state = self.state.lock().unwrap();
        TraceDocument {
            version: TRACE_DOCUMENT_VERSION,
            entries: state.entries.clone(),
        }
    }

    /// Serialize the current on-demand chunk group access trace as JSON,
    /// e.g. `{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":4}]}`.
    pub fn encode_json(&self) -> String {
        serde_json::to_string(&self.snapshot())
            .unwrap_or_else(|_| "{\"version\":1,\"patterns\":[]}".to_string())
    }

    /// Clear all recorded accesses.
    #[cfg(test)]
    pub fn clear(&self) {
        let mut state = self.state.lock().unwrap();
        state.entries.clear();
        state.seen.clear();
    }
}

static TRACE: LazyLock<TraceRecorder> = LazyLock::new(TraceRecorder::default);

/// Record an on-demand access to a chunk group (see
/// [`TraceRecorder::record_chunk_group_access`]) in the process-global trace.
pub fn record_chunk_group_access(blob_index: u32, chunk_group_index: u32) {
    TRACE.record_chunk_group_access(blob_index, chunk_group_index);
}

/// Serialize the current on-demand chunk group access trace as JSON, e.g.
/// `{"version":1,"patterns":[{"blob_index":1,"chunk_group_index":4}]}`.
pub fn encode_json() -> String {
    TRACE.encode_json()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_json_records_first_access_order_and_dedups() {
        // Use blob indices unique to this test so the assertions are robust
        // against other tests sharing the process-global trace state.
        record_chunk_group_access(9001, 7);
        record_chunk_group_access(9002, 4);
        record_chunk_group_access(9001, 7); // duplicate, ignored
        record_chunk_group_access(9002, 5);

        let json = encode_json();
        let first = json
            .find("{\"blob_index\":9001,\"chunk_group_index\":7}")
            .expect("first access present");
        let second = json
            .find("{\"blob_index\":9002,\"chunk_group_index\":4}")
            .expect("second access present");
        assert!(first < second, "first-access order preserved: {json}");
        assert_eq!(
            json.matches("{\"blob_index\":9001,\"chunk_group_index\":7}")
                .count(),
            1,
            "duplicate deduped: {json}"
        );
    }

    #[test]
    fn recorder_snapshots_and_clears_instance_trace() {
        let recorder = TraceRecorder::default();
        recorder.record_chunk_group_access(1, 4);
        recorder.record_chunk_group_access(1, 4);
        recorder.record_chunk_group_access(2, 7);

        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.version, TRACE_DOCUMENT_VERSION);
        assert_eq!(
            snapshot.entries,
            vec![
                TraceEntry {
                    blob_index: 1,
                    chunk_group_index: 4,
                },
                TraceEntry {
                    blob_index: 2,
                    chunk_group_index: 7,
                },
            ]
        );
        assert_eq!(
            recorder.encode_json(),
            "{\"version\":1,\"patterns\":[{\"blob_index\":1,\"chunk_group_index\":4},{\"blob_index\":2,\"chunk_group_index\":7}]}"
        );

        recorder.clear();
        assert!(recorder.snapshot().entries.is_empty());
        assert_eq!(recorder.encode_json(), "{\"version\":1,\"patterns\":[]}");
    }
}
