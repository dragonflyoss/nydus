//! Block group-level on-demand access tracing.
//!
//! Records, in first-access order, every blob meta block group touched by an
//! on-demand (FUSE) read as a `(blob_index, block_group_index)` pair. The resulting
//! ordered list is exposed as JSON by the apiserver's `/trace` endpoint and is
//! intended to seed future prefetch ordering. Prefetch reads are not recorded.
//!
//! Each block group is recorded once, at the position of its first on-demand access,
//! so the trace stays bounded and reflects the access pattern rather than raw
//! repeat counts.

use std::collections::HashSet;
use std::sync::LazyLock;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Version of the serialized trace document, bumped on incompatible changes.
pub const TRACE_DOCUMENT_VERSION: u32 = 1;

/// A single block group access in the on-demand trace.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceEntry {
    /// Device/blob index in the merged image (external blobs are 1-based;
    /// device 0 is the primary bootstrap image and never produces block group reads).
    pub blob_index: u32,
    /// Block group index within that blob's blob meta.
    pub block_group_index: u32,
}

/// The serialized trace document: `{"version":1,"patterns":[...]}`. The
/// explicit format version lets future fields be added (or the pattern shape
/// change) without breaking consumers, and keeps the document self-describing
/// wherever it travels (files, HTTP bodies, embedding hosts).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TraceDocument {
    pub version: u32,
    /// Serialized as `patterns` — the `/trace` wire key predates the rename
    /// and is asserted byte-for-byte by consumers.
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
    seen: HashSet<(u32, u32)>,
}

#[derive(Default)]
pub struct TraceRecorder {
    state: Mutex<TraceState>,
}

impl TraceRecorder {
    /// Record an on-demand access to `(blob_index, block_group_index)`. The first
    /// access to a given pair is appended in order; later accesses to the same
    /// pair are ignored.
    pub fn record_block_group_access(&self, blob_index: u32, block_group_index: u32) {
        let mut state = self.state.lock().unwrap();
        if state.seen.insert((blob_index, block_group_index)) {
            state.entries.push(TraceEntry {
                blob_index,
                block_group_index,
            });
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

    /// Serialize the current on-demand block group access trace as JSON, e.g.
    /// `{"version":1,"patterns":[{"blob_index":1,"block_group_index":4}]}`.
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

/// Record an on-demand access to `(blob_index, block_group_index)`. The first access
/// to a given pair is appended in order; later accesses to the same pair are
/// ignored so the trace captures the access pattern without unbounded growth.
pub fn record_block_group_access(blob_index: u32, block_group_index: u32) {
    TRACE.record_block_group_access(blob_index, block_group_index);
}

/// Serialize the current on-demand block group access trace as JSON, e.g.
/// `{"version":1,"patterns":[{"blob_index":1,"block_group_index":4}]}`.
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
        record_block_group_access(9001, 7);
        record_block_group_access(9002, 4);
        record_block_group_access(9001, 7); // duplicate, ignored
        record_block_group_access(9002, 5);

        let json = encode_json();
        let first = json
            .find("{\"blob_index\":9001,\"block_group_index\":7}")
            .expect("first access present");
        let second = json
            .find("{\"blob_index\":9002,\"block_group_index\":4}")
            .expect("second access present");
        assert!(first < second, "first-access order preserved: {json}");
        assert_eq!(
            json.matches("{\"blob_index\":9001,\"block_group_index\":7}")
                .count(),
            1,
            "duplicate deduped: {json}"
        );
    }

    #[test]
    fn recorder_snapshots_and_clears_instance_trace() {
        let recorder = TraceRecorder::default();
        recorder.record_block_group_access(1, 4);
        recorder.record_block_group_access(1, 4);
        recorder.record_block_group_access(2, 7);

        let snapshot = recorder.snapshot();
        assert_eq!(snapshot.version, TRACE_DOCUMENT_VERSION);
        assert_eq!(
            snapshot.entries,
            vec![
                TraceEntry {
                    blob_index: 1,
                    block_group_index: 4,
                },
                TraceEntry {
                    blob_index: 2,
                    block_group_index: 7,
                },
            ]
        );
        assert_eq!(
            recorder.encode_json(),
            "{\"version\":1,\"patterns\":[{\"blob_index\":1,\"block_group_index\":4},{\"blob_index\":2,\"block_group_index\":7}]}"
        );

        recorder.clear();
        assert!(recorder.snapshot().entries.is_empty());
    }
}
