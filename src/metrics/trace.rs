//! Group-level on-demand access tracing.
//!
//! Records, in first-access order, every blob meta group touched by an
//! on-demand (FUSE) read as a `(blob_index, group_index)` pair. The resulting
//! ordered list is exposed as JSON by the apiserver's `/trace` endpoint and is
//! intended to seed future prefetch ordering. Prefetch reads are not recorded.
//!
//! Each group is recorded once, at the position of its first on-demand access,
//! so the trace stays bounded and reflects the access pattern rather than raw
//! repeat counts.

use std::collections::HashSet;
use std::sync::LazyLock;
use std::sync::Mutex;

use serde::Serialize;

/// A single group access in the on-demand trace.
#[derive(Debug, Clone, Copy, Serialize)]
struct GroupAccess {
    /// Device/blob index in the merged image (external blobs are 1-based;
    /// device 0 is the primary bootstrap image and never produces group reads).
    blob_index: u32,
    /// Group index within that blob's blob meta.
    group_index: u32,
}

/// The serialized trace document. Wrapped in a struct (rather than a bare array)
/// so future fields can be added without breaking consumers.
#[derive(Debug, Default, Serialize)]
struct TraceDocument {
    patterns: Vec<GroupAccess>,
}

#[derive(Default)]
struct TraceState {
    patterns: Vec<GroupAccess>,
    seen: HashSet<(u32, u32)>,
}

static TRACE: LazyLock<Mutex<TraceState>> = LazyLock::new(|| Mutex::new(TraceState::default()));

/// Record an on-demand access to `(blob_index, group_index)`. The first access
/// to a given pair is appended in order; later accesses to the same pair are
/// ignored so the trace captures the access pattern without unbounded growth.
pub fn record_group_access(blob_index: u32, group_index: u32) {
    let mut state = TRACE.lock().unwrap();
    if state.seen.insert((blob_index, group_index)) {
        state.patterns.push(GroupAccess {
            blob_index,
            group_index,
        });
    }
}

/// Serialize the current on-demand group access trace as JSON, e.g.
/// `{"patterns":[{"blob_index":1,"group_index":4}]}`.
pub fn encode_json() -> String {
    let state = TRACE.lock().unwrap();
    let doc = TraceDocument {
        patterns: state.patterns.clone(),
    };
    serde_json::to_string(&doc).unwrap_or_else(|_| "{\"patterns\":[]}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_json_records_first_access_order_and_dedups() {
        // Use blob indices unique to this test so the assertions are robust
        // against other tests sharing the process-global trace state.
        record_group_access(9001, 7);
        record_group_access(9002, 4);
        record_group_access(9001, 7); // duplicate, ignored
        record_group_access(9002, 5);

        let json = encode_json();
        let first = json
            .find("{\"blob_index\":9001,\"group_index\":7}")
            .expect("first access present");
        let second = json
            .find("{\"blob_index\":9002,\"group_index\":4}")
            .expect("second access present");
        assert!(first < second, "first-access order preserved: {json}");
        assert_eq!(
            json.matches("{\"blob_index\":9001,\"group_index\":7}")
                .count(),
            1,
            "duplicate deduped: {json}"
        );
    }
}
