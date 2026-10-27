//! A [`Backend`] that injects scripted faults, so storage and core tests
//! can make a backend fail, truncate, corrupt or stall chosen reads and
//! count the calls it served.
//!
//! [`FaultBackend`] serves blobs from another backend ([`FaultBackend::wrap`],
//! typically a [`nydus_backend::Local`] over blobs a test saved) or from
//! memory ([`FaultBackend::in_memory`] plus [`FaultBackend::with_blob`]).
//! Faults are [`FaultRule`]s injected at any time; each call applies the
//! first rule that matches it, and every call is logged as a [`ReadCall`].
//!
//! Only reads and blob meta lookups pass through the rules. Cache keys and
//! raw device resolution go straight to the wrapped backend.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::ops::Range;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use nydus_backend::{Backend, RawDeviceFile, ReadKind};
use nydus_format::blob::BlobMetadata;
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_telemetry::metrics::Metrics;

/// A blob id, the SHA-256 digest a backend resolves blobs by.
type BlobId = [u8; SHA256_DIGEST_SIZE];

/// Builds the error a [`Fault::ErrorWith`] fails with.
pub type ErrorFn = Arc<dyn Fn() -> io::Error + Send + Sync>;

/// What a matching call suffers.
#[derive(Clone)]
pub enum Fault {
    /// Fail with an [`io::Error`] of this kind.
    Error(io::ErrorKind),
    /// Fail with the error the function builds, for errors a kind cannot
    /// express.
    ErrorWith(ErrorFn),
    /// Serve only the first `len` bytes of the read, zero the rest of the
    /// buffer and report success: a backend that lost the tail of a
    /// response. Matches only reads longer than `len`.
    ShortRead { len: usize },
    /// Flip bit `bit` (0..8) of the byte at data region offset `offset` and
    /// report success: a backend that served corrupted bytes. Matches only
    /// reads covering `offset`.
    FlipBit { offset: u64, bit: u8 },
    /// Sleep this long, then serve the call normally.
    Delay(Duration),
}

impl Fault {
    fn error(&self) -> Option<io::Error> {
        match self {
            Fault::Error(kind) => Some(io::Error::new(*kind, "injected backend fault")),
            Fault::ErrorWith(make) => Some(make()),
            _ => None,
        }
    }
}

impl fmt::Debug for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::Error(kind) => f.debug_tuple("Error").field(kind).finish(),
            Fault::ErrorWith(_) => f.write_str("ErrorWith(..)"),
            Fault::ShortRead { len } => f.debug_struct("ShortRead").field("len", len).finish(),
            Fault::FlipBit { offset, bit } => f
                .debug_struct("FlipBit")
                .field("offset", offset)
                .field("bit", bit)
                .finish(),
            Fault::Delay(delay) => f.debug_tuple("Delay").field(delay).finish(),
        }
    }
}

/// Which kind of backend call a rule applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Read,
    Metadata,
}

/// A fault and the calls it applies to. A new rule matches every call of
/// its target, without limit; the builder methods narrow it, and all the
/// conditions given must hold.
#[derive(Clone, Debug)]
pub struct FaultRule {
    fault: Fault,
    target: Target,
    blob_id: Option<BlobId>,
    range: Option<Range<u64>>,
    kind: Option<ReadKind>,
    call: Option<usize>,
    remaining: Option<usize>,
}

impl FaultRule {
    /// A rule for data reads ([`Backend::read_range_into`]).
    pub fn read(fault: Fault) -> Self {
        Self::new(fault, Target::Read)
    }

    /// A rule for blob meta lookups ([`Backend::read_blob_metadata`]). Only
    /// the error faults and [`Fault::Delay`] apply to them.
    pub fn metadata(fault: Fault) -> Self {
        Self::new(fault, Target::Metadata)
    }

    fn new(fault: Fault, target: Target) -> Self {
        Self {
            fault,
            target,
            blob_id: None,
            range: None,
            kind: None,
            call: None,
            remaining: None,
        }
    }

    /// Only calls for `blob_id`.
    pub fn on_blob(mut self, blob_id: BlobId) -> Self {
        self.blob_id = Some(blob_id);
        self
    }

    /// Only reads overlapping `range` of the data region.
    pub fn overlapping(mut self, range: Range<u64>) -> Self {
        self.range = Some(range);
        self
    }

    /// Only reads of `kind`.
    pub fn on_kind(mut self, kind: ReadKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Only the `index`th call of the rule's target (0-based, counted over
    /// the backend's lifetime, faulted calls included).
    pub fn on_call(mut self, index: usize) -> Self {
        self.call = Some(index);
        self
    }

    /// Fire at most `count` times, then stop matching.
    pub fn times(mut self, count: usize) -> Self {
        self.remaining = Some(count);
        self
    }

    /// Whether the rule applies to `call`, the `index`th of its target.
    fn matches(&self, call: &Call, index: usize) -> bool {
        if self.target != call.target || self.remaining == Some(0) {
            return false;
        }
        if self.blob_id.is_some_and(|id| id != call.blob_id)
            || self.call.is_some_and(|wanted| wanted != index)
        {
            return false;
        }
        let Some((offset, len, kind)) = call.read else {
            // Metadata lookups carry no range, kind or data to corrupt.
            return self.range.is_none()
                && self.kind.is_none()
                && matches!(
                    self.fault,
                    Fault::Error(_) | Fault::ErrorWith(_) | Fault::Delay(_)
                );
        };
        let end = offset + len as u64;
        if self
            .range
            .as_ref()
            .is_some_and(|range| range.start >= end || offset >= range.end)
            || self.kind.is_some_and(|wanted| wanted != kind)
        {
            return false;
        }
        match self.fault {
            Fault::ShortRead { len: short } => short < len,
            Fault::FlipBit { offset: flip, .. } => (offset..end).contains(&flip),
            _ => true,
        }
    }
}

/// One call as the rules see it.
struct Call {
    target: Target,
    blob_id: BlobId,
    /// `(offset, len, kind)` of a data read.
    read: Option<(u64, usize, ReadKind)>,
}

/// One data read the backend was asked for, in call order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadCall {
    pub blob_id: BlobId,
    /// Offset in the blob's data region.
    pub offset: u64,
    pub len: usize,
    pub kind: ReadKind,
    /// Whether a rule fired on this read.
    pub faulted: bool,
}

impl ReadCall {
    /// The data region range the read asked for.
    pub fn range(&self) -> Range<u64> {
        self.offset..self.offset + self.len as u64
    }
}

/// A blob held in memory: its data region and serialized blob meta.
struct MemoryBlob {
    data: Vec<u8>,
    metadata: Vec<u8>,
}

enum Source {
    Wrapped(Arc<dyn Backend>),
    Memory(HashMap<BlobId, MemoryBlob>),
}

#[derive(Default)]
struct State {
    rules: Vec<FaultRule>,
    reads: Vec<ReadCall>,
    metadata_calls: usize,
}

/// A backend that serves blobs from another backend or from memory and
/// applies the injected [`FaultRule`]s to the calls it serves.
pub struct FaultBackend {
    source: Source,
    state: Mutex<State>,
    metrics: Arc<Metrics>,
}

impl FaultBackend {
    /// Serve the blobs `inner` serves.
    pub fn wrap(inner: Arc<dyn Backend>) -> Self {
        Self {
            metrics: inner.metrics().clone(),
            source: Source::Wrapped(inner),
            state: Mutex::default(),
        }
    }

    /// Serve only the blobs added with [`Self::with_blob`].
    pub fn in_memory() -> Self {
        Self {
            source: Source::Memory(HashMap::new()),
            state: Mutex::default(),
            metrics: Arc::new(Metrics::new()),
        }
    }

    /// Add blob `blob_id` with data region `data` described by
    /// `blob_metadata`, as `nydus_test_utils::metadata` builds them.
    ///
    /// # Panics
    ///
    /// On a backend made by [`Self::wrap`], which serves the wrapped
    /// backend's blobs only.
    pub fn with_blob(
        mut self,
        blob_id: BlobId,
        data: Vec<u8>,
        blob_metadata: &BlobMetadata,
    ) -> Self {
        let Source::Memory(blobs) = &mut self.source else {
            panic!("FaultBackend::with_blob needs a backend made by FaultBackend::in_memory");
        };
        let mut metadata = Vec::new();
        blob_metadata
            .write_to(&mut metadata)
            .expect("serializing blob meta into memory does not fail");
        blobs.insert(blob_id, MemoryBlob { data, metadata });
        self
    }

    /// Add `rule` behind the rules injected before it.
    pub fn inject(&self, rule: FaultRule) {
        self.state().rules.push(rule);
    }

    /// Drop every rule; later calls are served normally.
    pub fn clear_faults(&self) {
        self.state().rules.clear();
    }

    /// Data reads served so far, faulted ones included.
    pub fn read_calls(&self) -> usize {
        self.state().reads.len()
    }

    /// Blob meta lookups served so far, faulted ones included.
    pub fn metadata_calls(&self) -> usize {
        self.state().metadata_calls
    }

    /// Every data read so far, in call order.
    pub fn reads(&self) -> Vec<ReadCall> {
        self.state().reads.clone()
    }

    /// Data reads so far that overlapped `range` of the data region.
    pub fn reads_overlapping(&self, range: Range<u64>) -> usize {
        self.state()
            .reads
            .iter()
            .filter(|read| read.offset < range.end && range.start < read.range().end)
            .count()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Log `call` and return the fault of the first rule matching it,
    /// spending one of that rule's firings.
    fn admit(&self, call: Call) -> Option<Fault> {
        let mut state = self.state();
        let index = match call.target {
            Target::Read => state.reads.len(),
            Target::Metadata => state.metadata_calls,
        };
        let rule = state
            .rules
            .iter_mut()
            .find(|rule| rule.matches(&call, index));
        let fault = rule.map(|rule| {
            if let Some(remaining) = rule.remaining.as_mut() {
                *remaining -= 1;
            }
            rule.fault.clone()
        });
        match call.read {
            Some((offset, len, kind)) => state.reads.push(ReadCall {
                blob_id: call.blob_id,
                offset,
                len,
                kind,
                faulted: fault.is_some(),
            }),
            None => state.metadata_calls += 1,
        }
        fault
    }

    fn serve_read(
        &self,
        blob_id: &BlobId,
        offset: u64,
        dst: &mut [u8],
        kind: ReadKind,
    ) -> io::Result<()> {
        let blobs = match &self.source {
            Source::Wrapped(inner) => {
                return match kind {
                    ReadKind::Ondemand => inner.read_range_into(blob_id, offset, dst),
                    ReadKind::Prefetch => inner.prefetch_range_into(blob_id, offset, dst),
                }
            }
            Source::Memory(blobs) => blobs,
        };
        let blob = blobs.get(blob_id).ok_or_else(|| unknown_blob(blob_id))?;
        let start = usize::try_from(offset).ok();
        let source = start
            .and_then(|start| blob.data.get(start..start.checked_add(dst.len())?))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "backend range read exceeds data region",
                )
            })?;
        dst.copy_from_slice(source);
        Ok(())
    }
}

fn unknown_blob(blob_id: &BlobId) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("blob {} is not in the fault backend", hex::encode(blob_id)),
    )
}

impl Backend for FaultBackend {
    fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    fn full_blob_id(&self, blob_id: &BlobId) -> io::Result<BlobId> {
        match &self.source {
            Source::Wrapped(inner) => inner.full_blob_id(blob_id),
            Source::Memory(_) => Ok(*blob_id),
        }
    }

    fn read_blob_metadata(&self, blob_id: &BlobId) -> io::Result<BlobMetadata> {
        self.metadata(blob_id, ReadKind::Ondemand)
    }

    fn prefetch_blob_metadata(&self, blob_id: &BlobId) -> io::Result<BlobMetadata> {
        self.metadata(blob_id, ReadKind::Prefetch)
    }

    fn is_raw_device(&self, blob_id: &BlobId) -> io::Result<bool> {
        match &self.source {
            Source::Wrapped(inner) => inner.is_raw_device(blob_id),
            Source::Memory(_) => Ok(false),
        }
    }

    fn open_raw_device_file(&self, blob_id: &BlobId) -> io::Result<Option<RawDeviceFile>> {
        match &self.source {
            Source::Wrapped(inner) => inner.open_raw_device_file(blob_id),
            Source::Memory(_) => Ok(None),
        }
    }

    fn read_range_into(&self, blob_id: &BlobId, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        self.read(blob_id, offset, dst, ReadKind::Ondemand)
    }

    fn prefetch_range_into(&self, blob_id: &BlobId, offset: u64, dst: &mut [u8]) -> io::Result<()> {
        self.read(blob_id, offset, dst, ReadKind::Prefetch)
    }
}

impl FaultBackend {
    fn metadata(&self, blob_id: &BlobId, kind: ReadKind) -> io::Result<BlobMetadata> {
        let call = Call {
            target: Target::Metadata,
            blob_id: *blob_id,
            read: None,
        };
        match self.admit(call) {
            Some(Fault::Delay(delay)) => std::thread::sleep(delay),
            Some(fault) => {
                if let Some(err) = fault.error() {
                    return Err(err);
                }
            }
            None => {}
        }
        match &self.source {
            Source::Wrapped(inner) => match kind {
                ReadKind::Ondemand => inner.read_blob_metadata(blob_id),
                ReadKind::Prefetch => inner.prefetch_blob_metadata(blob_id),
            },
            Source::Memory(blobs) => {
                let blob = blobs.get(blob_id).ok_or_else(|| unknown_blob(blob_id))?;
                BlobMetadata::from_bytes(blob.metadata.clone()).map_err(io::Error::other)
            }
        }
    }

    fn read(
        &self,
        blob_id: &BlobId,
        offset: u64,
        dst: &mut [u8],
        kind: ReadKind,
    ) -> io::Result<()> {
        let call = Call {
            target: Target::Read,
            blob_id: *blob_id,
            read: Some((offset, dst.len(), kind)),
        };
        let Some(fault) = self.admit(call) else {
            return self.serve_read(blob_id, offset, dst, kind);
        };
        if let Some(err) = fault.error() {
            return Err(err);
        }
        match fault {
            Fault::Delay(delay) => {
                std::thread::sleep(delay);
                self.serve_read(blob_id, offset, dst, kind)
            }
            Fault::ShortRead { len } => {
                self.serve_read(blob_id, offset, dst, kind)?;
                dst[len..].fill(0);
                Ok(())
            }
            Fault::FlipBit { offset: flip, bit } => {
                self.serve_read(blob_id, offset, dst, kind)?;
                dst[(flip - offset) as usize] ^= 1 << (bit % 8);
                Ok(())
            }
            Fault::Error(_) | Fault::ErrorWith(_) => {
                unreachable!("error faults return above")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::single_chunk_group;

    const BLOB: BlobId = [7u8; SHA256_DIGEST_SIZE];

    fn backend() -> FaultBackend {
        let data: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        let meta = single_chunk_group(&data);
        FaultBackend::in_memory().with_blob(BLOB, data, &meta)
    }

    fn read(
        backend: &FaultBackend,
        offset: u64,
        len: usize,
        kind: ReadKind,
    ) -> io::Result<Vec<u8>> {
        let mut dst = vec![0xeeu8; len];
        match kind {
            ReadKind::Ondemand => backend.read_range_into(&BLOB, offset, &mut dst),
            ReadKind::Prefetch => backend.prefetch_range_into(&BLOB, offset, &mut dst),
        }?;
        Ok(dst)
    }

    fn expected(offset: u64, len: usize) -> Vec<u8> {
        (offset..offset + len as u64).map(|i| i as u8).collect()
    }

    #[test]
    fn serves_memory_blobs_and_logs_calls() {
        let backend = backend();
        assert_eq!(backend.read_blob_metadata(&BLOB).unwrap().chunk_count(), 1);
        assert_eq!(
            read(&backend, 100, 50, ReadKind::Ondemand).unwrap(),
            expected(100, 50)
        );
        assert_eq!(
            read(&backend, 4000, 200, ReadKind::Ondemand)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        let mut dst = [0u8; 1];
        let err = backend
            .read_range_into(&[0u8; 32], 0, &mut dst)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert_eq!(backend.read_calls(), 3);
        assert_eq!(backend.metadata_calls(), 1);
        assert_eq!(backend.reads()[0].range(), 100..150);
        assert_eq!(backend.reads_overlapping(50..101), 1);
        assert_eq!(backend.reads_overlapping(150..4000), 0);
    }

    #[test]
    fn rules_fire_on_matching_calls_only() {
        let backend = backend();
        backend.inject(
            FaultRule::read(Fault::Error(io::ErrorKind::ConnectionReset))
                .overlapping(1000..1001)
                .times(1),
        );
        backend.inject(
            FaultRule::read(Fault::Error(io::ErrorKind::TimedOut)).on_kind(ReadKind::Prefetch),
        );
        backend.inject(FaultRule::read(Fault::ShortRead { len: 3 }).on_call(4));

        assert!(read(&backend, 0, 1000, ReadKind::Ondemand).is_ok());
        let err = read(&backend, 0, 1001, ReadKind::Ondemand).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        // The first rule is spent; the read goes through.
        assert!(read(&backend, 0, 1001, ReadKind::Ondemand).is_ok());
        let err = read(&backend, 0, 10, ReadKind::Prefetch).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let short = read(&backend, 10, 8, ReadKind::Ondemand).unwrap();
        assert_eq!(&short[..3], &expected(10, 3)[..]);
        assert_eq!(&short[3..], &[0u8; 5]);

        let faulted: Vec<bool> = backend.reads().iter().map(|read| read.faulted).collect();
        assert_eq!(faulted, [false, true, false, true, true]);
        backend.clear_faults();
        assert!(read(&backend, 0, 10, ReadKind::Prefetch).is_ok());
    }

    #[test]
    fn flips_one_bit_and_delays() {
        let backend = backend();
        backend.inject(FaultRule::read(Fault::FlipBit { offset: 20, bit: 3 }));
        // A read not covering the offset is untouched.
        assert_eq!(
            read(&backend, 21, 10, ReadKind::Ondemand).unwrap(),
            expected(21, 10)
        );
        let mut want = expected(16, 8);
        want[4] ^= 1 << 3;
        assert_eq!(read(&backend, 16, 8, ReadKind::Ondemand).unwrap(), want);

        backend.clear_faults();
        backend.inject(FaultRule::read(Fault::Delay(Duration::from_millis(30))));
        let start = std::time::Instant::now();
        assert_eq!(
            read(&backend, 0, 4, ReadKind::Ondemand).unwrap(),
            expected(0, 4)
        );
        assert!(start.elapsed() >= Duration::from_millis(30));
    }

    #[test]
    fn metadata_rules_fail_lookups() {
        let backend = backend();
        backend.inject(
            FaultRule::metadata(Fault::ErrorWith(Arc::new(|| {
                io::Error::new(io::ErrorKind::PermissionDenied, "denied")
            })))
            .on_blob(BLOB)
            .times(1),
        );
        // Read-only faults never match a lookup.
        backend.inject(FaultRule::metadata(Fault::ShortRead { len: 0 }));
        let err = backend.read_blob_metadata(&BLOB).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(backend.read_blob_metadata(&BLOB).is_ok());
        assert_eq!(backend.metadata_calls(), 2);
        assert_eq!(backend.read_calls(), 0);
    }

    #[test]
    fn wraps_another_backend() {
        let inner = Arc::new(backend());
        let backend = FaultBackend::wrap(inner.clone());
        backend.inject(FaultRule::read(Fault::Error(io::ErrorKind::TimedOut)).on_call(0));
        assert_eq!(
            read(&backend, 0, 4, ReadKind::Ondemand).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            read(&backend, 0, 4, ReadKind::Ondemand).unwrap(),
            expected(0, 4)
        );
        // Only the call that was served reached the wrapped backend.
        assert_eq!(inner.read_calls(), 1);
        assert_eq!(backend.read_calls(), 2);
    }

    #[test]
    fn wrapped_prefetch_keeps_its_read_kind() {
        let inner = Arc::new(backend());
        inner.inject(
            FaultRule::read(Fault::Error(io::ErrorKind::TimedOut)).on_kind(ReadKind::Ondemand),
        );
        let backend = FaultBackend::wrap(inner.clone());
        assert_eq!(
            read(&backend, 0, 4, ReadKind::Prefetch).unwrap(),
            expected(0, 4)
        );
        assert_eq!(inner.reads()[0].kind, ReadKind::Prefetch);
        backend.inject(FaultRule::metadata(Fault::Error(io::ErrorKind::NotFound)).times(1));
        assert_eq!(
            backend.prefetch_blob_metadata(&BLOB).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert!(backend.prefetch_blob_metadata(&BLOB).is_ok());
        assert_eq!(inner.metadata_calls(), 1);
    }
}
