//! A [`Backend`] that injects scripted faults, so storage and core tests
//! can make a backend fail, truncate, corrupt or stall chosen reads and
//! count the calls it served.
//!
//! [`FaultBackend`] serves blobs from another backend ([`FaultBackend::wrap`],
//! typically a [`nydus_backend::Local`] over blobs a test saved) or from
//! memory ([`FaultBackend::in_memory`] plus [`FaultBackend::with_blob`]).
//! Faults are [`FaultRule`]s injected at any time; each call applies the
//! first rule that matches it, and every data read is logged as a
//! [`ReadCall`].
//!
//! Only reads and blob meta lookups pass through the rules. Cache keys and
//! raw device resolution go straight to the wrapped backend.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, BufRead, Read};
use std::ops::Range;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use nydus_backend::{Backend, RawDeviceFile, ReadKind};
use nydus_format::blob::BlobMetadata;
use nydus_format::utils::SHA256_DIGEST_SIZE;
use nydus_telemetry::metrics::Metrics;

/// The blob id, the SHA-256 digest a backend resolves blobs by.
type BlobId = [u8; SHA256_DIGEST_SIZE];

/// The function building the error a [`Fault::ErrorWith`] fails with.
pub type ErrorFn = Arc<dyn Fn() -> io::Error + Send + Sync>;

/// The fault a matching call suffers.
#[derive(Clone)]
pub enum Fault {
    /// Fails with an [`io::Error`] of this kind.
    Error(io::ErrorKind),

    /// Fails with the error the function builds, for errors a kind cannot
    /// express.
    ErrorWith(ErrorFn),

    /// Serves only the first `len` bytes and zeroes the rest, matching reads
    /// longer than `len`.
    ShortRead {
        /// The number of bytes served.
        len: usize,
    },

    /// Serves only the first `len` bytes and ends the read there, matching
    /// reads longer than `len`.
    Truncate {
        /// The number of bytes served.
        len: usize,
    },

    /// Flips bit `bit` of the byte at `offset`, matching reads covering it.
    FlipBit {
        /// The data region offset of the byte to corrupt.
        offset: u64,

        /// The index of the bit to flip, modulo 8.
        bit: u8,
    },

    /// Sleeps this long, then serves the call normally.
    Delay(Duration),
}

/// Implements the fault.
impl Fault {
    /// Applies the error or delay of the fault before the call is served.
    fn fail_or_delay(&self) -> io::Result<()> {
        match self {
            Fault::Error(kind) => Err(io::Error::new(*kind, "injected backend fault")),
            Fault::ErrorWith(make) => Err(make()),
            Fault::Delay(delay) => {
                std::thread::sleep(*delay);
                Ok(())
            }
            Fault::ShortRead { .. } | Fault::Truncate { .. } | Fault::FlipBit { .. } => Ok(()),
        }
    }
}

/// Implements [`fmt::Debug`] for the fault, which [`ErrorFn`] lacks.
impl fmt::Debug for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fault::Error(kind) => f.debug_tuple("Error").field(kind).finish(),
            Fault::ErrorWith(_) => f.write_str("ErrorWith(..)"),
            Fault::ShortRead { len } => f.debug_struct("ShortRead").field("len", len).finish(),
            Fault::Truncate { len } => f.debug_struct("Truncate").field("len", len).finish(),
            Fault::FlipBit { offset, bit } => f
                .debug_struct("FlipBit")
                .field("offset", offset)
                .field("bit", bit)
                .finish(),
            Fault::Delay(delay) => f.debug_tuple("Delay").field(delay).finish(),
        }
    }
}

/// The kind of backend call a rule applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    /// A data read.
    Read,

    /// A blob meta lookup.
    Metadata,
}

/// A fault and the calls it applies to, narrowed by the builder methods.
#[derive(Clone, Debug)]
pub struct FaultRule {
    /// The fault a matching call suffers.
    fault: Fault,

    /// The kind of call the rule applies to.
    target: Target,

    /// The only blob the rule applies to.
    blob_id: Option<BlobId>,

    /// The data region range a matching read overlaps.
    range: Option<Range<u64>>,

    /// The only read kind the rule applies to.
    kind: Option<ReadKind>,

    /// The only call index of the target the rule applies to.
    call: Option<usize>,

    /// The firings left, unlimited when unset.
    remaining: Option<usize>,
}

/// Implements the fault rule.
impl FaultRule {
    /// Creates a rule for data reads ([`Backend::read`] and
    /// [`Backend::prefetch`]).
    pub fn read(fault: Fault) -> Self {
        Self::new(fault, Target::Read)
    }

    /// Creates a rule for blob meta lookups, which suffer only error and delay
    /// faults.
    pub fn metadata(fault: Fault) -> Self {
        Self::new(fault, Target::Metadata)
    }

    /// Creates a rule matching every call of `target`.
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

    /// Narrows the rule to the calls for `blob_id`.
    pub fn on_blob(mut self, blob_id: BlobId) -> Self {
        self.blob_id = Some(blob_id);
        self
    }

    /// Narrows the rule to the reads overlapping `range` of the data region.
    pub fn overlapping(mut self, range: Range<u64>) -> Self {
        self.range = Some(range);
        self
    }

    /// Narrows the rule to the reads of `kind`.
    pub fn on_kind(mut self, kind: ReadKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Narrows the rule to the `index`th call of its target, counted from 0
    /// over the backend's lifetime, faulted calls included.
    pub fn on_call(mut self, index: usize) -> Self {
        self.call = Some(index);
        self
    }

    /// Limits the rule to `count` firings, after which it stops matching.
    pub fn times(mut self, count: usize) -> Self {
        self.remaining = Some(count);
        self
    }

    /// Returns whether the rule applies to `call`, the `index`th call of its
    /// target.
    fn matches(&self, call: &Call, index: usize) -> bool {
        if self.target != call.target || self.remaining == Some(0) {
            return false;
        }

        if self.blob_id.is_some_and(|id| id != call.blob_id)
            || self.call.is_some_and(|wanted| wanted != index)
        {
            return false;
        }

        // Match a blob meta lookup only without read conditions.
        let Some((offset, len, kind)) = call.read else {
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
            Fault::ShortRead { len: short } | Fault::Truncate { len: short } => short < len,
            Fault::FlipBit { offset: flip, .. } => (offset..end).contains(&flip),
            _ => true,
        }
    }
}

/// The call as the rules see it.
struct Call {
    /// The kind of call.
    target: Target,

    /// The blob the call is for.
    blob_id: BlobId,

    /// The `(offset, len, kind)` of a data read, unset for a meta lookup.
    read: Option<(u64, usize, ReadKind)>,
}

/// The data read the backend was asked for, logged in call order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadCall {
    /// The blob read.
    pub blob_id: BlobId,

    /// The offset in the blob's data region.
    pub offset: u64,

    /// The length of the read.
    pub len: usize,

    /// The kind of the read.
    pub kind: ReadKind,

    /// Whether a rule fired on the read.
    pub faulted: bool,
}

/// Implements the logged data read.
impl ReadCall {
    /// Returns the data region range the read asked for.
    pub fn range(&self) -> Range<u64> {
        self.offset..self.offset + self.len as u64
    }
}

/// The blob held in memory.
struct MemoryBlob {
    /// The data region.
    data: Vec<u8>,

    /// The serialized blob meta.
    metadata: Vec<u8>,
}

/// The blobs the backend serves.
enum Source {
    /// The blobs another backend serves.
    Wrapped(Arc<dyn Backend>),

    /// The blobs held in memory, by blob id.
    Memory(HashMap<BlobId, MemoryBlob>),
}

/// The injected rules and the log of the calls served.
#[derive(Default)]
struct State {
    /// The injected rules, the first matching one firing.
    rules: Vec<FaultRule>,

    /// The data reads served, in call order.
    reads: Vec<ReadCall>,

    /// The number of blob meta lookups served.
    metadata_calls: usize,
}

/// A backend that serves blobs from another backend or from memory and
/// applies the injected [`FaultRule`]s to the calls it serves.
pub struct FaultBackend {
    /// The blobs the backend serves.
    source: Source,

    /// The injected rules and the log of the calls served.
    state: Mutex<State>,

    /// The metrics of the image, the wrapped backend's when wrapping one.
    metrics: Arc<Metrics>,
}

/// Implements the fault-injecting backend.
impl FaultBackend {
    /// Creates a backend serving the blobs `inner` serves.
    pub fn wrap(inner: Arc<dyn Backend>) -> Self {
        Self {
            metrics: inner.metrics().clone(),
            source: Source::Wrapped(inner),
            state: Mutex::default(),
        }
    }

    /// Creates a backend serving only blobs added with [`Self::with_blob`].
    pub fn in_memory() -> Self {
        Self {
            source: Source::Memory(HashMap::new()),
            state: Mutex::default(),
            metrics: Arc::new(Metrics::new()),
        }
    }

    /// Adds blob `blob_id` with data region `data` described by
    /// `blob_metadata`, as [`crate::metadata`] builds them.
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

    /// Adds `rule` behind the rules injected before it.
    pub fn inject(&self, rule: FaultRule) {
        self.state().rules.push(rule);
    }

    /// Removes every rule, so later calls are served normally.
    pub fn clear_faults(&self) {
        self.state().rules.clear();
    }

    /// Returns the number of data reads, faulted ones included.
    pub fn read_calls(&self) -> usize {
        self.state().reads.len()
    }

    /// Returns the number of blob meta lookups, faulted ones included.
    pub fn metadata_calls(&self) -> usize {
        self.state().metadata_calls
    }

    /// Returns every data read in call order.
    pub fn reads(&self) -> Vec<ReadCall> {
        self.state().reads.clone()
    }

    /// Returns the number of data reads overlapping `range`.
    pub fn reads_overlapping(&self, range: Range<u64>) -> usize {
        self.state()
            .reads
            .iter()
            .filter(|read| read.offset < range.end && range.start < read.range().end)
            .count()
    }

    /// Locks the state, recovering it from a test that panicked holding it.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Logs `call` and returns the fault of the first rule matching it,
    /// spending one of that rule's firings.
    fn admit(&self, call: Call) -> Option<Fault> {
        let mut state = self.state();
        let index = match call.target {
            Target::Read => state.reads.len(),
            Target::Metadata => state.metadata_calls,
        };

        let fault = state
            .rules
            .iter_mut()
            .find(|rule| rule.matches(&call, index))
            .map(|rule| {
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

    /// Serves `len` bytes from `offset` for a read of `kind`, faults applied.
    fn serve(
        &self,
        blob_id: &BlobId,
        offset: u64,
        len: usize,
        kind: ReadKind,
    ) -> io::Result<Box<dyn BufRead + Send>> {
        let fault = self.admit(Call {
            target: Target::Read,
            blob_id: *blob_id,
            read: Some((offset, len, kind)),
        });
        if let Some(fault) = &fault {
            fault.fail_or_delay()?;
        }

        let mut buf = vec![0; len];
        match &self.source {
            Source::Wrapped(inner) => match kind {
                ReadKind::Ondemand => inner.read(blob_id, offset, len)?,
                ReadKind::Prefetch => inner.prefetch(blob_id, offset, len)?,
            }
            .read_exact(&mut buf)?,
            Source::Memory(blobs) => {
                let blob = blobs.get(blob_id).ok_or_else(|| unknown_blob(blob_id))?;
                let data = usize::try_from(offset)
                    .ok()
                    .and_then(|start| blob.data.get(start..start.checked_add(buf.len())?))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "backend range read exceeds data region",
                        )
                    })?;
                buf.copy_from_slice(data);
            }
        }

        // Corrupt the bytes served for a short read, a truncated read or a
        // flipped bit.
        match fault {
            Some(Fault::ShortRead { len }) => buf[len..].fill(0),
            Some(Fault::Truncate { len }) => buf.truncate(len),
            Some(Fault::FlipBit { offset: flip, bit }) => {
                buf[(flip - offset) as usize] ^= 1 << (bit % 8)
            }
            _ => {}
        }

        Ok(Box::new(io::Cursor::new(buf)))
    }
}

/// Returns the error for `blob_id` missing from an in-memory backend.
fn unknown_blob(blob_id: &BlobId) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("blob {} is not in the fault backend", hex::encode(blob_id)),
    )
}

/// Implements the blob backend over the injected faults.
impl Backend for FaultBackend {
    /// Returns the metrics of the image.
    fn metrics(&self) -> &Arc<Metrics> {
        &self.metrics
    }

    /// Returns the full blob digest, `blob_id` itself in memory.
    fn full_blob_id(&self, blob_id: &BlobId) -> io::Result<BlobId> {
        match &self.source {
            Source::Wrapped(inner) => inner.full_blob_id(blob_id),
            Source::Memory(_) => Ok(*blob_id),
        }
    }

    /// Reads the blob's metadata for an on-demand read, faults applied.
    fn read_blob_metadata(&self, blob_id: &BlobId) -> io::Result<BlobMetadata> {
        if let Some(fault) = self.admit(Call {
            target: Target::Metadata,
            blob_id: *blob_id,
            read: None,
        }) {
            fault.fail_or_delay()?;
        }

        match &self.source {
            Source::Wrapped(inner) => inner.read_blob_metadata(blob_id),
            Source::Memory(blobs) => {
                let blob = blobs.get(blob_id).ok_or_else(|| unknown_blob(blob_id))?;
                BlobMetadata::from_bytes(blob.metadata.clone()).map_err(io::Error::other)
            }
        }
    }

    /// Reads the blob's metadata for a prefetch read, faults applied.
    fn prefetch_blob_metadata(&self, blob_id: &BlobId) -> io::Result<BlobMetadata> {
        if let Some(fault) = self.admit(Call {
            target: Target::Metadata,
            blob_id: *blob_id,
            read: None,
        }) {
            fault.fail_or_delay()?;
        }

        match &self.source {
            Source::Wrapped(inner) => inner.prefetch_blob_metadata(blob_id),
            Source::Memory(blobs) => {
                let blob = blobs.get(blob_id).ok_or_else(|| unknown_blob(blob_id))?;
                BlobMetadata::from_bytes(blob.metadata.clone()).map_err(io::Error::other)
            }
        }
    }

    /// Returns whether the blob is a raw device, never in memory.
    fn is_raw_device(&self, blob_id: &BlobId) -> io::Result<bool> {
        match &self.source {
            Source::Wrapped(inner) => inner.is_raw_device(blob_id),
            Source::Memory(_) => Ok(false),
        }
    }

    /// Opens the wrapped backend's raw device file, none in memory.
    fn open_raw_device_file(&self, blob_id: &BlobId) -> io::Result<Option<RawDeviceFile>> {
        match &self.source {
            Source::Wrapped(inner) => inner.open_raw_device_file(blob_id),
            Source::Memory(_) => Ok(None),
        }
    }

    /// Reads `len` bytes from `offset` for an on-demand read, faults applied.
    fn read(
        &self,
        blob_id: &BlobId,
        offset: u64,
        len: usize,
    ) -> io::Result<Box<dyn BufRead + Send>> {
        self.serve(blob_id, offset, len, ReadKind::Ondemand)
    }

    /// Reads `len` bytes from `offset` for a prefetch read, faults applied.
    fn prefetch(
        &self,
        blob_id: &BlobId,
        offset: u64,
        len: usize,
    ) -> io::Result<Box<dyn BufRead + Send>> {
        self.serve(blob_id, offset, len, ReadKind::Prefetch)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;
    use crate::metadata::single_chunk_group;
    use std::time::Instant;

    const BLOB_ID: BlobId = [7u8; SHA256_DIGEST_SIZE];

    fn backend() -> FaultBackend {
        let data = blob_data(0, 4096);
        let blob_metadata = single_chunk_group(&data);
        FaultBackend::in_memory().with_blob(BLOB_ID, data, &blob_metadata)
    }

    fn blob_data(offset: u64, len: usize) -> Vec<u8> {
        (offset..offset + len as u64).map(|i| i as u8).collect()
    }

    fn read(backend: &FaultBackend, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        backend.read(&BLOB_ID, offset, len)?.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn prefetch(backend: &FaultBackend, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        backend
            .prefetch(&BLOB_ID, offset, len)?
            .read_to_end(&mut buf)?;
        Ok(buf)
    }

    #[test]
    fn in_memory_serves_blobs_and_logs_every_call() {
        let backend = backend();

        let blob_metadata = backend.read_blob_metadata(&BLOB_ID).unwrap();
        let data = read(&backend, 100, 50).unwrap();
        let eof_err = read(&backend, 4000, 200).unwrap_err();
        let unknown_err = backend
            .read(&[0u8; SHA256_DIGEST_SIZE], 0, 1)
            .err()
            .unwrap();

        assert_eq!(blob_metadata.chunk_count(), 1);
        assert_eq!(data, blob_data(100, 50));
        assert_eq!(eof_err.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(unknown_err.kind(), io::ErrorKind::NotFound);
        assert_eq!(backend.read_calls(), 3);
        assert_eq!(backend.metadata_calls(), 1);
        assert_eq!(backend.reads()[0].range(), 100..150);
        assert_eq!(backend.reads_overlapping(50..101), 1);
        assert_eq!(backend.reads_overlapping(150..4000), 0);
    }

    #[test]
    fn inject_fires_rules_on_matching_calls_only() {
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

        assert_eq!(read(&backend, 0, 1000).unwrap(), blob_data(0, 1000));
        assert_eq!(
            read(&backend, 0, 1001).unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        assert_eq!(read(&backend, 0, 1001).unwrap(), blob_data(0, 1001));
        assert_eq!(
            prefetch(&backend, 0, 10).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            read(&backend, 10, 8).unwrap(),
            [blob_data(10, 3), vec![0; 5]].concat()
        );

        let faulted: Vec<bool> = backend.reads().iter().map(|read| read.faulted).collect();
        assert_eq!(faulted, [false, true, false, true, true]);
    }

    #[test]
    fn clear_faults_serves_later_calls_normally() {
        let backend = backend();
        backend.inject(FaultRule::read(Fault::Error(io::ErrorKind::TimedOut)));

        backend.clear_faults();

        assert_eq!(prefetch(&backend, 0, 10).unwrap(), blob_data(0, 10));
    }

    #[test]
    fn read_corrupts_only_the_reads_a_fault_covers() {
        let mut flipped = blob_data(16, 8);
        flipped[4] ^= 1 << 3;
        let test_cases = vec![
            (
                Fault::ShortRead { len: 3 },
                10,
                8,
                [blob_data(10, 3), vec![0; 5]].concat(),
            ),
            (Fault::ShortRead { len: 8 }, 10, 8, blob_data(10, 8)),
            (Fault::Truncate { len: 3 }, 10, 8, blob_data(10, 3)),
            (Fault::Truncate { len: 8 }, 10, 8, blob_data(10, 8)),
            (Fault::FlipBit { offset: 20, bit: 3 }, 16, 8, flipped),
            (
                Fault::FlipBit { offset: 20, bit: 3 },
                21,
                10,
                blob_data(21, 10),
            ),
        ];

        for (fault, offset, len, expected) in test_cases {
            let backend = backend();
            backend.inject(FaultRule::read(fault));

            assert_eq!(read(&backend, offset, len).unwrap(), expected);
        }
    }

    #[test]
    fn read_serves_after_a_delay() {
        let backend = backend();
        backend.inject(FaultRule::read(Fault::Delay(Duration::from_millis(30))));

        let start = Instant::now();
        let data = read(&backend, 0, 4).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(data, blob_data(0, 4));
        assert!(elapsed >= Duration::from_millis(30));
    }

    #[test]
    fn read_blob_metadata_suffers_only_lookup_faults() {
        let backend = backend();
        backend.inject(
            FaultRule::metadata(Fault::ErrorWith(Arc::new(|| {
                io::Error::new(io::ErrorKind::PermissionDenied, "denied")
            })))
            .on_blob(BLOB_ID)
            .times(1),
        );
        backend.inject(FaultRule::metadata(Fault::ShortRead { len: 0 }));

        let err = backend.read_blob_metadata(&BLOB_ID).unwrap_err();
        let blob_metadata = backend.read_blob_metadata(&BLOB_ID);

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(blob_metadata.is_ok());
        assert_eq!(backend.metadata_calls(), 2);
        assert_eq!(backend.read_calls(), 0);
    }

    #[test]
    fn wrap_serves_only_unfaulted_reads_from_the_inner_backend() {
        let inner = Arc::new(backend());
        let backend = FaultBackend::wrap(inner.clone());
        backend.inject(FaultRule::read(Fault::Error(io::ErrorKind::TimedOut)).on_call(0));

        let err = read(&backend, 0, 4).unwrap_err();
        let data = read(&backend, 0, 4).unwrap();

        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(data, blob_data(0, 4));
        assert_eq!(inner.read_calls(), 1);
        assert_eq!(backend.read_calls(), 2);
    }

    #[test]
    fn wrap_keeps_the_kind_of_prefetches() {
        let inner = Arc::new(backend());
        inner.inject(
            FaultRule::read(Fault::Error(io::ErrorKind::TimedOut)).on_kind(ReadKind::Ondemand),
        );
        let backend = FaultBackend::wrap(inner.clone());
        backend.inject(FaultRule::metadata(Fault::Error(io::ErrorKind::NotFound)).times(1));

        let data = prefetch(&backend, 0, 4).unwrap();
        let err = backend.prefetch_blob_metadata(&BLOB_ID).unwrap_err();
        let blob_metadata = backend.prefetch_blob_metadata(&BLOB_ID);

        assert_eq!(data, blob_data(0, 4));
        assert_eq!(inner.reads()[0].kind, ReadKind::Prefetch);
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(blob_metadata.is_ok());
        assert_eq!(inner.metadata_calls(), 1);
    }
}
