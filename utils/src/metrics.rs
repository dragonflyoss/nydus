// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Rafs fop stats accounting and exporting.

use std::collections::{HashMap, HashSet};
use std::ops::{Deref, Drop};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use serde_json::Error as SerdeError;

use crate::logger::ErrorHolder;
use crate::InodeBitmap;

pub type Inode = u64;

#[derive(PartialEq, Copy)]
pub enum StatsFop {
    Getattr,
    Readlink,
    Open,
    Release,
    Read,
    Statfs,
    Getxattr,
    Listxattr,
    Opendir,
    Lookup,
    Readdir,
    Readdirplus,
    Access,
    Forget,
    BatchForget,
    Max,
}

#[derive(Debug)]
pub enum IoStatsError {
    NoCounter,
    Serialize(SerdeError),
}

type IoStatsResult<T> = Result<T, IoStatsError>;

impl Clone for StatsFop {
    fn clone(&self) -> Self {
        *self
    }
}

/// Block size separated counters.
/// 1K; 4K; 16K; 64K, 128K, 512K, 1M
const BLOCK_READ_COUNT_MAX: usize = 8;

fn request_size_index(size: usize) -> usize {
    match size {
        // <=1K
        _ if size >> 10 == 0 => 0,
        // <=4K
        _ if size >> 12 == 0 => 1,
        // <=16K
        _ if size >> 14 == 0 => 2,
        // <=64K
        _ if size >> 16 == 0 => 3,
        // <=128K
        _ if size >> 17 == 0 => 4,
        // <=512K
        _ if size >> 19 == 0 => 5,
        // <=1M
        _ if size >> 20 == 0 => 6,
        // > 1M
        // Match `BLOCK_READ_COUNT_MAX = 8`
        _ => 7,
    }
}

/// <=200us, <=500us, <=1ms, <=20ms, <=50ms, <=100ms, <=500ms, >500ms
const READ_LATENCY_RANGE_MAX: usize = 8;

// Defining below global static metrics set so that a specific metrics counter can
// be found as per the rafs backend mountpoint/id. Remind that nydusd can have
// multiple backends mounted.
lazy_static! {
    static ref IOS_SET: RwLock<HashMap<String, Arc<GlobalIOStats>>> = Default::default();
}

lazy_static! {
    static ref BACKEND_METRICS: RwLock<HashMap<String, Arc<BackendMetrics>>> = Default::default();
}

lazy_static! {
    static ref BLOBCACHE_METRICS: RwLock<HashMap<String, Arc<BlobcacheMetrics>>> =
        Default::default();
}

lazy_static! {
    pub static ref ERROR_HOLDER: Arc<Mutex<ErrorHolder>> =
        Arc::new(Mutex::new(ErrorHolder::init(500, 50 * 1024)));
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct GlobalIOStats {
    // Whether to enable each file accounting switch.
    // As fop accounting might consume much memory space, it is disabled by default.
    // But global fop accounting is always working within each Rafs.
    files_account_enabled: AtomicBool,
    access_pattern_enabled: AtomicBool,
    record_latest_read_files_enabled: AtomicBool,
    // Given the fact that we don't have to measure latency all the time,
    // use this to turn it off.
    measure_latency: AtomicBool,
    id: String,
    // Total bytes read against the filesystem.
    data_read: AtomicUsize,
    // Cumulative bytes for different block size.
    block_count_read: [AtomicUsize; BLOCK_READ_COUNT_MAX],
    // Counters for successful various file operations.
    fop_hits: [AtomicUsize; StatsFop::Max as usize],
    // Counters for failed file operations.
    fop_errors: [AtomicUsize; StatsFop::Max as usize],
    // Cumulative latency's life cycle is equivalent to Rafs, unlike incremental
    // latency which will be cleared each time dumped. Unit as micro-seconds.
    //   * @total means io_stats simply adds every fop latency to the counter which is never cleared.
    //     It is useful for other tools to calculate their metrics report.
    fop_cumulative_latency_total: [AtomicUsize; StatsFop::Max as usize],
    // Record how many times read latency drops to the ranges.
    // This helps us to understand the io service time stability.
    read_latency_dist: [AtomicIsize; READ_LATENCY_RANGE_MAX],
    // Total number of files that are currently open.
    nr_opens: AtomicUsize,
    nr_max_opens: AtomicUsize,
    // Record last rafs fop timestamp, this helps us with detecting backend hang or
    // inside dead-lock, etc.
    last_fop_tp: AtomicUsize,
    // Rwlock closes the race that more than one threads are creating counters concurrently.
    #[serde(skip_serializing, skip_deserializing)]
    file_counters: RwLock<HashMap<Inode, Arc<InodeIOStats>>>,
    #[serde(skip_serializing, skip_deserializing)]
    access_patterns: RwLock<HashMap<Inode, Arc<AccessPattern>>>,
    // record regular file read
    #[serde(skip_serializing, skip_deserializing)]
    recent_read_files: InodeBitmap,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct InodeIOStats {
    // Total open number of this file.
    nr_open: AtomicUsize,
    nr_max_open: AtomicUsize,
    total_fops: AtomicUsize,
    data_read: AtomicUsize,
    // Cumulative bytes for different block size.
    block_count_read: [AtomicUsize; BLOCK_READ_COUNT_MAX],
    fop_hits: [AtomicUsize; StatsFop::Max as usize],
    fop_errors: [AtomicUsize; StatsFop::Max as usize],
}

/// Records how a file is accessed.
/// For security sake, each file can associate an access pattern recorder, which
/// is globally configured through nydusd configuration file.
/// For now, the pattern is composed of:
///     1. How many times a file is read regardless of io block size and request offset.
///        And this counter can not be cleared.
///     2. First time point at which this file is read. It's wall-time in unit of seconds.
///     3. File path relative to current rafs root.
///
/// Yes, we now don't have an abundant pattern recorder now. It can be negotiated in the
/// future about how to enrich it.
///
#[derive(Default, Debug, Serialize)]
pub struct AccessPattern {
    file_path: PathBuf,
    nr_read: AtomicUsize,
    /// In unit of seconds.
    first_access_time: AtomicUsize,
}

pub trait InodeStatsCounter {
    fn stats_fop_inc(&self, fop: StatsFop);
    fn stats_fop_err_inc(&self, fop: StatsFop);
    fn stats_cumulative(&self, fop: StatsFop, value: usize);
}

impl InodeStatsCounter for InodeIOStats {
    fn stats_fop_inc(&self, fop: StatsFop) {
        self.fop_hits[fop as usize].fetch_add(1, Ordering::Relaxed);
        self.total_fops.fetch_add(1, Ordering::Relaxed);
        if fop == StatsFop::Open {
            self.nr_open.fetch_add(1, Ordering::Relaxed);
            // Below can't guarantee that load and store are atomic but it should be OK
            // for debug tracing info.
            if self.nr_open.load(Ordering::Relaxed) > self.nr_max_open.load(Ordering::Relaxed) {
                self.nr_max_open
                    .store(self.nr_open.load(Ordering::Relaxed), Ordering::Relaxed)
            }
        }
    }

    fn stats_fop_err_inc(&self, fop: StatsFop) {
        self.fop_errors[fop as usize].fetch_add(1, Ordering::Relaxed);
    }

    fn stats_cumulative(&self, fop: StatsFop, value: usize) {
        if fop == StatsFop::Read {
            self.data_read.fetch_add(value, Ordering::Relaxed);
            // Put counters into $BLOCK_READ_COUNT_MAX catagories
            // 1K; 4K; 16K; 64K, 128K, 512K, 1M
            let idx = request_size_index(value);
            self.block_count_read[idx].fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn new(id: &str) -> Arc<GlobalIOStats> {
    let c = Arc::new(GlobalIOStats {
        id: id.to_string(),
        ..Default::default()
    });
    IOS_SET.write().unwrap().insert(id.to_string(), c.clone());
    c.init();
    c
}

/// <=1ms, <=20ms, <=50ms, <=100ms, <=500ms, <=1s, <=2s, >2s
fn latency_range_index(elapsed: usize) -> usize {
    match elapsed {
        _ if elapsed <= 1000 => 0,
        _ if elapsed <= 20_000 => 1,
        _ if elapsed <= 50_000 => 2,
        _ if elapsed <= 100_000 => 3,
        _ if elapsed <= 500_000 => 4,
        _ if elapsed <= 1_000_000 => 5,
        _ if elapsed <= 2_000_000 => 6,
        _ => 7,
    }
}

macro_rules! impl_iostat_option {
    ($get:ident, $set:ident, $opt:ident) => {
        #[inline]
        fn $get(&self) -> bool {
            self.$opt.load(Ordering::Relaxed)
        }

        #[inline]
        pub fn $set(&self, switch: bool) {
            self.$opt.store(switch, Ordering::Relaxed)
        }
    };
}

impl GlobalIOStats {
    pub fn init(&self) {
        self.files_account_enabled.store(false, Ordering::Relaxed);
        self.measure_latency.store(true, Ordering::Relaxed);
    }

    impl_iostat_option!(files_enabled, toggle_files_recording, files_account_enabled);
    impl_iostat_option!(
        access_pattern_enabled,
        toggle_access_pattern,
        access_pattern_enabled
    );
    impl_iostat_option!(
        record_latest_read_files_enabled,
        toggle_latest_read_files_recording,
        record_latest_read_files_enabled
    );

    /// For now, each inode has its iostats counter regardless whether it is
    /// enabled per rafs.
    pub fn new_file_counter<F>(&self, ino: Inode, path_getter: F)
    where
        F: Fn(u64) -> PathBuf,
    {
        if self.files_enabled() {
            let mut counters = self.file_counters.write().unwrap();
            if counters.get(&ino).is_none() {
                counters.insert(ino, Arc::new(InodeIOStats::default()));
            }
        }

        if self.access_pattern_enabled() {
            let mut records = self.access_patterns.write().unwrap();
            if records.get(&ino).is_none() {
                records.insert(
                    ino,
                    Arc::new(AccessPattern {
                        file_path: path_getter(ino),
                        ..Default::default()
                    }),
                );
            }
        }
    }

    fn file_stats_update(&self, ino: Inode, fop: StatsFop, bsize: usize, success: bool) {
        self.global_update(fop, bsize, success);

        if self.files_enabled() {
            let counters = self.file_counters.read().unwrap();
            match counters.get(&ino) {
                Some(c) => {
                    c.stats_fop_inc(fop);
                    c.stats_cumulative(fop, bsize);
                }
                None => warn!("No iostats counter for file {}", ino),
            }
        }

        if self.access_pattern_enabled() && fop == StatsFop::Read {
            let records = self.access_patterns.read().unwrap();
            match records.get(&ino) {
                Some(r) => {
                    r.nr_read.fetch_add(1, Ordering::Relaxed);
                    if r.first_access_time.load(Ordering::Relaxed) == 0 {
                        // FIXME: Conversion from `u64` to `usize` on 32-bit platform
                        // is not reliable. Fix this by using AtomicU64 instead.
                        r.first_access_time.store(
                            SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as usize,
                            Ordering::Relaxed,
                        );
                    }
                }
                None => warn!("No pattern record for file {}", ino),
            }
        }

        if self.record_latest_read_files_enabled() && fop == StatsFop::Read && success {
            self.recent_read_files.set(ino);
        }
    }

    fn global_update(&self, fop: StatsFop, value: usize, success: bool) {
        self.last_fop_tp.store(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as usize,
            Ordering::Relaxed,
        );

        // We put block count into 5 catagories e.g. 1K; 4K; 16K; 64K, 128K.
        if fop == StatsFop::Read {
            match value {
                // <=1K
                _ if value >> 10 == 0 => self.block_count_read[0].fetch_add(1, Ordering::Relaxed),
                // <=4K
                _ if value >> 12 == 0 => self.block_count_read[1].fetch_add(1, Ordering::Relaxed),
                // <=16K
                _ if value >> 14 == 0 => self.block_count_read[2].fetch_add(1, Ordering::Relaxed),
                // <=64K
                _ if value >> 16 == 0 => self.block_count_read[3].fetch_add(1, Ordering::Relaxed),
                // >64K
                _ => self.block_count_read[4].fetch_add(1, Ordering::Relaxed),
            };
        }

        if success {
            self.fop_hits[fop as usize].fetch_add(1, Ordering::Relaxed);
            match fop {
                StatsFop::Read => self.data_read.fetch_add(value, Ordering::Relaxed),
                StatsFop::Open => self.nr_opens.fetch_add(1, Ordering::Relaxed),
                StatsFop::Release => self.nr_opens.fetch_sub(1, Ordering::Relaxed),
                _ => 0,
            };
        } else {
            self.fop_errors[fop as usize].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Paired with `latency_end` to record elapsed time for a certain type of fop.
    pub fn latency_start(&self) -> Option<SystemTime> {
        if !self.measure_latency.load(Ordering::Relaxed) {
            return None;
        }

        Some(SystemTime::now())
    }

    pub fn latency_end(&self, start: &Option<SystemTime>, fop: StatsFop) {
        if let Some(start) = start {
            if let Ok(d) = SystemTime::elapsed(start) {
                // Converting u128 to u64 here is safe since it's delta.
                let elapsed = d.as_micros() as usize;
                self.read_latency_dist[latency_range_index(elapsed)]
                    .fetch_add(1, Ordering::Relaxed);
                self.fop_cumulative_latency_total[fop as usize]
                    .fetch_add(elapsed as usize, Ordering::Relaxed);
            }
        }
    }

    fn export_files_stats(&self) -> Result<String, IoStatsError> {
        serde_json::to_string(
            self.file_counters
                .read()
                .expect("Not expect poisoned lock")
                .deref(),
        )
        .map_err(IoStatsError::Serialize)
    }

    fn export_latest_read_files(&self) -> String {
        serde_json::json!(self.recent_read_files.bitmap_to_array_and_clear()).to_string()
    }

    fn export_files_access_patterns(&self) -> Result<String, IoStatsError> {
        serde_json::to_string(
            &self
                .access_patterns
                .read()
                .expect("Not poisoned lock")
                .deref()
                .values()
                .filter(|r| r.nr_read.load(Ordering::Relaxed) != 0)
                .collect::<Vec<&Arc<AccessPattern>>>(),
        )
        .map_err(IoStatsError::Serialize)
    }

    fn export_global_stats(&self) -> Result<String, IoStatsError> {
        serde_json::to_string(self).map_err(IoStatsError::Serialize)
    }
}

/// If you need FOP recorder count file system operations.
/// Call its `settle()` method to generate an on-stack recorder.
/// If the operation succeeds, call `mark_success()` to change the recorder's internal state.
/// If the operation fails, its internal state will not be changed.
/// Finally, when the recorder is being destroyed, iostats counter will be updated.
pub struct FopRecorder<'a> {
    fop: StatsFop,
    inode: u64,
    success: bool,
    // Now, the size only makes sense for `Read` FOP.
    size: usize,
    ios: &'a GlobalIOStats,
}

impl<'a> Drop for FopRecorder<'a> {
    fn drop(&mut self) {
        self.ios
            .file_stats_update(self.inode, self.fop, self.size, self.success);
    }
}

impl<'a> FopRecorder<'a> {
    pub fn settle<'b, T>(fop: StatsFop, inode: u64, ios: &'b T) -> Self
    where
        T: AsRef<GlobalIOStats>,
        'b: 'a,
    {
        FopRecorder {
            fop,
            inode,
            success: false,
            size: 0,
            ios: ios.as_ref(),
        }
    }

    pub fn mark_success(&mut self, size: usize) {
        self.success = true;
        self.size = size;
    }
}

pub fn export_files_stats(
    name: &Option<String>,
    latest_read_files: bool,
) -> Result<String, IoStatsError> {
    let ios_set = IOS_SET.read().unwrap();

    match name {
        Some(k) => ios_set.get(k).ok_or(IoStatsError::NoCounter).map(|v| {
            if !latest_read_files {
                v.export_files_stats()
            } else {
                Ok(v.export_latest_read_files())
            }
        })?,
        None => {
            if ios_set.len() == 1 {
                if let Some(ios) = ios_set.values().next() {
                    return if !latest_read_files {
                        ios.export_files_stats()
                    } else {
                        Ok(ios.export_latest_read_files())
                    };
                }
            }
            Err(IoStatsError::NoCounter)
        }
    }
}

pub fn export_files_access_pattern(name: &Option<String>) -> Result<String, IoStatsError> {
    let ios_set = IOS_SET.read().unwrap();
    match name {
        Some(k) => ios_set
            .get(k)
            .ok_or(IoStatsError::NoCounter)
            .map(|v| v.export_files_access_patterns())?,
        None => {
            if ios_set.len() == 1 {
                if let Some(ios) = ios_set.values().next() {
                    return ios.export_files_access_patterns();
                }
            }
            Err(IoStatsError::NoCounter)
        }
    }
}

pub fn export_global_stats(name: &Option<String>) -> Result<String, IoStatsError> {
    // With only one rafs instance, we allow caller to ask for an unknown ios name.
    let ios_set = IOS_SET.read().unwrap();

    match name {
        Some(k) => ios_set
            .get(k)
            .ok_or(IoStatsError::NoCounter)
            .map(|v| v.export_global_stats())?,
        None => {
            if ios_set.len() == 1 {
                if let Some(ios) = ios_set.values().next() {
                    return ios.export_global_stats();
                }
            }
            Err(IoStatsError::NoCounter)
        }
    }
}

pub fn export_backend_metrics(name: &Option<String>) -> IoStatsResult<String> {
    let metrics = BACKEND_METRICS.read().unwrap();

    match name {
        Some(k) => metrics
            .get(k)
            .ok_or(IoStatsError::NoCounter)
            .map(|v| v.export_metrics())?,
        None => {
            if metrics.len() == 1 {
                if let Some(m) = metrics.values().next() {
                    return m.export_metrics();
                }
            }
            Err(IoStatsError::NoCounter)
        }
    }
}

pub fn export_blobcache_metrics(id: &Option<String>) -> IoStatsResult<String> {
    let metrics = BLOBCACHE_METRICS.read().unwrap();

    match id {
        Some(k) => metrics
            .get(k)
            .ok_or(IoStatsError::NoCounter)
            .map(|v| v.export_metrics())?,
        None => {
            if metrics.len() == 1 {
                if let Some(m) = metrics.values().next() {
                    return m.export_metrics();
                }
            }
            Err(IoStatsError::NoCounter)
        }
    }
}

pub fn export_events() -> IoStatsResult<String> {
    serde_json::to_string(ERROR_HOLDER.lock().unwrap().deref()).map_err(IoStatsError::Serialize)
}

pub trait Metric {
    /// Adds `value` to the current counter.
    fn add(&self, value: usize);
    /// Increments by 1 unit the current counter.
    fn inc(&self) {
        self.add(1);
    }
    /// Returns current value of the counter.
    fn count(&self) -> usize;
}

#[derive(Default, Serialize, Debug)]
pub struct BasicMetric(AtomicUsize);

/*
Exported backend metrics look like:
```json
{'read_count': 901, 'read_errors': 0, 'read_amount_total': 28650387, 'read_cumulative_latency_total': 4776473,
'read_latency_dist':   [[0, 0, 0, 72, 1, 0, 0, 0],
                        [0, 0, 0, 203, 1, 1, 0, 0],
                        [0, 0, 0, 545, 3, 1, 0, 0],
                        [0, 0, 0, 10, 0, 0, 0, 0],
                        [0, 0, 0, 45, 0, 0, 0, 0],
                        [0, 0, 0, 0, 0, 0, 0, 0],
                        [0, 0, 0, 0, 2, 0, 0, 0],
                        [0, 0, 0, 0, 17, 0, 0, 0]]
}
*/
#[derive(Default, Serialize, Debug)]
pub struct BackendMetrics {
    #[serde(skip_serializing, skip_deserializing)]
    id: String,
    // TODO: Turn this into enum?
    backend_type: String,
    // Cumulative count of read request to backend
    read_count: BasicMetric,
    // Cumulative count of read failure to backend
    read_errors: BasicMetric,
    // Cumulative amount of data from to backend in unit of Bytes. External tools
    // is responsible for calculating BPS from this field.
    read_amount_total: BasicMetric,
    read_cumulative_latency_total: BasicMetric,
    // Categorize metrics as per their latency and request size
    read_latency_dist: [[BasicMetric; READ_LATENCY_RANGE_MAX]; BLOCK_READ_COUNT_MAX],
}

impl Metric for BasicMetric {
    fn add(&self, value: usize) {
        self.0.fetch_add(value, Ordering::Relaxed);
    }

    fn count(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

impl BackendMetrics {
    pub fn new(id: &str, backend_type: &str) -> Arc<Self> {
        let backend_metrics = Arc::new(Self {
            id: id.to_string(),
            backend_type: backend_type.to_string(),
            ..Default::default()
        });

        BACKEND_METRICS
            .write()
            .unwrap()
            .insert(id.to_string(), backend_metrics.clone());

        backend_metrics
    }

    pub fn release(&self) -> IoStatsResult<()> {
        BACKEND_METRICS
            .write()
            .unwrap()
            .remove(&self.id)
            .map(|_| ())
            .ok_or(IoStatsError::NoCounter)
    }

    pub fn begin(&self) -> SystemTime {
        SystemTime::now()
    }

    pub fn end(&self, begin: &SystemTime, size: usize, error: bool) {
        if let Ok(d) = SystemTime::elapsed(begin) {
            // Below conversion from u128 to usize is acceptable since elapsed
            // is a short duration.
            let elapsed = d.as_micros() as usize;
            self.read_count.inc();
            self.read_cumulative_latency_total.add(elapsed);
            self.read_amount_total.add(size);

            if error {
                self.read_errors.inc();
            }

            let lat_idx = latency_range_index(elapsed);
            let size_idx = request_size_index(size);
            self.read_latency_dist[size_idx][lat_idx].inc();
        }
    }

    fn export_metrics(&self) -> IoStatsResult<String> {
        serde_json::to_string(self).map_err(IoStatsError::Serialize)
    }
}

#[derive(Debug, Default, Serialize)]
pub struct BlobcacheMetrics {
    #[serde(skip_serializing, skip_deserializing)]
    id: String,
    // Prefer to let external tool get file's state like file size and disk usage.
    // Because stat(2) file may get blocked.
    pub underlying_files: Mutex<HashSet<String>>,
    pub store_path: String,
    // Cache hit percentage = (partial_hits + whole_hits) / total
    pub partial_hits: BasicMetric,
    pub whole_hits: BasicMetric,
    pub total: BasicMetric,
    // Scale of blobcache. Blobcache does not evict entries.
    // Means the number of chunks in ready status.
    pub entries_count: BasicMetric,
    // In unit of Bytes
    pub prefetch_data_amount: BasicMetric,
    pub prefetch_workers: AtomicUsize,
    pub prefetch_policy: Mutex<HashSet<String>>,
    // Together with below two fields, we can figure out average merging size thus
    // to estimate the possibility to merge backend IOs.
    pub prefetch_total_size: BasicMetric,
    pub prefetch_mr_count: BasicMetric,
    pub prefetch_unmerged_chunks: BasicMetric,
}

impl BlobcacheMetrics {
    pub fn new(id: &str, store_path: &str) -> Arc<Self> {
        let metrics = Arc::new(Self {
            id: id.to_string(),
            store_path: store_path.to_string(),
            ..Default::default()
        });

        // Old metrics will be dropped when BlobCache is swapped. So we don't
        // have to worry about swapping its metrics either which means it's
        // not necessary to release metrics recorder when blobcache is dropped due to swapping.
        BLOBCACHE_METRICS
            .write()
            .unwrap()
            .insert(id.to_string(), metrics.clone());

        metrics
    }

    pub fn release(&self) -> IoStatsResult<()> {
        BLOBCACHE_METRICS
            .write()
            .unwrap()
            .remove(&self.id)
            .map(|_| ())
            .ok_or(IoStatsError::NoCounter)
    }

    pub fn export_metrics(&self) -> IoStatsResult<String> {
        serde_json::to_string(self).map_err(IoStatsError::Serialize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_read_count() {
        let g = GlobalIOStats::default();
        g.init();
        g.global_update(StatsFop::Read, 4000, true);
        assert_eq!(g.block_count_read[1].load(Ordering::Relaxed), 1);

        g.global_update(StatsFop::Read, 4096, true);
        assert_eq!(g.block_count_read[1].load(Ordering::Relaxed), 1);

        g.global_update(StatsFop::Read, 65535, true);
        assert_eq!(g.block_count_read[3].load(Ordering::Relaxed), 1);

        g.global_update(StatsFop::Read, 131072, true);
        assert_eq!(g.block_count_read[4].load(Ordering::Relaxed), 1);

        g.global_update(StatsFop::Read, 65520, true);
        assert_eq!(g.block_count_read[3].load(Ordering::Relaxed), 2);

        g.global_update(StatsFop::Read, 2015520, true);
        assert_eq!(g.block_count_read[3].load(Ordering::Relaxed), 2);
    }
}
