// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
// Rafs fop stats accounting and exporting.

use std::collections::HashMap;
use std::ops::{Deref, Drop};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use serde_json::Error as SerdeError;

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

type FilesStatsCounters = RwLock<Vec<Arc<Option<InodeIOStats>>>>;

/// Block size separated counters.
/// 1K; 4K; 16K; 64K, 128K, 512K, 1M
const BLOCK_READ_COUNT_MAX: usize = 8;

/// <=200us, <=500us, <=1ms, <=20ms, <=50ms, <=100ms, <=500ms, >500ms
const READ_LATENCY_RANGE_MAX: usize = 8;

lazy_static! {
    static ref IOS_SET: RwLock<HashMap<String, Arc<GlobalIOStats>>> = Default::default();
}

lazy_static! {
    static ref BACKEND_METRICS: RwLock<HashMap<String, Arc<BackendMetrics>>> = Default::default();
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct GlobalIOStats {
    // Whether to enable each file accounting switch.
    // As fop accounting might consume much memory space, it is disabled by default.
    // But global fop accounting is always working within each Rafs.
    files_account_enabled: AtomicBool,
    access_pattern_enabled: AtomicBool,
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
            // We put block count into 5 catagories e.g. 1K; 4K; 16K; 64K, 128K.
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

/// <=200us, <=500us, <=1ms, <=20ms, <=50ms, <=100ms, <=500ms, >500ms
fn latency_range_index(elapsed: usize) -> usize {
    match elapsed {
        _ if elapsed <= 200 => 0,
        _ if elapsed <= 500 => 1,
        _ if elapsed <= 1000 => 2,
        _ if elapsed <= 20_000 => 3,
        _ if elapsed <= 50_000 => 4,
        _ if elapsed <= 100_000 => 5,
        _ if elapsed <= 500_000 => 6,
        _ => 7,
    }
}

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
        _ => 7,
    }
}

impl GlobalIOStats {
    pub fn init(&self) {
        self.files_account_enabled.store(false, Ordering::Relaxed);
        self.measure_latency.store(true, Ordering::Relaxed);
    }

    fn files_enabled(&self) -> bool {
        self.files_account_enabled.load(Ordering::Relaxed)
    }

    fn access_pattern_enabled(&self) -> bool {
        self.access_pattern_enabled.load(Ordering::Relaxed)
    }

    pub fn toggle_files_recording(&self, switch: bool) {
        self.files_account_enabled.store(switch, Ordering::Relaxed)
    }

    pub fn toggle_access_pattern(&self, switch: bool) {
        self.access_pattern_enabled.store(switch, Ordering::Relaxed)
    }

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
                // FIXME: converting u128 to isize is fragile.
                let elapsed = d.as_micros() as usize;
                self.read_latency_dist[latency_range_index(elapsed)]
                    .fetch_add(1, Ordering::Relaxed);
                self.fop_cumulative_latency_total[fop as usize]
                    .fetch_add(elapsed as usize, Ordering::Relaxed);
                let fop_cnt = self.fop_hits[fop as usize].load(Ordering::Relaxed);

                // Zero fop count is hardly to meet, but still check here in
                // case callers misuses ios-latency
                if fop_cnt == 0 {
                    return;
                }
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

pub fn export_files_stats(name: &Option<String>) -> Result<String, IoStatsError> {
    let ios_set = IOS_SET.read().unwrap();

    match name {
        Some(k) => ios_set
            .get(k)
            .ok_or(IoStatsError::NoCounter)
            .map(|v| v.export_files_stats())?,
        None => {
            if ios_set.len() == 1 {
                if let Some(ios) = ios_set.values().next() {
                    return ios.export_files_stats();
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
struct BasicMetric(AtomicUsize);

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
    // Categorize metrics per as to their latency and request size
    read_latency_dist: [[BasicMetric; READ_LATENCY_RANGE_MAX]; BLOCK_READ_COUNT_MAX],
    // TODO: Allocate memory ring-buffer to keep error messages.
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

    pub fn begin(&self) -> SystemTime {
        SystemTime::now()
    }

    pub fn end(&self, begin: &SystemTime, size: usize, error: bool) {
        if let Ok(d) = SystemTime::elapsed(begin) {
            // FIXME: converting u128 to usize is fragile.
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
