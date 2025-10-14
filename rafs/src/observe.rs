use crate::metadata::RafsPrefetchFileInfo;
use nydus_utils::metrics::GlobalIoStats;
use nydus_utils::metrics::StatsFop::Read;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::sleep;
use std::time::Duration;

pub const OBSERVER_READY: u8 = 0;
pub const OBSERVER_RUNNING: u8 = 1;
pub const OBSERVER_TERMINATED: u8 = 2;

#[derive(Clone, Default, Deserialize)]
pub struct FsObserveControl {
    #[serde(default)]
    pub enable: bool,
    pub sample: bool,
    pub period: u64,
    pub hint_file: String,
}
#[derive(Default)]
struct RafsSample {
    enable: bool,
    index: AtomicU64,
    sample_map: Arc<Mutex<HashMap<PathBuf, Vec<(u64, (u64, u64))>>>>,
    hint_path: String,
}

#[derive(Default, Clone)]
pub struct RafsObserve {
    enable: bool,
    period: u64,
    state: Arc<AtomicU8>,
    sample: Arc<RafsSample>,
    hint_set: HashSet<PathBuf>,
    total_bio: Arc<AtomicU64>,
    missed_bio: Arc<AtomicU64>,
    missed_hint_file: Arc<AtomicU32>,
    cache_hit_ratio: Arc<Mutex<f32>>,
    cumulative_read_latency: Arc<Mutex<f64>>,
    pub prefetch_time: Arc<Mutex<f64>>,
    lock: Arc<Mutex<bool>>,
    cvar: Arc<Condvar>,
}

impl RafsSample {
    pub fn new(enable: bool, hint_path: String) -> RafsSample {
        RafsSample {
            enable,
            index: AtomicU64::new(0),
            sample_map: Arc::new(Mutex::new(HashMap::new())),
            hint_path,
        }
    }
}

impl RafsObserve {
    pub fn new(
        observe_enable: bool,
        sample_enable: bool,
        period: u64,
        hint_path: String,
        prefetch_files: &Option<Vec<RafsPrefetchFileInfo>>,
    ) -> RafsObserve {
        let mut set = HashSet::new();
        if let Some(files) = prefetch_files {
            set.extend(files.iter().map(|info| info.file.clone()));
        }
        RafsObserve {
            enable: observe_enable,
            period,
            state: Arc::new(AtomicU8::new(OBSERVER_READY)),
            sample: Arc::new(RafsSample::new(sample_enable, hint_path)),
            hint_set: set,
            total_bio: Arc::new(AtomicU64::new(0)),
            missed_bio: Arc::new(AtomicU64::new(0)),
            missed_hint_file: Arc::new(AtomicU32::new(0)),
            cache_hit_ratio: Arc::new(Mutex::new(-1.00)),
            cumulative_read_latency: Arc::new(Mutex::new(-1.0)),
            prefetch_time: Arc::new(Mutex::new(-1.00)),
            lock: Arc::new(Mutex::new(false)),
            cvar: Arc::new(Condvar::new()),
        }
    }

    pub fn get_working_state(&self) -> u8 {
        self.state.load(Ordering::Acquire)
    }
    pub fn wait_for_running(&self) {
        let mut running = self.lock.lock().unwrap();
        while !*running {
            running = self.cvar.wait(running).unwrap();
        }
    }

    pub fn switch_to_running(&self) {
        match self.state.compare_exchange(
            OBSERVER_READY,
            OBSERVER_RUNNING,
            Ordering::SeqCst,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                let mut running = self.lock.lock().unwrap();
                *running = true;
                self.cvar.notify_all();
            }
            Err(_) => {}
        }
    }

    pub fn sampler_collect_read_ios(&self, path: PathBuf, start: u64, end: u64) {
        if self.get_working_state() == OBSERVER_TERMINATED {
            return;
        }

        if self.sample.enable {
            self.sample
                .sample_map
                .lock()
                .unwrap()
                .entry(path)
                .or_insert_with(|| Vec::new())
                .push((
                    self.sample.index.fetch_add(1, Ordering::Relaxed),
                    (start, end),
                ));
        }
    }

    pub fn sampler_generate_hint_file(&self) {
        if !self.enable || !self.sample.enable {
            return;
        }

        let obs = self.clone();
        let _ = std::thread::spawn(move || {
            obs.wait_for_running();
            sleep(Duration::from_secs(obs.period));
            obs.state.store(OBSERVER_TERMINATED, Ordering::SeqCst);

            let guard = match obs.sample.sample_map.lock() {
                Ok(guard) => guard,
                Err(error) => {
                    error!("Acquire lock error on sample_map: {}", error);
                    return;
                }
            };
            let tmp_path = obs.sample.hint_path.clone() + ".sample.tmp";
            let mut hint_file = match File::create(tmp_path.clone()) {
                Ok(file) => file,
                Err(error) => {
                    error!("Failed to create hint file: {}", error);
                    return;
                }
            };
            let mut result: Vec<(u64, String)> = Vec::new();
            for (path, vec) in guard.iter() {
                /* The parameter v represents a Vec containing several file read intervals.
                 * fn_merge merges all overlapping intervals and returns a non-overlapping
                 * interval Vec.
                 */
                let fn_merge = |v: Vec<(u64, (u64, u64))>| -> (u64, Vec<(u64, u64)>) {
                    let mut intervals: Vec<(u64, u64)> = Vec::new();
                    let mut min_idx = u64::MAX;
                    for (idx, tuple) in v {
                        intervals.push(tuple);
                        if idx < min_idx {
                            min_idx = idx
                        }
                    }
                    intervals.sort();
                    let mut r = vec![];
                    let (mut start, mut end) = (intervals[0].0, intervals[0].1);
                    intervals.iter().skip(1).for_each(|x| {
                        if x.0 > end {
                            r.push((start, end));
                            start = x.0;
                        }
                        end = end.max(x.1);
                    });
                    r.push((start, end));
                    (min_idx, r)
                };
                // idx indicates the access order of the file
                let (idx, merged) = fn_merge(vec.clone());
                let mut str = format!("{} ", path.display());
                for (start, end) in merged {
                    let range = format!("{}-{},", start, end);
                    str = str + &range;
                }
                // remove last ','
                str.pop();
                result.push((idx, str));
            }
            result.sort();
            for (_, string) in result {
                if let Err(error) = hint_file.write_all(string.as_bytes()) {
                    error!("Failed to write to hint file: {}", error);
                    return;
                }
                if let Err(error) = hint_file.write_all(b"\n") {
                    error!("Failed to write to hint file: {}", error);
                    return;
                }
            }
            if let Err(error) = fs::rename(tmp_path, obs.sample.hint_path.clone()) {
                error!("Failed to rename hint file: {}", error);
            }
        });
    }

    pub fn observer_statistics_rafs_io(&self, cache_miss: bool) {
        if self.enable && self.get_working_state() == OBSERVER_RUNNING {
            self.total_bio.fetch_add(1, Ordering::Relaxed);
            if cache_miss {
                self.missed_bio.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    pub fn observer_rating_rafs_hintfile(&self, name: &PathBuf) {
        if self.enable && self.get_working_state() == OBSERVER_RUNNING {
            if !self.hint_set.contains(name) {
                self.missed_hint_file.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn observer_io_result_analyze(&self, ios: Arc<GlobalIoStats>) {
        if !self.enable {
            return;
        }

        let obs = self.clone();
        let _ = std::thread::spawn(move || {
            obs.wait_for_running();
            sleep(Duration::from_secs(obs.period));
            obs.state.store(OBSERVER_TERMINATED, Ordering::SeqCst);

            let total = obs.total_bio.load(Ordering::Relaxed);
            let missed = obs.missed_bio.load(Ordering::Relaxed);
            let read_lat = ios.export_fop_cumulative_latency(Read) as f64 / 1000.0;
            let mut hit_rate = 0f64;
            if total != 0 {
                hit_rate = (total - missed) as f64 / total as f64;
            }
            info!(
                "Sample Analyze Result: Cache hit rate: {:.2}%, total io: {}, Read latency: {:.2}ms, prefetch_time: {:.2}ms",
                hit_rate * 100.0,
                total,
                read_lat,
            	*obs.prefetch_time.lock().unwrap(),
            );
            let mut ratio = obs.cache_hit_ratio.lock().unwrap();
            let mut lat = obs.cumulative_read_latency.lock().unwrap();
            *ratio = hit_rate as f32;
            *lat = read_lat;
        });
    }

    pub fn observer_export_io_analyze_result(&self) -> (f32, f64, u64, u32, f64) {
        (
            *self.cache_hit_ratio.lock().unwrap(),
            *self.cumulative_read_latency.lock().unwrap(),
            self.total_bio.load(Ordering::Relaxed),
            self.missed_hint_file.load(Ordering::Relaxed),
            *self.prefetch_time.lock().unwrap(),
        )
    }
}
