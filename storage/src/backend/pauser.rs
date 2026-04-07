// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// A pauser that allows any thread to pause all threads for a specified duration.
///
/// All threads calling `wait()` will block until the pause duration expires.
/// Any thread can call `set_pause()` to initiate a pause.
#[derive(Clone)]
pub struct Pauser {
    inner: Arc<Mutex<PauserInner>>,
    condvar: Arc<Condvar>,
}

struct PauserInner {
    /// When the pause will end (None if not paused)
    pause_until: Option<Instant>,
}

impl Pauser {
    /// Create a new pauser with no initial pause.
    pub fn new() -> Self {
        Pauser {
            inner: Arc::new(Mutex::new(PauserInner { pause_until: None })),
            condvar: Arc::new(Condvar::new()),
        }
    }

    /// Set a pause duration. All threads calling `wait()` will be paused for this duration.
    ///
    /// If a pause is already in progress, the new pause duration will replace it.
    ///
    /// # Arguments
    ///
    /// * `duration` - The duration to pause for
    pub fn set_pause(&self, duration: Duration) {
        let mut inner = self.inner.lock().unwrap();
        inner.pause_until = Some(Instant::now() + duration);

        // Notify all waiting threads to check the pause status
        drop(inner); // Unlock before notifying
        self.condvar.notify_all();
    }

    /// Clear any active pause, allowing all threads to proceed immediately.
    pub fn clear_pause(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.pause_until = None;

        // Notify all waiting threads to proceed
        drop(inner); // Unlock before notifying
        self.condvar.notify_all();
    }

    /// Wait if currently paused. Returns the duration that was paused.
    ///
    /// If a pause is active, this method will block until the pause duration expires.
    /// If no pause is active, this returns immediately with a zero duration.
    ///
    /// # Returns
    ///
    /// The duration of the pause (or zero if not paused)
    pub fn wait(&self) -> Duration {
        let start = Instant::now();

        loop {
            let mut inner = self.inner.lock().unwrap();

            match inner.pause_until {
                Some(pause_until) => {
                    let now = Instant::now();
                    if now >= pause_until {
                        // Pause has expired
                        inner.pause_until = None;
                        return now.duration_since(start);
                    } else {
                        // Still paused, wait until timeout or notification
                        let remaining = pause_until.duration_since(now);
                        let _result = self.condvar.wait_timeout(inner, remaining).unwrap();
                        // Loop back to check if pause has expired
                    }
                }
                None => {
                    // No pause active, return immediately
                    return Duration::ZERO;
                }
            }
        }
    }

    /// Check if currently paused without blocking.
    ///
    /// Returns the time remaining in the pause, or None if not paused.
    pub fn is_paused(&self) -> Option<Duration> {
        let inner = self.inner.lock().unwrap();
        match inner.pause_until {
            Some(pause_until) => {
                let now = Instant::now();
                if now >= pause_until {
                    None
                } else {
                    Some(pause_until.duration_since(now))
                }
            }
            None => None,
        }
    }

    /// Get information about the current pause status.
    ///
    /// Returns (is_paused, remaining_duration)
    pub fn status(&self) -> (bool, Option<Duration>) {
        let inner = self.inner.lock().unwrap();
        match inner.pause_until {
            Some(pause_until) => {
                let now = Instant::now();
                if now >= pause_until {
                    (false, None)
                } else {
                    (true, Some(pause_until.duration_since(now)))
                }
            }
            None => (false, None),
        }
    }
}

impl Default for Pauser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;
    use std::thread;

    #[test]
    fn test_pauser_creation() {
        let pauser = Pauser::new();
        let (is_paused, remaining) = pauser.status();
        assert!(!is_paused);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_set_pause() {
        let pauser = Pauser::new();
        pauser.set_pause(Duration::from_millis(100));

        let (is_paused, remaining) = pauser.status();
        assert!(is_paused);
        assert!(remaining.is_some());
        assert!(remaining.unwrap().as_millis() > 0);
    }

    #[test]
    fn test_clear_pause() {
        let pauser = Pauser::new();
        pauser.set_pause(Duration::from_secs(10));

        let (is_paused, _) = pauser.status();
        assert!(is_paused);

        pauser.clear_pause();

        let (is_paused, remaining) = pauser.status();
        assert!(!is_paused);
        assert!(remaining.is_none());
    }

    #[test]
    fn test_wait_without_pause() {
        let pauser = Pauser::new();
        let start = Instant::now();
        let paused_duration = pauser.wait();
        let elapsed = start.elapsed();

        // Should return immediately
        assert_eq!(paused_duration, Duration::ZERO);
        assert!(elapsed.as_millis() < 10);
    }

    #[test]
    fn test_wait_with_pause() {
        let pauser = Pauser::new();
        pauser.set_pause(Duration::from_millis(100));

        let start = Instant::now();
        let paused_duration = pauser.wait();
        let elapsed = start.elapsed();

        // Should have waited approximately 100ms
        assert!(elapsed.as_millis() >= 80 && elapsed.as_millis() <= 150);
        assert!(paused_duration.as_millis() >= 80);
    }

    #[test]
    fn test_concurrent_pause_and_wait() {
        use std::sync::Barrier;

        let pauser = Pauser::new();
        let counter = StdArc::new(AtomicUsize::new(0));
        let barrier = StdArc::new(Barrier::new(6)); // 5 threads + main
        let mut handles = vec![];

        // Set pause BEFORE spawning threads so they block inside wait()
        pauser.set_pause(Duration::from_secs(10));

        // Spawn 5 threads that will call wait() and block
        for _ in 0..5 {
            let pauser = pauser.clone();
            let counter = StdArc::clone(&counter);
            let barrier = StdArc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier.wait();
                let _paused = pauser.wait();
                counter.fetch_add(1, Ordering::SeqCst);
            });
            handles.push(handle);
        }

        // Synchronize: all threads reach barrier, then enter wait()
        barrier.wait();
        thread::sleep(Duration::from_millis(50));

        // All threads should be blocked inside wait()
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "threads should be blocked in wait()"
        );

        // Clear pause to let threads proceed
        pauser.clear_pause();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // All 5 threads should have been released
        assert_eq!(counter.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn test_multiple_waits() {
        let pauser = Pauser::new();

        // First pause
        pauser.set_pause(Duration::from_millis(50));
        let start = Instant::now();
        pauser.wait();
        let first_elapsed = start.elapsed();
        assert!(first_elapsed.as_millis() >= 40);

        // Second pause
        pauser.set_pause(Duration::from_millis(50));
        let start = Instant::now();
        pauser.wait();
        let second_elapsed = start.elapsed();
        assert!(second_elapsed.as_millis() >= 40);
    }

    #[test]
    fn test_pause_replacement() {
        let pauser = Pauser::new();

        // Set initial pause for 500ms
        pauser.set_pause(Duration::from_millis(500));

        thread::sleep(Duration::from_millis(100));

        // Check initial pause is active
        let (is_paused, remaining) = pauser.status();
        assert!(is_paused);
        let first_remaining = remaining.unwrap();

        // Replace with a longer pause
        pauser.set_pause(Duration::from_secs(10));

        thread::sleep(Duration::from_millis(100));

        // Check new pause is longer than what would remain from first
        let (is_paused, remaining) = pauser.status();
        assert!(is_paused);
        let second_remaining = remaining.unwrap();
        assert!(second_remaining > first_remaining);
    }

    #[test]
    fn test_concurrent_set_pause() {
        let pauser = Pauser::new();
        let mut handles = vec![];

        // Multiple threads setting pauses concurrently
        for i in 0..5 {
            let pauser = pauser.clone();
            let handle = thread::spawn(move || {
                thread::sleep(Duration::from_millis(i * 10));
                pauser.set_pause(Duration::from_millis(100 + i as u64 * 10));
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // Final pause should be set by the last thread
        let (is_paused, _) = pauser.status();
        assert!(is_paused);
    }

    #[test]
    fn test_is_paused_non_blocking() {
        let pauser = Pauser::new();

        // Initially not paused
        let remaining = pauser.is_paused();
        assert!(remaining.is_none());

        // Set pause
        pauser.set_pause(Duration::from_millis(100));

        let remaining = pauser.is_paused();
        assert!(remaining.is_some());
        assert!(remaining.unwrap().as_millis() > 0);
    }

    #[test]
    fn test_concurrent_wait_with_late_pause() {
        let pauser = Pauser::new();
        let counter = StdArc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        // Spawn threads that will wait
        for _ in 0..3 {
            let pauser = pauser.clone();
            let counter = StdArc::clone(&counter);

            let handle = thread::spawn(move || {
                pauser.wait();
                counter.fetch_add(1, Ordering::SeqCst);
            });
            handles.push(handle);
        }

        // Delay before setting pause
        thread::sleep(Duration::from_millis(100));

        pauser.set_pause(Duration::from_millis(50));

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // All threads should complete
        assert_eq!(counter.load(Ordering::SeqCst), 3);
    }
}
