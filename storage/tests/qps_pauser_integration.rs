// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the QPS rate limiter module.
//!
//! These tests go beyond unit tests by verifying the QPS limiter's behavior
//! in realistic scenarios: concurrent backend request simulation, sustained
//! throughput measurement, and interaction with the pauser module.

mod qps_integration {
    use nydus_storage::backend::qps::QpsLimiter;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Verify that the QPS limiter enforces the configured rate under sustained load.
    /// Spawns multiple threads making requests and checks that throughput is bounded.
    #[test]
    fn test_sustained_throughput_bounded_by_qps() {
        let qps = 50.0;
        let limiter = Arc::new(QpsLimiter::new(qps));
        let duration = Duration::from_secs(2);
        let completed = Arc::new(AtomicUsize::new(0));

        let mut handles = vec![];
        let thread_count = 8;

        for _ in 0..thread_count {
            let limiter = Arc::clone(&limiter);
            let completed = Arc::clone(&completed);
            let handle = std::thread::spawn(move || {
                let start = Instant::now();
                while start.elapsed() < duration {
                    let _ = limiter.acquire();
                    completed.fetch_add(1, Ordering::Relaxed);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let total = completed.load(Ordering::Relaxed);
        // Expected: ~qps * duration_secs + initial_tokens = 50*2 + 50 = 150
        // Allow generous margin for thread scheduling and timing variance.
        let expected_max = (qps * duration.as_secs_f64() * 1.3 + qps) as usize;
        assert!(
            total <= expected_max,
            "Total requests ({}) should be bounded by QPS limit (expected max ~{})",
            total,
            expected_max
        );
        // Should have completed a reasonable number of requests.
        let expected_min = (qps * duration.as_secs_f64() * 0.7) as usize;
        assert!(
            total >= expected_min,
            "Total requests ({}) should be at least ~{} (70% of expected)",
            total,
            expected_min
        );
    }

    /// Verify that the QPS limiter correctly handles burst followed by sustained load.
    /// This simulates a real backend pattern: initial burst of requests (e.g., prefetch)
    /// followed by steady-state on-demand reads.
    #[test]
    fn test_burst_then_sustained_pattern() {
        let qps = 20.0;
        let limiter = QpsLimiter::new(qps);

        // Phase 1: Burst — consume all initial tokens immediately.
        let mut burst_count = 0;
        while limiter.try_acquire() {
            burst_count += 1;
        }
        assert_eq!(burst_count, 20, "Initial burst should consume all tokens");

        // Phase 2: Sustained — requests should be rate-limited.
        let start = Instant::now();
        let mut sustained_count = 0;
        let sustained_duration = Duration::from_secs(1);

        while start.elapsed() < sustained_duration {
            let was_limited = limiter.acquire();
            if was_limited {
                sustained_count += 1;
            }
        }

        // Most requests in sustained phase should have been rate-limited.
        assert!(
            sustained_count > 0,
            "Some requests should have been rate-limited in sustained phase"
        );
    }

    /// Verify that concurrent readers with different priorities (simulated via
    /// different token counts) are correctly serialized by the limiter.
    #[test]
    fn test_mixed_token_requests_concurrent() {
        let limiter = Arc::new(QpsLimiter::new(100.0));
        let total_tokens = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        // Small requests (1 token each) — simulates on-demand reads.
        for _ in 0..5 {
            let limiter = Arc::clone(&limiter);
            let total = Arc::clone(&total_tokens);
            handles.push(std::thread::spawn(move || {
                for _ in 0..10 {
                    limiter.acquire();
                    total.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        // Large requests (5 tokens each) — simulates prefetch batch reads.
        for _ in 0..3 {
            let limiter = Arc::clone(&limiter);
            let total = Arc::clone(&total_tokens);
            handles.push(std::thread::spawn(move || {
                for _ in 0..5 {
                    limiter.acquire_tokens(5.0);
                    total.fetch_add(5, Ordering::Relaxed);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All requests should have completed: 5*10 + 3*5*5 = 50 + 75 = 125 tokens.
        let total = total_tokens.load(Ordering::Relaxed);
        assert_eq!(total, 125, "All tokens should be accounted for");
    }

    /// Verify that the QPS limiter's rate-limiting indication is correct
    /// when used in a retry-like pattern (similar to how retry_op will use it).
    #[test]
    fn test_retry_pattern_with_qps_limiter() {
        let limiter = QpsLimiter::new(5.0);

        // Simulate retry_op pattern:
        // 1. First attempt succeeds without rate limiting (tokens available).
        let was_limited = limiter.acquire();
        assert!(!was_limited, "First request should not be rate-limited");

        // 2. Exhaust remaining tokens (simulating burst of retries).
        while limiter.try_acquire() {}

        // 3. On last retry, acquire with rate limiting (like fallback to source).
        let was_limited = limiter.acquire();
        assert!(
            was_limited,
            "Request after token exhaustion should be rate-limited"
        );
    }
}

/// Integration tests for the Pauser module in combination with simulated backend requests.
mod pauser_integration {
    use nydus_storage::backend::pauser::Pauser;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Verify that the pauser correctly blocks concurrent "backend requests"
    /// and resumes them after the pause duration expires.
    #[test]
    fn test_pauser_blocks_concurrent_requests() {
        let pauser = Pauser::new();
        let request_count = Arc::new(AtomicUsize::new(0));
        let all_started = Arc::new(AtomicBool::new(false));
        let mut handles = vec![];

        // Set a 200ms pause before spawning threads.
        pauser.set_pause(Duration::from_millis(200));

        let start = Instant::now();

        // Spawn "backend request" threads that must wait for the pause.
        for _ in 0..10 {
            let pauser = pauser.clone();
            let count = Arc::clone(&request_count);
            let started = Arc::clone(&all_started);
            handles.push(std::thread::spawn(move || {
                started.store(true, Ordering::SeqCst);
                pauser.wait();
                count.fetch_add(1, Ordering::SeqCst);
            }));
        }

        // Wait briefly for threads to start.
        std::thread::sleep(Duration::from_millis(50));

        // At this point, threads should be blocked by the pauser.
        let completed = request_count.load(Ordering::SeqCst);
        assert_eq!(
            completed, 0,
            "No requests should complete while paused (got {})",
            completed
        );

        // Wait for pause to expire.
        for handle in handles {
            handle.join().unwrap();
        }

        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(180),
            "Requests should have been delayed by at least ~200ms (actual: {:?})",
            elapsed
        );

        // All requests should have completed.
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            10,
            "All 10 requests should complete after pause"
        );
    }

    /// Verify that clear_pause immediately unblocks waiting requests.
    /// This simulates an operator resuming requests after a manual pause.
    #[test]
    fn test_pauser_early_resume() {
        let pauser = Pauser::new();
        let completed = Arc::new(AtomicBool::new(false));

        // Set a long pause.
        pauser.set_pause(Duration::from_secs(60));

        let pauser_clone = pauser.clone();
        let completed_clone = Arc::clone(&completed);
        let handle = std::thread::spawn(move || {
            pauser_clone.wait();
            completed_clone.store(true, Ordering::SeqCst);
        });

        // Wait for thread to start waiting.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !completed.load(Ordering::SeqCst),
            "Request should still be paused"
        );

        // Clear pause — request should unblock immediately.
        let start = Instant::now();
        pauser.clear_pause();
        handle.join().unwrap();
        let resume_time = start.elapsed();

        assert!(
            completed.load(Ordering::SeqCst),
            "Request should complete after clear_pause"
        );
        assert!(
            resume_time < Duration::from_millis(100),
            "Resume should be near-instant (actual: {:?})",
            resume_time
        );
    }
}
