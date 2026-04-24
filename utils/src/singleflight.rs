//! Singleflight implementation for Rust.
//!
//! This module provides a mechanism to suppress duplicate function calls
//! for the same key. When multiple goroutines/tasks request the same key
//! simultaneously, only one will execute the function, and all others
//! will wait and share the result.

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use tokio::sync::{watch, Mutex};

/// Result of a singleflight call.
#[derive(Clone, Debug)]
pub struct CallResult<T> {
    /// The value returned by the function.
    pub value: T,
    /// Whether this call was shared with other callers (not the original caller).
    pub shared: bool,
}

/// Error type for singleflight operations.
#[derive(Clone, Debug)]
pub enum SingleflightError<E> {
    /// The underlying function returned an error.
    FunctionError(E),
    /// Type mismatch when downcasting the result (internal error).
    TypeMismatch,
    /// The singleflight call was cancelled without setting a result.
    Cancelled,
}

impl<E: std::fmt::Display> std::fmt::Display for SingleflightError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SingleflightError::FunctionError(e) => write!(f, "function error: {}", e),
            SingleflightError::TypeMismatch => write!(f, "type mismatch in singleflight result"),
            SingleflightError::Cancelled => write!(f, "singleflight call was cancelled"),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for SingleflightError<E> {}

/// Type-erased result for internal storage.
type BoxedResult = Arc<dyn Any + Send + Sync>;

/// Wrapper type for storing Result<T, E> in type-erased storage.
#[derive(Clone)]
struct ResultWrapper<T: Clone, E: Clone>(Result<T, E>);

/// State for in-flight calls.
enum CallState {
    /// A call is currently in progress; wait on the receiver.
    InFlight(watch::Receiver<Option<Result<BoxedResult, String>>>),
}

/// Singleflight group that manages in-flight calls.
///
/// When multiple callers request the same key simultaneously, only one
/// will execute the function and the result will be shared with all callers.
pub struct Group {
    /// Map of in-flight calls keyed by the request key.
    calls: Arc<Mutex<HashMap<String, CallState>>>,
}

impl Default for Group {
    fn default() -> Self {
        Self::new()
    }
}

impl Group {
    /// Create a new singleflight group.
    pub fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Execute the function for the given key, suppressing duplicate calls.
    ///
    /// If there's already an in-flight call for this key, this function will
    /// wait for it to complete and return the shared result.
    ///
    /// # Arguments
    /// * `key` - The key to deduplicate calls by.
    /// * `func` - The async function to execute if no call is in-flight.
    ///
    /// # Returns
    /// A `CallResult` containing the value and whether the result was shared,
    /// or a `SingleflightError` if the call failed.
    pub async fn do_call<T, E, F, Fut>(
        &self,
        key: &str,
        func: F,
    ) -> Result<CallResult<T>, SingleflightError<E>>
    where
        T: Clone + Send + Sync + 'static,
        E: Clone + Send + Sync + 'static,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let key = key.to_string();

        let mut calls = self.calls.lock().await;

        // Check after acquiring lock.
        if let Some(CallState::InFlight(rx)) = calls.get(&key) {
            let is_stale = {
                let borrowed = rx.borrow();
                let empty = borrowed.is_none();
                drop(borrowed);
                empty && rx.has_changed().is_err()
            };

            if is_stale {
                warn!(
                    "singleflight was canceled during the previous call, remove the stale key: {}",
                    key
                );
                calls.remove(&key);
            } else {
                let rx = rx.clone();
                drop(calls);
                return Self::wait_for_result::<T, E>(rx)
                    .await
                    .map(|value| CallResult {
                        value,
                        shared: true,
                    });
            }
        }

        // We are the one to perform the call.
        let (tx, rx) = watch::channel(None);
        calls.insert(key.clone(), CallState::InFlight(rx));
        drop(calls);

        // Execute the function.
        let result = func().await;

        // Store the result wrapped in Arc for type-erased storage.
        let wrapper = Arc::new(ResultWrapper(result.clone())) as BoxedResult;
        let send_result: Result<BoxedResult, String> = Ok(wrapper);

        // Notify all waiting tasks.
        let _ = tx.send(Some(send_result));

        // Update state and remove the in-flight entry.
        {
            let mut calls = self.calls.lock().await;
            calls.remove(&key);
        }

        result
            .map(|value| CallResult {
                value,
                shared: false,
            })
            .map_err(SingleflightError::FunctionError)
    }

    /// Wait for an in-flight call to complete and return the result.
    async fn wait_for_result<T, E>(
        mut rx: watch::Receiver<Option<Result<BoxedResult, String>>>,
    ) -> Result<T, SingleflightError<E>>
    where
        T: Clone + Send + Sync + 'static,
        E: Clone + Send + Sync + 'static,
    {
        loop {
            // Check current value.
            {
                let borrowed = rx.borrow_and_update();
                if let Some(result) = borrowed.as_ref() {
                    match result {
                        Ok(boxed) => {
                            // Try to downcast to our wrapper type.
                            if let Some(wrapper) = boxed.downcast_ref::<ResultWrapper<T, E>>() {
                                return wrapper.0.clone().map_err(SingleflightError::FunctionError);
                            }
                            // Type mismatch - this shouldn't happen if types are consistent.
                            return Err(SingleflightError::TypeMismatch);
                        }
                        Err(_) => {
                            // Unexpected error state.
                            return Err(SingleflightError::Cancelled);
                        }
                    }
                }
            }
            // Wait for a change. If sender is dropped, check one more time.
            if rx.changed().await.is_err() {
                // Sender was dropped. Check if value was set before drop.
                let borrowed = rx.borrow();
                if let Some(result) = borrowed.as_ref() {
                    match result {
                        Ok(boxed) => {
                            if let Some(wrapper) = boxed.downcast_ref::<ResultWrapper<T, E>>() {
                                return wrapper.0.clone().map_err(SingleflightError::FunctionError);
                            }
                            return Err(SingleflightError::TypeMismatch);
                        }
                        Err(_) => {
                            return Err(SingleflightError::Cancelled);
                        }
                    }
                }
                return Err(SingleflightError::Cancelled);
            }
        }
    }

    /// Forget a key, allowing the next call to execute even if one is in-flight.
    ///
    /// This is useful when you want to force a refresh.
    pub async fn forget(&self, key: &str) {
        let mut calls = self.calls.lock().await;
        calls.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn test_single_call() {
        let group = Group::default();
        let call_count = Arc::new(AtomicU64::new(0));

        let count = call_count.clone();
        let result: Result<CallResult<String>, SingleflightError<String>> = group
            .do_call("key1", || async move {
                count.fetch_add(1, Ordering::Relaxed);
                Ok("value1".to_string())
            })
            .await;

        let call_result = result.expect("call should succeed");
        assert_eq!(call_result.value, "value1");
        assert!(!call_result.shared);
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_concurrent_calls_singleflight() {
        let group = Arc::new(Group::new());
        let call_count = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for _ in 0..50 {
            let group = group.clone();
            let count = call_count.clone();
            let handle = tokio::spawn(async move {
                let result: Result<CallResult<String>, SingleflightError<String>> = group
                    .do_call("same_key", || async move {
                        count.fetch_add(1, Ordering::Relaxed);
                        // Simulate some work.
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        Ok("shared_value".to_string())
                    })
                    .await;
                result
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;

        // All should succeed.
        for result in &results {
            let call_result = result.as_ref().unwrap().as_ref().unwrap();
            assert_eq!(call_result.value, "shared_value");
        }

        // Only one actual call should have been made.
        let actual_calls = call_count.load(Ordering::Relaxed);
        assert_eq!(
            actual_calls, 1,
            "Singleflight should result in exactly 1 call, got {}",
            actual_calls
        );

        // Count how many were shared vs original.
        let shared_count = results
            .iter()
            .filter(|r| r.as_ref().unwrap().as_ref().unwrap().shared)
            .count();
        assert_eq!(
            shared_count, 49,
            "49 calls should be shared, got {}",
            shared_count
        );
    }

    #[tokio::test]
    async fn test_different_keys_independent() {
        let group = Arc::new(Group::new());
        let call_count = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for i in 0..5 {
            let group = group.clone();
            let count = call_count.clone();
            let key = format!("key_{}", i);
            let handle = tokio::spawn(async move {
                let key_clone = key.clone();
                let result: Result<CallResult<String>, SingleflightError<String>> = group
                    .do_call(&key, || async move {
                        count.fetch_add(1, Ordering::Relaxed);
                        Ok(format!("value_{}", key_clone))
                    })
                    .await;
                result
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;

        // All should succeed and none should be shared.
        for result in &results {
            let call_result = result.as_ref().unwrap().as_ref().unwrap();
            assert!(!call_result.shared);
        }

        // Each key should trigger its own call.
        assert_eq!(call_count.load(Ordering::Relaxed), 5);
    }

    #[tokio::test]
    async fn test_error_handling() {
        let group = Group::new();
        let call_count = Arc::new(AtomicU64::new(0));

        let count = call_count.clone();
        let result: Result<CallResult<String>, SingleflightError<String>> = group
            .do_call("error_key", || async move {
                count.fetch_add(1, Ordering::Relaxed);
                Err("something went wrong".to_string())
            })
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            SingleflightError::FunctionError(e) => {
                assert_eq!(e, "something went wrong");
                assert_eq!(
                    SingleflightError::FunctionError(e).to_string(),
                    "function error: something went wrong"
                );
            }
            _ => panic!("Expected FunctionError"),
        }

        let type_mismatch: SingleflightError<String> = SingleflightError::TypeMismatch;
        assert_eq!(
            type_mismatch.to_string(),
            "type mismatch in singleflight result"
        );

        let cancelled: SingleflightError<String> = SingleflightError::Cancelled;
        assert_eq!(cancelled.to_string(), "singleflight call was cancelled");

        let error_ref: &dyn std::error::Error = &cancelled;
        assert!(error_ref.source().is_none());

        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_concurrent_error_singleflight() {
        let group = Arc::new(Group::new());
        let call_count = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for _ in 0..20 {
            let group = group.clone();
            let count = call_count.clone();
            let handle = tokio::spawn(async move {
                let result: Result<CallResult<String>, SingleflightError<String>> = group
                    .do_call("error_key", || async move {
                        count.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        Err("shared error".to_string())
                    })
                    .await;
                result
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;

        // All should fail with the same error.
        for result in &results {
            match result.as_ref().unwrap().as_ref().unwrap_err() {
                SingleflightError::FunctionError(e) => assert_eq!(e, "shared error"),
                _ => panic!("Expected FunctionError"),
            }
        }

        // Only one actual call should have been made.
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_sequential_calls_after_completion() {
        let group = Arc::new(Group::new());
        let call_count = Arc::new(AtomicU64::new(0));

        // First call.
        let count = call_count.clone();
        let result1: Result<CallResult<String>, SingleflightError<String>> = group
            .do_call("key", || async move {
                count.fetch_add(1, Ordering::Relaxed);
                Ok("first".to_string())
            })
            .await;
        let call_result1 = result1.unwrap();
        assert_eq!(call_result1.value, "first");
        assert!(!call_result1.shared);

        // Second call (should execute again since first is complete).
        let count = call_count.clone();
        let result2: Result<CallResult<String>, SingleflightError<String>> = group
            .do_call("key", || async move {
                count.fetch_add(1, Ordering::Relaxed);
                Ok("second".to_string())
            })
            .await;
        let call_result2 = result2.unwrap();
        assert_eq!(call_result2.value, "second");
        assert!(!call_result2.shared);

        // Both calls should have executed.
        assert_eq!(call_count.load(Ordering::Relaxed), 2);

        // Forget should allow a new execution even while one call is still in flight.
        let count = call_count.clone();
        let group_clone = group.clone();
        let handle = tokio::spawn(async move {
            group_clone
                .do_call("forced_refresh", || async move {
                    count.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok::<_, String>("stale".to_string())
                })
                .await
        });

        tokio::time::sleep(Duration::from_millis(50)).await;
        group.forget("forced_refresh").await;

        let count = call_count.clone();
        let refreshed = group
            .do_call("forced_refresh", || async move {
                count.fetch_add(1, Ordering::Relaxed);
                Ok::<_, String>("fresh".to_string())
            })
            .await
            .expect("forget should allow a fresh execution");

        assert_eq!(refreshed.value, "fresh");
        assert!(!refreshed.shared);
        assert_eq!(call_count.load(Ordering::Relaxed), 4);

        handle.abort();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn test_with_custom_types() {
        #[derive(Clone, Debug, PartialEq)]
        struct CustomResult {
            id: u64,
            name: String,
        }

        #[derive(Clone, Debug, PartialEq)]
        struct CustomError {
            code: i32,
            message: String,
        }

        let group = Arc::new(Group::new());
        let call_count = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();
        for _ in 0..10 {
            let group = group.clone();
            let count = call_count.clone();
            let handle = tokio::spawn(async move {
                let result: Result<CallResult<CustomResult>, SingleflightError<CustomError>> =
                    group
                        .do_call("custom_key", || async move {
                            count.fetch_add(1, Ordering::Relaxed);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            Ok(CustomResult {
                                id: 42,
                                name: "test".to_string(),
                            })
                        })
                        .await;
                result
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;

        // All should succeed with the same custom result.
        for result in &results {
            let call_result = result.as_ref().unwrap().as_ref().unwrap();
            assert_eq!(call_result.value.id, 42);
            assert_eq!(call_result.value.name, "test");
        }

        // Only one actual call should have been made.
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_channel_notification_logic() {
        // This test explicitly validates the tokio::watch channel behavior relied upon by Singleflight.
        // It ensures that data is accessible to subscribers regardless of whether they
        // subscribe before or after the data is sent (but before the channel is dropped).

        let (tx, rx) = tokio::sync::watch::channel::<Option<Result<BoxedResult, String>>>(None);

        // Case 1: Subscriber arrives BEFORE data is ready (simulates standard waiting caller)
        let rx_early = rx.clone();
        let early_handle = tokio::spawn(async move {
            Group::wait_for_result::<String, String>(rx_early)
                .await
                .map(|boxed| boxed)
        });

        tokio::time::sleep(Duration::from_secs(1)).await;

        // 2. Send the result (simulates the function completing)
        // Use ResultWrapper to match what wait_for_result expects
        let wrapper: ResultWrapper<String, String> = ResultWrapper(Ok("success".to_string()));
        let boxed_value: BoxedResult = Arc::new(wrapper);
        tx.send(Some(Ok(boxed_value))).expect("send failed");
        let rx_late1 = rx.clone();
        drop(tx);

        // Case 3: Subscriber arrives AFTER data is sent (simulates race condition before map cleanup)
        // In Singleflight, we remove the key after sending, but a thread might grab the lock
        // and clone the rx just before removal.
        let rx_late2 = rx.clone();

        // Verify rx_late sees the value immediately without needing to await .changed()
        {
            let late_result = Group::wait_for_result::<String, String>(rx_late2)
                .await
                .map(|boxed| boxed)
                .unwrap();
            assert_eq!(
                late_result, "success",
                "Late subscriber should see value immediately"
            );

            let late_result2 = Group::wait_for_result::<String, String>(rx_late1)
                .await
                .map(|boxed| boxed)
                .unwrap();
            assert_eq!(
                late_result2, "success",
                "Late subscriber should see value immediately"
            );
        }

        // Verify early subscriber also received the data
        tokio::time::sleep(Duration::from_secs(1)).await;
        let early_result = early_handle.await.unwrap();
        assert_eq!(
            early_result.unwrap(),
            "success".to_string(),
            "Early subscriber should receive notification"
        );

        // Case 4: The receiver sees a value of the wrong concrete type.
        let wrong_wrapper: ResultWrapper<u64, String> = ResultWrapper(Ok(7));
        let wrong_boxed: BoxedResult = Arc::new(wrong_wrapper);
        let (_tx, rx_type_mismatch) = tokio::sync::watch::channel::<
            Option<Result<BoxedResult, String>>,
        >(Some(Ok(wrong_boxed)));
        let type_mismatch = Group::wait_for_result::<String, String>(rx_type_mismatch).await;
        assert!(matches!(
            type_mismatch,
            Err(SingleflightError::TypeMismatch)
        ));

        // Case 5: The receiver sees an unexpected channel error payload.
        let (_tx, rx_cancelled) = tokio::sync::watch::channel::<Option<Result<BoxedResult, String>>>(
            Some(Err("sender failed".to_string())),
        );
        let cancelled = Group::wait_for_result::<String, String>(rx_cancelled).await;
        assert!(matches!(cancelled, Err(SingleflightError::Cancelled)));
    }

    // =============================================================================
    // Regression tests for two DNS-related paths:
    //
    // 1. The DNS query returns Err directly.
    //    This is a normal completion path: the error is published to waiters and
    //    the in-flight entry is removed.
    //
    // 2. The DNS query future is dropped by an external timeout.
    //    This is the buggy path: the sender disappears before publishing any
    //    result, leaving behind a stale in-flight receiver.
    //
    // The fix keeps the existing normal error flow unchanged and only teaches the
    // next caller to detect and discard a stale receiver before waiting on it.
    // =============================================================================

    /// Scenario 1: func() returns Err directly (e.g., DNS lookup error after
    /// hickory-resolver's internal 5s×2 retry timeout).
    ///
    /// The error flows through the normal code path: func().await returns Err,
    /// it gets wrapped in ResultWrapper and sent via the watch channel, the
    /// InFlight entry is removed. Subsequent calls are NOT affected.
    ///
    /// This test passes on BOTH old and new code — this path was never buggy.
    #[tokio::test]
    async fn test_func_error_does_not_cause_cancelled() {
        let group = Arc::new(Group::new());
        let call_count = Arc::new(AtomicU64::new(0));

        // First call: func returns Err (simulates DNS lookup failure).
        let group_clone = group.clone();
        let count_clone = call_count.clone();
        let result1 = group_clone
            .do_call("dns_key", || async move {
                count_clone.fetch_add(1, Ordering::Relaxed);
                // Simulate hickory-resolver returning an error after internal timeout.
                Err::<String, String>("no record found for name".to_string())
            })
            .await;

        // Should get FunctionError, NOT Cancelled.
        assert!(
            matches!(&result1, Err(SingleflightError::FunctionError(e)) if e == "no record found for name"),
            "First call should return FunctionError, got: {:?}",
            result1
        );
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        // Second call with same key: should execute a NEW call, not get Cancelled.
        let group_clone = group.clone();
        let count_clone = call_count.clone();
        let result2 = group_clone
            .do_call("dns_key", || async move {
                count_clone.fetch_add(1, Ordering::Relaxed);
                Ok::<_, String>("resolved_now".to_string())
            })
            .await;

        let call_result = result2.expect("Second call should succeed, NOT return Cancelled");
        assert_eq!(call_result.value, "resolved_now");
        assert!(!call_result.shared, "Should be a fresh call, not shared");
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            2,
            "Two actual calls should have been made"
        );
    }

    /// Scenario 1b: func() returns Err with concurrent waiters.
    ///
    /// All waiters should get FunctionError (shared), and the next call
    /// should work normally. No Cancelled anywhere.
    #[tokio::test]
    async fn test_func_error_with_concurrent_waiters_no_cancelled() {
        let group = Arc::new(Group::new());
        let call_count = Arc::new(AtomicU64::new(0));

        // Spawn concurrent calls where the executor returns Err.
        let mut handles = Vec::new();
        for _ in 0..20 {
            let group_clone = group.clone();
            let count_clone = call_count.clone();
            let handle = tokio::spawn(async move {
                group_clone
                    .do_call("err_key", || async move {
                        count_clone.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        Err::<String, String>("dns timeout".to_string())
                    })
                    .await
            });
            handles.push(handle);
        }

        let results: Vec<_> = futures::future::join_all(handles).await;

        // ALL should get FunctionError, NONE should get Cancelled.
        for (i, result) in results.iter().enumerate() {
            let inner = result.as_ref().unwrap();
            assert!(
                matches!(inner, Err(SingleflightError::FunctionError(e)) if e == "dns timeout"),
                "Call {} should get FunctionError, got: {:?}",
                i,
                inner
            );
        }

        // Only one actual call due to singleflight.
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        // Next call should work normally — no stale state.
        let group_clone = group.clone();
        let count_clone = call_count.clone();
        let result = group_clone
            .do_call("err_key", || async move {
                count_clone.fetch_add(1, Ordering::Relaxed);
                Ok::<_, String>("ok_now".to_string())
            })
            .await;

        assert_eq!(result.unwrap().value, "ok_now");
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    /// Scenario 2: External timeout cancels the do_call future (e.g., reqwest
    /// drops the DNS resolve future after its connection timeout).
    ///
    /// The executor's future is dropped mid-flight: func().await never returns,
    /// watch::Sender is dropped without sending any result, but the InFlight
    /// entry stays in the HashMap.
    ///
    /// The cancelled executor leaves behind a stale receiver. The next caller
    /// must detect that stale receiver and start a fresh execution instead of
    /// returning Cancelled forever.
    #[tokio::test]
    async fn test_external_timeout_causes_cancelled() {
        let group = Arc::new(Group::new());
        let call_count = Arc::new(AtomicU64::new(0));

        // Simulate reqwest's connection timeout cancelling the resolve future.
        // tokio::time::timeout plays the role of reqwest's timeout wrapper.
        let group_clone = group.clone();
        let count_clone = call_count.clone();
        let result = tokio::time::timeout(Duration::from_millis(100), async move {
            group_clone
                .do_call("timeout_key", || async move {
                    count_clone.fetch_add(1, Ordering::Relaxed);
                    // Simulate DNS query hanging due to network outage.
                    // This will be cancelled by the outer timeout.
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok::<_, String>("should_not_complete".to_string())
                })
                .await
        })
        .await;

        // The outer timeout fires, dropping the do_call future.
        assert!(result.is_err(), "Should timeout");
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            1,
            "func was entered once before cancellation"
        );

        // Now try the same key again. The stale receiver should be discarded and
        // this call should execute normally.
        let group_clone = group.clone();
        let count_clone = call_count.clone();
        let result = tokio::time::timeout(Duration::from_secs(5), async move {
            group_clone
                .do_call("timeout_key", || async move {
                    count_clone.fetch_add(1, Ordering::Relaxed);
                    Ok::<_, String>("recovered_after_timeout".to_string())
                })
                .await
        })
        .await;

        let call_result = result
            .expect("Should not timeout — stale entry should be cleaned up")
            .expect("Should succeed, not return Cancelled");
        assert_eq!(call_result.value, "recovered_after_timeout");
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            2,
            "Recovery call should execute func again"
        );
    }

    /// Regression test: when an executor task is cancelled (future dropped),
    /// the in-flight entry must be cleaned up so subsequent calls can recover.
    ///
    /// **Reproduces the bug**: with the old code, after the executor is aborted,
    /// the stale InFlight entry remains in the map forever. The second do_call
    /// finds it, clones the dead rx, and immediately gets Cancelled — permanently.
    #[tokio::test]
    async fn test_cancelled_executor_recovers() {
        let group = Arc::new(Group::new());
        let call_count = Arc::new(AtomicU64::new(0));

        // Start an executor that will be cancelled mid-flight.
        let group_clone = group.clone();
        let count_clone = call_count.clone();
        let handle = tokio::spawn(async move {
            group_clone
                .do_call("cancel_key", || async move {
                    count_clone.fetch_add(1, Ordering::Relaxed);
                    // Simulate a long-running operation that will be cancelled.
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok::<_, String>("should_not_complete".to_string())
                })
                .await
        });

        // Give the executor time to start and register in the map.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Cancel the executor task (simulates reqwest timeout dropping the future).
        handle.abort();
        let _ = handle.await;

        // Now try to call with the same key. This must succeed (not hang or return Cancelled).
        let group_clone = group.clone();
        let count_clone = call_count.clone();
        let result = tokio::time::timeout(Duration::from_secs(5), async move {
            group_clone
                .do_call("cancel_key", || async move {
                    count_clone.fetch_add(1, Ordering::Relaxed);
                    Ok::<_, String>("recovered".to_string())
                })
                .await
        })
        .await;

        let call_result = result
            .expect("Should not timeout - stale entry should be cleaned up")
            .expect("Call should succeed after recovery");
        assert_eq!(call_result.value, "recovered");
        assert!(!call_result.shared);
    }

    /// Regression test: when an executor is cancelled with waiting callers,
    /// the waiters get Cancelled but subsequent NEW callers can succeed.
    ///
    /// **Reproduces the bug**: with the old code, the stale entry stays in the map
    /// after the executor is aborted, so the "new caller" at the end also gets
    /// Cancelled or hangs forever.
    #[tokio::test]
    async fn test_cancelled_executor_with_waiting_callers() {
        let group = Arc::new(Group::new());

        // Start an executor.
        let group_clone = group.clone();
        let executor_handle = tokio::spawn(async move {
            group_clone
                .do_call("wait_key", || async move {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Ok::<_, String>("should_not_complete".to_string())
                })
                .await
        });

        // Give the executor time to register.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Start some waiting callers (they will wait on the same rx).
        let mut waiter_handles = Vec::new();
        for _ in 0..5 {
            let group_clone = group.clone();
            let handle = tokio::spawn(async move {
                group_clone
                    .do_call("wait_key", || async move {
                        Ok::<_, String>("waiter_value".to_string())
                    })
                    .await
            });
            waiter_handles.push(handle);
        }

        // Give waiters time to start waiting.
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Cancel the executor.
        executor_handle.abort();
        let _ = executor_handle.await;

        // Waiters that were already waiting on the dead sender get Cancelled.
        for handle in waiter_handles {
            let result = handle.await.unwrap();
            assert!(
                matches!(result, Err(SingleflightError::Cancelled)),
                "Waiting callers should get Cancelled, got: {:?}",
                result
            );
        }

        // But a NEW caller must succeed once the stale entry is detected.
        let group_clone = group.clone();
        let result = tokio::time::timeout(Duration::from_secs(5), async move {
            group_clone
                .do_call("wait_key", || async move {
                    Ok::<_, String>("new_caller_value".to_string())
                })
                .await
        })
        .await;

        let call_result = result
            .expect("Should not timeout")
            .expect("New caller should succeed");
        assert_eq!(call_result.value, "new_caller_value");
    }

    /// Repeat the cancel-and-recover flow to make sure stale receiver detection
    /// keeps working across multiple rounds and does not leave corrupted state.
    #[tokio::test]
    async fn test_cancelled_executor_recovers_repeated() {
        // Variant: cancel and recover multiple times to ensure no state corruption.
        let group = Arc::new(Group::new());

        for round in 0..5 {
            // Start executor, then cancel it.
            let group_clone = group.clone();
            let handle = tokio::spawn(async move {
                group_clone
                    .do_call("repeat_key", || async move {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        Ok::<_, String>("never".to_string())
                    })
                    .await
            });

            tokio::time::sleep(Duration::from_millis(50)).await;
            handle.abort();
            let _ = handle.await;

            // Recover.
            let group_clone = group.clone();
            let expected = format!("recovered_{}", round);
            let expected_clone = expected.clone();
            let result = tokio::time::timeout(Duration::from_secs(5), async move {
                group_clone
                    .do_call(
                        "repeat_key",
                        || async move { Ok::<_, String>(expected_clone) },
                    )
                    .await
            })
            .await;

            let call_result = result
                .unwrap_or_else(|_| panic!("Timeout on round {}", round))
                .unwrap_or_else(|e| panic!("Error on round {}: {:?}", round, e));
            assert_eq!(call_result.value, expected);
        }
    }
}
