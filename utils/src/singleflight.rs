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
            let rx = rx.clone();
            drop(calls);
            return Self::wait_for_result::<T, E>(rx)
                .await
                .map(|value| CallResult {
                    value,
                    shared: true,
                });
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
        let group = Group::new();
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
            SingleflightError::FunctionError(e) => assert_eq!(e, "something went wrong"),
            _ => panic!("Expected FunctionError"),
        }
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
        let group = Group::new();
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
        let early_handle =
            tokio::spawn(async move { Group::wait_for_result::<String, String>(rx_early).await });

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
                .unwrap();
            assert_eq!(
                late_result, "success",
                "Late subscriber should see value immediately"
            );

            let late_result2 = Group::wait_for_result::<String, String>(rx_late1)
                .await
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
    }
}
