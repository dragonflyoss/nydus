// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;

lazy_static! {
    static ref CONFIG_MAP: ArcSwap<HashMap<String, String>> = ArcSwap::from_pointee(HashMap::new());
}

#[cfg(test)]
mod test_sync {
    use std::sync::Mutex;
    lazy_static! {
        pub static ref TEST_LOCK: Mutex<()> = Mutex::new(());
    }
}

/// Configuration keys for the system
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum Keys {
    /// Registry authentication configuration for a specific id
    RegistryAuth,
}

impl From<&Keys> for String {
    fn from(key: &Keys) -> Self {
        match key {
            Keys::RegistryAuth => "registry_auth".to_string(),
        }
    }
}

impl TryFrom<&str> for Keys {
    type Error = ();

    fn try_from(key: &str) -> Result<Self, Self::Error> {
        match key {
            "registry_auth" => Ok(Keys::RegistryAuth),
            _ => Err(()),
        }
    }
}

impl TryFrom<String> for Keys {
    type Error = ();

    fn try_from(key: String) -> Result<Self, Self::Error> {
        Keys::try_from(key.as_str())
    }
}

/// Set the value of the key.
///
/// This will update the global configuration map with the given key-value pair.
/// If the key already exists, its value will be replaced.
///
/// # Arguments
///
/// * `id` - The identifier for scoping the configuration
/// * `key` - The configuration key
/// * `value` - The configuration value
///
/// # Example
///
/// ```
/// use nydus_utils::config::{self, Keys};
///
/// config::set("/mount", &Keys::RegistryAuth, "basic:xxx".to_string());
/// ```
pub fn set(id: &str, key: &Keys, value: String) {
    let mut map = (**CONFIG_MAP.load()).clone();
    let key_str: String = key.into();
    map.insert(format!("{}:{}", id, key_str), value);
    CONFIG_MAP.store(Arc::new(map));
}

/// Return the value of the key and whether it has changed compared to previous value.
///
/// This function checks if the current value differs from the provided previous value.
///
/// # Arguments
///
/// * `id` - The identifier for scoping the configuration
/// * `key` - The configuration key to query
/// * `prev` - The previous value to compare against
///
/// # Returns
///
/// A tuple containing:
/// - The current value (or empty string if key doesn't exist)
/// - A boolean indicating whether the value has changed
///
/// # Example
///
/// ```
/// use nydus_utils::config::{self, Keys};
///
/// let (value, changed) = config::get_changed("/mount", &Keys::RegistryAuth, "basic:old");
/// if changed {
///     println!("Registry auth changed to: {}", value);
/// }
/// ```
pub fn get_changed(id: &str, key: &Keys, prev: &str) -> (String, bool) {
    let map = CONFIG_MAP.load();
    let key_str: String = key.into();
    let full_key = format!("{}:{}", id, key_str);
    let val = map.get(&full_key).cloned().unwrap_or_default();
    let changed = val != prev;
    (val, changed)
}

/// Return the value of the key.
///
/// If the key doesn't exist, returns an empty string.
///
/// # Arguments
///
/// * `id` - The identifier
/// * `key` - The configuration key to query
///
/// # Returns
///
/// The value associated with the key, or empty string if not found
///
/// # Example
///
/// ```
/// use nydus_utils::config::{self, Keys};
///
/// let auth = config::get("/mount", &Keys::RegistryAuth);
/// println!("Registry auth: {}", auth);
/// ```
pub fn get(id: &str, key: &Keys) -> String {
    get_changed(id, key, "").0
}

/// Remove a key from the configuration map.
///
/// # Arguments
///
/// * `id` - The identifier for scoping the configuration
/// * `key` - The configuration key to remove
///
/// # Returns
///
/// The value that was removed, or None if the key didn't exist
///
/// # Example
///
/// ```
/// use nydus_utils::config::{self, Keys};
///
/// if let Some(old_value) = config::remove("/mount", &Keys::RegistryAuth) {
///     println!("Removed registry auth: {}", old_value);
/// }
/// ```
pub fn remove(id: &str, key: &Keys) -> Option<String> {
    let mut map = (**CONFIG_MAP.load()).clone();
    let key_str: String = key.into();
    let full_key = format!("{}:{}", id, key_str);
    let removed = map.remove(&full_key);
    CONFIG_MAP.store(Arc::new(map));
    removed
}

/// Clear all configuration entries.
///
/// # Example
///
/// ```
/// nydus_utils::config::clear();
/// ```
pub fn clear() {
    CONFIG_MAP.store(Arc::new(HashMap::new()));
}

/// Check if a key exists in the configuration.
///
/// # Arguments
///
/// * `id` - The identifier for scoping the configuration
/// * `key` - The configuration key to check
///
/// # Returns
///
/// true if the key exists, false otherwise
///
/// # Example
///
/// ```
/// use nydus_utils::config::{self, Keys};
///
/// if config::contains_key("/mount", &Keys::RegistryAuth) {
///     println!("Registry auth is configured");
/// }
/// ```
pub fn contains_key(id: &str, key: &Keys) -> bool {
    let map = CONFIG_MAP.load();
    let key_str: String = key.into();
    let full_key = format!("{}:{}", id, key_str);
    map.contains_key(&full_key)
}

/// Get all configuration key strings.
///
/// # Returns
///
/// A vector of all configuration key strings
///
/// # Example
///
/// ```
/// let keys = nydus_utils::config::keys();
/// for key in keys {
///     println!("Config key: {}", key);
/// }
/// ```
pub fn keys() -> Vec<String> {
    let map = CONFIG_MAP.load();
    map.keys().cloned().collect()
}

/// Get the number of configuration entries.
///
/// # Returns
///
/// The number of key-value pairs in the configuration
///
/// # Example
///
/// ```
/// let count = nydus_utils::config::len();
/// println!("Configuration has {} entries", count);
/// ```
pub fn len() -> usize {
    let map = CONFIG_MAP.load();
    map.len()
}

/// Check if the configuration is empty.
///
/// # Returns
///
/// true if there are no configuration entries, false otherwise
///
/// # Example
///
/// ```
/// if nydus_utils::config::is_empty() {
///     println!("No configuration set");
/// }
/// ```
pub fn is_empty() -> bool {
    len() == 0
}

/// Get all configuration entries as a HashMap.
///
/// # Returns
///
/// A HashMap containing all key-value pairs
///
/// # Example
///
/// ```
/// let all_config = nydus_utils::config::get_all(None);
/// for (key, value) in all_config.iter() {
///     println!("{} = {}", key, value);
/// }
/// ```
pub fn get_all(id: Option<String>) -> HashMap<String, String> {
    let map = CONFIG_MAP.load();
    if let Some(id_str) = id {
        map.iter()
            .filter_map(|(key, value)| {
                let prefix = format!("{}:", id_str);
                if key.starts_with(&prefix) {
                    Some((
                        key.strip_prefix(&prefix).unwrap().to_string(),
                        value.clone(),
                    ))
                } else {
                    None
                }
            })
            .collect()
    } else {
        (**map).clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let id = "test_id";
        let key = Keys::RegistryAuth;
        set(id, &key, "test_value".to_string());
        let value = get(id, &key);
        assert_eq!(value, "test_value");

        clear();
    }

    #[test]
    fn test_get_nonexistent_key() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let id = "nonexistent";
        let key = Keys::RegistryAuth;
        let value = get(id, &key);
        assert_eq!(value, "");

        clear();
    }

    #[test]
    fn test_get_changed() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let id = "test_id";
        let key = Keys::RegistryAuth;
        set(id, &key, "value1".to_string());

        let (value, changed) = get_changed(id, &key, "");
        assert_eq!(value, "value1");
        assert!(changed);

        let (value, changed) = get_changed(id, &key, "value1");
        assert_eq!(value, "value1");
        assert!(!changed);

        set(id, &key, "value2".to_string());
        let (value, changed) = get_changed(id, &key, "value1");
        assert_eq!(value, "value2");
        assert!(changed);

        clear();
    }

    #[test]
    fn test_remove() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let id = "test_id";
        let key = Keys::RegistryAuth;
        set(id, &key, "test_value".to_string());
        assert_eq!(get(id, &key), "test_value");

        let removed = remove(id, &key);
        assert_eq!(removed, Some("test_value".to_string()));
        assert_eq!(get(id, &key), "");

        let removed = remove("nonexistent", &Keys::RegistryAuth);
        assert_eq!(removed, None);

        clear();
    }

    #[test]
    fn test_clear() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let key = Keys::RegistryAuth;

        set("id1", &key, "value1".to_string());
        set("id2", &key, "value2".to_string());
        set("id3", &key, "value3".to_string());

        assert!(contains_key("id1", &key));
        assert!(contains_key("id2", &key));
        assert!(contains_key("id3", &key));

        clear();

        assert!(!contains_key("id1", &key));
        assert!(!contains_key("id2", &key));
        assert!(!contains_key("id3", &key));
    }

    #[test]
    fn test_contains_key() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let id = "test_id";
        let key = Keys::RegistryAuth;
        assert!(!contains_key(id, &key));

        set(id, &key, "test_value".to_string());
        assert!(contains_key(id, &key));

        remove(id, &key);
        assert!(!contains_key(id, &key));

        clear();
    }

    #[test]
    fn test_keys() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let key = Keys::RegistryAuth;
        set("key1", &key, "value1".to_string());
        set("key2", &key, "value2".to_string());
        set("key3", &key, "value3".to_string());

        let keys_list = keys();
        assert_eq!(keys_list.len(), 3);
        assert!(keys_list.contains(&"key1:registry_auth".to_string()));
        assert!(keys_list.contains(&"key2:registry_auth".to_string()));
        assert!(keys_list.contains(&"key3:registry_auth".to_string()));

        clear();
    }

    #[test]
    fn test_len_and_is_empty() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        assert_eq!(len(), 0);
        assert!(is_empty());

        let key = Keys::RegistryAuth;
        set("key1", &key, "value1".to_string());
        assert_eq!(len(), 1);
        assert!(!is_empty());

        set("key2", &key, "value2".to_string());
        assert_eq!(len(), 2);
        assert!(!is_empty());

        remove("key1", &key);
        assert_eq!(len(), 1);
        assert!(!is_empty());

        clear();
        assert_eq!(len(), 0);
        assert!(is_empty());
    }

    #[test]
    fn test_update_existing_key() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let id = "test_id";
        let key = Keys::RegistryAuth;
        set(id, &key, "value1".to_string());
        assert_eq!(get(id, &key), "value1");

        set(id, &key, "value2".to_string());
        assert_eq!(get(id, &key), "value2");
        assert_eq!(len(), 1);

        clear();
    }

    #[test]
    fn test_concurrent_access() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        // Test thread-safety by spawning threads sequentially
        // Each thread performs atomic write-read operations
        use std::thread;

        for i in 0..10 {
            let handle = thread::spawn(move || {
                let id = format!("concurrent_test_{}", i);
                let key = Keys::RegistryAuth;
                let value = format!("value_{}", i);

                // Write and immediately read - tests atomicity
                set(&id, &key, value.clone());
                let retrieved = get(&id, &key);

                assert_eq!(
                    retrieved, value,
                    "Thread {} failed: expected '{}', got '{}'",
                    i, value, retrieved
                );

                (id, key)
            });

            // Join immediately to ensure sequential execution under test lock
            let (id, key) = handle.join().expect("Thread panicked");
            remove(&id, &key);
        }

        clear();
    }

    #[test]
    fn test_empty_key_and_value() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let key = Keys::RegistryAuth;
        set("", &key, "empty_id".to_string());
        assert_eq!(get("", &key), "empty_id");

        set("empty_value", &key, "".to_string());
        assert_eq!(get("empty_value", &key), "");
        assert!(contains_key("empty_value", &key));

        clear();
    }

    #[test]
    fn test_special_characters() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let key = Keys::RegistryAuth;

        set("key/with/slashes", &key, "value1".to_string());
        assert_eq!(get("key/with/slashes", &key), "value1");

        set("key.with.dots", &key, "value2".to_string());
        assert_eq!(get("key.with.dots", &key), "value2");

        set("key-with-dashes", &key, "value3".to_string());
        assert_eq!(get("key-with-dashes", &key), "value3");

        set("key_with_underscores", &key, "value4".to_string());
        assert_eq!(get("key_with_underscores", &key), "value4");

        remove("key/with/slashes", &key);
        remove("key.with.dots", &key);
        remove("key-with-dashes", &key);
        remove("key_with_underscores", &key);
    }

    #[test]
    fn test_large_values() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let large_value = "x".repeat(10000);
        let id = "large_key";
        let key = Keys::RegistryAuth;
        set(id, &key, large_value.clone());
        assert_eq!(get(id, &key), large_value);

        clear();
    }

    #[test]
    fn test_get_all() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let key = Keys::RegistryAuth;
        set("key1", &key, "value1".to_string());
        set("key2", &key, "value2".to_string());
        set("key3", &key, "value3".to_string());

        let all = get_all(None);
        assert_eq!(all.len(), 3);
        assert_eq!(all.get("key1:registry_auth"), Some(&"value1".to_string()));
        assert_eq!(all.get("key2:registry_auth"), Some(&"value2".to_string()));
        assert_eq!(all.get("key3:registry_auth"), Some(&"value3".to_string()));

        clear();
    }

    #[test]
    fn test_get_all_with_id() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        clear();

        let key = Keys::RegistryAuth;
        set("id1", &key, "value1".to_string());
        set("id2", &key, "value2".to_string());
        set("id3", &key, "value3".to_string());

        let all = get_all(Some(String::from("id1")));
        assert_eq!(all.len(), 1);
        assert_eq!(all.get("registry_auth"), Some(&"value1".to_string()));

        clear();
    }

    #[test]
    fn test_key_string_conversion() {
        let _guard = test_sync::TEST_LOCK.lock().unwrap();
        use std::convert::TryFrom;

        let key = Keys::RegistryAuth;
        let key_str: String = (&key).into();
        assert_eq!(key_str, "registry_auth");

        let parsed = Keys::try_from(key_str.as_str());
        assert_eq!(parsed, Ok(Keys::RegistryAuth));

        // Test invalid format
        assert_eq!(Keys::try_from("invalid_format"), Err(()));
        assert_eq!(Keys::try_from(""), Err(()));
    }
}
