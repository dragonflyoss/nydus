// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{fs, path};

use anyhow::Result;
use gix_attributes::parse;
use gix_attributes::parse::Kind;

const KEY_TYPE: &str = "type";
const KEY_CRCS: &str = "crcs";
const VAL_EXTERNAL: &str = "external";

pub struct Parser {}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Item {
    pub pattern: PathBuf,
    pub attributes: HashMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct Attributes {
    pub items: HashMap<PathBuf, HashMap<String, String>>,
    pub crcs: HashMap<PathBuf, Vec<u32>>,
}

impl Attributes {
    /// Parse nydus attributes from a file.
    pub fn from<P: AsRef<Path>>(path: P) -> Result<Attributes> {
        let content = fs::read(path)?;
        let _items = parse(&content);

        let mut items = HashMap::new();
        let mut crcs = HashMap::new();
        for _item in _items {
            let _item = _item?;
            if let Kind::Pattern(pattern) = _item.0 {
                let mut path = PathBuf::from(pattern.text.to_string());
                if !path.is_absolute() {
                    path = path::Path::new("/").join(path);
                }
                let mut current_path = path.clone();
                let mut attributes = HashMap::new();
                let mut _type = String::new();
                let mut _crcs = vec![];
                for line in _item.1 {
                    let line = line?;
                    let name = line.name.as_str();
                    let state = line.state.as_bstr().unwrap_or_default();
                    if name == KEY_TYPE {
                        _type = state.to_string();
                    }
                    if name == KEY_CRCS {
                        _crcs = state
                            .to_string()
                            .split(',')
                            .map(|s| {
                                let trimmed = s.trim();
                                let hex_str = if let Some(stripped) = trimmed.strip_prefix("0x") {
                                    stripped
                                } else {
                                    trimmed
                                };
                                u32::from_str_radix(hex_str, 16).map_err(|e| anyhow::anyhow!(e))
                            })
                            .collect::<Result<Vec<u32>, _>>()?;
                    }
                    attributes.insert(name.to_string(), state.to_string());
                }
                crcs.insert(path.clone(), _crcs);
                items.insert(path, attributes);

                // process parent directory
                while let Some(parent) = current_path.parent() {
                    if parent == Path::new("/") {
                        break;
                    }
                    let mut attributes = HashMap::new();
                    if !items.contains_key(parent) {
                        attributes.insert(KEY_TYPE.to_string(), VAL_EXTERNAL.to_string());
                        items.insert(parent.to_path_buf(), attributes);
                    }
                    current_path = parent.to_path_buf();
                }
            }
        }

        Ok(Attributes { items, crcs })
    }

    fn check_external(&self, attributes: &HashMap<String, String>) -> bool {
        attributes.get(KEY_TYPE) == Some(&VAL_EXTERNAL.to_string())
    }

    pub fn is_external<P: AsRef<Path>>(&self, path: P) -> bool {
        if let Some(attributes) = self.items.get(path.as_ref()) {
            return self.check_external(attributes);
        }
        false
    }

    pub fn is_prefix_external<P: AsRef<Path>>(&self, target: P) -> bool {
        self.items
            .iter()
            .any(|item| item.0.starts_with(&target) && self.check_external(item.1))
    }

    pub fn get_value<P: AsRef<Path>, K: AsRef<str>>(&self, path: P, key: K) -> Option<String> {
        if let Some(attributes) = self.items.get(path.as_ref()) {
            return attributes.get(key.as_ref()).map(|s| s.to_string());
        }
        None
    }

    pub fn get_values<P: AsRef<Path>>(&self, path: P) -> Option<&HashMap<String, String>> {
        self.items.get(path.as_ref())
    }

    pub fn get_crcs<P: AsRef<Path>>(&self, path: P) -> Option<&Vec<u32>> {
        self.crcs.get(path.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, path::PathBuf};

    use super::{Attributes, Item};
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_attribute_parse() {
        let file = TempFile::new().unwrap();
        fs::write(
            file.as_path(),
            "/foo type=external crcs=0x1234,0x5678
            /bar type=external crcs=0x1234,0x5678
            /models/foo/bar type=external",
        )
        .unwrap();

        let attributes = Attributes::from(file.as_path()).unwrap();
        let _attributes_base: HashMap<String, String> =
            [("type".to_string(), "external".to_string())]
                .iter()
                .cloned()
                .collect();
        let _attributes: HashMap<String, String> = [
            ("type".to_string(), "external".to_string()),
            ("crcs".to_string(), "0x1234,0x5678".to_string()),
        ]
        .iter()
        .cloned()
        .collect();

        let items_map: HashMap<PathBuf, HashMap<String, String>> = vec![
            Item {
                pattern: PathBuf::from("/foo"),
                attributes: _attributes.clone(),
            },
            Item {
                pattern: PathBuf::from("/bar"),
                attributes: _attributes.clone(),
            },
            Item {
                pattern: PathBuf::from("/models"),
                attributes: _attributes_base.clone(),
            },
            Item {
                pattern: PathBuf::from("/models/foo"),
                attributes: _attributes_base.clone(),
            },
            Item {
                pattern: PathBuf::from("/models/foo/bar"),
                attributes: _attributes_base.clone(),
            },
        ]
        .into_iter()
        .map(|item| (item.pattern, item.attributes))
        .collect();

        assert_eq!(attributes.items, items_map);
        assert_eq!(attributes.get_crcs("/foo"), Some(&vec![0x1234, 0x5678]))
    }

    #[test]
    fn test_is_external() {
        let file = TempFile::new().unwrap();
        fs::write(file.as_path(), "/foo type=external\n/bar type=internal").unwrap();

        let attributes = Attributes::from(file.as_path()).unwrap();
        assert!(attributes.is_external("/foo"));
        assert!(!attributes.is_external("/bar"));
        assert!(!attributes.is_external("/nonexistent"));
    }

    #[test]
    fn test_is_prefix_external() {
        let file = TempFile::new().unwrap();
        fs::write(file.as_path(), "/external/path type=external").unwrap();

        let attributes = Attributes::from(file.as_path()).unwrap();
        assert!(attributes.is_prefix_external("/external"));
        assert!(!attributes.is_prefix_external("/nonexistent"));
    }

    #[test]
    fn test_get_value() {
        let file = TempFile::new().unwrap();
        fs::write(file.as_path(), "/foo type=external crcs=0x1234").unwrap();

        let attributes = Attributes::from(file.as_path()).unwrap();
        assert_eq!(
            attributes.get_value("/foo", "type"),
            Some("external".to_string())
        );
        assert_eq!(
            attributes.get_value("/foo", "crcs"),
            Some("0x1234".to_string())
        );
        assert_eq!(attributes.get_value("/foo", "nonexistent"), None);
        assert_eq!(attributes.get_value("/nonexistent", "type"), None);
    }

    #[test]
    fn test_get_values() {
        let file = TempFile::new().unwrap();
        fs::write(file.as_path(), "/foo type=external crcs=0x1234").unwrap();

        let attributes = Attributes::from(file.as_path()).unwrap();
        let values = attributes.get_values("/foo");
        assert!(values.is_some());
        assert_eq!(values.unwrap().get("type"), Some(&"external".to_string()));
        assert!(attributes.get_values("/nonexistent").is_none());
    }

    #[test]
    fn test_get_crcs() {
        let file = TempFile::new().unwrap();
        fs::write(
            file.as_path(),
            "/foo crcs=0x1234,0xabcd\n/bar type=external",
        )
        .unwrap();

        let attributes = Attributes::from(file.as_path()).unwrap();
        assert_eq!(attributes.get_crcs("/foo"), Some(&vec![0x1234, 0xabcd]));
        assert_eq!(attributes.get_crcs("/bar"), Some(&vec![]));
        assert_eq!(attributes.get_crcs("/nonexistent"), None);
    }

    #[test]
    fn test_attribute_parse_relative_path() {
        let file = TempFile::new().unwrap();
        fs::write(file.as_path(), "foo/bar type=external").unwrap();

        let attributes = Attributes::from(file.as_path()).unwrap();
        assert!(attributes.is_external("/foo/bar"));
        assert!(attributes.is_external("/foo"));
    }

    #[test]
    fn test_attribute_parse_hex_without_prefix() {
        let file = TempFile::new().unwrap();
        fs::write(file.as_path(), "/foo crcs=1234,abcd").unwrap();

        let attributes = Attributes::from(file.as_path()).unwrap();
        assert_eq!(attributes.get_crcs("/foo"), Some(&vec![0x1234, 0xabcd]));
    }

    #[test]
    fn test_attribute_parse_with_whitespace() {
        let file = TempFile::new().unwrap();
        fs::write(file.as_path(), "/foo crcs=0x1234,0xabcd").unwrap();

        let attributes = Attributes::from(file.as_path()).unwrap();
        assert_eq!(attributes.get_crcs("/foo"), Some(&vec![0x1234, 0xabcd]));
    }

    #[test]
    fn test_check_external() {
        let file = TempFile::new().unwrap();
        fs::write(file.as_path(), "/foo type=external").unwrap();

        let attributes = Attributes::from(file.as_path()).unwrap();
        let values = attributes.get_values("/foo").unwrap();
        assert!(attributes.check_external(values));

        let mut non_external = HashMap::new();
        non_external.insert("type".to_string(), "internal".to_string());
        assert!(!attributes.check_external(&non_external));
    }

    #[test]
    fn test_default_item() {
        let item = Item::default();
        assert_eq!(item.pattern, PathBuf::new());
        assert!(item.attributes.is_empty());
    }

    #[test]
    fn test_default_attributes() {
        let attributes = Attributes::default();
        assert!(attributes.items.is_empty());
        assert!(attributes.crcs.is_empty());
    }
}
