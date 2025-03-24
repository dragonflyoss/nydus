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
}

impl Attributes {
    /// Parse nydus attributes from a file.
    pub fn from<P: AsRef<Path>>(path: P) -> Result<Attributes> {
        let content = fs::read(path)?;
        let _items = parse(&content);

        let mut items = HashMap::new();
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
                for line in _item.1 {
                    let line = line?;
                    let name = line.name.as_str();
                    let state = line.state.as_bstr().unwrap_or_default();
                    if name == KEY_TYPE {
                        _type = state.to_string();
                    }
                    attributes.insert(name.to_string(), state.to_string());
                }
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

        Ok(Attributes { items })
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
            "/foo type=external
            /bar type=external
            /models/foo/bar type=external",
        )
        .unwrap();

        let attributes = Attributes::from(file.as_path()).unwrap();
        let _attributes: HashMap<String, String> = [("type".to_string(), "external".to_string())]
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
                attributes: _attributes.clone(),
            },
            Item {
                pattern: PathBuf::from("/models/foo"),
                attributes: _attributes.clone(),
            },
            Item {
                pattern: PathBuf::from("/models/foo/bar"),
                attributes: _attributes.clone(),
            },
        ]
        .into_iter()
        .map(|item| (item.pattern, item.attributes))
        .collect();

        assert_eq!(attributes, Attributes { items: items_map });
    }
}
