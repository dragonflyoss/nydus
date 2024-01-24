// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::{fs, path};

use anyhow::Result;
use gix_attributes::parse;
use gix_attributes::parse::Kind;

pub struct Attribute {}

impl Attribute {
    /// Parse nydus attributes from a file.
    pub fn parse<P: AsRef<Path>>(path: P) -> Result<HashMap<PathBuf, u32>> {
        let content = fs::read(path)?;
        let attributes = parse(&content);
        let mut result = HashMap::new();
        for attribute in attributes {
            let attribute = attribute?;
            if let Kind::Pattern(pattern) = attribute.0 {
                let mut path: Option<PathBuf> = None;
                let mut backend_index: Option<u32> = None;
                for line in attribute.1 {
                    let line = line?;
                    if line.name.as_str() == "type"
                        && line.state.as_bstr().unwrap_or_default() == "external"
                    {
                        let _path = PathBuf::from(pattern.text.to_string());
                        if !_path.is_absolute() {
                            path = Some(path::Path::new("/").join(_path));
                        }
                    }
                    if line.name.as_str() == "backend_index" {
                        backend_index = Some(
                            line.state
                                .as_bstr()
                                .unwrap_or_default()
                                .to_string()
                                .parse()?,
                        );
                    }
                }
                match (path, backend_index) {
                    (Some(path), Some(backend_index)) => {
                        result.insert(path, backend_index);
                    }
                    _ => {}
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, path::PathBuf};

    use super::Attribute;
    use vmm_sys_util::tempfile::TempFile;

    #[test]
    fn test_attribute_parse() {
        let file = TempFile::new().unwrap();
        fs::write(
            file.as_path(),
            "/foo type=external backend_index=0
            /bar type=external backend_index=0
            /models/foo type=external backend_index=1",
        )
        .unwrap();
        let paths = Attribute::parse(file.as_path()).unwrap();
        assert_eq!(
            paths,
            [
                (PathBuf::from("/foo"), 0),
                (PathBuf::from("/bar"), 0),
                (PathBuf::from("/models/foo"), 1)
            ]
            .iter()
            .cloned()
            .collect::<HashMap<PathBuf, u32>>()
        );
    }
}
