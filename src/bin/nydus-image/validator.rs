// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! Validator for RAFS format

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use nydus_api::ConfigV2;
use nydus_builder::Tree;
use nydus_rafs::metadata::{RafsSuper, RafsVersion};
use nydus_storage::device::BlobInfo;
use nydus_utils::compress;

pub struct Validator {
    sb: RafsSuper,
}

impl Validator {
    pub fn new(bootstrap_path: &Path, config: Arc<ConfigV2>) -> Result<Self> {
        let (sb, _) = RafsSuper::load_from_file(bootstrap_path, config, false)?;

        Ok(Self { sb })
    }

    pub fn check(
        &mut self,
        verbosity: bool,
    ) -> Result<(Vec<Arc<BlobInfo>>, compress::Algorithm, RafsVersion)> {
        let err = "failed to load bootstrap for validator";
        let tree = Tree::from_bootstrap(&self.sb, &mut ()).context(err)?;

        let pre = &mut |t: &Tree| -> Result<()> {
            let node = t.borrow_mut_node();
            if verbosity {
                println!("inode: {}", node);
                for chunk in &node.chunks {
                    println!("\t chunk: {}", chunk);
                }
            }
            Ok(())
        };
        tree.walk_dfs_pre(pre)?;
        let compressor = self.sb.meta.get_compressor();
        let rafs_version: RafsVersion = self.sb.meta.version.try_into().unwrap();

        Ok((
            self.sb.superblock.get_blob_infos(),
            compressor,
            rafs_version,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;

    fn create_test_config(blob_dir: &str) -> Arc<ConfigV2> {
        let content = format!(
            r#"{{
                "version": 2,
                "id": "validator-test",
                "backend": {{
                    "type": "localfs",
                    "localfs": {{
                        "dir": "{}"
                    }}
                }},
                "cache": {{
                    "type": "filecache",
                    "filecache": {{
                        "work_dir": "{}"
                    }}
                }}
            }}"#,
            blob_dir, blob_dir
        );
        Arc::new(serde_json::from_str(&content).unwrap())
    }

    fn prepare_fixture_root() -> (vmm_sys_util::tempdir::TempDir, PathBuf) {
        let tmp_dir = vmm_sys_util::tempdir::TempDir::new().unwrap();
        let root_dir = std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let fixture_blob = PathBuf::from(&root_dir).join(
            "tests/texture/blobs/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef",
        );
        let target_blob = tmp_dir
            .as_path()
            .join("be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        fs::copy(fixture_blob, target_blob).unwrap();

        let bootstrap = PathBuf::from(root_dir).join("tests/texture/bootstrap/rafs-v6-2.2.boot");
        (tmp_dir, bootstrap)
    }

    #[test]
    fn test_validator_new_rejects_invalid_bootstrap() {
        let config = create_test_config("/tmp");
        assert!(Validator::new(Path::new("/does/not/exist"), config).is_err());
    }

    #[test]
    fn test_validator_check_returns_blob_metadata() {
        let (tmp_dir, bootstrap) = prepare_fixture_root();
        let config = create_test_config(tmp_dir.as_path().to_str().unwrap());

        let mut validator = Validator::new(&bootstrap, config).unwrap();
        let (blobs, compressor, rafs_version) = validator.check(false).unwrap();

        assert_eq!(blobs.len(), 1);
        assert_eq!(
            blobs[0].raw_blob_id(),
            "be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef"
        );
        assert!(!blobs[0].blob_id().is_empty());
        assert_eq!(compressor, compress::Algorithm::Zstd);
        assert_eq!(rafs_version, RafsVersion::V6);
    }
}
