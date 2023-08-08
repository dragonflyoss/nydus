// // Copyright (C) 2022 Alibaba Cloud. All rights reserved.
// //
// // SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Ok, Result};

use nydus_api::{BackendConfigV2, ConfigV2};
use nydus_rafs::metadata::chunk::ChunkWrapper;
use nydus_rafs::metadata::{RafsSuper, RafsSuperFlags, RafsVersion};
use nydus_rafs::{RafsIoReader, RafsIoWrite};
use nydus_utils::cas::CasMgr;
use nydus_utils::digest::{self, RafsDigest};
use nydus_utils::{root_tracer, timing_tracer};

use crate::core::bootstrap::Bootstrap;
use crate::core::context::{
    ArtifactFileWriter, ArtifactWriter, BlobManager, BuildContext, ConversionType,
};

use crate::core::feature::Features;
use crate::core::overlay::WhiteoutSpec;
use crate::core::tree::Tree;
use crate::ArtifactStorage;

pub struct BootstrapDedup {
    cas_mgr: CasMgr,
    rs: RafsSuper,
    cache_chunks: HashMap<RafsDigest, ChunkWrapper>,
    insert_chunks: Vec<(String, String, String)>,
    insert_blobs: Vec<(String, String, String)>,
    reader: RafsIoReader,
    writer: Box<dyn RafsIoWrite>,
    backend: BackendConfigV2,
    encrypt: bool,
}

impl BootstrapDedup {
    pub fn new(bootstrap_path: PathBuf, output_path: PathBuf, cfg: &Arc<ConfigV2>) -> Result<Self> {
        let (rs, _reader) = RafsSuper::load_from_file(&bootstrap_path, cfg.clone(), false)?;

        let reader = Box::new(
            fs::OpenOptions::new()
                .read(true)
                .write(false)
                .open(&bootstrap_path)?,
        ) as RafsIoReader;

        let dedup_config = cfg.get_dedup_config()?;
        let db_dir = dedup_config.get_work_dir()?;
        let cas_mgr = CasMgr::new(db_dir)?;

        let cache_chunks = HashMap::new();
        let insert_chunks = vec![];
        let insert_blobs = vec![];
        let backend = cfg.get_backend_config().unwrap().clone();
        let encrypt = !rs.meta.flags.contains(RafsSuperFlags::ENCRYPTION_NONE);
        let writer = Box::new(ArtifactFileWriter(ArtifactWriter::new(
            ArtifactStorage::SingleFile(PathBuf::from(&output_path)),
        )?)) as Box<dyn RafsIoWrite>;

        fs::copy(&bootstrap_path, &output_path)?;

        Ok(BootstrapDedup {
            cas_mgr,
            rs,
            cache_chunks,
            insert_chunks,
            insert_blobs,
            reader,
            writer,
            backend,
            encrypt,
        })
    }

    fn is_tarfs(&self) -> bool {
        self.rs.meta.flags.contains(RafsSuperFlags::TARTFS_MODE)
    }

    pub fn do_dedup(&mut self) -> Result<()> {
        let conversion_type = if self.is_tarfs() {
            ConversionType::TarToTarfs
        } else {
            ConversionType::DirectoryToRafs
        };
        let mut build_ctx = BuildContext::new(
            "".to_string(),
            false,
            0,
            self.rs.meta.get_compressor(),
            self.rs.meta.get_digester(),
            self.rs.meta.explicit_uidgid(),
            WhiteoutSpec::Oci,
            conversion_type,
            PathBuf::from(""),
            Default::default(),
            None,
            false,
            Features::new(),
            self.encrypt,
        );

        build_ctx.set_fs_version(RafsVersion::try_from(self.rs.meta.version).unwrap());

        let is_v6 = match &build_ctx.fs_version {
            RafsVersion::V5 => false,
            RafsVersion::V6 => true,
        };
        let tree = Tree::from_bootstrap(&self.rs, &mut ())?;

        let mut chunk_cache = BTreeMap::new();
        let mut blob_mgr = BlobManager::new(digest::Algorithm::Sha256);
        blob_mgr
            .extend_from_blob_table(&build_ctx, self.rs.superblock.get_blob_infos())
            .unwrap();

        // Dump bootstrap
        timing_tracer!(
            {
                tree.walk_bfs(true, &mut |n| {
                    n.lock_node().dedup_chunk_for_node(
                        &build_ctx,
                        &mut blob_mgr,
                        &self.rs.meta,
                        self.writer.as_mut(),
                        &mut self.cache_chunks,
                        &mut self.insert_chunks,
                        &self.cas_mgr,
                        &mut chunk_cache,
                    )
                })
            },
            "chunk_dedup"
        )?;

        let blob_table = blob_mgr.to_blob_table(&build_ctx)?;
        let mut bootstrap = Bootstrap::new(tree)?;
        bootstrap.dedup(
            &build_ctx,
            &self.rs,
            &mut self.reader,
            self.writer.as_mut(),
            &blob_table,
            &chunk_cache,
        )?;

        let blobs = self.rs.superblock.get_blob_infos();
        for blob in &blobs {
            self.insert_blobs.push((
                blob.blob_id(),
                serde_json::to_string(&blob)?,
                serde_json::to_string(&self.backend)?,
            ));
        }
        self.cas_mgr.add_blobs(&self.insert_blobs, is_v6)?;
        self.cas_mgr.add_chunks(&self.insert_chunks, is_v6)?;

        Ok(())
    }
}
