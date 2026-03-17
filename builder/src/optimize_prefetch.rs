use crate::anyhow;
use crate::core::blob::Blob;
use crate::finalize_blob;
use crate::Artifact;
use crate::ArtifactWriter;
use crate::BlobContext;
use crate::BlobManager;
use crate::Bootstrap;
use crate::BootstrapManager;
use crate::BuildContext;
use crate::BuildOutput;
use crate::ChunkSource;
use crate::ConversionType;
use crate::NodeChunk;
use crate::Path;
use crate::PathBuf;
use crate::Tree;
use anyhow::{bail, Context, Result};
use nydus_api::ConfigV2;
use nydus_rafs::metadata::layout::RafsBlobTable;
use nydus_rafs::metadata::RafsSuper;
use nydus_rafs::metadata::RafsVersion;
use nydus_storage::backend::BlobBackend;
use nydus_storage::device::BlobInfo;
use nydus_storage::meta::BatchContextGenerator;
use nydus_storage::meta::BlobChunkInfoV2Ondisk;
use nydus_utils::compress;
use serde::Deserialize;
use sha2::Digest;
use std::cmp::{max, min};
use std::mem::size_of;
use std::sync::Arc;
pub struct OptimizePrefetch {}

struct PrefetchBlobState {
    blob_info: BlobInfo,
    blob_ctx: BlobContext,
    blob_writer: Box<dyn Artifact>,
}

#[derive(Clone)]
struct PrefetchFileRange {
    offset: u64,
    size: usize,
}

#[derive(Clone)]
pub struct PrefetchFileInfo {
    path: PathBuf,
    ranges: Option<Vec<PrefetchFileRange>>,
}

#[derive(Deserialize)]
struct PrefetchJson {
    version: String,
    files: Vec<PrefetchFileJson>,
}

#[derive(Deserialize)]
struct PrefetchFileJson {
    path: String,
    ranges: Option<Vec<[u64; 2]>>,
}

impl PrefetchBlobState {
    fn new(ctx: &BuildContext, blob_layer_num: u32, output_blob_dir_path: &Path) -> Result<Self> {
        let mut blob_info = BlobInfo::new(
            blob_layer_num,
            String::from("prefetch-blob"),
            0,
            0,
            ctx.chunk_size,
            u32::MAX,
            ctx.blob_features,
        );
        blob_info.set_compressor(ctx.compressor);
        blob_info.set_separated_with_prefetch_files_feature(true);
        let mut blob_ctx = BlobContext::from(ctx, &blob_info, ChunkSource::Build)?;
        blob_ctx.blob_meta_info_enabled = true;
        let blob_writer = ArtifactWriter::new(crate::ArtifactStorage::FileDir((
            output_blob_dir_path.to_path_buf(),
            String::new(),
        )))
        .map(|writer| Box::new(writer) as Box<dyn Artifact>)?;
        Ok(Self {
            blob_info,
            blob_ctx,
            blob_writer,
        })
    }
}

impl OptimizePrefetch {
    /// Generate a new bootstrap for prefetch.
    pub fn generate_prefetch(
        tree: &mut Tree,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_table: &mut RafsBlobTable,
        output_blob_dir_path: PathBuf,
        prefetch_files: Vec<PrefetchFileInfo>,
        backend: Arc<dyn BlobBackend + Send + Sync>,
    ) -> Result<BuildOutput> {
        // create a new blob for prefetch layer

        let blob_layer_num = match blob_table {
            RafsBlobTable::V5(table) => table.get_all().len(),
            RafsBlobTable::V6(table) => table.get_all().len(),
        };
        let mut blob_state =
            PrefetchBlobState::new(ctx, blob_layer_num as u32, &output_blob_dir_path)?;
        let mut batch = BatchContextGenerator::new(0)?;
        for node in prefetch_files.clone() {
            Self::process_prefetch_node(
                tree,
                node,
                &mut blob_state,
                &mut batch,
                blob_table,
                backend.clone(),
            )?;
        }

        Self::dump_blob(ctx, blob_table, &mut blob_state)?;

        debug!("prefetch blob id: {}", ctx.blob_id);

        let blob_mgr =
            Self::build_dump_bootstrap(tree, ctx, bootstrap_mgr, blob_table, prefetch_files)?;
        BuildOutput::new(&blob_mgr, None, &bootstrap_mgr.bootstrap_storage, &None)
    }

    fn build_dump_bootstrap(
        tree: &mut Tree,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_table: &mut RafsBlobTable,
        prefetch_files: Vec<PrefetchFileInfo>,
    ) -> Result<BlobManager> {
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx()?;
        let mut bootstrap = Bootstrap::new(tree.clone())?;

        // Build bootstrap
        bootstrap.build(ctx, &mut bootstrap_ctx)?;

        // carefully address hardlink
        for node in prefetch_files.clone() {
            let file = &node.path;
            if tree.get_node(file).is_none() {
                warn!(
                    "prefetch file {} is skipped, no need to fixing hardlink",
                    file.display()
                );
                continue;
            }

            let tree_node = tree
                .get_node(file)
                .ok_or(anyhow!("failed to get node"))?
                .node
                .as_ref();
            let child_node = tree_node.borrow();
            let key = (
                child_node.layer_idx,
                child_node.info.src_ino,
                child_node.info.src_dev,
            );
            let chunks = child_node.chunks.clone();
            drop(child_node);

            if let Some(indexes) = bootstrap_ctx.inode_map.get_mut(&key) {
                for n in indexes.iter() {
                    // Rewrite blob chunks to the prefetch blob's chunks
                    n.borrow_mut().chunks = chunks.clone();
                }
            }
        }
        // generate blob table with extended table
        let mut blob_mgr = BlobManager::new(ctx.digester, false);
        let blob_info = match blob_table {
            RafsBlobTable::V5(table) => table.get_all(),
            RafsBlobTable::V6(table) => table.get_all(),
        };
        blob_mgr.extend_from_blob_table(ctx, blob_info)?;
        let blob_table_withprefetch = blob_mgr.to_blob_table(ctx)?;

        bootstrap.dump(
            ctx,
            &mut bootstrap_mgr.bootstrap_storage,
            &mut bootstrap_ctx,
            &blob_table_withprefetch,
        )?;
        Ok(blob_mgr)
    }

    fn dump_blob(
        ctx: &mut BuildContext,
        blob_table: &mut RafsBlobTable,
        blob_state: &mut PrefetchBlobState,
    ) -> Result<()> {
        match blob_table {
            RafsBlobTable::V5(table) => {
                table.entries.push(blob_state.blob_info.clone().into());
            }
            RafsBlobTable::V6(table) => {
                table.entries.push(blob_state.blob_info.clone().into());
            }
        }

        let mut blob_mgr = BlobManager::new(ctx.digester, false);
        blob_mgr.add_blob(blob_state.blob_ctx.clone());
        blob_mgr.set_current_blob_index(0);
        Blob::finalize_blob_data(ctx, &mut blob_mgr, blob_state.blob_writer.as_mut())?;
        if let RafsBlobTable::V6(_) = blob_table {
            if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
                Blob::dump_meta_data(ctx, blob_ctx, blob_state.blob_writer.as_mut()).unwrap();
            };
        }
        ctx.blob_id = String::from("");
        blob_mgr.get_current_blob().unwrap().1.blob_id = String::from("");
        finalize_blob(ctx, &mut blob_mgr, blob_state.blob_writer.as_mut())?;
        ctx.blob_id = blob_mgr
            .get_current_blob()
            .ok_or(anyhow!("failed to get current blob"))?
            .1
            .blob_id
            .clone();

        let entries = match blob_table {
            RafsBlobTable::V5(table) => table.get_all(),
            RafsBlobTable::V6(table) => table.get_all(),
        };

        // Verify and update prefetch blob
        assert!(
            entries
                .iter()
                .filter(|blob| blob.blob_id() == "prefetch-blob")
                .count()
                == 1,
            "Expected exactly one prefetch-blob"
        );
        // Rewrite prefetch blob id
        match blob_table {
            RafsBlobTable::V5(table) => {
                rewrite_blob_id(&mut table.entries, "prefetch-blob", ctx.blob_id.clone())
            }
            RafsBlobTable::V6(table) => {
                rewrite_blob_id(&mut table.entries, "prefetch-blob", ctx.blob_id.clone())
            }
        }
        Ok(())
    }

    fn process_prefetch_node(
        tree: &mut Tree,
        prefetch_file_info: PrefetchFileInfo,
        prefetch_state: &mut PrefetchBlobState,
        batch: &mut BatchContextGenerator,
        blob_table: &RafsBlobTable,
        backend: Arc<dyn BlobBackend + Send + Sync>,
    ) -> Result<()> {
        let file = prefetch_file_info.path.clone();
        if tree.get_node_mut(&file).is_none() {
            warn!("prefetch file {} is bad, skip it", file.display());
            return Ok(());
        }

        let tree_node = tree
            .get_node_mut(&file)
            .ok_or(anyhow!("failed to get node"))?
            .node
            .as_ref();
        let entries = match blob_table {
            RafsBlobTable::V5(table) => table.get_all(),
            RafsBlobTable::V6(table) => table.get_all(),
        };

        let mut child = tree_node.borrow_mut();
        let chunks: &mut Vec<NodeChunk> = child.chunks.as_mut();
        let blob_ctx = &mut prefetch_state.blob_ctx;
        let blob_info = &mut prefetch_state.blob_info;
        let encrypted = blob_ctx.blob_compressor != compress::Algorithm::None;

        for chunk in chunks {
            // check the file range
            if let Some(ref ranges) = prefetch_file_info.ranges {
                let mut should_skip = true;
                for range in ranges {
                    if range_overlap(chunk, range) {
                        should_skip = false;
                        break;
                    }
                }
                if should_skip {
                    continue;
                }
            }

            let blob_id = entries
                .get(chunk.inner.blob_index() as usize)
                .map(|entry| entry.blob_id())
                .ok_or(anyhow!("failed to get blob id"))?;

            let inner = Arc::make_mut(&mut chunk.inner);

            let reader = backend
                .clone()
                .get_reader(&blob_id.clone())
                .expect("get blob err");
            let mut buf = vec![0u8; inner.compressed_size() as usize];
            reader
                .read(&mut buf, inner.compressed_offset())
                .expect("read blob err");
            prefetch_state.blob_writer.write_all(&buf)?;
            inner.set_blob_index(blob_info.blob_index());
            if blob_ctx.chunk_count == u32::MAX {
                blob_ctx.chunk_count = 0;
            }
            inner.set_index(blob_ctx.chunk_count);
            blob_ctx.chunk_count += 1;
            inner.set_compressed_offset(blob_ctx.current_compressed_offset);
            inner.set_uncompressed_offset(blob_ctx.current_uncompressed_offset);
            let mut aligned_d_size: u64 = inner.uncompressed_size() as u64;
            if let RafsBlobTable::V6(_) = blob_table {
                aligned_d_size = nydus_utils::try_round_up_4k(inner.uncompressed_size())
                    .ok_or_else(|| anyhow!("invalid size"))?;
                let info = batch.generate_chunk_info(
                    blob_ctx.current_compressed_offset,
                    blob_ctx.current_uncompressed_offset,
                    inner.uncompressed_size(),
                    encrypted,
                )?;
                blob_info.set_meta_ci_compressed_size(
                    (blob_info.meta_ci_compressed_size()
                        + size_of::<BlobChunkInfoV2Ondisk>() as u64) as usize,
                );

                blob_info.set_meta_ci_uncompressed_size(
                    (blob_info.meta_ci_uncompressed_size()
                        + size_of::<BlobChunkInfoV2Ondisk>() as u64) as usize,
                );
                blob_ctx.add_chunk_meta_info(inner, Some(info))?;
            }
            blob_ctx.compressed_blob_size += inner.compressed_size() as u64;
            blob_ctx.uncompressed_blob_size += aligned_d_size;
            blob_ctx.current_compressed_offset += inner.compressed_size() as u64;
            blob_ctx.current_uncompressed_offset += aligned_d_size;
            blob_ctx.blob_hash.update(&buf);

            blob_info.set_compressed_size(blob_ctx.compressed_blob_size as usize);
            blob_info.set_uncompressed_size(blob_ctx.uncompressed_blob_size as usize);
            blob_info.set_chunk_count(blob_ctx.chunk_count as usize);
        }

        Ok(())
    }
}

fn rewrite_blob_id(entries: &mut [Arc<BlobInfo>], blob_id: &str, new_blob_id: String) {
    entries
        .iter_mut()
        .filter(|blob| blob.blob_id() == blob_id)
        .for_each(|blob| {
            let mut info = (**blob).clone();
            info.set_blob_id(new_blob_id.clone());
            *blob = Arc::new(info);
        });
}

pub fn update_ctx_from_bootstrap(
    ctx: &mut BuildContext,
    config: Arc<ConfigV2>,
    bootstrap_path: &Path,
) -> Result<RafsSuper> {
    let (sb, _) = RafsSuper::load_from_file(bootstrap_path, config, false)?;

    ctx.blob_features = sb
        .superblock
        .get_blob_infos()
        .first()
        .ok_or_else(|| anyhow!("No blob info found in superblock"))?
        .features();

    let config = sb.meta.get_config();
    if config.is_tarfs_mode {
        ctx.conversion_type = ConversionType::TarToRafs;
    }

    ctx.fs_version =
        RafsVersion::try_from(sb.meta.version).context("Failed to get RAFS version")?;
    ctx.compressor = config.compressor;
    Ok(sb)
}

pub fn generate_prefetch_file_info(prefetch_file: &Path) -> Result<Vec<PrefetchFileInfo>> {
    let content = std::fs::read_to_string(prefetch_file).map_err(|e| {
        anyhow!(
            "failed to read prefetch files from {}: {}",
            prefetch_file.display(),
            e
        )
    })?;

    if content.trim().is_empty() {
        return Ok(Vec::new());
    }

    let prefetch_json: PrefetchJson = serde_json::from_str(&content)
        .map_err(|e| anyhow!("failed to parse prefetch file as JSON: {}", e))?;

    if prefetch_json.version != "v1" {
        bail!(
            "unsupported prefetch file version: {}",
            prefetch_json.version
        );
    }

    let mut prefetch_nodes = Vec::new();
    for file_json in prefetch_json.files {
        let path = PathBuf::from(file_json.path);
        if !path.is_absolute() {
            warn!(
                "prefetch file path is not absolute, skipping: {}",
                path.display()
            );
            continue;
        }
        let ranges = file_json.ranges.map(|rs| {
            rs.into_iter()
                .map(|r| PrefetchFileRange {
                    offset: r[0],
                    size: r[1] as usize,
                })
                .collect()
        });
        prefetch_nodes.push(PrefetchFileInfo { path, ranges });
    }
    Ok(prefetch_nodes)
}

fn range_overlap(chunk: &mut NodeChunk, range: &PrefetchFileRange) -> bool {
    if max(range.offset, chunk.inner.file_offset())
        <= min(
            range.offset + range.size as u64,
            chunk.inner.file_offset() + chunk.inner.uncompressed_size() as u64,
        )
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_rafs::metadata::chunk::ChunkWrapper;
    use std::io::Write;
    use vmm_sys_util::tempfile::TempFile;

    fn write_temp_json(content: &str) -> TempFile {
        let f = TempFile::new().unwrap();
        f.as_file().write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_generate_prefetch_file_info_empty_content() {
        let f = write_temp_json("   \n  ");
        let result = generate_prefetch_file_info(f.as_path());
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_generate_prefetch_file_info_unsupported_version() {
        let f = write_temp_json(r#"{"version":"v2","files":[]}"#);
        let result = generate_prefetch_file_info(f.as_path());
        assert!(result.is_err());
        let err_msg = match result {
            Err(e) => format!("{}", e),
            Ok(_) => panic!("expected error"),
        };
        assert!(err_msg.contains("unsupported prefetch file version"));
    }

    #[test]
    fn test_generate_prefetch_file_info_invalid_json() {
        let f = write_temp_json("this is not valid json");
        let result = generate_prefetch_file_info(f.as_path());
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_prefetch_file_info_v1_no_files() {
        let f = write_temp_json(r#"{"version":"v1","files":[]}"#);
        let result = generate_prefetch_file_info(f.as_path());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_generate_prefetch_file_info_absolute_paths_included() {
        let json = r#"{"version":"v1","files":[
            {"path":"/usr/bin/ls","ranges":null},
            {"path":"/usr/lib/libc.so","ranges":[[0,4096],[8192,4096]]}
        ]}"#;
        let f = write_temp_json(json);
        let result = generate_prefetch_file_info(f.as_path());
        assert!(result.is_ok());
        let infos = result.unwrap();
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].path, std::path::PathBuf::from("/usr/bin/ls"));
        assert!(infos[0].ranges.is_none());
        let ranges = infos[1].ranges.as_ref().unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].offset, 0);
        assert_eq!(ranges[0].size, 4096);
        assert_eq!(ranges[1].offset, 8192);
        assert_eq!(ranges[1].size, 4096);
    }

    #[test]
    fn test_generate_prefetch_file_info_relative_paths_skipped() {
        let json = r#"{"version":"v1","files":[
            {"path":"relative/path/file","ranges":null},
            {"path":"/absolute/path","ranges":null}
        ]}"#;
        let f = write_temp_json(json);
        let result = generate_prefetch_file_info(f.as_path());
        assert!(result.is_ok());
        let infos = result.unwrap();
        // Relative path should be skipped, only absolute path kept
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].path, std::path::PathBuf::from("/absolute/path"));
    }

    #[test]
    fn test_generate_prefetch_file_info_missing_file() {
        let result =
            generate_prefetch_file_info(std::path::Path::new("/nonexistent/path/file.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_optimize_prefetch_struct_default() {
        // OptimizePrefetch is a zero-sized struct
        let _op = OptimizePrefetch {};
        assert_eq!(std::mem::size_of::<OptimizePrefetch>(), 0);
    }

    #[test]
    fn test_prefetch_file_info_clone() {
        let json = r#"{"version":"v1","files":[{"path":"/bin/sh","ranges":[[0,512]]}]}"#;
        let f = write_temp_json(json);
        let infos = generate_prefetch_file_info(f.as_path()).unwrap();
        assert_eq!(infos.len(), 1);
        // PrefetchFileInfo implements Clone
        let cloned = infos[0].clone();
        assert_eq!(cloned.path, infos[0].path);
    }

    fn make_chunk(file_offset: u64, uncompressed_size: u32) -> NodeChunk {
        let mut cw = ChunkWrapper::new(RafsVersion::V6);
        cw.set_file_offset(file_offset);
        cw.set_uncompressed_size(uncompressed_size);
        NodeChunk {
            source: ChunkSource::Build,
            inner: Arc::new(cw),
        }
    }

    #[test]
    fn test_range_overlap_chunk_inside_range() {
        // chunk [100, 150) is fully inside range [0, 500)
        let mut chunk = make_chunk(100, 50);
        let range = PrefetchFileRange {
            offset: 0,
            size: 500,
        };
        assert!(range_overlap(&mut chunk, &range));
    }

    #[test]
    fn test_range_overlap_range_inside_chunk() {
        // range [200, 300) is fully inside chunk [0, 1000)
        let mut chunk = make_chunk(0, 1000);
        let range = PrefetchFileRange {
            offset: 200,
            size: 100,
        };
        assert!(range_overlap(&mut chunk, &range));
    }

    #[test]
    fn test_range_overlap_partial_overlap() {
        // chunk [100, 200) overlaps with range [150, 350)
        let mut chunk = make_chunk(100, 100);
        let range = PrefetchFileRange {
            offset: 150,
            size: 200,
        };
        assert!(range_overlap(&mut chunk, &range));
    }

    #[test]
    fn test_range_overlap_touching_boundary_counts_as_overlap() {
        // range ends exactly where chunk starts: range [100, 200), chunk [200, 300)
        // max(100, 200) = 200 <= min(200, 300) = 200 → true
        let mut chunk = make_chunk(200, 100);
        let range = PrefetchFileRange {
            offset: 100,
            size: 100,
        };
        assert!(range_overlap(&mut chunk, &range));
    }

    #[test]
    fn test_range_overlap_no_overlap_range_before() {
        // range [0, 100) is entirely before chunk [500, 600)
        let mut chunk = make_chunk(500, 100);
        let range = PrefetchFileRange {
            offset: 0,
            size: 100,
        };
        assert!(!range_overlap(&mut chunk, &range));
    }

    #[test]
    fn test_range_overlap_no_overlap_range_after() {
        // range [500, 600) is entirely after chunk [0, 100)
        let mut chunk = make_chunk(0, 100);
        let range = PrefetchFileRange {
            offset: 500,
            size: 100,
        };
        assert!(!range_overlap(&mut chunk, &range));
    }

    #[test]
    fn test_rewrite_blob_id_matching_entry() {
        let mut blob = BlobInfo::new(0, "old-id".to_string(), 0, 0, 0, 0, Default::default());
        blob.set_blob_id("old-id".to_string());
        let mut entries: Vec<Arc<BlobInfo>> = vec![Arc::new(blob)];
        rewrite_blob_id(&mut entries, "old-id", "new-id".to_string());
        assert_eq!(entries[0].blob_id(), "new-id");
    }

    #[test]
    fn test_rewrite_blob_id_no_match() {
        let mut blob = BlobInfo::new(0, "other-id".to_string(), 0, 0, 0, 0, Default::default());
        blob.set_blob_id("other-id".to_string());
        let mut entries: Vec<Arc<BlobInfo>> = vec![Arc::new(blob)];
        rewrite_blob_id(&mut entries, "old-id", "new-id".to_string());
        // Should not modify entries that don't match.
        assert_eq!(entries[0].blob_id(), "other-id");
    }

    #[test]
    fn test_rewrite_blob_id_multiple_entries() {
        let blobs: Vec<Arc<BlobInfo>> = vec![
            Arc::new(BlobInfo::new(
                0,
                "target".to_string(),
                0,
                0,
                0,
                0,
                Default::default(),
            )),
            Arc::new(BlobInfo::new(
                1,
                "other".to_string(),
                0,
                0,
                0,
                0,
                Default::default(),
            )),
            Arc::new(BlobInfo::new(
                2,
                "target".to_string(),
                0,
                0,
                0,
                0,
                Default::default(),
            )),
        ];
        let mut entries = blobs;
        rewrite_blob_id(&mut entries, "target", "replaced".to_string());
        assert_eq!(entries[0].blob_id(), "replaced");
        assert_eq!(entries[1].blob_id(), "other");
        assert_eq!(entries[2].blob_id(), "replaced");
    }
}
