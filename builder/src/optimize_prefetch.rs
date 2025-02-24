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
use crate::TreeNode;
use anyhow::Context;
use anyhow::{Ok, Result};
use nydus_api::ConfigV2;
use nydus_rafs::metadata::layout::RafsBlobTable;
use nydus_rafs::metadata::RafsSuper;
use nydus_rafs::metadata::RafsVersion;
use nydus_storage::device::BlobInfo;
use nydus_storage::meta::BatchContextGenerator;
use nydus_storage::meta::BlobChunkInfoV1Ondisk;
use nydus_utils::{compress, crc};
use sha2::Digest;
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::mem::size_of;
use std::sync::Arc;
pub struct OptimizePrefetch {}

struct PrefetchBlobState {
    blob_info: BlobInfo,
    blob_ctx: BlobContext,
    blob_writer: Box<dyn Artifact>,
}

impl PrefetchBlobState {
    fn new(ctx: &BuildContext, blob_layer_num: u32, blobs_dir_path: &Path) -> Result<Self> {
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
        let blob_writer = ArtifactWriter::new(crate::ArtifactStorage::FileDir(
            blobs_dir_path.to_path_buf(),
        ))
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
        blobs_dir_path: PathBuf,
        prefetch_nodes: Vec<TreeNode>,
    ) -> Result<BuildOutput> {
        // create a new blob for prefetch layer

        let blob_layer_num = match blob_table {
            RafsBlobTable::V5(table) => table.get_all().len(),
            RafsBlobTable::V6(table) => table.get_all().len(),
        };
        let mut blob_state = PrefetchBlobState::new(&ctx, blob_layer_num as u32, &blobs_dir_path)?;
        let mut batch = BatchContextGenerator::new(0)?;
        for node in &prefetch_nodes {
            Self::process_prefetch_node(
                tree,
                &node,
                &mut blob_state,
                &mut batch,
                blob_table,
                &blobs_dir_path,
            )?;
        }

        let blob_mgr = Self::dump_blob(ctx, blob_table, &mut blob_state)?;

        debug!("prefetch blob id: {}", ctx.blob_id);

        Self::build_dump_bootstrap(tree, ctx, bootstrap_mgr, blob_table)?;
        BuildOutput::new(&blob_mgr, &bootstrap_mgr.bootstrap_storage)
    }

    fn build_dump_bootstrap(
        tree: &mut Tree,
        ctx: &mut BuildContext,
        bootstrap_mgr: &mut BootstrapManager,
        blob_table: &mut RafsBlobTable,
    ) -> Result<()> {
        let mut bootstrap_ctx = bootstrap_mgr.create_ctx()?;
        let mut bootstrap = Bootstrap::new(tree.clone())?;

        // Build bootstrap
        bootstrap.build(ctx, &mut bootstrap_ctx)?;

        let blob_table_withprefetch = match blob_table {
            RafsBlobTable::V5(table) => RafsBlobTable::V5(table.clone()),
            RafsBlobTable::V6(table) => RafsBlobTable::V6(table.clone()),
        };
        bootstrap.dump(
            ctx,
            &mut bootstrap_mgr.bootstrap_storage,
            &mut bootstrap_ctx,
            &blob_table_withprefetch,
        )?;
        Ok(())
    }

    fn dump_blob(
        ctx: &mut BuildContext,
        blob_table: &mut RafsBlobTable,
        blob_state: &mut PrefetchBlobState,
    ) -> Result<BlobManager> {
        match blob_table {
            RafsBlobTable::V5(table) => {
                table.entries.push(blob_state.blob_info.clone().into());
            }
            RafsBlobTable::V6(table) => {
                table.entries.push(blob_state.blob_info.clone().into());
            }
        }

        let mut blob_mgr = BlobManager::new(ctx.digester);
        blob_mgr.add_blob(blob_state.blob_ctx.clone());
        blob_mgr.set_current_blob_index(0);
        Blob::finalize_blob_data(&ctx, &mut blob_mgr, blob_state.blob_writer.as_mut())?;
        if let Some((_, blob_ctx)) = blob_mgr.get_current_blob() {
            Blob::dump_meta_data(&ctx, blob_ctx, blob_state.blob_writer.as_mut()).unwrap();
        };
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
        Ok(blob_mgr)
    }

    fn process_prefetch_node(
        tree: &mut Tree,
        node: &TreeNode,
        prefetch_state: &mut PrefetchBlobState,
        batch: &mut BatchContextGenerator,
        blob_table: &RafsBlobTable,
        blobs_dir_path: &Path,
    ) -> Result<()> {
        let tree_node = tree
            .get_node_mut(&node.borrow().path())
            .ok_or(anyhow!("failed to get node"))?
            .node
            .as_ref();
        let entries = match blob_table {
            RafsBlobTable::V5(table) => table.get_all(),
            RafsBlobTable::V6(table) => table.get_all(),
        };
        let blob_id = tree_node
            .borrow()
            .chunks
            .first()
            .and_then(|chunk| entries.get(chunk.inner.blob_index() as usize).cloned())
            .map(|entry| entry.blob_id())
            .ok_or(anyhow!("failed to get blob id"))?;
        let mut blob_file = Arc::new(File::open(blobs_dir_path.join(blob_id))?);

        tree_node.borrow_mut().layer_idx = prefetch_state.blob_info.blob_index() as u16;

        let mut child = tree_node.borrow_mut();
        let chunks: &mut Vec<NodeChunk> = child.chunks.as_mut();
        let blob_ctx = &mut prefetch_state.blob_ctx;
        let blob_info = &mut prefetch_state.blob_info;
        let encrypted = blob_ctx.blob_compressor != compress::Algorithm::None;
        let crc_enable = blob_ctx.blob_crc_checker != crc::Algorithm::None;

        for chunk in chunks {
            let inner = Arc::make_mut(&mut chunk.inner);

            let mut buf = vec![0u8; inner.compressed_size() as usize];
            blob_file.seek(std::io::SeekFrom::Start(inner.compressed_offset()))?;
            blob_file.read_exact(&mut buf)?;
            prefetch_state.blob_writer.write_all(&buf)?;
            let info = batch.generate_chunk_info(
                blob_ctx.current_compressed_offset,
                blob_ctx.current_uncompressed_offset,
                inner.uncompressed_size(),
                encrypted,
                crc_enable,
            )?;
            inner.set_blob_index(blob_info.blob_index());
            if blob_ctx.chunk_count == u32::MAX {
                blob_ctx.chunk_count = 0;
            }
            inner.set_index(blob_ctx.chunk_count);
            blob_ctx.chunk_count += 1;
            inner.set_compressed_offset(blob_ctx.current_compressed_offset);
            inner.set_uncompressed_offset(blob_ctx.current_uncompressed_offset);
            let aligned_d_size: u64 = nydus_utils::try_round_up_4k(inner.uncompressed_size())
                .ok_or_else(|| anyhow!("invalid size"))?;
            blob_ctx.compressed_blob_size += inner.compressed_size() as u64;
            blob_ctx.uncompressed_blob_size += aligned_d_size;
            blob_ctx.current_compressed_offset += inner.compressed_size() as u64;
            blob_ctx.current_uncompressed_offset += aligned_d_size;
            blob_ctx.add_chunk_meta_info(&inner, Some(info))?;
            blob_ctx.blob_hash.update(&buf);

            blob_info.set_meta_ci_compressed_size(
                (blob_info.meta_ci_compressed_size() + size_of::<BlobChunkInfoV1Ondisk>() as u64)
                    as usize,
            );

            blob_info.set_meta_ci_uncompressed_size(
                (blob_info.meta_ci_uncompressed_size() + size_of::<BlobChunkInfoV1Ondisk>() as u64)
                    as usize,
            );
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
