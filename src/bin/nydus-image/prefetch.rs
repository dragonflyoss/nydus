use anyhow::{Context, Result};
use nydus_api::ConfigV2;
use nydus_builder::{BuildContext, ConversionType};
use nydus_rafs::metadata::RafsSuper;
use nydus_rafs::metadata::RafsVersion;
use std::result::Result::Ok;
use std::{path::Path, sync::Arc};

pub fn update_ctx_from_bootstrap(
    ctx: &mut BuildContext,
    config: Arc<ConfigV2>,
    bootstrap_path: &Path,
) -> Result<RafsSuper> {
    let (sb, _) = RafsSuper::load_from_file(bootstrap_path, config, false)?;
    sb.superblock
        .get_blob_infos()
        .iter()
        .for_each(|info| println!("{:?}", info));

    ctx.blob_features = sb.superblock.get_blob_infos().first().unwrap().features();

    let config = sb.meta.get_config();
    if config.is_tarfs_mode {
        ctx.conversion_type = ConversionType::TarToRafs;
    }

    ctx.fs_version =
        RafsVersion::try_from(sb.meta.version).context("Failed to get RAFS version")?;
    ctx.compressor = config.compressor;
    Ok(sb)
}
