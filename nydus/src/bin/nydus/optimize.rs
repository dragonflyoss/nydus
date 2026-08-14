use clap::Args;
use nydus::error::{Context, Error, Result};

use crate::cli_common;
use nydus::optimize::{build_ondemand_blob, load_patterns_from_apiserver, load_patterns_from_file};
use nydus_backend::build_backend;
use nydus_config::Config;
use nydus_format::blob::BLOB_METADATA_SUFFIX;
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use nydus_format::utils::hex_string;
use nydus_telemetry::logging::init_command_tracing;
use std::fs;
use std::path::PathBuf;
use tracing::info;

#[derive(Args)]
pub struct OptimizeArgs {
    /// Apiserver address of a running `nydus fuse` mount, e.g.
    /// `unix:///path/to/api.sock`. The access patterns are fetched live from
    /// its `/trace` endpoint. Mutually exclusive with `--trace-file`.
    #[arg(long, required_unless_present = "trace_file")]
    pub apiserver: Option<String>,

    /// Path to a JSON trace file containing access patterns: the versioned
    /// `{"version":1,"patterns":[{"blob_index":..,"group_index":..}]}`
    /// document, exactly as produced by the apiserver `/trace` endpoint.
    /// Mutually exclusive with `--apiserver`.
    #[arg(long, conflicts_with = "apiserver")]
    pub trace_file: Option<PathBuf>,

    /// Input merged bootstrap to optimize (left untouched).
    #[arg(long)]
    pub parent_bootstrap: PathBuf,

    /// Output path for the rewritten bootstrap.
    #[arg(long)]
    pub bootstrap: PathBuf,

    /// Output directory for the ondemand blob (named by its SHA256 digest)
    /// and its `.blob.meta` sidecar.
    #[arg(long)]
    pub blob_dir: PathBuf,

    /// Storage config YAML (same format as `nydus fuse --config`) providing
    /// the backend serving the source blobs and the local cache directory.
    #[arg(long)]
    pub config: PathBuf,

    #[command(flatten)]
    pub log: cli_common::CommandLogArgs,
}

/// Resolve the CLI arguments, run the optimize pipeline from
/// [`nydus::optimize`], and write out its artifacts.
pub fn run_optimize(args: OptimizeArgs) -> Result<()> {
    let _guards = init_command_tracing(args.log.log_level, args.log.console);

    if args.parent_bootstrap == args.bootstrap {
        return Err(Error::InvalidParameter(
            "--parent-bootstrap and --bootstrap must point to different files".to_string(),
        ));
    }

    let patterns = match (&args.trace_file, &args.apiserver) {
        (Some(path), _) => load_patterns_from_file(path)?,
        (None, Some(apiserver)) => load_patterns_from_apiserver(apiserver)?,
        (None, None) => {
            return Err(Error::InvalidParameter(
                "either --trace-file or --apiserver must be provided".to_string(),
            ))
        }
    };
    if patterns.is_empty() {
        return Err(Error::InvalidParameter(
            "no group accesses found in the access trace; exercise the workload before optimizing"
                .to_string(),
        ));
    }

    let storage_config = Config::load(&args.config).context("failed to load storage config")?;
    let backend = build_backend(&storage_config.backend).context("failed to build blob backend")?;
    // Source groups are pulled through the local blob cache, so diskless mode
    // cannot apply.
    let Some(cache_dir) = &storage_config.storage.dir else {
        return Err(Error::InvalidConfig(
            "optimize requires storage.dir: source groups are pulled through the local blob cache"
                .to_string(),
        ));
    };
    fs::create_dir_all(cache_dir)
        .with_context(|| format!("failed to create cache directory: {}", cache_dir.display()))?;

    let ondemand = build_ondemand_blob(&args.parent_bootstrap, &patterns, backend, cache_dir)?;
    let digest_hex = hex_string(&ondemand.full_blob_digest);

    fs::create_dir_all(&args.blob_dir).with_context(|| {
        format!(
            "failed to create blob directory: {}",
            args.blob_dir.display()
        )
    })?;
    let blob_path = args.blob_dir.join(&digest_hex);
    fs::write(&blob_path, &ondemand.artifact)
        .with_context(|| format!("failed to write ondemand blob: {}", blob_path.display()))?;
    let blob_metadata_path = args
        .blob_dir
        .join(format!("{digest_hex}{BLOB_METADATA_SUFFIX}"));
    ondemand
        .blob_metadata
        .save(&blob_metadata_path)
        .with_context(|| format!("failed to save blob meta: {}", blob_metadata_path.display()))?;

    fs::write(&args.bootstrap, &ondemand.bootstrap).with_context(|| {
        format!(
            "failed to write rewritten bootstrap: {}",
            args.bootstrap.display()
        )
    })?;

    info!(
        "optimized {} groups from {} source blobs into ondemand blob",
        patterns.len(),
        ondemand.source_blob_count
    );
    println!("[ondemand blob]");
    println!("    ondemand_blob_digest: {digest_hex}");
    println!("    ondemand_blob_path: {}", blob_path.display());
    println!("    blob_metadata_path: {}", blob_metadata_path.display());
    println!("    bootstrap_path: {}", args.bootstrap.display());
    println!("    group_count: {}", patterns.len());
    println!(
        "    compressed_data_size: {}",
        ondemand.footer.compressed_data_size()
    );
    println!(
        "    uncompressed_data_size: {}",
        ondemand.uncompressed_blocks * EROFS_BLOCK_SIZE as u64
    );
    Ok(())
}
