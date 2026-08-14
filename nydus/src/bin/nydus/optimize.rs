use clap::Parser;
use nydus::error::{Context, Error, Result};
use nydus::optimize::{build_ondemand_blob, load_patterns_from_apiserver, load_patterns_from_file};
use nydus_backend::build_backend;
use nydus_config::Config;
use nydus_format::blob::BLOB_METADATA_SUFFIX;
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use nydus_format::utils::hex_string;
use nydus_telemetry::logging::init_command_tracing;
use std::fs;
use std::path::PathBuf;
use tracing::{info, Level};

/// The subcommand of optimize.
#[derive(Debug, Clone, Parser)]
pub struct OptimizeCommand {
    #[arg(
        long,
        required_unless_present = "trace_file",
        env = "NYDUS_OPTIMIZE_APISERVER",
        help = "Specify the apiserver address of a running `nydus fuse` mount, e.g. `unix:///path/to/api.sock`. The access patterns are fetched live from its `/trace` endpoint. Mutually exclusive with `--trace-file`"
    )]
    apiserver: Option<String>,

    #[arg(
        long,
        conflicts_with = "apiserver",
        env = "NYDUS_OPTIMIZE_TRACE_FILE",
        help = "Specify the path to a JSON trace file containing access patterns: the versioned `{\"version\":1,\"patterns\":[{\"blob_index\":..,\"group_index\":..}]}` document, exactly as produced by the apiserver `/trace` endpoint. Mutually exclusive with `--apiserver`"
    )]
    trace_file: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_OPTIMIZE_PARENT_BOOTSTRAP",
        help = "Specify the input merged bootstrap to optimize (left untouched)"
    )]
    parent_bootstrap: PathBuf,

    #[arg(
        long,
        env = "NYDUS_OPTIMIZE_BOOTSTRAP",
        help = "Specify the output path for the rewritten bootstrap"
    )]
    bootstrap: PathBuf,

    #[arg(
        long,
        env = "NYDUS_OPTIMIZE_BLOB_DIR",
        help = "Specify the output directory for the ondemand blob (named by its SHA256 digest) and its `.blob.meta` sidecar"
    )]
    blob_dir: PathBuf,

    #[arg(
        long,
        env = "NYDUS_OPTIMIZE_CONFIG",
        help = "Specify the storage config YAML (same format as `nydus fuse --config`) providing the backend serving the source blobs and the local cache directory"
    )]
    config: PathBuf,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        env = "NYDUS_OPTIMIZE_LOG_LEVEL",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    log_level: Level,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        env = "NYDUS_OPTIMIZE_CONSOLE",
        help = "Specify whether to print log"
    )]
    console: bool,
}

/// Implement the execute for OptimizeCommand.
impl OptimizeCommand {
    /// Executes the optimize sub command, running the optimize pipeline from
    /// [`nydus::optimize`] and writing out its artifacts.
    pub fn execute(&self) -> Result<()> {
        // Initialize tracing.
        let _guards = init_command_tracing(self.log_level, self.console);

        if self.parent_bootstrap == self.bootstrap {
            return Err(Error::InvalidParameter(
                "--parent-bootstrap and --bootstrap must point to different files".to_string(),
            ));
        }

        let patterns = match (&self.trace_file, &self.apiserver) {
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

        // Load the storage config.
        let storage_config = Config::load(&self.config).context("failed to load storage config")?;
        let backend =
            build_backend(&storage_config.backend).context("failed to build blob backend")?;
        // Source groups are pulled through the local blob cache, so diskless mode
        // cannot apply.
        let Some(cache_dir) = &storage_config.storage.dir else {
            return Err(Error::InvalidConfig(
                "optimize requires storage.dir: source groups are pulled through the local blob cache"
                    .to_string(),
            ));
        };
        fs::create_dir_all(cache_dir).with_context(|| {
            format!("failed to create cache directory: {}", cache_dir.display())
        })?;

        let ondemand = build_ondemand_blob(&self.parent_bootstrap, &patterns, backend, cache_dir)?;
        let digest_hex = hex_string(&ondemand.full_blob_digest);

        fs::create_dir_all(&self.blob_dir).with_context(|| {
            format!(
                "failed to create blob directory: {}",
                self.blob_dir.display()
            )
        })?;
        let blob_path = self.blob_dir.join(&digest_hex);
        fs::write(&blob_path, &ondemand.artifact)
            .with_context(|| format!("failed to write ondemand blob: {}", blob_path.display()))?;
        let blob_metadata_path = self
            .blob_dir
            .join(format!("{digest_hex}{BLOB_METADATA_SUFFIX}"));
        ondemand
            .blob_metadata
            .save(&blob_metadata_path)
            .with_context(|| {
                format!("failed to save blob meta: {}", blob_metadata_path.display())
            })?;

        fs::write(&self.bootstrap, &ondemand.bootstrap).with_context(|| {
            format!(
                "failed to write rewritten bootstrap: {}",
                self.bootstrap.display()
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
        println!("    bootstrap_path: {}", self.bootstrap.display());
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
}
