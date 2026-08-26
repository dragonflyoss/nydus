use clap::Parser;
use nydus::error::{Context, Error, Result};
use nydus::optimize::{
    build_ondemand_blob, load_patterns_from_apiserver, load_patterns_from_file, BlockGroupRef,
};
use nydus_backend::{build_backend, BlobBackend};
use nydus_config::Config;
use nydus_format::blob::NYDUS_BLOB_METADATA_SUFFIX;
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use nydus_format::utils::hex_string;
use nydus_telemetry::logging::init_command_tracing;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tabled::{settings::Style, Table, Tabled};
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
        help = "Specify the path to a JSON trace file containing access patterns: the versioned `{\"version\":1,\"patterns\":[{\"blob_index\":..,\"block_group_index\":..}]}` document, exactly as produced by the apiserver `/trace` endpoint. Mutually exclusive with `--apiserver`"
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
        help = "Specify the content-addressed store directory to save the ondemand blob into, named by its SHA256, next to its `.blob.meta` sidecar"
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
        // Initializes the tracing subscriber for logging, using the specified log level and
        // console output preference.
        let _guards = init_command_tracing(self.log_level, self.console);

        // Validates the flag combination before any expensive work.
        self.validate()?;

        // Prepares the access patterns, blob backend, and cache directory from the raw CLI flags.
        let (patterns, backend, cache_dir) = self.prepare()?;

        // Runs the optimize pipeline, persisting its artifacts and printing the summary.
        self.run(&patterns, backend, &cache_dir)
    }

    /// Validates the flag combination before any expensive work: the
    /// rewritten bootstrap must not overwrite its parent.
    fn validate(&self) -> Result<()> {
        if self.parent_bootstrap == self.bootstrap {
            return Err(Error::InvalidParameter(
                "--parent-bootstrap and --bootstrap must point to different files".to_string(),
            ));
        }

        Ok(())
    }

    /// Lowers the raw CLI flags into the optimize inputs: the access patterns
    /// from the trace source, the blob backend, and the local cache directory
    /// the source block groups are pulled through.
    fn prepare(&self) -> Result<(Vec<BlockGroupRef>, Arc<dyn BlobBackend>, PathBuf)> {
        let patterns = match (&self.trace_file, &self.apiserver) {
            (Some(path), _) => load_patterns_from_file(path)?,
            (None, Some(apiserver)) => load_patterns_from_apiserver(apiserver)?,
            _ => unreachable!("clap enforces exactly one of --trace-file and --apiserver"),
        };
        if patterns.is_empty() {
            return Err(Error::InvalidParameter(
                "no block group accesses found in the access trace (exercise the workload before optimizing)"
                    .to_string(),
            ));
        }

        // Load the storage config.
        let storage_config = Config::load(&self.config)?;
        let backend =
            build_backend(&storage_config.backend).context("failed to build blob backend")?;
        // Source block groups are pulled through the local blob cache, so diskless mode
        // cannot apply.
        let Some(cache_dir) = storage_config.storage.dir else {
            return Err(Error::InvalidConfig(
                "optimize requires storage.dir: source block groups are pulled through the local blob cache"
                    .to_string(),
            ));
        };

        Ok((patterns, backend, cache_dir))
    }

    /// Runs the optimize pipeline: builds the ondemand blob, persists the
    /// blob, its metadata, and the rewritten bootstrap, and prints the summary.
    fn run(
        &self,
        patterns: &[BlockGroupRef],
        backend: Arc<dyn BlobBackend>,
        cache_dir: &Path,
    ) -> Result<()> {
        fs::create_dir_all(cache_dir).with_context(|| {
            format!("failed to create cache directory: {}", cache_dir.display())
        })?;

        let ondemand = build_ondemand_blob(&self.parent_bootstrap, patterns, backend, cache_dir)?;
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
            .join(format!("{digest_hex}{NYDUS_BLOB_METADATA_SUFFIX}"));
        ondemand.blob_metadata.save(&blob_metadata_path)?;

        fs::write(&self.bootstrap, &ondemand.bootstrap).with_context(|| {
            format!(
                "failed to write rewritten bootstrap: {}",
                self.bootstrap.display()
            )
        })?;

        info!(
            "optimized {} block groups from {} source blobs into ondemand blob",
            patterns.len(),
            ondemand.source_blob_count
        );

        // Define the table struct for printing.
        #[derive(Debug, Tabled)]
        #[tabled(rename_all = "UPPERCASE")]
        struct OndemandBlobRow {
            #[tabled(rename = "ONDEMAND BLOB DIGEST")]
            ondemand_blob_digest: String,
            #[tabled(rename = "ONDEMAND BLOB PATH")]
            ondemand_blob_path: String,
            #[tabled(rename = "BLOB METADATA PATH")]
            blob_metadata_path: String,
            #[tabled(rename = "BOOTSTRAP PATH")]
            bootstrap_path: String,
            #[tabled(rename = "BLOCK GROUP COUNT")]
            block_group_count: String,
            #[tabled(rename = "COMPRESSED DATA SIZE")]
            compressed_data_size: String,
            #[tabled(rename = "UNCOMPRESSED DATA SIZE")]
            uncompressed_data_size: String,
        }

        let row = OndemandBlobRow {
            ondemand_blob_digest: digest_hex,
            ondemand_blob_path: blob_path.display().to_string(),
            blob_metadata_path: blob_metadata_path.display().to_string(),
            bootstrap_path: self.bootstrap.display().to_string(),
            block_group_count: patterns.len().to_string(),
            compressed_data_size: ondemand.footer.compressed_data_size().to_string(),
            uncompressed_data_size: (ondemand.uncompressed_blocks * EROFS_BLOCK_SIZE as u64)
                .to_string(),
        };

        // Create a table and print it.
        let mut table = Table::kv(vec![row]);
        table.with(Style::blank());
        println!("{table}");
        Ok(())
    }
}
