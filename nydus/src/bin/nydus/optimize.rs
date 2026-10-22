use clap::{Parser, ValueEnum};
use nydus::build::save_blob_metadata_sidecar;
use nydus::error::{Context, Error, Result};
use nydus::optimize::{
    build_ondemand_blob, load_patterns_from_apiserver, load_patterns_from_file, ChunkGroupRef,
};
use nydus_backend::Backend;
use nydus_config::{Config, StorageConfig};
use nydus_core::CacheOptions;
use nydus_format::erofs::EROFS_BLOCK_SIZE;
use nydus_telemetry::logging::init_command_tracing;
use nydus_telemetry::metrics::Metrics;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tabled::{settings::Style, Table, Tabled};
use tracing::{info, Level};

/// The artifact optimize builds.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum OptimizeType {
    /// An ondemand blob: the recorded chunk groups copied out of their source
    /// blobs in first-access order, with the bootstrap rewritten to prefetch it.
    Ondemand,
}

/// The subcommand of optimize.
#[derive(Debug, Clone, Parser)]
pub struct OptimizeCommand {
    #[arg(
        long,
        value_enum,
        default_value_t = OptimizeType::Ondemand,
        env = "NYDUS_OPTIMIZE_TYPE",
        help = "Specify the artifact to build: ondemand copies the recorded chunk groups into an ondemand blob and rewrites the bootstrap to prefetch it"
    )]
    r#type: OptimizeType,

    #[arg(
        long,
        required_unless_present = "trace_file",
        env = "NYDUS_OPTIMIZE_APISERVER",
        help = "Specify the apiserver address of a running `nydus fuse` mount, e.g. `unix:///path/to/api.sock`. The access patterns are fetched live from its `/trace` endpoint. Mutually exclusive with `--trace-file`"
    )]
    apiserver: Option<String>,

    #[arg(
        long,
        visible_alias = "pattern",
        conflicts_with = "apiserver",
        env = "NYDUS_OPTIMIZE_TRACE_FILE",
        help = "Specify the path to a JSON trace file containing access patterns: the versioned `{\"version\":1,\"patterns\":[{\"blob_index\":..,\"chunk_group_index\":..}]}` document, exactly as produced by the apiserver `/trace` endpoint. Mutually exclusive with `--apiserver`"
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

        // Prepares the access patterns, blob backend, cache directory and
        // cache options from the raw CLI flags.
        let (patterns, backend, storage) = self.prepare()?;

        // Runs the pipeline of the requested artifact, persisting its
        // artifacts and printing the summary.
        match self.r#type {
            OptimizeType::Ondemand => self.run_ondemand_blob(&patterns, backend, &storage),
        }
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
    /// from the ondemand record (file or apiserver), the blob backend, and the storage section the
    /// source blobs' caches are opened with.
    fn prepare(&self) -> Result<(Vec<ChunkGroupRef>, Arc<dyn Backend>, StorageConfig)> {
        let patterns = match (&self.trace_file, &self.apiserver) {
            (Some(path), _) => load_patterns_from_file(path)?,
            (None, Some(apiserver)) => load_patterns_from_apiserver(apiserver)?,
            _ => unreachable!("clap enforces exactly one of --trace-file and --apiserver"),
        };
        if patterns.is_empty() {
            return Err(Error::InvalidParameter(
                "no chunk group accesses found in the ondemand record (exercise the workload before optimizing)"
                    .to_string(),
            ));
        }

        // Load the storage config.
        let storage_config = Config::load(&self.config)?;
        let backend = <dyn Backend>::new(
            &storage_config.backend,
            &storage_config.prefetch,
            None,
            Arc::new(Metrics::new()),
        )
        .context("failed to build blob backend")?;

        Ok((patterns, backend, storage_config.storage))
    }

    /// Runs the ondemand blob pipeline: builds the ondemand blob, persists the
    /// blob, its metadata, and the rewritten bootstrap, and prints the summary.
    fn run_ondemand_blob(
        &self,
        patterns: &[ChunkGroupRef],
        backend: Arc<dyn Backend>,
        storage: &StorageConfig,
    ) -> Result<()> {
        // Source chunks are read through the local blob cache's backend, so
        // diskless mode cannot apply.
        let Some(cache_dir) = &storage.dir else {
            return Err(Error::InvalidConfig(
                "optimize requires storage.dir: source chunks are read through the local blob cache"
                    .to_string(),
            ));
        };
        fs::create_dir_all(cache_dir).with_context(|| {
            format!("failed to create cache directory: {}", cache_dir.display())
        })?;

        let ondemand = build_ondemand_blob(
            &self.parent_bootstrap,
            patterns,
            backend,
            cache_dir,
            CacheOptions::from(storage),
        )?;
        let digest_hex = hex::encode(ondemand.full_blob_digest);

        fs::create_dir_all(&self.blob_dir).with_context(|| {
            format!(
                "failed to create blob directory: {}",
                self.blob_dir.display()
            )
        })?;
        let blob_path = self.blob_dir.join(&digest_hex);
        fs::write(&blob_path, &ondemand.artifact)
            .with_context(|| format!("failed to write ondemand blob: {}", blob_path.display()))?;
        let blob_metadata_path = save_blob_metadata_sidecar(&ondemand.blob_metadata, &blob_path)?;

        fs::write(&self.bootstrap, &ondemand.bootstrap).with_context(|| {
            format!(
                "failed to write rewritten bootstrap: {}",
                self.bootstrap.display()
            )
        })?;

        info!(
            "optimized {} chunk groups from {} source blobs into ondemand blob",
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
            #[tabled(rename = "CHUNK GROUP COUNT")]
            chunk_group_count: String,
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
            chunk_group_count: patterns.len().to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn optimize_parses_the_type_default_and_the_pattern_alias() {
        let test_cases = vec![
            (
                vec!["--trace-file", "/tmp/trace.json"],
                OptimizeType::Ondemand,
            ),
            (vec!["--pattern", "/tmp/trace.json"], OptimizeType::Ondemand),
            (
                vec!["--pattern", "/tmp/trace.json", "--type", "ondemand"],
                OptimizeType::Ondemand,
            ),
        ];

        for (flags, expected_type) in test_cases {
            let mut args = vec![
                "optimize",
                "--parent-bootstrap",
                "/tmp/parent",
                "--bootstrap",
                "/tmp/bootstrap",
                "--blob-dir",
                "/tmp/blobs",
                "--config",
                "/tmp/config.yaml",
            ];
            args.extend(flags);
            let cmd = OptimizeCommand::try_parse_from(args).unwrap();
            assert_eq!(cmd.r#type, expected_type);
            assert_eq!(
                cmd.trace_file.as_deref(),
                Some(Path::new("/tmp/trace.json"))
            );
        }
    }

    #[test]
    fn optimize_rejects_an_unknown_type_and_a_trace_file_with_an_apiserver() {
        let base = [
            "optimize",
            "--parent-bootstrap",
            "/tmp/parent",
            "--bootstrap",
            "/tmp/bootstrap",
            "--blob-dir",
            "/tmp/blobs",
            "--config",
            "/tmp/config.yaml",
        ];
        let test_cases = vec![
            vec!["--trace-file", "/tmp/trace.json", "--type", "ondemand-blob"],
            vec![
                "--pattern",
                "/tmp/trace.json",
                "--apiserver",
                "unix:///tmp/api.sock",
            ],
            vec![],
        ];

        for flags in test_cases {
            let args = base.iter().copied().chain(flags).collect::<Vec<_>>();
            assert!(OptimizeCommand::try_parse_from(args).is_err());
        }
    }
}
