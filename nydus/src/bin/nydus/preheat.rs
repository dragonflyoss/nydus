use clap::Parser;
use nydus::error::{Context, Error, Result};
use nydus::preheat::{write_failure, Preheat};
use nydus_backend::Backend;
use nydus_config::Config;
use nydus_core::{CacheOptions, ErofsReader, Metrics};
use nydus_telemetry::logging::{init_journald_tracing, init_tracing};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, Level};

use super::{default_log_dir, NAME};

/// The subcommand of preheat.
#[derive(Debug, Clone, Parser)]
pub struct PreheatCommand {
    #[arg(
        long,
        env = "NYDUS_PREHEAT_BOOTSTRAP",
        help = "Specify the file path to nydus bootstrap"
    )]
    bootstrap: PathBuf,

    #[arg(
        long,
        env = "NYDUS_PREHEAT_CONFIG",
        help = "Specify the file path to a YAML storage config (same format as `nydus fuse --config`) providing the backend the blobs are downloaded from and the cache directory they are downloaded into"
    )]
    config: PathBuf,

    #[arg(
        long,
        env = "NYDUS_PREHEAT_STATE_FILE",
        help = "Specify the file path the state of the preheat is written to as JSON, replaced atomically while the blobs download and once the preheat ends"
    )]
    state_file: PathBuf,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        env = "NYDUS_PREHEAT_LOG_LEVEL",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    log_level: Level,

    #[arg(
        long,
        default_value_os_t = default_log_dir(),
        env = "NYDUS_PREHEAT_LOG_DIR",
        help = "Specify the log directory"
    )]
    log_dir: PathBuf,

    #[arg(
        long,
        default_value_t = 6,
        env = "NYDUS_PREHEAT_LOG_MAX_FILES",
        help = "Specify the max number of log files"
    )]
    log_max_files: usize,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        env = "NYDUS_PREHEAT_CONSOLE",
        help = "Specify whether to print log"
    )]
    console: bool,

    #[arg(
        long,
        env = "NYDUS_PREHEAT_LOG_JOURNALD",
        help = "Specify whether to log to the systemd journal instead of the log directory and the console"
    )]
    log_journald: bool,
}

/// Implement the execute for PreheatCommand.
impl PreheatCommand {
    /// Executes the preheat sub command, downloading every blob of the image
    /// into the cache directory and writing the outcome to the state file.
    pub fn execute(&self) -> Result<()> {
        // Initialize tracing.
        let _guards = if self.log_journald {
            init_journald_tracing(NAME, self.log_level)?
        } else {
            init_tracing(
                NAME,
                self.log_dir.clone(),
                self.log_level,
                self.log_max_files,
                self.console,
            )?
        };

        self.run()
            .inspect_err(|err| error!("nydus preheat failed: {}", err.report()))
    }

    /// Runs the preheat. A preheat that cannot start has no status yet, so
    /// its failure is written to the state file here.
    fn run(&self) -> Result<()> {
        self.prepare()
            .inspect_err(|err| write_failure(&self.state_file, err))?
            .run()
    }

    /// Lowers the raw CLI flags into the preheat: the blob backend and the
    /// cache directory from the config, and the image from the bootstrap.
    fn prepare(&self) -> Result<Preheat> {
        // Load the storage config. A preheat ends at the first blob that
        // fails, so a prefetch read does not wait hours to be sent once more.
        let mut config = Config::load(&self.config)?;
        config.prefetch.retry_interval = Duration::ZERO;

        let Some(cache_dir) = &config.storage.dir else {
            return Err(Error::InvalidConfig(
                "preheat requires storage.dir: the blobs are downloaded into the local blob cache"
                    .to_string(),
            ));
        };
        fs::create_dir_all(cache_dir).with_context(|| {
            format!("failed to create cache directory: {}", cache_dir.display())
        })?;

        let backend = <dyn Backend>::new(&config, None, Arc::new(Metrics::new()))
            .context("failed to build blob backend")?;
        let reader = ErofsReader::open_bootstrap(
            &self.bootstrap,
            backend,
            Some(cache_dir),
            None,
            CacheOptions::from(&config.storage),
        )
        .context("failed to open EROFS image")?;

        Preheat::new(
            &reader,
            config.prefetch.concurrent_blob_count,
            config.prefetch.request_timeout,
            &self.state_file,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::tempdir;

    const FLAGS: [&str; 6] = [
        "--bootstrap",
        "/tmp/bootstrap",
        "--config",
        "/tmp/config.yaml",
        "--state-file",
        "/tmp/state.json",
    ];

    #[test]
    fn preheat_parses_the_bootstrap_the_config_and_the_state_file() {
        let cmd = PreheatCommand::try_parse_from(["preheat"].into_iter().chain(FLAGS)).unwrap();

        assert_eq!(cmd.bootstrap, Path::new("/tmp/bootstrap"));
        assert_eq!(cmd.config, Path::new("/tmp/config.yaml"));
        assert_eq!(cmd.state_file, Path::new("/tmp/state.json"));
        assert_eq!(cmd.log_level, Level::INFO);
        assert_eq!(cmd.log_max_files, 6);
    }

    #[test]
    fn preheat_rejects_a_missing_flag() {
        let test_cases = vec![
            vec![
                "--config",
                "/tmp/config.yaml",
                "--state-file",
                "/tmp/state.json",
            ],
            vec![
                "--bootstrap",
                "/tmp/bootstrap",
                "--state-file",
                "/tmp/state.json",
            ],
            vec![
                "--bootstrap",
                "/tmp/bootstrap",
                "--config",
                "/tmp/config.yaml",
            ],
        ];

        for flags in test_cases {
            assert!(PreheatCommand::try_parse_from(["preheat"].into_iter().chain(flags)).is_err());
        }
    }

    #[test]
    fn run_writes_the_failure_of_a_preheat_that_cannot_start() {
        let test_cases = vec![
            (
                "backend:\n  type: local\n  config:\n    dir: /blobs\n",
                "preheat requires storage.dir",
            ),
            ("backend: {}\n", "failed to parse nydus config"),
            (
                "backend:\n  type: local\n  config:\n    dir: /blobs\nstorage:\n  dir: CACHE\n",
                "failed to open EROFS image",
            ),
        ];

        for (config, expected) in test_cases {
            let dir = tempdir().unwrap();
            let config_path = dir.path().join("config.yaml");
            let state_file = dir.path().join("state.json");
            let cache_dir = dir.path().join("cache");
            fs::write(
                &config_path,
                config.replace("CACHE", cache_dir.to_str().unwrap()),
            )
            .unwrap();
            let cmd = PreheatCommand::try_parse_from([
                "preheat",
                "--bootstrap",
                dir.path().join("bootstrap").to_str().unwrap(),
                "--config",
                config_path.to_str().unwrap(),
                "--state-file",
                state_file.to_str().unwrap(),
            ])
            .unwrap();

            let err = cmd.run().unwrap_err();

            let status: serde_json::Value =
                serde_json::from_slice(&fs::read(&state_file).unwrap()).unwrap();
            assert!(
                err.report().to_string().starts_with(expected),
                "{}",
                err.report()
            );
            assert_eq!(status["state"], "failed");
            assert_eq!(status["description"], err.report().to_string());
        }
    }
}
