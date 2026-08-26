use clap::{Parser, ValueEnum};
use nydus::build::merge::{merge_sources_to_bootstrap_writer, WhiteoutSpec as MergeWhiteoutSpec};
use nydus::error::{Context, Result};
use nydus_telemetry::logging::init_command_tracing;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use tracing::Level;

/// The whiteout specification to apply while merging layers.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum WhiteoutSpec {
    Oci,
}

/// The subcommand of merge.
#[derive(Debug, Clone, Parser)]
pub struct MergeCommand {
    #[arg(
        required = true,
        help = "Specify the nydus layer blob paths named by their SHA256"
    )]
    sources: Vec<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_MERGE_BOOTSTRAP",
        help = "Specify the file path to save the generated overlaid nydus bootstrap"
    )]
    bootstrap: PathBuf,

    #[arg(
        long,
        value_enum,
        default_value_t = WhiteoutSpec::Oci,
        env = "NYDUS_MERGE_WHITEOUT_SPEC",
        help = "Specify the whiteout specification to apply while merging layers"
    )]
    whiteout_spec: WhiteoutSpec,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        env = "NYDUS_MERGE_LOG_LEVEL",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    log_level: Level,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        env = "NYDUS_MERGE_CONSOLE",
        help = "Specify whether to print log"
    )]
    console: bool,
}

/// Implement the execute for MergeCommand.
impl MergeCommand {
    /// Executes the merge sub command, merging the layer blobs into an
    /// overlaid bootstrap.
    pub fn execute(&self) -> Result<()> {
        // Initializes the tracing subscriber for logging, using the specified log level and
        // console output preference.
        let _guards = init_command_tracing(self.log_level, self.console);

        // Runs the merge, writing the overlaid bootstrap to the output.
        self.run()
    }

    /// Runs the merge: overlays the source layers in order and streams the
    /// merged bootstrap straight to the output file.
    fn run(&self) -> Result<()> {
        let whiteout_spec = match self.whiteout_spec {
            WhiteoutSpec::Oci => MergeWhiteoutSpec::Oci,
        };

        let output = File::create(&self.bootstrap)
            .with_context(|| format!("failed to create bootstrap: {}", self.bootstrap.display()))?;
        let mut writer = BufWriter::new(output);
        merge_sources_to_bootstrap_writer(&self.sources, whiteout_spec, &mut writer)?;
        writer
            .flush()
            .with_context(|| format!("failed to flush bootstrap: {}", self.bootstrap.display()))?;

        Ok(())
    }
}
