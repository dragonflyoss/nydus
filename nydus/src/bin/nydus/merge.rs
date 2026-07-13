use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use nydus::merge::{merge_sources_to_bootstrap_bytes, WhiteoutSpec as MergeWhiteoutSpec};
use nydus::tracing::init_command_tracing;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use tracing::Level;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum WhiteoutSpec {
    Oci,
}

#[derive(Args)]
pub struct MergeArgs {
    /// Nydus layer blob paths named by their SHA256.
    #[arg(required = true)]
    pub sources: Vec<PathBuf>,

    /// File path to save the generated overlaid nydus bootstrap.
    #[arg(long)]
    pub bootstrap: PathBuf,

    /// Whiteout specification to apply while merging layers.
    #[arg(long, value_enum, default_value_t = WhiteoutSpec::Oci)]
    pub whiteout_spec: WhiteoutSpec,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    pub log_level: Level,

    #[arg(long, hide = true, default_value_t = true)]
    pub console: bool,
}

pub fn run_merge(args: MergeArgs) -> Result<()> {
    let _guards = init_command_tracing(args.log_level, args.console);

    let whiteout_spec = match args.whiteout_spec {
        WhiteoutSpec::Oci => MergeWhiteoutSpec::Oci,
    };
    let bootstrap_bytes = merge_sources_to_bootstrap_bytes(&args.sources, whiteout_spec)?;

    let output = File::create(&args.bootstrap)
        .with_context(|| format!("failed to create bootstrap: {}", args.bootstrap.display()))?;
    let mut writer = BufWriter::new(output);
    writer
        .write_all(&bootstrap_bytes)
        .with_context(|| format!("failed to write bootstrap: {}", args.bootstrap.display()))?;
    writer
        .flush()
        .with_context(|| format!("failed to flush bootstrap: {}", args.bootstrap.display()))?;

    Ok(())
}
