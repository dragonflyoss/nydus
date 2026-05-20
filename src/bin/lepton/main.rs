// lepton — single CLI for lepton image creation, merge and mounting.

mod build;
mod check;
mod merge;
mod mount;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::build::{run_build, BuildArgs};
use crate::check::{run_check, CheckArgs};
use crate::merge::{run_merge, MergeArgs};
use crate::mount::{run_fuse_mount, Driver, MountArgs};

#[derive(Parser)]
#[command(name = "lepton", about = "Lepton filesystem tools")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create an lepton filesystem image (chunk-based).
    Build(BuildArgs),
    /// Statically inspect an lepton / EROFS image.
    Check(CheckArgs),
    /// Merge multiple lepton layers into an overlaid bootstrap.
    Merge(MergeArgs),
    /// Mount an lepton image.
    Mount(MountArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build(args) => run_build(args),
        Commands::Check(args) => run_check(args),
        Commands::Merge(args) => run_merge(args),
        Commands::Mount(args) => match args.driver {
            Driver::Fuse => run_fuse_mount(args),
        },
    }
}
