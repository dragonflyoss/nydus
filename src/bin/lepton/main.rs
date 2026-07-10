// lepton — single CLI for lepton image creation, merge and mounting.

mod apiserver;
mod build;
mod check;
mod fuse;
mod merge;
mod optimize;
#[cfg(feature = "uffd")]
mod uffd;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::build::{run_build, BuildArgs};
use crate::check::{run_check, CheckArgs};
use crate::fuse::{run_fuse_mount, FuseArgs};
use crate::merge::{run_merge, MergeArgs};
use crate::optimize::{run_optimize, OptimizeArgs};
#[cfg(feature = "uffd")]
use crate::uffd::{run_uffd_service, UffdArgs};

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
    /// Build an ondemand blob from a /trace access pattern and rewrite the bootstrap.
    Optimize(OptimizeArgs),
    /// Mount an lepton image through FUSE.
    Fuse(FuseArgs),
    /// Serve a flattened lepton image through userfaultfd.
    #[cfg(feature = "uffd")]
    Uffd(UffdArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build(args) => run_build(args),
        Commands::Check(args) => run_check(args),
        Commands::Merge(args) => run_merge(args),
        Commands::Optimize(args) => run_optimize(args),
        Commands::Fuse(args) => run_fuse_mount(args),
        #[cfg(feature = "uffd")]
        Commands::Uffd(args) => run_uffd_service(args),
    }
}
