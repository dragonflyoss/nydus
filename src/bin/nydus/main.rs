// nydus — single CLI for nydus image creation, merge and mounting.

mod apiserver;
mod build;
mod check;
mod fuse;
mod merge;
mod optimize;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::build::{run_build, BuildArgs};
use crate::check::{run_check, CheckArgs};
use crate::fuse::{run_fuse_mount, FuseArgs};
use crate::merge::{run_merge, MergeArgs};
use crate::optimize::{run_optimize, OptimizeArgs};

#[derive(Parser)]
#[command(name = "nydus", about = "Nydus filesystem tools")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create an nydus filesystem image (chunk-based).
    Build(BuildArgs),
    /// Statically inspect an nydus / EROFS image.
    Check(CheckArgs),
    /// Merge multiple nydus layers into an overlaid bootstrap.
    Merge(MergeArgs),
    /// Build an ondemand blob from a /trace access pattern and rewrite the bootstrap.
    Optimize(OptimizeArgs),
    /// Mount an nydus image through FUSE.
    Fuse(FuseArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build(args) => run_build(args),
        Commands::Check(args) => run_check(args),
        Commands::Merge(args) => run_merge(args),
        Commands::Optimize(args) => run_optimize(args),
        Commands::Fuse(args) => run_fuse_mount(args),
    }
}
