// nydus — single CLI for nydus image creation, merge and mounting.

mod api_server;
mod build;
mod check;
mod cli_common;
#[cfg(feature = "fanotify")]
mod fanotify;
mod fuse;
mod merge;
#[cfg(feature = "nbd")]
mod nbd;
mod optimize;
#[cfg(feature = "ublk")]
mod ublk;
#[cfg(feature = "uffd")]
mod uffd;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::build::{run_build, BuildArgs};
use crate::check::{run_check, CheckArgs};
#[cfg(feature = "fanotify")]
use crate::fanotify::{run_fanotify, FanotifyArgs};
use crate::fuse::{run_fuse, FuseArgs};
use crate::merge::{run_merge, MergeArgs};
#[cfg(feature = "nbd")]
use crate::nbd::{run_nbd, NbdArgs};
use crate::optimize::{run_optimize, OptimizeArgs};
#[cfg(feature = "ublk")]
use crate::ublk::{run_ublk, UblkArgs};
#[cfg(feature = "uffd")]
use crate::uffd::{run_uffd, UffdArgs};

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
    /// Serve a flattened nydus image as a ublk block device.
    #[cfg(feature = "ublk")]
    Ublk(UblkArgs),
    /// Serve a flattened nydus image through userfaultfd.
    #[cfg(feature = "uffd")]
    Uffd(UffdArgs),
    /// Serve an EROFS image on demand through fanotify pre-content hooks.
    #[cfg(feature = "fanotify")]
    Fanotify(FanotifyArgs),
    /// Export a nydus image as a block device through the NBD protocol.
    #[cfg(feature = "nbd")]
    Nbd(NbdArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build(args) => run_build(args),
        Commands::Check(args) => run_check(args),
        Commands::Merge(args) => run_merge(args),
        Commands::Optimize(args) => run_optimize(args),
        Commands::Fuse(args) => run_fuse(args),
        #[cfg(feature = "ublk")]
        Commands::Ublk(args) => run_ublk(args),
        #[cfg(feature = "uffd")]
        Commands::Uffd(args) => run_uffd(args),
        #[cfg(feature = "fanotify")]
        Commands::Fanotify(args) => run_fanotify(args),
        #[cfg(feature = "nbd")]
        Commands::Nbd(args) => run_nbd(args),
    }
}
