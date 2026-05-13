// lepton — single CLI for EROFS image creation and mounting.
//
// Subcommands:
//   lepton build <image> --blobdev <path> --chunksize <bytes> <source>
//   lepton mount [--driver fuse] <image> <mountpoint> [--blobdev <path>] [--threads N] [--fsname NAME]

mod build;
mod mount;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::build::{run_build, BuildArgs};
use crate::mount::{run_fuse_mount, Driver, MountArgs};

#[derive(Parser)]
#[command(name = "lepton", about = "EROFS filesystem tools")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create an EROFS filesystem image (chunk-based)
    Build(BuildArgs),
    /// Mount an EROFS image
    Mount(MountArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build(args) => run_build(args),
        Commands::Mount(args) => match args.driver {
            Driver::Fuse => run_fuse_mount(args),
        },
    }
}
