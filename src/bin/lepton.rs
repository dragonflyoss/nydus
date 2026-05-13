// lepton — single CLI for EROFS image creation and FUSE mounting.
//
// Subcommands:
//   lepton mkfs <image> --blobdev <path> --chunksize <bytes> <source>
//   lepton fuse mount <image> <mountpoint> [--blobdev <path>] [--threads N] [--fsname NAME]

use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use log::{error, info, LevelFilter};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;
use simple_logger::SimpleLogger;

use fuser::{Config, MountOption, Session};

use mkfs_erofs::build::blobchunk::BlobWriter;
use mkfs_erofs::build::dir::{serialize_directory, DirChild};
use mkfs_erofs::build::image::write_image;
use mkfs_erofs::build::inode::{
    build_tree, inode_meta_size, serialize_inode, InodeData, InodeInfo,
};
use mkfs_erofs::fs::{ErofsFs, ErofsReader};
use mkfs_erofs::metadata::layout::MetadataLayout;
use mkfs_erofs::metadata::*;

#[derive(Parser)]
#[command(name = "lepton", about = "EROFS filesystem tools")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create an EROFS filesystem image (chunk-based)
    Mkfs(MkfsArgs),
    /// FUSE-related operations
    Fuse(FuseArgs),
}

#[derive(Args)]
struct MkfsArgs {
    /// Output image file path
    image: PathBuf,

    /// Extra blob device to store chunked data
    #[arg(long)]
    blobdev: PathBuf,

    /// Chunk size in bytes (must be a power of two, >= 4096)
    #[arg(long)]
    chunksize: u32,

    /// Source directory
    source: PathBuf,
}

#[derive(Args)]
struct FuseArgs {
    #[command(subcommand)]
    command: FuseCommands,
}

#[derive(Subcommand)]
enum FuseCommands {
    /// Mount an EROFS image via FUSE
    Mount(MountArgs),
}

#[derive(Args)]
struct MountArgs {
    /// EROFS image file
    image: String,

    /// Mount point
    mountpoint: String,

    /// Optional blob device for chunk-based files
    #[arg(long)]
    blobdev: Option<String>,

    /// Number of worker threads
    #[arg(long, default_value_t = 4)]
    threads: usize,

    /// Filesystem name shown in /proc/mounts SOURCE column
    #[arg(long, default_value = "lepton")]
    fsname: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Mkfs(args) => run_mkfs(args),
        Commands::Fuse(FuseArgs {
            command: FuseCommands::Mount(args),
        }) => run_fuse_mount(args),
    }
}

fn run_mkfs(args: MkfsArgs) -> Result<()> {
    // Validate chunksize
    if args.chunksize < EROFS_BLOCK_SIZE {
        bail!(
            "chunksize {} must be >= block size {}",
            args.chunksize,
            EROFS_BLOCK_SIZE
        );
    }
    if !args.chunksize.is_power_of_two() {
        bail!("chunksize {} must be a power of two", args.chunksize);
    }
    let chunkbits = args.chunksize.trailing_zeros();

    // Validate source is a directory
    if !args.source.is_dir() {
        bail!("source {} is not a directory", args.source.display());
    }

    let epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_secs();

    // Phase 1: Build inode tree and write chunk data to blobdev
    eprintln!("Building filesystem tree from {}...", args.source.display());
    let mut blob_writer = BlobWriter::new(&args.blobdev, args.chunksize)?;
    let mut inodes = build_tree(&args.source, &mut blob_writer, args.chunksize)?;

    let total_inodes = inodes.len() as u64;
    eprintln!(
        "  {} inodes, {} blob blocks, {} bytes saved by dedup",
        total_inodes,
        blob_writer.total_blocks(),
        blob_writer.saved_by_dedup
    );

    // Phase 2: Layout metadata
    eprintln!("Laying out metadata...");
    let mut layout = MetadataLayout::new();
    let blkszbits = EROFS_BLKSZBITS as u32;

    // Phase 2a: Allocate inode slots
    for inode in &mut inodes {
        let meta_size = inode_meta_size(inode, chunkbits, blkszbits);
        let (offset, nid) = layout.alloc_inode(meta_size);
        inode.meta_offset = offset;
        inode.nid = nid;
    }

    // Set parent NIDs for directories
    set_parent_nids(&mut inodes);

    // Phase 2b: Serialize and allocate directory data
    layout.pad_to_block();

    let dir_infos: Vec<(usize, Vec<DirChild>, u64, u64)> = inodes
        .iter()
        .enumerate()
        .filter_map(|(idx, inode)| {
            if let InodeData::Directory {
                ref children,
                parent_nid,
                ..
            } = inode.data
            {
                let self_nid = inode.nid;
                let dir_children: Vec<DirChild> = children
                    .iter()
                    .map(|de| DirChild {
                        name: de.name.clone(),
                        nid: inodes[de.inode_idx].nid,
                        file_type: de.file_type,
                    })
                    .collect();
                Some((idx, dir_children, self_nid, parent_nid))
            } else {
                None
            }
        })
        .collect();

    for (idx, dir_children, self_nid, parent_nid) in dir_infos {
        let dir_data = serialize_directory(&dir_children, self_nid, parent_nid);
        let dir_data_len = dir_data.len();
        let (data_offset, startblk) = layout.alloc_dir_data(dir_data_len);
        layout.write_at(data_offset, &dir_data);

        if let InodeData::Directory {
            startblk: ref mut sb,
            dir_data_size: ref mut dds,
            ..
        } = inodes[idx].data
        {
            *sb = startblk;
            *dds = dir_data_len;
        }
        inodes[idx].size = dir_data_len as u64;
    }

    // Phase 2c: Serialize inodes into metadata buffer
    for inode in &inodes {
        let inode_bytes = serialize_inode(inode, epoch, chunkbits);
        let offset = inode.meta_offset;
        layout.write_at(offset, &inode_bytes);
    }

    // Phase 3: Write image
    eprintln!("Writing image to {}...", args.image.display());
    let root_nid = inodes[0].nid;
    assert!(root_nid <= u16::MAX as u64, "root NID exceeds 16-bit range");

    let uuid = uuid::Uuid::new_v4();
    let uuid_bytes: [u8; 16] = *uuid.as_bytes();

    let img_file = File::create(&args.image)
        .with_context(|| format!("failed to create image: {}", args.image.display()))?;
    let mut writer = BufWriter::new(img_file);

    write_image(
        &mut writer,
        &layout.buf,
        root_nid as u16,
        total_inodes,
        epoch,
        blob_writer.total_blocks(),
        &uuid_bytes,
    )?;

    eprintln!(
        "Done. Image: {} blocks, Blob: {} blocks",
        1 + layout.total_blocks(),
        blob_writer.total_blocks()
    );
    Ok(())
}

/// Set parent_nid for all directory inodes by traversing the tree.
fn set_parent_nids(inodes: &mut [InodeInfo]) {
    let root_nid = inodes[0].nid;
    if let InodeData::Directory {
        ref mut parent_nid, ..
    } = inodes[0].data
    {
        *parent_nid = root_nid;
    }

    let dir_infos: Vec<(u64, Vec<usize>)> = inodes
        .iter()
        .filter_map(|inode| {
            if let InodeData::Directory { ref children, .. } = inode.data {
                let child_dir_idxs: Vec<usize> = children
                    .iter()
                    .filter(|de| de.file_type == EROFS_FT_DIR)
                    .map(|de| de.inode_idx)
                    .collect();
                if child_dir_idxs.is_empty() {
                    None
                } else {
                    Some((inode.nid, child_dir_idxs))
                }
            } else {
                None
            }
        })
        .collect();

    for (parent_nid_val, child_idxs) in dir_infos {
        for child_idx in child_idxs {
            if let InodeData::Directory {
                ref mut parent_nid, ..
            } = inodes[child_idx].data
            {
                *parent_nid = parent_nid_val;
            }
        }
    }
}

fn run_fuse_mount(args: MountArgs) -> Result<()> {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .map_err(|e| anyhow!("failed to init logger: {}", e))?;

    let mountpoint = Path::new(&args.mountpoint);
    if !mountpoint.is_dir() {
        bail!("mountpoint {} is not a directory", args.mountpoint);
    }

    // ErofsReader::open() is async — use a temporary tokio runtime for initialization.
    let reader = {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build tokio runtime")?;
        rt.block_on(ErofsReader::open(&args.image, args.blobdev.as_deref()))
            .context("failed to open EROFS image")?
    };
    info!(
        "opened EROFS image: root_nid={}, blocks={}, inos={}",
        reader.sb().root_nid(),
        reader.sb().blocks(),
        reader.sb().inos()
    );

    let fs = ErofsFs::new(Arc::new(reader));

    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::RO,
        MountOption::FSName(args.fsname.clone()),
        MountOption::DefaultPermissions,
    ];
    config.n_threads = Some(args.threads);
    config.clone_fd = args.threads > 1;

    let mut session =
        Session::new(fs, mountpoint, &config).map_err(|e| anyhow!("mount failed: {}", e))?;
    info!("mounted on {}", args.mountpoint);

    let mut unmounter = session.unmount_callable();

    // Spawn a thread to wait for termination signals and trigger unmount.
    let mut signals = Signals::new(TERM_SIGNALS).context("failed to register signal handler")?;
    std::thread::Builder::new()
        .name("lepton_fuse_signal".to_string())
        .spawn(move || {
            if let Some(_sig) = signals.forever().next() {
                info!("received termination signal, unmounting...");
                if let Err(e) = unmounter.unmount() {
                    error!("unmount error: {:?}", e);
                }
            }
        })
        .context("failed to spawn signal thread")?;

    // Run the session loop in the background and wait for it to finish.
    let bg = session
        .spawn()
        .map_err(|e| anyhow!("spawn failed: {}", e))?;
    bg.join().map_err(|e| anyhow!("join failed: {}", e))?;

    Ok(())
}
