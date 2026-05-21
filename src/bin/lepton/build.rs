use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use lepton::build::blobchunk::BlobWriter;
use lepton::build::bootstrap::render_bootstrap;
use lepton::build::inode::{build_tree, InodeData, InodeInfo};
use lepton::metadata::*;
use lepton::tracing::init_command_tracing;
use lepton::utils::{hex_string, sha256_file};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{warn, Level};

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ConversionType {
    DirLepton,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Compressor {
    None,
    Zstd,
}

#[derive(Args)]
pub struct BuildArgs {
    /// Source directory to build the image from.
    pub source: PathBuf,

    /// Conversion type.
    #[arg(long = "type", value_enum, default_value_t = ConversionType::DirLepton)]
    pub conversion_type: ConversionType,

    /// File path to save the generated lepton blob (also include bootstrap).
    #[arg(
        long,
        conflicts_with = "blob_dir",
        required_unless_present = "blob_dir"
    )]
    pub blob: Option<PathBuf>,

    /// Directory path to save the generated lepton blob with its SHA256 file name.
    #[arg(long, conflicts_with = "blob", required_unless_present = "blob")]
    pub blob_dir: Option<PathBuf>,

    /// File path to save the generated lepton bootstrap.
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,

    /// Chunk size in bytes (must be a power of two, >= 4096).
    #[arg(long = "chunk-size")]
    pub chunk_size: u32,

    /// Algorithm to compress data chunks.
    #[arg(long, value_enum, default_value_t = Compressor::Zstd)]
    pub compressor: Compressor,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    pub log_level: Level,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        help = "Specify whether to print log"
    )]
    pub console: bool,
}

/// Run the build process to create an lepton image from the source directory.
pub fn run_build(args: BuildArgs) -> Result<()> {
    init_command_tracing(args.log_level, args.console);

    let requested_blob_path = args.blob.clone();
    if let (Some(bootstrap), Some(blob)) = (&args.bootstrap, requested_blob_path.as_ref()) {
        if *bootstrap == *blob {
            bail!("--bootstrap and --blob must point to different files");
        }
    }

    // Validate chunksize.
    if args.chunk_size < EROFS_BLOCK_SIZE {
        bail!(
            "chunksize {} must be >= block size {}",
            args.chunk_size,
            EROFS_BLOCK_SIZE
        );
    }
    if !args.chunk_size.is_power_of_two() {
        bail!("chunksize {} must be a power of two", args.chunk_size);
    }
    let chunkbits = args.chunk_size.trailing_zeros();

    // Validate source is a directory.
    if !args.source.is_dir() {
        bail!("source {} is not a directory", args.source.display());
    }

    if args.compressor == Compressor::Zstd {
        warn!(
            "zstd chunk compression is reserved in the new CLI but not implemented yet; writing uncompressed chunk data"
        );
    }

    let build_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_secs();

    let temp_blob_data_path =
        std::env::temp_dir().join(format!("lepton-build-{}.blobdata", uuid::Uuid::new_v4()));

    // Phase 1: Build inode tree and write chunk data to blobdev.
    eprintln!("Building filesystem tree from {}...", args.source.display());
    let mut blob_writer = BlobWriter::new(&temp_blob_data_path, args.chunk_size)?;
    let mut inodes = build_tree(&args.source, &mut blob_writer, args.chunk_size)?;
    let epoch = inodes
        .iter()
        .map(|inode| inode.mtime)
        .min()
        .unwrap_or(build_time);

    let total_inodes = inodes.len() as u64;
    eprintln!(
        "  {} inodes, {} blob blocks, {} bytes saved by dedup",
        total_inodes,
        blob_writer.total_blocks(),
        blob_writer.saved_by_dedup
    );

    // Phase 3: Materialize bootstrap bytes and final artifacts.
    let blob_target_desc = requested_blob_path
        .as_ref()
        .map(|path| path.display().to_string())
        .or_else(|| {
            args.blob_dir
                .as_ref()
                .map(|dir| format!("{}/<sha256>", dir.display()))
        })
        .expect("clap enforces either --blob or --blob-dir");
    eprintln!("Materializing bootstrap for {}...", blob_target_desc);

    let uuid = uuid::Uuid::new_v4();
    let uuid_bytes: [u8; 16] = *uuid.as_bytes();
    let blob_id = sha256_file(&temp_blob_data_path)?;
    let provisional_device_slots = [ErofsDeviceSlot::with_blob_id(
        blob_writer.total_blocks(),
        &blob_id,
    )];

    let provisional_bootstrap = render_bootstrap(
        &mut inodes,
        epoch,
        chunkbits,
        &provisional_device_slots,
        &uuid_bytes,
    )?;
    let bootstrap_blocks = provisional_bootstrap
        .len()
        .div_ceil(EROFS_BLOCK_SIZE as usize) as u64;
    rebase_external_chunk_blkaddrs(&mut inodes, bootstrap_blocks)?;

    let device_slots = [ErofsDeviceSlot::with_blob_id(
        bootstrap_blocks + blob_writer.total_blocks(),
        &blob_id,
    )];
    let bootstrap_bytes =
        render_bootstrap(&mut inodes, epoch, chunkbits, &device_slots, &uuid_bytes)?;

    if let Some(bootstrap) = &args.bootstrap {
        eprintln!("Writing bootstrap to {}...", bootstrap.display());
        let bootstrap_file = File::create(bootstrap)
            .with_context(|| format!("failed to create bootstrap: {}", bootstrap.display()))?;
        let mut writer = BufWriter::new(bootstrap_file);
        writer
            .write_all(&bootstrap_bytes)
            .with_context(|| format!("failed to write bootstrap: {}", bootstrap.display()))?;
        writer
            .flush()
            .with_context(|| format!("failed to flush bootstrap: {}", bootstrap.display()))?;
    }

    let (temp_full_blob_path, final_blob_path) =
        prepare_blob_output(requested_blob_path.as_deref(), args.blob_dir.as_deref())?;
    eprintln!("Writing full blob to {}...", temp_full_blob_path.display());
    let blob_file = File::create(&temp_full_blob_path)
        .with_context(|| format!("failed to create blob: {}", temp_full_blob_path.display()))?;
    let mut blob_writer_stream = BufWriter::new(blob_file);
    blob_writer_stream
        .write_all(&bootstrap_bytes)
        .with_context(|| {
            format!(
                "failed to write blob bootstrap: {}",
                temp_full_blob_path.display()
            )
        })?;

    let mut data_file = File::open(&temp_blob_data_path).with_context(|| {
        format!(
            "failed to reopen temp blob data: {}",
            temp_blob_data_path.display()
        )
    })?;
    io::copy(&mut data_file, &mut blob_writer_stream).with_context(|| {
        format!(
            "failed to append blob data: {}",
            temp_full_blob_path.display()
        )
    })?;
    blob_writer_stream
        .flush()
        .with_context(|| format!("failed to flush blob: {}", temp_full_blob_path.display()))?;

    let full_blob_id = sha256_file(&temp_full_blob_path)?;
    let final_blob_path = finalize_blob_output(
        &temp_full_blob_path,
        final_blob_path,
        &full_blob_id,
        args.blob_dir.as_deref(),
    )?;

    let _ = fs::remove_file(&temp_blob_data_path);

    eprintln!(
        "Done. Bootstrap: {} blocks, Data: {} blocks, Data blob id: {}, Blob sha256: {}, Blob path: {}",
        bootstrap_bytes.len().div_ceil(EROFS_BLOCK_SIZE as usize),
        blob_writer.total_blocks(),
        hex_string(&blob_id),
        hex_string(&full_blob_id),
        final_blob_path.display()
    );
    Ok(())
}

fn prepare_blob_output(
    blob: Option<&Path>,
    blob_dir: Option<&Path>,
) -> Result<(PathBuf, Option<PathBuf>)> {
    match (blob, blob_dir) {
        (Some(blob), None) => Ok((blob.to_path_buf(), None)),
        (None, Some(dir)) => {
            fs::create_dir_all(dir)
                .with_context(|| format!("failed to create blob-dir: {}", dir.display()))?;
            let temp_path = dir.join(format!(".lepton-build-{}.tmp", uuid::Uuid::new_v4()));
            Ok((temp_path, Some(dir.to_path_buf())))
        }
        _ => bail!("build expects either --blob <path> or --blob-dir <dir>"),
    }
}

fn finalize_blob_output(
    temp_path: &Path,
    blob_path: Option<PathBuf>,
    blob_sha256: &[u8; EROFS_BLOB_ID_SIZE],
    blob_dir: Option<&Path>,
) -> Result<PathBuf> {
    if blob_dir.is_none() {
        return Ok(blob_path.unwrap_or_else(|| temp_path.to_path_buf()));
    }

    let dir = blob_dir.expect("blob_dir is checked above");
    let final_path = dir.join(hex_string(blob_sha256));
    if final_path.exists() {
        fs::remove_file(temp_path).with_context(|| {
            format!(
                "failed to remove temporary blob after dedup hit: {}",
                temp_path.display()
            )
        })?;
        return Ok(final_path);
    }

    fs::rename(temp_path, &final_path).with_context(|| {
        format!(
            "failed to rename blob {} -> {}",
            temp_path.display(),
            final_path.display()
        )
    })?;
    Ok(final_path)
}

fn rebase_external_chunk_blkaddrs(inodes: &mut [InodeInfo], base_blocks: u64) -> Result<()> {
    for inode in inodes {
        let InodeData::RegularFile { chunk_indexes, .. } = &mut inode.data else {
            continue;
        };

        for chunk_index in chunk_indexes {
            if chunk_index.device_id == 0 || chunk_index.blkaddr == EROFS_NULL_ADDR {
                continue;
            }

            chunk_index.blkaddr = chunk_index
                .blkaddr
                .checked_add(base_blocks)
                .context("chunk block address overflow while rebasing full blob offsets")?;
        }
    }

    Ok(())
}
