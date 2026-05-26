use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use lepton::build::blob_chunk::BlobWriter;
use lepton::build::bootstrap::render_bootstrap;
use lepton::build::inode::build_tree;
use lepton::metadata::*;
use lepton::tracing::init_command_tracing;
use lepton::utils::{hex_string, sha256_file};
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::Level;

const DEFAULT_CHUNK_SIZE: u32 = 1_048_576;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ConversionType {
    DirLepton,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Compressor {
    None,
    Zstd,
}

impl From<Compressor> for BlobMetaCompressor {
    fn from(value: Compressor) -> Self {
        match value {
            Compressor::None => Self::None,
            Compressor::Zstd => Self::Zstd,
        }
    }
}

#[derive(Args)]
pub struct BuildArgs {
    /// Source directory to build the image from.
    pub source: PathBuf,

    /// Conversion type.
    #[arg(long = "type", value_enum, default_value_t = ConversionType::DirLepton)]
    pub conversion_type: ConversionType,

    /// File path to save the generated lepton full blob (also emits <blob>.blob.meta).
    #[arg(
        long,
        conflicts_with = "blob_dir",
        required_unless_present = "blob_dir"
    )]
    pub blob: Option<PathBuf>,

    /// Directory path to save the generated lepton full blob and blob meta with SHA256 file names.
    #[arg(long, conflicts_with = "blob", required_unless_present = "blob")]
    pub blob_dir: Option<PathBuf>,

    /// File path to save the generated lepton bootstrap.
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,

    /// File chunk size in bytes (must be a power of two, >= 4KiB, and 4KiB-aligned).
    #[arg(long = "chunk-size", default_value_t = DEFAULT_CHUNK_SIZE)]
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
    let _guards = init_command_tracing(args.log_level, args.console);

    let requested_blob_path = args.blob.clone();
    if let (Some(bootstrap), Some(blob)) = (&args.bootstrap, requested_blob_path.as_ref()) {
        if *bootstrap == *blob {
            bail!("--bootstrap and --blob must point to different files");
        }
    }

    // Validate EROFS file chunksize. BlobMeta groups are formed separately and
    // are at least 1MiB even when file chunk indexes are smaller.
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
    if args.chunk_size % EROFS_BLOCK_SIZE != 0 {
        bail!("chunksize {} must be block aligned", args.chunk_size);
    }
    let chunkbits = args.chunk_size.trailing_zeros();

    // Validate source is a directory.
    if !args.source.is_dir() {
        bail!("source {} is not a directory", args.source.display());
    }

    let build_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_secs();

    let temp_blob_data_path =
        std::env::temp_dir().join(format!("lepton-build-{}.blobdata", uuid::Uuid::new_v4()));

    let mut blob_writer = BlobWriter::new_with_compressor(
        &temp_blob_data_path,
        args.chunk_size,
        args.compressor.into(),
    )?;
    let mut inodes = build_tree(&args.source, &mut blob_writer, args.chunk_size)?;
    blob_writer.finish()?;
    let epoch = inodes
        .iter()
        .map(|inode| inode.mtime)
        .min()
        .unwrap_or(build_time);

    let uuid_bytes = [0u8; 16];
    let blob_id = sha256_file(&temp_blob_data_path)?;
    let device_slots = [ErofsDeviceSlot::with_blob_id(
        blob_writer.total_blocks(),
        &blob_id,
    )];
    let bootstrap_bytes =
        render_bootstrap(&mut inodes, epoch, chunkbits, &device_slots, &uuid_bytes)?;
    let bootstrap_blocks = bootstrap_bytes.len().div_ceil(EROFS_BLOCK_SIZE as usize) as u64;

    if let Some(bootstrap) = &args.bootstrap {
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
    let blob_meta_path = blob_meta_output_path(
        requested_blob_path.as_deref(),
        args.blob_dir.as_deref(),
        &full_blob_id,
    );
    let blob_meta = blob_writer.blob_meta(blob_id, bootstrap_blocks * EROFS_BLOCK_SIZE as u64)?;
    blob_meta.save(&blob_meta_path)?;

    let _ = fs::remove_file(&temp_blob_data_path);

    print_blob_summary(
        0,
        &blob_id,
        &full_blob_id,
        &blob_meta,
        &final_blob_path,
        &blob_meta_path,
        args.bootstrap.as_deref(),
    );
    Ok(())
}

fn print_blob_summary(
    index: usize,
    data_blob_digest: &[u8; EROFS_BLOB_ID_SIZE],
    full_blob_digest: &[u8; EROFS_BLOB_ID_SIZE],
    blobmeta: &BlobMeta,
    full_blob_path: &Path,
    blobmeta_path: &Path,
    bootstrap_path: Option<&Path>,
) {
    println!("Blobs");
    println!("  Blob {}", index);
    println!("    blob_index: {}", index);
    println!("    data_blob_digest: {}", hex_string(data_blob_digest));
    println!("    full_blob_digest: {}", hex_string(full_blob_digest));
    println!("    chunk_size: {}", blobmeta.chunk_size());
    println!("    chunk_count: {}", blobmeta.chunk_count());
    println!("    chunk_digester: {}", blobmeta.digester());
    println!("    chunk_compressor: {}", blobmeta.compressor());
    println!(
        "    blob_compressed_size: {}",
        blobmeta.total_compressed_size()
    );
    println!(
        "    blob_uncompressed_size: {}",
        blobmeta.total_uncompressed_size()
    );
    println!("    full_blob_path: {}", full_blob_path.display());
    println!("    blob_meta_path: {}", blobmeta_path.display());
    if let Some(bootstrap_path) = bootstrap_path {
        println!("    bootstrap_path: {}", bootstrap_path.display());
    }
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

fn blob_meta_output_path(
    blob_path: Option<&Path>,
    blob_dir: Option<&Path>,
    full_blob_sha256: &[u8; EROFS_BLOB_ID_SIZE],
) -> PathBuf {
    if let Some(dir) = blob_dir {
        let file_name = format!("{}.blob.meta", hex_string(full_blob_sha256));
        return dir.join(file_name);
    }

    if let Some(blob_path) = blob_path {
        let mut path = blob_path.as_os_str().to_os_string();
        path.push(".blob.meta");
        return PathBuf::from(path);
    }

    Path::new(".").join(format!("{}.blob.meta", hex_string(full_blob_sha256)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_meta_output_path_uses_blob_dir_when_present() {
        let digest = [0x11u8; EROFS_BLOB_ID_SIZE];
        let path = blob_meta_output_path(
            Some(Path::new("/tmp/custom.blob")),
            Some(Path::new("/var/lib/lepton")),
            &digest,
        );

        assert_eq!(
            path,
            Path::new("/var/lib/lepton").join(format!("{}.blob.meta", hex_string(&digest)))
        );
    }

    #[test]
    fn blob_meta_output_path_appends_suffix_for_blob_path() {
        let digest = [0x22u8; EROFS_BLOB_ID_SIZE];
        let path = blob_meta_output_path(Some(Path::new("/tmp/custom.blob")), None, &digest);

        assert_eq!(path, Path::new("/tmp/custom.blob.blob.meta"));
    }

    #[test]
    fn default_chunk_size_is_one_megabyte() {
        assert_eq!(DEFAULT_CHUNK_SIZE, 1_048_576);
    }
}
