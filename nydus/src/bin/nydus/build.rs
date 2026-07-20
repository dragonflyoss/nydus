use anyhow::{bail, Context, Result};
use clap::{Args, ValueEnum};
use nydus::build::blob_chunk::BlobWriter;
use nydus::build::bootstrap::{render_bootstrap, render_flattened_bootstrap};
use nydus::build::inode::{build_tree, set_root_prefetch_blobs_xattr};
use nydus::metadata::*;
use nydus::tracing::init_command_tracing;
use nydus::utils::hex_string;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::Level;

const MIB: u32 = 1_048_576;
const DEFAULT_CHUNK_SIZE: u32 = MIB;
const DEFAULT_COMPRESS_SIZE: u32 = 4 * MIB;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ConversionType {
    DirNydus,
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
    #[arg(long = "type", value_enum, default_value_t = ConversionType::DirNydus)]
    pub conversion_type: ConversionType,

    /// File path to save the generated nydus full blob.
    #[arg(
        long,
        conflicts_with = "blob_dir",
        required_unless_present = "blob_dir"
    )]
    pub blob: Option<PathBuf>,

    /// Directory path to save the generated nydus full blob with its SHA256 file name.
    #[arg(long, conflicts_with = "blob", required_unless_present = "blob")]
    pub blob_dir: Option<PathBuf>,

    /// File path to save the generated nydus bootstrap.
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,

    /// File chunk size in bytes (must be a power of two, >= 4KiB, and 4KiB-aligned).
    #[arg(long = "chunk-size", default_value_t = DEFAULT_CHUNK_SIZE)]
    pub chunk_size: u32,

    /// Group uncompressed size in bytes (must be a power of two, >= 1MiB, and
    /// >= the chunk size). Controls the uncompressed size of each blob meta
    /// group used for compression.
    #[arg(long = "compress-size", default_value_t = DEFAULT_COMPRESS_SIZE)]
    pub compress_size: u32,

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

    /// Absolute or current-working-directory-relative paths to exclude.
    /// May be specified multiple times. Entries inside the source tree are
    /// omitted from the blob and the resulting filesystem tree entirely.
    #[arg(long = "exclude")]
    pub exclude: Vec<String>,
}

/// Run the build process to create an nydus image from the source directory.
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

    // Validate compress (group uncompressed) size: a power of two (the blob
    // meta header stores it as the log2 exponent `group_block_bits`), at
    // least 1MiB, and at least the file chunk size so a chunk always fits in
    // a group.
    if !args.compress_size.is_power_of_two() || args.compress_size < MIB {
        bail!(
            "compress size {} must be a power of two and at least 1MiB",
            args.compress_size
        );
    }
    if args.compress_size < args.chunk_size {
        bail!(
            "compress size {} must be >= chunk size {}",
            args.compress_size,
            args.chunk_size
        );
    }

    // Validate source is a directory and canonicalize it so that all paths
    // produced by the recursive directory walk are absolute and match
    // correctly against the exclude set.
    if !args.source.is_dir() {
        bail!("source {} is not a directory", args.source.display());
    }
    let source = args.source.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize source directory: {}",
            args.source.display()
        )
    })?;

    // Build the exclude set from --exclude flags. Each value is interpreted as
    // either an absolute path or a path relative to the current working
    // directory, canonicalized, then checked against the canonicalized source.
    // Non-existent paths are ignored.
    let mut exclude: HashSet<PathBuf> = HashSet::new();
    for raw in &args.exclude {
        let abs = match Path::new(raw).canonicalize() {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("--exclude {}: canonicalize failed ({})", raw, e);
                continue;
            }
        };
        // Only exclude if the path is inside the source tree.
        if abs.starts_with(&source) {
            exclude.insert(abs);
        }
    }

    let build_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_secs();

    let blob_output =
        prepare_blob_output(requested_blob_path.as_deref(), args.blob_dir.as_deref())?;
    let blob_file = open_blob_output(&blob_output)?;

    let mut blob_writer = BlobWriter::from_file(
        blob_file,
        args.chunk_size,
        args.compress_size,
        args.compressor.into(),
    )?;
    let mut inodes = build_tree(&source, &mut blob_writer, args.chunk_size, &exclude)?;
    blob_writer.finish()?;
    let epoch = inodes
        .iter()
        .map(|inode| inode.mtime)
        .min()
        .unwrap_or(build_time);

    let uuid_bytes = [0u8; 16];
    let blob_blocks = blob_writer.total_blocks();
    let blob_id = blob_writer.data_digest();
    let device_slots = [ErofsDeviceSlot::with_blob_id(blob_blocks, &blob_id)];
    set_root_prefetch_blobs_xattr(&mut inodes[0], &[1])?;
    let bootstrap_bytes =
        render_bootstrap(&mut inodes, epoch, chunkbits, &device_slots, &uuid_bytes)?;

    let compressed_data_size = blob_writer.data_size();
    let blob_meta = blob_writer.blob_meta(blob_id, 0)?;
    let blob_meta_size = blob_meta.metadata_size();
    let mut blob_meta_bytes = Vec::with_capacity(
        usize::try_from(blob_meta_size).context("blob meta size exceeds usize")?,
    );
    blob_meta
        .write_to(&mut blob_meta_bytes)
        .context("failed to serialize blob meta")?;
    if blob_meta_bytes.len() as u64 != blob_meta_size {
        bail!(
            "serialized blob meta size mismatch: expected {}, got {}",
            blob_meta_size,
            blob_meta_bytes.len()
        );
    }
    let (blob_file, full_blob_hasher) = blob_writer.into_file_and_data_hasher();
    let mut blob_writer_stream = HashingWriter::new(BufWriter::new(blob_file), full_blob_hasher);

    let compressed_data_offset = 0u64;
    let bootstrap_offset = align_u64(
        compressed_data_offset + compressed_data_size,
        NYDUS_BLOB_FOOTER_ALIGNMENT,
    );
    write_zero_padding(
        &mut blob_writer_stream,
        compressed_data_offset + compressed_data_size,
        bootstrap_offset,
    )?;
    blob_writer_stream
        .write_all(&bootstrap_bytes)
        .with_context(|| {
            format!(
                "failed to write blob bootstrap: {}",
                blob_output.write_path.display()
            )
        })?;

    let bootstrap_size = u64::try_from(bootstrap_bytes.len()).context("bootstrap exceeds u64")?;
    let bootstrap_blocks = bytes_to_blocks(bootstrap_size, "bootstrap")?;
    let blob_meta_blocks = bytes_to_blocks(blob_meta_size, "blob meta")?;
    let blob_meta_offset = align_u64(
        bootstrap_offset + bootstrap_size,
        NYDUS_BLOB_FOOTER_ALIGNMENT,
    );
    write_zero_padding(
        &mut blob_writer_stream,
        bootstrap_offset + bootstrap_size,
        blob_meta_offset,
    )?;
    blob_writer_stream
        .write_all(&blob_meta_bytes)
        .with_context(|| {
            format!(
                "failed to write blob meta: {}",
                blob_output.write_path.display()
            )
        })?;

    let footer = BlobFooter::new(
        compressed_data_offset,
        compressed_data_size,
        bootstrap_offset,
        bootstrap_blocks,
        blob_meta_offset,
        blob_meta_blocks,
    )?;
    footer.write_to(&mut blob_writer_stream).with_context(|| {
        format!(
            "failed to write blob footer: {}",
            blob_output.write_path.display()
        )
    })?;
    let full_blob_id = blob_writer_stream
        .finish()
        .with_context(|| format!("failed to flush blob: {}", blob_output.write_path.display()))?;
    let final_blob_path = finalize_blob_output(&blob_output, &full_blob_id)?;
    let blob_meta_path = blob_meta_output_path(&final_blob_path)?;
    blob_meta
        .save(&blob_meta_path)
        .with_context(|| format!("failed to save blob meta: {}", blob_meta_path.display()))?;

    if let Some(bootstrap) = &args.bootstrap {
        let standalone_device_slots = [ErofsDeviceSlot::with_blob_id(blob_blocks, &full_blob_id)];
        let standalone_bootstrap_bytes = render_flattened_bootstrap(
            &mut inodes,
            epoch,
            chunkbits,
            &standalone_device_slots,
            &uuid_bytes,
        )?;
        let bootstrap_file = File::create(bootstrap)
            .with_context(|| format!("failed to create bootstrap: {}", bootstrap.display()))?;
        let mut writer = BufWriter::new(bootstrap_file);
        writer
            .write_all(&standalone_bootstrap_bytes)
            .with_context(|| format!("failed to write bootstrap: {}", bootstrap.display()))?;
        writer
            .flush()
            .with_context(|| format!("failed to flush bootstrap: {}", bootstrap.display()))?;
    }

    print_blob_summary(BlobSummary {
        index: 0,
        data_blob_digest: &blob_id,
        full_blob_digest: &full_blob_id,
        blob_meta: &blob_meta,
        footer: &footer,
        full_blob_path: &final_blob_path,
        blob_meta_path: &blob_meta_path,
        bootstrap_path: args.bootstrap.as_deref(),
    });
    Ok(())
}

fn align_u64(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (value + align - 1) & !(align - 1)
}

fn bytes_to_blocks(size: u64, name: &str) -> Result<u32> {
    if size % EROFS_BLOCK_SIZE as u64 != 0 {
        bail!("{name} size is not block aligned: {size}");
    }
    u32::try_from(size / EROFS_BLOCK_SIZE as u64)
        .with_context(|| format!("{name} exceeds u32 block count"))
}

fn write_zero_padding(writer: &mut dyn Write, current: u64, aligned: u64) -> Result<()> {
    if aligned < current {
        bail!("invalid blob region alignment");
    }
    let padding = (aligned - current) as usize;
    if padding > 0 {
        writer.write_all(&vec![0u8; padding])?;
    }
    Ok(())
}

struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W, hasher: Sha256) -> Self {
        Self { inner, hasher }
    }

    fn finish(mut self) -> io::Result<[u8; EROFS_BLOB_ID_SIZE]> {
        self.inner.flush()?;
        let mut digest = [0u8; EROFS_BLOB_ID_SIZE];
        digest.copy_from_slice(&self.hasher.finalize());
        Ok(digest)
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct BlobSummary<'a> {
    index: usize,
    data_blob_digest: &'a [u8; EROFS_BLOB_ID_SIZE],
    full_blob_digest: &'a [u8; EROFS_BLOB_ID_SIZE],
    blob_meta: &'a BlobMeta,
    footer: &'a BlobFooter,
    full_blob_path: &'a Path,
    blob_meta_path: &'a Path,
    bootstrap_path: Option<&'a Path>,
}

fn print_blob_summary(summary: BlobSummary<'_>) {
    let BlobSummary {
        index,
        data_blob_digest,
        full_blob_digest,
        blob_meta,
        footer,
        full_blob_path,
        blob_meta_path,
        bootstrap_path,
    } = summary;

    println!("Blobs");
    println!("  Blob {index}");
    println!("    blob_index: {index}");
    println!("    data_blob_digest: {}", hex_string(data_blob_digest));
    println!("    full_blob_digest: {}", hex_string(full_blob_digest));
    println!("    chunk_size: {}", blob_meta.chunk_size());
    println!("    chunk_count: {}", blob_meta.chunk_count());
    println!("    group_count: {}", blob_meta.group_count());
    println!("    chunk_digester: {}", blob_meta.digester());
    println!("    chunk_compressor: {}", blob_meta.compressor());
    println!(
        "    blob_compressed_size: {}",
        blob_meta.total_compressed_size()
    );
    println!(
        "    blob_uncompressed_size: {}",
        blob_meta.total_uncompressed_size()
    );
    println!(
        "    compressed_data_offset: {}",
        footer.compressed_data_offset()
    );
    println!(
        "    compressed_data_size: {}",
        footer.compressed_data_size()
    );
    println!("    bootstrap_offset: {}", footer.bootstrap_offset());
    println!("    bootstrap_blocks: {}", footer.bootstrap_blocks());
    println!("    blob_meta_offset: {}", footer.blob_meta_offset());
    println!("    blob_meta_blocks: {}", footer.blob_meta_blocks());
    println!("    full_blob_path: {}", full_blob_path.display());
    println!("    blob_meta_path: {}", blob_meta_path.display());
    if let Some(bootstrap_path) = bootstrap_path {
        println!("    bootstrap_path: {}", bootstrap_path.display());
    }
}

fn blob_meta_output_path(blob_path: &Path) -> Result<PathBuf> {
    let file_name = blob_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("blob path has no file name: {}", blob_path.display()))?;
    Ok(blob_path.with_file_name(format!("{}.blob.meta", file_name.to_string_lossy())))
}

struct BlobOutput {
    write_path: PathBuf,
    blob_dir: Option<PathBuf>,
    is_fifo: bool,
}

fn prepare_blob_output(blob: Option<&Path>, blob_dir: Option<&Path>) -> Result<BlobOutput> {
    match (blob, blob_dir) {
        (Some(blob), None) => Ok(BlobOutput {
            write_path: blob.to_path_buf(),
            blob_dir: None,
            is_fifo: blob_is_fifo(blob)?,
        }),
        (None, Some(dir)) => {
            fs::create_dir_all(dir)
                .with_context(|| format!("failed to create blob-dir: {}", dir.display()))?;
            let temp_path = dir.join(format!(".nydus-build-{}.tmp", uuid::Uuid::new_v4()));
            Ok(BlobOutput {
                write_path: temp_path,
                blob_dir: Some(dir.to_path_buf()),
                is_fifo: false,
            })
        }
        _ => bail!("build expects either --blob <path> or --blob-dir <dir>"),
    }
}

fn blob_is_fifo(path: &Path) -> Result<bool> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_fifo()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("failed to stat blob: {}", path.display())),
    }
}

fn open_blob_output(output: &BlobOutput) -> Result<File> {
    if output.is_fifo {
        OpenOptions::new()
            .write(true)
            .open(&output.write_path)
            .with_context(|| format!("failed to open blob fifo: {}", output.write_path.display()))
    } else {
        File::create(&output.write_path)
            .with_context(|| format!("failed to create blob: {}", output.write_path.display()))
    }
}

fn finalize_blob_output(
    output: &BlobOutput,
    blob_sha256: &[u8; EROFS_BLOB_ID_SIZE],
) -> Result<PathBuf> {
    if output.blob_dir.is_none() {
        return Ok(output.write_path.clone());
    }

    let dir = output.blob_dir.as_ref().expect("blob_dir is checked above");
    let final_path = dir.join(hex_string(blob_sha256));
    if final_path.exists() {
        fs::remove_file(&output.write_path).with_context(|| {
            format!(
                "failed to remove temporary blob after dedup hit: {}",
                output.write_path.display()
            )
        })?;
        return Ok(final_path);
    }

    fs::rename(&output.write_path, &final_path).with_context(|| {
        format!(
            "failed to rename blob {} -> {}",
            output.write_path.display(),
            final_path.display()
        )
    })?;
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use tempfile::tempdir;

    #[test]
    fn default_chunk_size_is_one_megabyte() {
        assert_eq!(DEFAULT_CHUNK_SIZE, 1_048_576);
    }

    #[test]
    fn align_u64_rounds_up_to_alignment() {
        assert_eq!(align_u64(0, 8), 0);
        assert_eq!(align_u64(1, 8), 8);
        assert_eq!(align_u64(16, 8), 16);
    }

    #[test]
    fn prepare_blob_output_detects_fifo_blob_path() {
        let dir = tempdir().unwrap();
        let fifo = dir.path().join("stream.blob");
        make_fifo(&fifo);

        let output = prepare_blob_output(Some(&fifo), None).unwrap();

        assert_eq!(output.write_path, fifo);
        assert!(output.blob_dir.is_none());
        assert!(output.is_fifo);
    }

    #[test]
    fn build_bootstrap_device_slot_uses_full_blob_digest() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let blob_dir = dir.path().join("blobs");
        let bootstrap = dir.path().join("nydus-bootstrap.boot");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&blob_dir).unwrap();
        fs::write(source.join("hello.txt"), b"hello nydus").unwrap();

        run_build(BuildArgs {
            source,
            conversion_type: ConversionType::DirNydus,
            blob: None,
            blob_dir: Some(blob_dir.clone()),
            bootstrap: Some(bootstrap.clone()),
            chunk_size: DEFAULT_CHUNK_SIZE,
            compress_size: DEFAULT_COMPRESS_SIZE,
            compressor: Compressor::Zstd,
            log_level: Level::ERROR,
            console: false,
            exclude: Vec::new(),
        })
        .unwrap();

        let full_blob_digest = fs::read_dir(&blob_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .find(|name| name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .unwrap();
        let bootstrap_bytes = fs::read(&bootstrap).unwrap();
        let slot_offset = EROFS_SUPER_OFFSET as usize + EROFS_SB_BASE_SIZE;
        let slot = cast_ref::<ErofsDeviceSlot>(
            &bootstrap_bytes[slot_offset..slot_offset + EROFS_DEVICESLOT_SIZE],
        );

        assert_eq!(hex_string(&slot.blob_id().unwrap()), full_blob_digest);
    }

    fn make_fifo(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let ret = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(ret, 0, "mkfifo failed: {}", io::Error::last_os_error());
    }
}
