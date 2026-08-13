use crate::cli_common;
use clap::{Args, ValueEnum};
use nydus::error::{Context, Error, Result};
use nydus::unpack::unpack_to_tar;
use nydus_core::blob::{BlobFooter, BlobMeta, BlobMetaCompressor, BLOB_META_SUFFIX};
use nydus_core::build::{build_dir_image, DirImageOptions};
use nydus_core::fs::ErofsReader;
use nydus_core::metadata::EROFS_BLOB_ID_SIZE;
use nydus_core::telemetry::logging::{init_command_tracing, init_command_tracing_stderr};
use nydus_core::utils::{hex_string, MIB};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

const DEFAULT_CHUNK_SIZE: u32 = MIB;
const DEFAULT_COMPRESS_SIZE: u32 = 4 * MIB;

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ConversionType {
    DirNydus,
    NydusTar,
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
    /// Source to build from: a directory for `dir-nydus`, a nydus full blob
    /// for `nydus-tar`.
    pub source: PathBuf,

    /// Conversion type.
    #[arg(long = "type", value_enum, default_value_t = ConversionType::DirNydus)]
    pub conversion_type: ConversionType,

    /// File path to save the generated nydus full blob.
    #[arg(long, conflicts_with = "blob_dir")]
    pub blob: Option<PathBuf>,

    /// Directory path to save the generated nydus full blob with its SHA256 file name.
    #[arg(long, conflicts_with = "blob")]
    pub blob_dir: Option<PathBuf>,

    /// File path to save the generated nydus bootstrap.
    #[arg(long)]
    pub bootstrap: Option<PathBuf>,

    /// `nydus-tar` only: file path to save the generated tar stream, or `-`
    /// for stdout.
    #[arg(long, default_value = "-")]
    pub output: PathBuf,

    /// File chunk size in bytes (must be a power of two, >= 4KiB, and 4KiB-aligned).
    #[arg(long = "chunk-size", default_value_t = DEFAULT_CHUNK_SIZE)]
    pub chunk_size: u32,

    /// Group uncompressed size in bytes (must be a power of two, >= 1MiB,
    /// and >= the chunk size). Controls the uncompressed size of each blob
    /// meta group used for compression.
    #[arg(long = "compress-size", default_value_t = DEFAULT_COMPRESS_SIZE)]
    pub compress_size: u32,

    /// Algorithm to compress data chunks.
    #[arg(long, value_enum, default_value_t = Compressor::Zstd)]
    pub compressor: Compressor,

    #[command(flatten)]
    pub log: cli_common::CommandLogArgs,

    /// Absolute or current-working-directory-relative paths to exclude.
    /// May be specified multiple times. Entries inside the source tree are
    /// omitted from the blob and the resulting filesystem tree entirely.
    #[arg(long = "exclude")]
    pub exclude: Vec<String>,
}

/// Run the requested conversion.
pub fn run_build(args: BuildArgs) -> Result<()> {
    let tar_to_stdout =
        args.conversion_type == ConversionType::NydusTar && args.output == Path::new("-");
    // Logging to stdout would corrupt a tar stream written to stdout.
    let _guards = if tar_to_stdout {
        init_command_tracing_stderr(args.log.log_level, args.log.console)
    } else {
        init_command_tracing(args.log.log_level, args.log.console)
    };

    match args.conversion_type {
        ConversionType::DirNydus => run_dir_to_nydus(args),
        ConversionType::NydusTar => run_nydus_to_tar(args),
    }
}

/// Unpack a nydus full blob back into an uncompressed OCI layer tar stream.
fn run_nydus_to_tar(args: BuildArgs) -> Result<()> {
    for (name, set) in [
        ("--blob", args.blob.is_some()),
        ("--blob-dir", args.blob_dir.is_some()),
        ("--bootstrap", args.bootstrap.is_some()),
        ("--exclude", !args.exclude.is_empty()),
    ] {
        if set {
            return Err(Error::InvalidParameter(format!(
                "{name} is not supported with --type nydus-tar"
            )));
        }
    }
    if !args.source.is_file() {
        return Err(Error::InvalidParameter(format!(
            "source {} is not a nydus blob file",
            args.source.display()
        )));
    }

    let reader = ErofsReader::open(Some(&args.source), None, None, None)
        .with_context(|| format!("failed to open nydus blob: {}", args.source.display()))?;

    if args.output == Path::new("-") {
        let stdout = io::stdout();
        unpack_to_tar(&reader, BufWriter::new(stdout.lock()))?;
    } else {
        let file = File::create(&args.output)
            .with_context(|| format!("failed to create output: {}", args.output.display()))?;
        unpack_to_tar(&reader, BufWriter::new(file))?;
    }
    Ok(())
}

/// Create an nydus image from the source directory.
fn run_dir_to_nydus(args: BuildArgs) -> Result<()> {
    let requested_blob_path = args.blob.clone();
    if let (Some(bootstrap), Some(blob)) = (&args.bootstrap, requested_blob_path.as_ref()) {
        if *bootstrap == *blob {
            return Err(Error::InvalidParameter(
                "--bootstrap and --blob must point to different files".to_string(),
            ));
        }
    }

    // Validate source is a directory and canonicalize it so that all paths
    // produced by the recursive directory walk are absolute and match
    // correctly against the exclude set.
    if !args.source.is_dir() {
        return Err(Error::InvalidParameter(format!(
            "source {} is not a directory",
            args.source.display()
        )));
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

    let options = DirImageOptions {
        source: &source,
        chunk_size: args.chunk_size,
        compress_size: args.compress_size,
        compressor: args.compressor.into(),
        exclude: &exclude,
        standalone_bootstrap: args.bootstrap.is_some(),
    };
    // Fail on invalid chunk/compress geometry before creating output files.
    options.validate()?;

    let blob_output =
        prepare_blob_output(requested_blob_path.as_deref(), args.blob_dir.as_deref())?;
    let blob_file = open_blob_output(&blob_output)?;
    let image = build_dir_image(&options, blob_file).with_context(|| {
        format!(
            "failed to build nydus blob: {}",
            blob_output.write_path.display()
        )
    })?;

    let final_blob_path = finalize_blob_output(&blob_output, &image.full_blob_id)?;
    let blob_meta_path = blob_meta_output_path(&final_blob_path)?;
    image
        .blob_meta
        .save(&blob_meta_path)
        .with_context(|| format!("failed to save blob meta: {}", blob_meta_path.display()))?;

    if let (Some(bootstrap), Some(bytes)) = (&args.bootstrap, &image.standalone_bootstrap) {
        fs::write(bootstrap, bytes)
            .with_context(|| format!("failed to write bootstrap: {}", bootstrap.display()))?;
    }

    print_blob_summary(BlobSummary {
        index: 0,
        data_blob_digest: &image.data_digest,
        full_blob_digest: &image.full_blob_id,
        blob_meta: &image.blob_meta,
        footer: &image.footer,
        full_blob_path: &final_blob_path,
        blob_meta_path: &blob_meta_path,
        bootstrap_path: args.bootstrap.as_deref(),
    });
    Ok(())
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
    let file_name = blob_path.file_name().ok_or_else(|| {
        Error::InvalidParameter(format!(
            "blob path has no file name: {}",
            blob_path.display()
        ))
    })?;
    Ok(blob_path.with_file_name(format!("{}{BLOB_META_SUFFIX}", file_name.to_string_lossy())))
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
        _ => Err(Error::InvalidParameter(
            "build expects either --blob <path> or --blob-dir <dir>".to_string(),
        )),
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
    use nydus_core::metadata::{
        cast_ref, ErofsDeviceSlot, EROFS_BLOCK_SIZE, EROFS_DEVICESLOT_SIZE, EROFS_SB_BASE_SIZE,
        EROFS_SUPER_OFFSET,
    };
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use tempfile::tempdir;

    #[test]
    fn default_chunk_size_is_one_megabyte() {
        assert_eq!(DEFAULT_CHUNK_SIZE, 1_048_576);
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
            output: PathBuf::from("-"),
            chunk_size: DEFAULT_CHUNK_SIZE,
            compress_size: DEFAULT_COMPRESS_SIZE,
            compressor: Compressor::Zstd,
            log: crate::cli_common::CommandLogArgs {
                log_level: tracing::Level::ERROR,
                console: false,
            },
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

    #[test]
    fn nydus_tar_round_trips_the_source_tree() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let blob = dir.path().join("layer.blob");
        let tar_path = dir.path().join("layer.tar");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        fs::write(source.join("nested/hello.txt"), b"hello nydus").unwrap();
        fs::write(source.join("empty.txt"), b"").unwrap();
        // Spans several 4KiB chunks so the chunk-based read path is exercised.
        let big = vec![b'x'; 10 * 1024];
        fs::write(source.join("big.bin"), &big).unwrap();
        fs::write(source.join("linked.txt"), b"link me").unwrap();
        fs::hard_link(source.join("linked.txt"), source.join("alias.txt")).unwrap();
        std::os::unix::fs::symlink("nested/hello.txt", source.join("link")).unwrap();
        // Whiteout markers are ordinary files on both sides of the conversion.
        fs::write(source.join(".wh.deleted"), b"").unwrap();
        let xattr_set = xattr::set(source.join("nested/hello.txt"), "user.demo", b"v1").is_ok();

        build_and_unpack(&source, &blob, &tar_path);

        let mut entries = BTreeMap::new();
        let mut archive = tar::Archive::new(File::open(&tar_path).unwrap());
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let header = entry.header().clone();
            let link = header
                .link_name()
                .unwrap()
                .map(|p| p.to_string_lossy().into_owned());
            let xattrs: Vec<_> = entry
                .pax_extensions()
                .unwrap()
                .into_iter()
                .flatten()
                .map(|ext| {
                    let ext = ext.unwrap();
                    (ext.key().unwrap().to_string(), ext.value_bytes().to_vec())
                })
                .collect();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();
            entries.insert(path, (header.entry_type(), link, data, xattrs));
        }

        let names: Vec<_> = entries.keys().cloned().collect();
        assert_eq!(
            names,
            vec![
                ".wh.deleted",
                "alias.txt",
                "big.bin",
                "empty.txt",
                "link",
                "linked.txt",
                "nested/",
                "nested/hello.txt",
            ]
        );

        assert_eq!(entries["nested/hello.txt"].2, b"hello nydus");
        assert_eq!(entries["big.bin"].2, big);
        assert!(entries["empty.txt"].2.is_empty());
        assert_eq!(entries["nested/"].0, tar::EntryType::Directory);
        assert_eq!(entries["link"].0, tar::EntryType::Symlink);
        assert_eq!(entries["link"].1.as_deref(), Some("nested/hello.txt"));

        // The first path wins; the second becomes a hardlink pointing at it.
        assert_eq!(entries["alias.txt"].0, tar::EntryType::Regular);
        assert_eq!(entries["linked.txt"].0, tar::EntryType::Link);
        assert_eq!(entries["linked.txt"].1.as_deref(), Some("alias.txt"));

        if xattr_set {
            assert_eq!(
                entries["nested/hello.txt"].3,
                vec![("SCHILY.xattr.user.demo".to_string(), b"v1".to_vec())]
            );
        }
    }

    #[test]
    fn nydus_tar_drops_internal_nydus_xattrs() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let blob = dir.path().join("layer.blob");
        let tar_path = dir.path().join("layer.tar");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("sub")).unwrap();

        build_and_unpack(&source, &blob, &tar_path);

        let mut archive = tar::Archive::new(File::open(&tar_path).unwrap());
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let keys: Vec<String> = entry
                .pax_extensions()
                .unwrap()
                .into_iter()
                .flatten()
                .map(|ext| ext.unwrap().key().unwrap().to_string())
                .collect();
            assert!(
                !keys.iter().any(|key| key.contains("nydus")),
                "leaked internal xattr: {keys:?}"
            );
        }
    }

    #[test]
    fn nydus_tar_rejects_blob_output_flags() {
        let dir = tempdir().unwrap();
        let blob = dir.path().join("layer.blob");
        fs::write(&blob, b"").unwrap();

        let err = run_nydus_to_tar(BuildArgs {
            source: blob.clone(),
            conversion_type: ConversionType::NydusTar,
            blob: Some(blob),
            blob_dir: None,
            bootstrap: None,
            output: dir.path().join("out.tar"),
            chunk_size: DEFAULT_CHUNK_SIZE,
            compress_size: DEFAULT_COMPRESS_SIZE,
            compressor: Compressor::Zstd,
            log: crate::cli_common::CommandLogArgs {
                log_level: tracing::Level::ERROR,
                console: false,
            },
            exclude: Vec::new(),
        })
        .unwrap_err();

        assert!(err.to_string().contains("--blob is not supported"));
    }

    fn build_and_unpack(source: &Path, blob: &Path, tar_path: &Path) {
        run_dir_to_nydus(BuildArgs {
            source: source.to_path_buf(),
            conversion_type: ConversionType::DirNydus,
            blob: Some(blob.to_path_buf()),
            blob_dir: None,
            bootstrap: None,
            output: PathBuf::from("-"),
            chunk_size: EROFS_BLOCK_SIZE,
            compress_size: MIB,
            compressor: Compressor::Zstd,
            log: crate::cli_common::CommandLogArgs {
                log_level: tracing::Level::ERROR,
                console: false,
            },
            exclude: Vec::new(),
        })
        .unwrap();

        run_nydus_to_tar(BuildArgs {
            source: blob.to_path_buf(),
            conversion_type: ConversionType::NydusTar,
            blob: None,
            blob_dir: None,
            bootstrap: None,
            output: tar_path.to_path_buf(),
            chunk_size: DEFAULT_CHUNK_SIZE,
            compress_size: DEFAULT_COMPRESS_SIZE,
            compressor: Compressor::Zstd,
            log: crate::cli_common::CommandLogArgs {
                log_level: tracing::Level::ERROR,
                console: false,
            },
            exclude: Vec::new(),
        })
        .unwrap();
    }

    fn make_fifo(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let ret = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(ret, 0, "mkfifo failed: {}", io::Error::last_os_error());
    }
}
