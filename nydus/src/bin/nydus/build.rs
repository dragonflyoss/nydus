use bytesize::ByteSize;
use clap::{Parser, ValueEnum};
use nydus::build::{build_dir_image, DirImageOptions};
use nydus::error::{Context, Error, Result};
use nydus::unpack::unpack_to_tar;
use nydus_core::ErofsReader;
use nydus_format::blob::{BlobFooter, BlobMetadata, BlobMetadataCompressor, BLOB_METADATA_SUFFIX};
use nydus_format::erofs::EROFS_BLOB_ID_SIZE;
use nydus_format::utils::hex_string;
use nydus_telemetry::logging::{init_command_tracing, init_command_tracing_stderr};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter};
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use tabled::{settings::Style, Table, Tabled};
use tracing::Level;

/// The conversion type of the build sub command.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ConversionType {
    DirNydus,
    NydusTar,
}

/// The algorithm to compress data chunks.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Compressor {
    None,
    Zstd,
}

/// Implement the conversion from Compressor to BlobMetadataCompressor.
impl From<Compressor> for BlobMetadataCompressor {
    fn from(value: Compressor) -> Self {
        match value {
            Compressor::None => Self::None,
            Compressor::Zstd => Self::Zstd,
        }
    }
}

/// The subcommand of build.
#[derive(Debug, Clone, Parser)]
pub struct BuildCommand {
    #[arg(
        help = "Specify the source to build from: a directory for `dir-nydus`, a nydus full blob for `nydus-tar`"
    )]
    source: PathBuf,

    #[arg(
        long = "type",
        value_enum,
        default_value_t = ConversionType::DirNydus,
        env = "NYDUS_BUILD_TYPE",
        help = "Specify the conversion type"
    )]
    conversion_type: ConversionType,

    #[arg(
        long,
        conflicts_with = "blob_dir",
        env = "NYDUS_BUILD_BLOB",
        help = "Specify the file path to save the generated nydus full blob"
    )]
    blob: Option<PathBuf>,

    #[arg(
        long,
        conflicts_with = "blob",
        env = "NYDUS_BUILD_BLOB_DIR",
        help = "Specify the directory path to save the generated nydus full blob with its SHA256 file name"
    )]
    blob_dir: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_BUILD_BOOTSTRAP",
        help = "Specify the file path to save the generated nydus bootstrap"
    )]
    bootstrap: Option<PathBuf>,

    #[arg(
        long,
        default_value = "-",
        env = "NYDUS_BUILD_OUTPUT",
        help = "Specify the file path to save the generated tar stream for `--type nydus-tar`, or `-` for stdout"
    )]
    output: PathBuf,

    #[arg(
        long = "chunk-size",
        default_value = "1MiB",
        env = "NYDUS_BUILD_CHUNK_SIZE",
        help = "Specify the file chunk size (must be a power of two, >= 4KiB, and 4KiB-aligned). The value needs to be set with human readable format, for example: 4kib, 1mib"
    )]
    chunk_size: ByteSize,

    #[arg(
        long = "compress-size",
        default_value = "4MiB",
        env = "NYDUS_BUILD_COMPRESS_SIZE",
        help = "Specify the group uncompressed size (must be a power of two, >= 1MiB, and >= the chunk size). Controls the uncompressed size of each blob meta group used for compression. The value needs to be set with human readable format, for example: 4mib, 16mib"
    )]
    compress_size: ByteSize,

    #[arg(
        long,
        value_enum,
        default_value_t = Compressor::Zstd,
        env = "NYDUS_BUILD_COMPRESSOR",
        help = "Specify the algorithm to compress data chunks"
    )]
    compressor: Compressor,

    #[arg(
        long = "exclude",
        help = "Specify the absolute or current-working-directory-relative paths to exclude. May be specified multiple times. Entries inside the source tree are omitted from the blob and the resulting filesystem tree entirely"
    )]
    exclude: Vec<String>,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        env = "NYDUS_BUILD_LOG_LEVEL",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    log_level: Level,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        env = "NYDUS_BUILD_CONSOLE",
        help = "Specify whether to print log"
    )]
    console: bool,
}

/// Implement the execute for BuildCommand.
impl BuildCommand {
    /// Executes the build sub command, running the requested conversion.
    pub fn execute(&self) -> Result<()> {
        let tar_to_stdout =
            self.conversion_type == ConversionType::NydusTar && self.output == Path::new("-");
        // Logging to stdout would corrupt a tar stream written to stdout.
        let _guards = if tar_to_stdout {
            init_command_tracing_stderr(self.log_level, self.console)
        } else {
            init_command_tracing(self.log_level, self.console)
        };

        match self.conversion_type {
            ConversionType::DirNydus => self.run_dir_to_nydus(),
            ConversionType::NydusTar => self.run_nydus_to_tar(),
        }
    }

    /// Unpack a nydus full blob back into an uncompressed OCI layer tar stream.
    fn run_nydus_to_tar(&self) -> Result<()> {
        for (name, set) in [
            ("--blob", self.blob.is_some()),
            ("--blob-dir", self.blob_dir.is_some()),
            ("--bootstrap", self.bootstrap.is_some()),
            ("--exclude", !self.exclude.is_empty()),
        ] {
            if set {
                return Err(Error::InvalidParameter(format!(
                    "{name} is not supported with --type nydus-tar"
                )));
            }
        }
        if !self.source.is_file() {
            return Err(Error::InvalidParameter(format!(
                "source {} is not a nydus blob file",
                self.source.display()
            )));
        }

        let reader = ErofsReader::open_blob(&self.source)
            .with_context(|| format!("failed to open nydus blob: {}", self.source.display()))?;

        if self.output == Path::new("-") {
            let stdout = io::stdout();
            unpack_to_tar(&reader, BufWriter::new(stdout.lock()))?;
        } else {
            let file = File::create(&self.output)
                .with_context(|| format!("failed to create output: {}", self.output.display()))?;
            unpack_to_tar(&reader, BufWriter::new(file))?;
        }
        Ok(())
    }

    /// Create an nydus image from the source directory.
    fn run_dir_to_nydus(&self) -> Result<()> {
        let requested_blob_path = self.blob.clone();
        if let (Some(bootstrap), Some(blob)) = (&self.bootstrap, requested_blob_path.as_ref()) {
            if *bootstrap == *blob {
                return Err(Error::InvalidParameter(
                    "--bootstrap and --blob must point to different files".to_string(),
                ));
            }
        }

        // Validate source is a directory and canonicalize it so that all paths
        // produced by the recursive directory walk are absolute and match
        // correctly against the exclude set.
        if !self.source.is_dir() {
            return Err(Error::InvalidParameter(format!(
                "source {} is not a directory",
                self.source.display()
            )));
        }
        let source = self.source.canonicalize().with_context(|| {
            format!(
                "failed to canonicalize source directory: {}",
                self.source.display()
            )
        })?;

        // Build the exclude set from --exclude flags. Each value is interpreted as
        // either an absolute path or a path relative to the current working
        // directory, canonicalized, then checked against the canonicalized source.
        // Non-existent paths are ignored.
        let mut exclude: HashSet<PathBuf> = HashSet::new();
        for raw in &self.exclude {
            let abs = match Path::new(raw).canonicalize() {
                Ok(p) => p,
                Err(err) => {
                    tracing::warn!("--exclude {}: canonicalize failed ({})", raw, err);
                    continue;
                }
            };
            // Only exclude if the path is inside the source tree.
            if abs.starts_with(&source) {
                exclude.insert(abs);
            }
        }

        let chunk_size = u32::try_from(self.chunk_size.as_u64()).map_err(|_| {
            Error::InvalidParameter(format!("chunk size {} is too large", self.chunk_size))
        })?;
        let compress_size = u32::try_from(self.compress_size.as_u64()).map_err(|_| {
            Error::InvalidParameter(format!("compress size {} is too large", self.compress_size))
        })?;

        let options = DirImageOptions {
            source: &source,
            chunk_size,
            compress_size,
            compressor: self.compressor.into(),
            exclude: &exclude,
            standalone_bootstrap: self.bootstrap.is_some(),
        };
        // Fail on invalid chunk/compress geometry before creating output files.
        options.validate()?;

        let blob_output =
            prepare_blob_output(requested_blob_path.as_deref(), self.blob_dir.as_deref())?;
        let blob_file = open_blob_output(&blob_output)?;
        let image = build_dir_image(&options, blob_file).with_context(|| {
            format!(
                "failed to build nydus blob: {}",
                blob_output.write_path.display()
            )
        })?;

        let final_blob_path = finalize_blob_output(&blob_output, &image.full_blob_digest)?;
        let blob_metadata_path = blob_metadata_output_path(&final_blob_path)?;
        image
            .blob_metadata
            .save(&blob_metadata_path)
            .with_context(|| {
                format!("failed to save blob meta: {}", blob_metadata_path.display())
            })?;

        if let (Some(bootstrap), Some(bytes)) = (&self.bootstrap, &image.standalone_bootstrap) {
            fs::write(bootstrap, bytes)
                .with_context(|| format!("failed to write bootstrap: {}", bootstrap.display()))?;
        }

        print_blob_summary(BlobBuildReport {
            index: 0,
            data_blob_digest: &image.data_digest,
            full_blob_digest: &image.full_blob_digest,
            blob_metadata: &image.blob_metadata,
            footer: &image.footer,
            full_blob_path: &final_blob_path,
            blob_metadata_path: &blob_metadata_path,
            bootstrap_path: self.bootstrap.as_deref(),
        });
        Ok(())
    }
}

struct BlobBuildReport<'a> {
    index: usize,
    data_blob_digest: &'a [u8; EROFS_BLOB_ID_SIZE],
    full_blob_digest: &'a [u8; EROFS_BLOB_ID_SIZE],
    blob_metadata: &'a BlobMetadata,
    footer: &'a BlobFooter,
    full_blob_path: &'a Path,
    blob_metadata_path: &'a Path,
    bootstrap_path: Option<&'a Path>,
}

fn print_blob_summary(summary: BlobBuildReport<'_>) {
    // Define the table struct for printing.
    #[derive(Debug, Tabled)]
    #[tabled(rename_all = "UPPERCASE")]
    struct BlobRow {
        #[tabled(rename = "BLOB INDEX")]
        blob_index: String,
        #[tabled(rename = "DATA BLOB DIGEST")]
        data_blob_digest: String,
        #[tabled(rename = "FULL BLOB DIGEST")]
        full_blob_digest: String,
        #[tabled(rename = "CHUNK SIZE")]
        chunk_size: String,
        #[tabled(rename = "CHUNK COUNT")]
        chunk_count: String,
        #[tabled(rename = "GROUP COUNT")]
        group_count: String,
        #[tabled(rename = "CHUNK DIGESTER")]
        chunk_digester: String,
        #[tabled(rename = "CHUNK COMPRESSOR")]
        chunk_compressor: String,
        #[tabled(rename = "BLOB COMPRESSED SIZE")]
        blob_compressed_size: String,
        #[tabled(rename = "BLOB UNCOMPRESSED SIZE")]
        blob_uncompressed_size: String,
        #[tabled(rename = "COMPRESSED DATA OFFSET")]
        compressed_data_offset: String,
        #[tabled(rename = "COMPRESSED DATA SIZE")]
        compressed_data_size: String,
        #[tabled(rename = "BOOTSTRAP OFFSET")]
        bootstrap_offset: String,
        #[tabled(rename = "BOOTSTRAP BLOCKS")]
        bootstrap_blocks: String,
        #[tabled(rename = "BLOB METADATA OFFSET")]
        blob_metadata_offset: String,
        #[tabled(rename = "BLOB METADATA BLOCKS")]
        blob_metadata_blocks: String,
        #[tabled(rename = "FULL BLOB PATH")]
        full_blob_path: String,
        #[tabled(rename = "BLOB METADATA PATH")]
        blob_metadata_path: String,
        #[tabled(rename = "BOOTSTRAP PATH")]
        bootstrap_path: String,
    }

    let row = BlobRow {
        blob_index: summary.index.to_string(),
        data_blob_digest: hex_string(summary.data_blob_digest),
        full_blob_digest: hex_string(summary.full_blob_digest),
        chunk_size: summary.blob_metadata.chunk_size().to_string(),
        chunk_count: summary.blob_metadata.chunk_count().to_string(),
        group_count: summary.blob_metadata.group_count().to_string(),
        chunk_digester: summary.blob_metadata.digester().to_string(),
        chunk_compressor: summary.blob_metadata.compressor().to_string(),
        blob_compressed_size: summary.blob_metadata.total_compressed_size().to_string(),
        blob_uncompressed_size: summary.blob_metadata.total_uncompressed_size().to_string(),
        compressed_data_offset: summary.footer.compressed_data_offset().to_string(),
        compressed_data_size: summary.footer.compressed_data_size().to_string(),
        bootstrap_offset: summary.footer.bootstrap_offset().to_string(),
        bootstrap_blocks: summary.footer.bootstrap_blocks().to_string(),
        blob_metadata_offset: summary.footer.blob_metadata_offset().to_string(),
        blob_metadata_blocks: summary.footer.blob_metadata_blocks().to_string(),
        full_blob_path: summary.full_blob_path.display().to_string(),
        blob_metadata_path: summary.blob_metadata_path.display().to_string(),
        bootstrap_path: summary
            .bootstrap_path
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string()),
    };

    // Create a table and print it.
    let mut table = Table::kv(vec![row]);
    table.with(Style::blank());
    println!("{table}");
}

fn blob_metadata_output_path(blob_path: &Path) -> Result<PathBuf> {
    let file_name = blob_path.file_name().ok_or_else(|| {
        Error::InvalidParameter(format!(
            "blob path has no file name: {}",
            blob_path.display()
        ))
    })?;
    Ok(blob_path.with_file_name(format!(
        "{}{BLOB_METADATA_SUFFIX}",
        file_name.to_string_lossy()
    )))
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
    use nydus_format::erofs::{
        cast_ref, ErofsDeviceSlot, EROFS_BLOCK_SIZE, EROFS_DEVICESLOT_SIZE, EROFS_SB_BASE_SIZE,
        EROFS_SUPER_OFFSET,
    };
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use tempfile::tempdir;

    #[test]
    fn build_uses_cli_defaults_when_options_are_omitted() {
        let cmd = BuildCommand::try_parse_from(["build", "/tmp/source"]).unwrap();
        assert_eq!(cmd.chunk_size, ByteSize::mib(1));
        assert_eq!(cmd.compress_size, ByteSize::mib(4));
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

        BuildCommand {
            source,
            conversion_type: ConversionType::DirNydus,
            blob: None,
            blob_dir: Some(blob_dir.clone()),
            bootstrap: Some(bootstrap.clone()),
            output: PathBuf::from("-"),
            chunk_size: ByteSize::mib(1),
            compress_size: ByteSize::mib(4),
            compressor: Compressor::Zstd,
            exclude: Vec::new(),
            log_level: Level::ERROR,
            console: false,
        }
        .execute()
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

        let err = BuildCommand {
            source: blob.clone(),
            conversion_type: ConversionType::NydusTar,
            blob: Some(blob),
            blob_dir: None,
            bootstrap: None,
            output: dir.path().join("out.tar"),
            chunk_size: ByteSize::mib(1),
            compress_size: ByteSize::mib(4),
            compressor: Compressor::Zstd,
            exclude: Vec::new(),
            log_level: Level::ERROR,
            console: false,
        }
        .run_nydus_to_tar()
        .unwrap_err();

        assert!(err.to_string().contains("--blob is not supported"));
    }

    fn build_and_unpack(source: &Path, blob: &Path, tar_path: &Path) {
        BuildCommand {
            source: source.to_path_buf(),
            conversion_type: ConversionType::DirNydus,
            blob: Some(blob.to_path_buf()),
            blob_dir: None,
            bootstrap: None,
            output: PathBuf::from("-"),
            chunk_size: ByteSize::b(EROFS_BLOCK_SIZE as u64),
            compress_size: ByteSize::mib(1),
            compressor: Compressor::Zstd,
            exclude: Vec::new(),
            log_level: Level::ERROR,
            console: false,
        }
        .run_dir_to_nydus()
        .unwrap();

        BuildCommand {
            source: blob.to_path_buf(),
            conversion_type: ConversionType::NydusTar,
            blob: None,
            blob_dir: None,
            bootstrap: None,
            output: tar_path.to_path_buf(),
            chunk_size: ByteSize::mib(1),
            compress_size: ByteSize::mib(4),
            compressor: Compressor::Zstd,
            exclude: Vec::new(),
            log_level: Level::ERROR,
            console: false,
        }
        .run_nydus_to_tar()
        .unwrap();
    }

    fn make_fifo(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let ret = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(ret, 0, "mkfifo failed: {}", io::Error::last_os_error());
    }
}
