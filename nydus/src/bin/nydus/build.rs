use bytesize::ByteSize;
use clap::{Parser, ValueEnum};
use nydus::build::{build_image, BuildImageOptions, Image};
use nydus::error::{Context, Error, Result};
use nydus_format::blob::{
    BlobFooter, BlobMetadata, BlobMetadataCompressor, DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE,
    DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE, NYDUS_BLOB_METADATA_SUFFIX,
};
use nydus_format::erofs::EROFS_BLOB_ID_SIZE;
use nydus_format::utils::hex_string;
use nydus_telemetry::logging::init_command_tracing;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use tabled::{settings::Style, Table, Tabled};
use tracing::Level;

#[derive(Debug, Clone, Parser)]
#[command(group(
    clap::ArgGroup::new("blob_output")
        .required(true)
        .args(["blob", "blob_dir"]),
))]
pub struct BuildCommand {
    #[arg(help = "Specify the source directory to build the nydus image from")]
    source: PathBuf,

    #[arg(
        long,
        env = "NYDUS_BUILD_BLOB",
        help = "Specify the file path to save the image as a single self-contained full blob; if the path is an existing FIFO the blob is streamed into it"
    )]
    blob: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_BUILD_BLOB_DIR",
        help = "Specify the content-addressed store directory to save the full blob into, named by its SHA256, so mounts resolve it through the bootstrap and images share the store"
    )]
    blob_dir: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_BUILD_BOOTSTRAP",
        help = "Specify the file path to save the standalone bootstrap: the store layout's entry point, whose device table records each blob's SHA256"
    )]
    bootstrap: Option<PathBuf>,

    #[arg(
        long,
        default_value = format!(
            "{}MiB",
            DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as u64 / bytesize::MIB
        ),
        env = "NYDUS_BUILD_CHUNK_SIZE",
        help = "Specify the file chunk size (must be a power of two, >= 4KiB, and 4KiB-aligned). The value needs to be set with human readable format, for example: 4kib, 1mib"
    )]
    chunk_size: ByteSize,

    #[arg(
        long,
        default_value = format!(
            "{}MiB",
            DEFAULT_NYDUS_BLOB_METADATA_BLOCK_GROUP_SIZE as u64 / bytesize::MIB
        ),
        env = "NYDUS_BUILD_BLOCK_GROUP_SIZE",
        help = "Specify the uncompressed size of each block group, the unit of compression and of a single backend read (must be a power of two, >= 1MiB, and >= the chunk size). The value needs to be set with human readable format, for example: 4mib, 16mib"
    )]
    block_group_size: ByteSize,

    #[arg(
        long,
        value_enum,
        default_value_t = Compressor::Zstd,
        env = "NYDUS_BUILD_COMPRESSOR",
        help = "Specify the algorithm to compress data chunks"
    )]
    compressor: Compressor,

    #[arg(
        long,
        help = "Specify the absolute or current-working-directory-relative paths to exclude. May be specified multiple times. Entries inside the source tree are omitted from the blob and the resulting filesystem tree entirely"
    )]
    exclude: Vec<PathBuf>,

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

/// Implement the execute for BuildCommand.
impl BuildCommand {
    /// Executes the build sub command, building a nydus image from the
    /// source directory.
    pub fn execute(&self) -> Result<()> {
        // Initializes the tracing subscriber for logging, using the specified log level and
        // console output preference.
        let _guards = init_command_tracing(self.log_level, self.console);

        // Validates the flag combination and the source directory before proceeding with the build.
        self.validate()?;

        // Prepares the build options by canonicalizing paths and checking the chunk/block-group geometry.
        let options = self.prepare()?;

        // Runs the build process, writing the full blob, settling it under its final name,
        // persisting sidecar artifacts, and printing the summary.
        self.run(&options)
    }

    /// Validates the flag combination before any expensive work: the
    /// standalone bootstrap must not overwrite the blob, and the source must
    /// be a directory.
    fn validate(&self) -> Result<()> {
        if let (Some(bootstrap), Some(blob)) = (&self.bootstrap, &self.blob) {
            if bootstrap == blob {
                return Err(Error::InvalidParameter(
                    "--bootstrap and --blob must point to different files".to_string(),
                ));
            }
        }

        if !self.source.is_dir() {
            return Err(Error::InvalidParameter(format!(
                "source {} is not a directory",
                self.source.display()
            )));
        }

        Ok(())
    }

    /// Lowers the raw CLI flags into validated [`BuildImageOptions`]: paths are
    /// canonicalized and the chunk/block-group geometry is checked before any
    /// output file or directory is created.
    fn prepare(&self) -> Result<BuildImageOptions> {
        let source = fs::canonicalize(&self.source)
            .with_context(|| format!("failed to canonicalize source: {}", self.source.display()))?;

        let mut excludes: HashSet<PathBuf> = HashSet::new();
        for path in &self.exclude {
            let canonical = fs::canonicalize(path)
                .with_context(|| format!("failed to canonicalize exclude: {}", path.display()))?;

            if canonical.starts_with(&source) {
                excludes.insert(canonical);
            }
        }

        let chunk_size = u32::try_from(self.chunk_size.as_u64()).map_err(|_| {
            Error::InvalidParameter(format!(
                "chunk size {} exceeds the u32 range",
                self.chunk_size
            ))
        })?;

        let block_group_size = u32::try_from(self.block_group_size.as_u64()).map_err(|_| {
            Error::InvalidParameter(format!(
                "block group size {} exceeds the u32 range",
                self.block_group_size
            ))
        })?;

        BuildImageOptions::new(
            source,
            chunk_size,
            block_group_size,
            self.compressor.into(),
            excludes,
            self.bootstrap.is_some(),
        )
    }

    /// Runs the build: writes the full blob, settles it under its final name,
    /// persists the sidecar artifacts, and prints the summary.
    fn run(&self, options: &BuildImageOptions) -> Result<()> {
        let blob_output = BlobOutput::new(self.blob.as_deref(), self.blob_dir.as_deref())?;
        let writer = blob_output.create()?;
        let image = build_image(options, writer)
            .with_context(|| format!("failed to build image: {}", blob_output.path().display()))?;

        let full_blob_path = blob_output.finalize(&image.full_blob_digest)?;
        let blob_metadata_path = Self::save_blob_metadata(&image, &full_blob_path)?;
        self.save_bootstrap(&image)?;

        print_blob_build_summary(BlobBuildSummary {
            index: 0,
            data_blob_digest: &image.data_blob_digest,
            full_blob_digest: &image.full_blob_digest,
            blob_metadata: &image.blob_metadata,
            blob_footer: &image.blob_footer,
            full_blob_path: &full_blob_path,
            blob_metadata_path: &blob_metadata_path,
            bootstrap_path: self.bootstrap.as_deref(),
        });
        Ok(())
    }

    /// Persists the blob metadata sidecar next to the full blob
    /// (`<full_blob>.blob.meta`) and returns its path.
    fn save_blob_metadata(image: &Image, full_blob_path: &Path) -> Result<PathBuf> {
        let mut path = full_blob_path.to_path_buf().into_os_string();
        path.push(NYDUS_BLOB_METADATA_SUFFIX);

        let blob_metadata_path: PathBuf = path.into();
        image.blob_metadata.save(&blob_metadata_path)?;
        Ok(blob_metadata_path)
    }

    /// Persists the standalone bootstrap rendered during the build when
    /// `--bootstrap` was given.
    fn save_bootstrap(&self, image: &Image) -> Result<()> {
        if let Some(bootstrap) = &self.bootstrap {
            let bytes = image.standalone_bootstrap.as_ref().ok_or_else(|| {
                Error::InvalidParameter(
                    "standalone bootstrap was not rendered, request it in BuildImageOptions"
                        .to_string(),
                )
            })?;

            fs::write(bootstrap, bytes)
                .with_context(|| format!("failed to write bootstrap: {}", bootstrap.display()))?;
        }

        Ok(())
    }
}

/// Where the built full blob lands: a caller-named file (`--blob`) or a
/// content-addressed store where its SHA256 names it (`--blob-dir`).
enum BlobOutput {
    /// The exact path to write; an existing FIFO is streamed into.
    File(PathBuf),

    /// A temporary file inside the store, renamed to the SHA256 on finalize.
    Store { dir: PathBuf, temp: PathBuf },
}

/// Implement the blob output lifecycle for BlobOutput.
impl BlobOutput {
    fn new(blob: Option<&Path>, blob_dir: Option<&Path>) -> Result<Self> {
        match (blob, blob_dir) {
            (Some(blob), None) => Ok(Self::File(blob.to_path_buf())),
            (None, Some(dir)) => {
                fs::create_dir_all(dir)
                    .with_context(|| format!("failed to create blob-dir: {}", dir.display()))?;

                Ok(Self::Store {
                    dir: dir.to_path_buf(),
                    temp: Self::temp_path(dir),
                })
            }
            _ => unreachable!("clap enforces exactly one of --blob and --blob-dir"),
        }
    }

    /// The path the blob bytes are written to: the final path for a file, the
    /// temporary file for a store.
    fn path(&self) -> &Path {
        match self {
            Self::File(path) => path,
            Self::Store { temp, .. } => temp,
        }
    }

    /// Generates a unique temporary blob path inside the store, hidden and
    /// suffixed so a crashed build never collides with a content-addressed
    /// entry.
    fn temp_path(dir: &Path) -> PathBuf {
        dir.join(format!(".nydus-build-{}.tmp", uuid::Uuid::new_v4()))
    }

    /// Creates the write target. A single open covers both a regular file and
    /// a pre-created FIFO: POSIX ignores `O_TRUNC` on a FIFO, so the kernel
    /// picks the behavior from what the path is.
    fn create(&self) -> Result<File> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(self.path())
            .with_context(|| format!("failed to create blob: {}", self.path().display()))
    }

    /// Settles the blob under its final name: a file keeps the caller-named
    /// path; a store entry is renamed to its SHA256, dropping the temporary
    /// file when that digest already exists (dedup).
    fn finalize(self, full_blob_digest: &[u8; EROFS_BLOB_ID_SIZE]) -> Result<PathBuf> {
        match self {
            Self::File(path) => Ok(path),
            Self::Store { dir, temp } => {
                let full_blob_path = dir.join(hex_string(full_blob_digest));
                if full_blob_path.exists() {
                    fs::remove_file(&temp).with_context(|| {
                        format!(
                            "failed to remove temporary blob after dedup hit: {}",
                            temp.display()
                        )
                    })?;

                    return Ok(full_blob_path);
                }

                fs::rename(&temp, &full_blob_path).with_context(|| {
                    format!(
                        "failed to rename blob {} to {}",
                        temp.display(),
                        full_blob_path.display()
                    )
                })?;

                Ok(full_blob_path)
            }
        }
    }
}

struct BlobBuildSummary<'a> {
    index: usize,
    data_blob_digest: &'a [u8; EROFS_BLOB_ID_SIZE],
    full_blob_digest: &'a [u8; EROFS_BLOB_ID_SIZE],
    blob_metadata: &'a BlobMetadata,
    blob_footer: &'a BlobFooter,
    full_blob_path: &'a Path,
    blob_metadata_path: &'a Path,
    bootstrap_path: Option<&'a Path>,
}

fn print_blob_build_summary(summary: BlobBuildSummary<'_>) {
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
        #[tabled(rename = "BLOCK GROUP COUNT")]
        block_group_count: String,
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
        block_group_count: summary.blob_metadata.block_group_count().to_string(),
        chunk_digester: summary.blob_metadata.digester().to_string(),
        chunk_compressor: summary.blob_metadata.compressor().to_string(),
        blob_compressed_size: summary.blob_metadata.compressed_end().to_string(),
        blob_uncompressed_size: summary.blob_metadata.uncompressed_size().to_string(),
        compressed_data_offset: summary.blob_footer.compressed_data_offset().to_string(),
        compressed_data_size: summary.blob_footer.compressed_data_size().to_string(),
        bootstrap_offset: summary.blob_footer.bootstrap_offset().to_string(),
        bootstrap_blocks: summary.blob_footer.bootstrap_blocks().to_string(),
        blob_metadata_offset: summary.blob_footer.blob_metadata_offset().to_string(),
        blob_metadata_blocks: summary.blob_footer.blob_metadata_blocks().to_string(),
        full_blob_path: summary.full_blob_path.display().to_string(),
        blob_metadata_path: summary.blob_metadata_path.display().to_string(),
        bootstrap_path: summary
            .bootstrap_path
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string()),
    };

    let mut table = Table::kv(vec![row]);
    table.with(Style::blank());
    println!("{table}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus_format::erofs::{
        cast_ref, ErofsDeviceSlot, EROFS_DEVICESLOT_SIZE, EROFS_SB_BASE_SIZE, EROFS_SUPER_OFFSET,
    };
    use tempfile::tempdir;

    #[test]
    fn build_uses_cli_defaults_when_options_are_omitted() {
        let cmd = BuildCommand::try_parse_from(["build", "/tmp/source", "--blob", "/tmp/out.blob"])
            .unwrap();
        assert_eq!(cmd.chunk_size, ByteSize::mib(1));
        assert_eq!(cmd.block_group_size, ByteSize::mib(4));
    }

    #[test]
    fn build_requires_exactly_one_blob_output() {
        assert!(BuildCommand::try_parse_from(["build", "/tmp/source"]).is_err());
        assert!(BuildCommand::try_parse_from([
            "build",
            "/tmp/source",
            "--blob",
            "/tmp/out.blob",
            "--blob-dir",
            "/tmp/blobs",
        ])
        .is_err());
    }

    #[test]
    fn validate_rejects_bootstrap_overwriting_blob() {
        let cmd = BuildCommand::try_parse_from([
            "build",
            "/tmp/source",
            "--blob",
            "/tmp/same",
            "--bootstrap",
            "/tmp/same",
        ])
        .unwrap();

        let err = cmd.validate().unwrap_err();
        assert!(err.to_string().contains("must point to different files"));
    }

    #[test]
    fn validate_rejects_source_that_is_not_a_directory() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("plain.txt");
        fs::write(&file, b"x").unwrap();
        let cmd = BuildCommand::try_parse_from([
            "build",
            file.to_str().unwrap(),
            "--blob",
            "/tmp/out.blob",
        ])
        .unwrap();

        let err = cmd.validate().unwrap_err();
        assert!(err.to_string().contains("is not a directory"));
    }

    #[test]
    fn prepare_rejects_missing_exclude_path() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        let missing = dir.path().join("no-such-dir");
        let cmd = BuildCommand::try_parse_from([
            "build",
            source.to_str().unwrap(),
            "--blob",
            "/tmp/out.blob",
            "--exclude",
            missing.to_str().unwrap(),
        ])
        .unwrap();

        let err = cmd.prepare().unwrap_err();
        assert!(err.to_string().contains("failed to canonicalize exclude"));
    }

    #[test]
    fn prepare_rejects_chunk_size_exceeding_u32() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        let cmd = BuildCommand::try_parse_from([
            "build",
            source.to_str().unwrap(),
            "--blob",
            "/tmp/out.blob",
            "--chunk-size",
            "8GiB",
        ])
        .unwrap();

        let err = cmd.prepare().unwrap_err();
        assert!(err.to_string().contains("exceeds the u32 range"));
    }

    #[test]
    fn blob_output_store_finalizes_temp_under_its_digest() {
        let dir = tempdir().unwrap();
        let store = dir.path().join("store");
        let output = BlobOutput::new(None, Some(&store)).unwrap();
        fs::write(output.path(), b"blob bytes").unwrap();
        let digest = [0xab_u8; EROFS_BLOB_ID_SIZE];

        let final_path = output.finalize(&digest).unwrap();

        assert_eq!(final_path, store.join(hex_string(&digest)));
        assert_eq!(fs::read(&final_path).unwrap(), b"blob bytes");
        assert_eq!(fs::read_dir(&store).unwrap().count(), 1);
    }

    #[test]
    fn blob_output_store_finalize_dedups_existing_digest() {
        let dir = tempdir().unwrap();
        let store = dir.path().join("store");
        let output = BlobOutput::new(None, Some(&store)).unwrap();
        let digest = [0xcd_u8; EROFS_BLOB_ID_SIZE];
        let existing = store.join(hex_string(&digest));
        fs::write(&existing, b"already stored").unwrap();
        fs::write(output.path(), b"duplicate bytes").unwrap();

        let final_path = output.finalize(&digest).unwrap();

        assert_eq!(final_path, existing);
        assert_eq!(fs::read(&existing).unwrap(), b"already stored");
        assert_eq!(fs::read_dir(&store).unwrap().count(), 1);
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
            blob: None,
            blob_dir: Some(blob_dir.clone()),
            bootstrap: Some(bootstrap.clone()),
            chunk_size: ByteSize::mib(1),
            block_group_size: ByteSize::mib(4),
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
}
