use bytesize::ByteSize;
use clap::{Parser, ValueEnum};
use nydus::build::{build_image, BuildImageOptions, Image};
use nydus::error::{Context, Error, Result};
use nydus_format::blob::{BlobFooter, BlobMetadata, BlobMetadataCompressor, BLOB_METADATA_SUFFIX};
use nydus_format::erofs::EROFS_BLOB_ID_SIZE;
use nydus_format::utils::hex_string;
use nydus_telemetry::logging::init_command_tracing;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use tabled::{settings::Style, Table, Tabled};
use tracing::Level;

/// The subcommand of build.
#[derive(Debug, Clone, Parser)]
#[command(group(
    clap::ArgGroup::new("blob_output")
        .required(true)
        .args(["blob", "blob_store"]),
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
        env = "NYDUS_BUILD_BLOB_STORE",
        help = "Specify the content-addressed store directory to save the full blob into, named by its SHA256, so mounts resolve it through the bootstrap and images share the store"
    )]
    blob_store: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_BUILD_BOOTSTRAP",
        help = "Specify the file path to save the standalone bootstrap: the store layout's entry point, whose device table records each blob's SHA256"
    )]
    bootstrap: Option<PathBuf>,

    #[arg(
        long,
        default_value = "1MiB",
        env = "NYDUS_BUILD_CHUNK_SIZE",
        help = "Specify the file chunk size (must be a power of two, >= 4KiB, and 4KiB-aligned). The value needs to be set with human readable format, for example: 4kib, 1mib"
    )]
    chunk_size: ByteSize,

    #[arg(
        long,
        default_value = "4MiB",
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
        let _guards = init_command_tracing(self.log_level, self.console);

        self.validate()?;
        let options = self.prepare()?;
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
        let source = self
            .source
            .canonicalize()
            .with_context(|| format!("failed to canonicalize source: {}", self.source.display()))?;

        let mut excludes: HashSet<PathBuf> = HashSet::new();
        for path in &self.exclude {
            let canonical = path
                .canonicalize()
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
        let blob_output = BlobOutput::new(self.blob.as_deref(), self.blob_store.as_deref())?;
        let writer = blob_output.create()?;
        let image = build_image(options, writer).with_context(|| {
            format!(
                "failed to build nydus blob: {}",
                blob_output.path().display()
            )
        })?;

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
        path.push(BLOB_METADATA_SUFFIX);
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
                    "standalone bootstrap was not rendered; request it in BuildImageOptions"
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
/// content-addressed store where its SHA256 names it (`--blob-store`).
enum BlobOutput {
    /// The exact path to write; an existing FIFO is streamed into.
    File(PathBuf),

    /// A temporary file inside the store, renamed to the SHA256 on finalize.
    Store { dir: PathBuf, temp: PathBuf },
}

/// Implement the blob output lifecycle for BlobOutput.
impl BlobOutput {
    fn new(blob: Option<&Path>, blob_store: Option<&Path>) -> Result<Self> {
        match (blob, blob_store) {
            (Some(blob), None) => Ok(Self::File(blob.to_path_buf())),
            (None, Some(dir)) => {
                fs::create_dir_all(dir)
                    .with_context(|| format!("failed to create blob-store: {}", dir.display()))?;

                Ok(Self::Store {
                    dir: dir.to_path_buf(),
                    temp: Self::temp_path(dir),
                })
            }
            _ => unreachable!("clap enforces exactly one blob output"),
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
                        "failed to rename blob {} -> {}",
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
        blob_compressed_size: summary.blob_metadata.total_compressed_size().to_string(),
        blob_uncompressed_size: summary.blob_metadata.total_uncompressed_size().to_string(),
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
        cast_ref, ErofsDeviceSlot, EROFS_BLOCK_SIZE, EROFS_DEVICESLOT_SIZE, EROFS_SB_BASE_SIZE,
        EROFS_SUPER_OFFSET,
    };
    use std::collections::BTreeMap;
    use std::io::Read;
    use tempfile::tempdir;

    #[test]
    fn build_uses_cli_defaults_when_options_are_omitted() {
        let cmd = BuildCommand::try_parse_from(["build", "/tmp/source", "--blob", "/tmp/out.blob"])
            .unwrap();
        assert_eq!(cmd.chunk_size, ByteSize::mib(1));
        assert_eq!(cmd.block_group_size, ByteSize::mib(4));
    }

    #[test]
    fn build_bootstrap_device_slot_uses_full_blob_digest() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let blob_store = dir.path().join("blobs");
        let bootstrap = dir.path().join("nydus-bootstrap.boot");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&blob_store).unwrap();
        fs::write(source.join("hello.txt"), b"hello nydus").unwrap();

        BuildCommand {
            source,
            blob: None,
            blob_store: Some(blob_store.clone()),
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

        let full_blob_digest = fs::read_dir(&blob_store)
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
    fn export_round_trips_the_source_tree() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let blob = dir.path().join("layer.blob");
        let tar_path = dir.path().join("layer.tar");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        fs::write(source.join("nested/hello.txt"), b"hello nydus").unwrap();
        fs::write(source.join("empty.txt"), b"").unwrap();

        let big = vec![b'x'; 10 * 1024];
        fs::write(source.join("big.bin"), &big).unwrap();
        fs::write(source.join("linked.txt"), b"link me").unwrap();
        fs::hard_link(source.join("linked.txt"), source.join("alias.txt")).unwrap();
        std::os::unix::fs::symlink("nested/hello.txt", source.join("link")).unwrap();
        fs::write(source.join(".wh.deleted"), b"").unwrap();
        let xattr_set = xattr::set(source.join("nested/hello.txt"), "user.demo", b"v1").is_ok();
        build_and_export(&source, &blob, &tar_path);

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
    fn export_drops_internal_nydus_xattrs() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        let blob = dir.path().join("layer.blob");
        let tar_path = dir.path().join("layer.tar");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("sub")).unwrap();
        build_and_export(&source, &blob, &tar_path);

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

    fn build_and_export(source: &Path, blob: &Path, tar_path: &Path) {
        BuildCommand {
            source: source.to_path_buf(),
            blob: Some(blob.to_path_buf()),
            blob_store: None,
            bootstrap: None,
            chunk_size: ByteSize::b(EROFS_BLOCK_SIZE as u64),
            block_group_size: ByteSize::mib(1),
            compressor: Compressor::Zstd,
            exclude: Vec::new(),
            log_level: Level::ERROR,
            console: false,
        }
        .execute()
        .unwrap();

        let reader = nydus_core::ErofsReader::open_blob(blob).unwrap();
        let tar_file = File::create(tar_path).unwrap();
        nydus::export::write_tar(&reader, std::io::BufWriter::new(tar_file)).unwrap();
    }
}
