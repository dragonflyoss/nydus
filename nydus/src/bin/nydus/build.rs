use bytesize::ByteSize;
use clap::{Parser, ValueEnum};
use nydus::build::{
    build_image, build_image_from_tar_layer, BuildImageOptions, Image, NativeLayout,
};
use nydus::error::{Context, Error, Result};
use nydus_format::blob::{
    BlobFooter, BlobMetadata, BlobMetadataCompressor, BlobMetadataDigester,
    DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE, NYDUS_BLOB_METADATA_SUFFIX,
};
use nydus_format::erofs::{ZAlgorithm, EROFS_BLOB_ID_SIZE};
use nydus_format::utils::hex_string;
use nydus_telemetry::logging::init_command_tracing;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::BufWriter;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use tabled::{settings::Style, Table, Tabled};
use tracing::Level;

#[derive(Debug, Clone, Parser)]
#[command(group(
    clap::ArgGroup::new("blob_output")
        .required(true)
        .args(["blob", "blob_dir"]),
))]
pub struct BuildCommand {
    #[arg(
        help = "Specify the source to build the nydus image from: a directory (--source-type dir) or one OCI layer tarball, gzip or plain (--source-type tar)"
    )]
    source: PathBuf,

    #[arg(
        long,
        value_enum,
        default_value_t = SourceType::Dir,
        env = "NYDUS_BUILD_SOURCE_TYPE",
        help = "Specify the source type. tar stream-converts one OCI layer tarball: file data is written to the blob as the tar is read, no rootfs is staged on disk, and whiteout entries are kept for the merge subcommand"
    )]
    source_type: SourceType,

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
        default_value = "0",
        env = "NYDUS_BUILD_EROFS_DATA_ALIGNMENT",
        help = "With an erofs-* compressor, start files of at least this size on this boundary of the layer data (a power of two multiple of 4KiB), so block-level dedup and snapshots of the volume see identical files at stable offsets, e.g. 2mib for cloud disks deduplicating at 2MiB; 0 (the default) packs files back to back"
    )]
    erofs_data_alignment: ByteSize,

    #[arg(
        long,
        env = "NYDUS_BUILD_BOOTSTRAP",
        help = "Specify the file path to save the standalone bootstrap: the store layout's entry point, whose device table records each blob's SHA256"
    )]
    bootstrap: Option<PathBuf>,

    #[arg(
        long,
        env = "NYDUS_BUILD_CHUNK_SIZE",
        help = "Specify the chunk size (must be a power of two, >= 4KiB, and 4KiB-aligned; default 1MiB): the largest chunk a file is cut into for the chunk-based layouts (none, zstd, lz4, erofs-none), and the size of every chunk group (the unit of compression, on-demand fetch and cache readiness): a chunk that fills a group or reaches --chunk-group-threshold is a group of its own, smaller chunks are packed into shared groups. It does not apply to erofs-lz4 and erofs-zstd, whose files are pclusters. The value needs to be set with human readable format, for example: 512kib, 1mib, 2mib"
    )]
    chunk_size: Option<ByteSize>,

    #[arg(
        long,
        env = "NYDUS_BUILD_CHUNK_GROUP_THRESHOLD",
        help = "Specify the chunk group threshold (a power of two of at most the chunk size; default 64KiB): a chunk of at least this size is a chunk group of its own, so its compressed bytes are one frame a content-addressed cache can serve by the chunk's digest alone, while smaller chunks (small files, file tails) are packed together into shared groups for compression ratio and request count. Equal to the chunk size, only full chunks stand alone. It does not apply to the erofs-* compressors. The value needs to be set with human readable format, for example: 16kib, 64kib, 256kib"
    )]
    chunk_group_threshold: Option<ByteSize>,

    #[arg(
        long,
        value_enum,
        default_value_t = Compressor::Zstd,
        env = "NYDUS_BUILD_COMPRESSOR",
        help = "Specify the data layout and compression. zstd, lz4 and none build chunk groups the nydus daemon fetches on demand and decodes, described by the blob meta. The erofs-* values instead build a native EROFS layer without blob meta: the full blob's data region is the raw layer device, so the store file serves as a device= of a kernel block-device mount and the nydus daemons never fetch it on demand. erofs-none stores the chunks uncompressed at their block addresses; erofs-lz4 and erofs-zstd compress file data into native LZ4 or zstd pclusters the kernel decompresses (64KiB pclusters, files up to 64KiB packed into the shared fragment inode; kernel mounts need 6.1+ for erofs-lz4 and 6.10+ for erofs-zstd). --digester does not apply to the erofs-* values"
    )]
    compressor: Compressor,

    #[arg(
        long,
        value_enum,
        default_value_t = Digester::Blake3,
        env = "NYDUS_BUILD_DIGESTER",
        help = "Specify the chunk digest algorithm recorded in the blob meta, one digest per chunk; \"none\" records no digests and skips hashing, for content already verified upstream"
    )]
    digester: Digester,

    #[arg(
        long,
        env = "NYDUS_BUILD_BLOB_ID",
        value_parser = parse_blob_id,
        help = "Name the blob with this 64-hex id (e.g. the OCI layer digest) instead of its SHA256, skipping the data and full-blob hashing; with --blob-dir an existing entry of that name is replaced. Only local stores resolve such blobs (the id is the file name under --blob-dir); a registry serves blobs by their real digest"
    )]
    blob_id: Option<[u8; EROFS_BLOB_ID_SIZE]>,

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

/// What the positional source is.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum SourceType {
    /// A directory tree.
    Dir,
    /// One OCI layer tarball (gzip or plain tar).
    Tar,
}

/// The data layout and compression.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Compressor {
    /// Chunk groups stored plain.
    None,
    /// Chunk groups compressed with zstd.
    Zstd,
    /// Chunk groups compressed with LZ4 (block format).
    Lz4,
    /// Native EROFS device with uncompressed chunks at their block addresses.
    ErofsNone,
    /// Native EROFS device of z_erofs LZ4 pclusters decompressed by the kernel.
    ErofsLz4,
    /// Native EROFS device of z_erofs zstd pclusters decompressed by the
    /// kernel (6.10+).
    ErofsZstd,
}

impl Compressor {
    /// The native layout, for the values that build a raw EROFS device
    /// instead of chunk groups.
    fn native(self) -> Option<NativeLayout> {
        match self {
            Self::ErofsNone => Some(NativeLayout::Plain),
            Self::ErofsLz4 => Some(NativeLayout::Compressed(ZAlgorithm::Lz4)),
            Self::ErofsZstd => Some(NativeLayout::Compressed(ZAlgorithm::Zstd)),
            Self::None | Self::Zstd | Self::Lz4 => None,
        }
    }
}

/// Implement the conversion from Compressor to BlobMetadataCompressor.
impl From<Compressor> for BlobMetadataCompressor {
    fn from(value: Compressor) -> Self {
        match value {
            Compressor::None => Self::None,
            Compressor::Zstd => Self::Zstd,
            Compressor::Lz4 => Self::Lz4Block,
            // Native layers carry no chunk-based compression.
            Compressor::ErofsNone | Compressor::ErofsLz4 | Compressor::ErofsZstd => Self::None,
        }
    }
}

/// The chunk digest algorithm.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Digester {
    Blake3,
    None,
}

impl From<Digester> for BlobMetadataDigester {
    fn from(value: Digester) -> Self {
        match value {
            Digester::Blake3 => Self::Blake3,
            Digester::None => Self::None,
        }
    }
}

fn parse_blob_id(s: &str) -> std::result::Result<[u8; EROFS_BLOB_ID_SIZE], String> {
    let s = s.strip_prefix("sha256:").unwrap_or(s);
    if s.len() != EROFS_BLOB_ID_SIZE * 2 {
        return Err(format!(
            "blob id must be {} hex characters",
            EROFS_BLOB_ID_SIZE * 2
        ));
    }
    let mut id = [0u8; EROFS_BLOB_ID_SIZE];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| "blob id must be hexadecimal".to_string())?;
    }
    Ok(id)
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

        // Prepares the build options by canonicalizing paths and checking the chunk geometry.
        let options = self.prepare()?;

        // Runs the build process, writing the full blob, settling it under its final name,
        // persisting sidecar artifacts, and printing the summary.
        self.run(&options)
    }

    /// Validates the flag combination before any expensive work: the
    /// standalone bootstrap must not overwrite the blob, and the source must
    /// match `--source-type` (a directory, or a layer tarball which may be a
    /// FIFO).
    fn validate(&self) -> Result<()> {
        let full_blob_path = self.blob.clone().or_else(|| {
            self.blob_dir
                .as_ref()
                .zip(self.blob_id.as_ref())
                .map(|(dir, id)| dir.join(hex_string(id)))
        });
        self.validate_output_paths(full_blob_path.as_deref())?;
        if self.erofs_data_alignment.as_u64() != 0 && self.compressor.native().is_none() {
            return Err(Error::InvalidParameter(
                "--erofs-data-alignment requires an erofs-* compressor".to_string(),
            ));
        }

        match self.source_type {
            SourceType::Dir => {
                if !self.source.is_dir() {
                    return Err(Error::InvalidParameter(format!(
                        "source {} is not a directory",
                        self.source.display()
                    )));
                }
            }
            // FIFOs are allowed so layers can be streamed in.
            SourceType::Tar => {
                if !self.source.exists() || self.source.is_dir() {
                    return Err(Error::InvalidParameter(format!(
                        "source {} is not a layer tarball",
                        self.source.display()
                    )));
                }
            }
        }

        Ok(())
    }

    fn validate_output_paths(&self, full_blob_path: Option<&Path>) -> Result<()> {
        let sidecar = full_blob_path.map(Self::blob_metadata_path);
        let mut paths = Vec::new();
        for (name, path) in [
            ("--blob", full_blob_path),
            ("blob metadata sidecar", sidecar.as_deref()),
            ("--bootstrap", self.bootstrap.as_deref()),
            (
                "tar source",
                (self.source_type == SourceType::Tar).then_some(self.source.as_path()),
            ),
        ] {
            let Some(path) = path else { continue };
            let resolved = Self::resolve_path(path)
                .with_context(|| format!("failed to resolve {name}: {}", path.display()))?;
            let identity = match fs::metadata(path) {
                Ok(metadata) => Some((metadata.dev(), metadata.ino())),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("failed to inspect {name}: {}", path.display()));
                }
            };
            for (other_name, other_path, other_identity) in &paths {
                if resolved == *other_path || (identity.is_some() && identity == *other_identity) {
                    return Err(Error::InvalidParameter(format!(
                        "{name} and {other_name} must point to different files: {}",
                        path.display()
                    )));
                }
            }
            paths.push((name, resolved, identity));
        }
        Ok(())
    }

    fn resolve_path(path: &Path) -> std::io::Result<PathBuf> {
        if path.as_os_str().is_empty() {
            return std::env::current_dir();
        }
        match fs::canonicalize(path) {
            Ok(resolved) => Ok(resolved),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let parent = path.parent().ok_or(err)?;
                if let Ok(target) = fs::read_link(path) {
                    return Self::resolve_path(&parent.join(target));
                }
                let mut resolved = Self::resolve_path(parent)?;
                match path.components().next_back() {
                    Some(Component::Normal(name)) => resolved.push(name),
                    Some(Component::ParentDir) => {
                        resolved.pop();
                    }
                    _ => {}
                }
                Ok(resolved)
            }
            Err(err) => Err(err),
        }
    }

    /// Lowers the raw CLI flags into validated [`BuildImageOptions`]: paths are
    /// canonicalized and the chunk/chunk-group geometry is checked before any
    /// output file or directory is created.
    fn prepare(&self) -> Result<BuildImageOptions> {
        let mut excludes: HashSet<PathBuf> = HashSet::new();
        let source = match self.source_type {
            SourceType::Dir => {
                let source = fs::canonicalize(&self.source).with_context(|| {
                    format!("failed to canonicalize source: {}", self.source.display())
                })?;

                for path in &self.exclude {
                    let canonical = fs::canonicalize(path).with_context(|| {
                        format!("failed to canonicalize exclude: {}", path.display())
                    })?;

                    if canonical.starts_with(&source) {
                        excludes.insert(canonical);
                    }
                }
                source
            }
            // The tar path streams from `self.source` directly (it may be a FIFO).
            SourceType::Tar => self.source.clone(),
        };

        let chunk_size = self
            .chunk_size
            .unwrap_or(ByteSize::b(DEFAULT_NYDUS_BLOB_METADATA_CHUNK_SIZE as u64));
        let chunk_size = u32::try_from(chunk_size.as_u64()).map_err(|_| {
            Error::InvalidParameter(format!("chunk size {chunk_size} exceeds the u32 range"))
        })?;

        let erofs_data_alignment =
            u32::try_from(self.erofs_data_alignment.as_u64()).map_err(|_| {
                Error::InvalidParameter(format!(
                    "data alignment {} exceeds the u32 range",
                    self.erofs_data_alignment
                ))
            })?;

        if let Some(layout) = self.compressor.native() {
            // Chunk groups and digests do not apply; the geometry is only
            // checked, and the chunk size cuts erofs-none files.
            return BuildImageOptions::new(
                source,
                chunk_size,
                BlobMetadataCompressor::None,
                excludes,
                self.bootstrap.is_some(),
            )?
            .with_digester(BlobMetadataDigester::None)
            .with_blob_id(self.blob_id)
            .with_native(layout, erofs_data_alignment);
        }

        let options = BuildImageOptions::new(
            source,
            chunk_size,
            self.compressor.into(),
            excludes,
            self.bootstrap.is_some(),
        )?
        .with_digester(self.digester.into())
        .with_blob_id(self.blob_id);
        let options = match self.chunk_group_threshold {
            Some(threshold) => {
                let threshold = u32::try_from(threshold.as_u64()).map_err(|_| {
                    Error::InvalidParameter(format!(
                        "chunk group threshold {threshold} exceeds the u32 range"
                    ))
                })?;
                options.with_chunk_group_threshold(threshold)?
            }
            None => options,
        };
        Ok(options)
    }

    /// Runs the build: writes the full blob, settles it under its final name,
    /// persists the sidecar artifacts, and prints the summary.
    fn run(&self, options: &BuildImageOptions) -> Result<()> {
        self.validate()?;
        let blob_output = BlobOutput::new(self.blob.as_deref(), self.blob_dir.as_deref())?;
        let writer = BufWriter::new(blob_output.create()?);
        let image = match self.source_type {
            SourceType::Dir => build_image(options, writer),
            SourceType::Tar => build_image_from_tar_layer(options, &self.source, writer),
        }
        .with_context(|| format!("failed to build image: {}", blob_output.path().display()))?;

        let final_path = match &blob_output {
            BlobOutput::File(path) => path.clone(),
            BlobOutput::Store { dir, .. } => dir.join(hex_string(&image.full_blob_digest)),
        };
        if let Err(err) = self.validate_output_paths(Some(&final_path)) {
            if let BlobOutput::Store { temp, .. } = &blob_output {
                fs::remove_file(temp).with_context(|| {
                    format!("failed to remove temporary blob: {}", temp.display())
                })?;
            }
            return Err(err);
        }
        let full_blob_path =
            blob_output.finalize(&image.full_blob_digest, options.blob_id().is_some())?;
        let blob_metadata_path = Self::save_blob_metadata(&image, &full_blob_path)?;
        self.save_bootstrap(&image)?;

        print_blob_build_summary(BlobBuildSummary {
            index: 0,
            data_blob_digest: &image.data_blob_digest,
            full_blob_digest: &image.full_blob_digest,
            blob_metadata: image.blob_metadata.as_ref(),
            blob_footer: &image.blob_footer,
            full_blob_path: &full_blob_path,
            blob_metadata_path: blob_metadata_path.as_deref(),
            bootstrap_path: self.bootstrap.as_deref(),
            native: options.native(),
        });
        Ok(())
    }

    /// Persists the blob metadata sidecar next to the full blob
    /// (`<full_blob>.blob.meta`) and returns its path; native layers carry
    /// no blob meta and get no sidecar.
    fn save_blob_metadata(image: &Image, full_blob_path: &Path) -> Result<Option<PathBuf>> {
        let Some(blob_metadata) = image.blob_metadata.as_ref() else {
            return Ok(None);
        };
        let blob_metadata_path = Self::blob_metadata_path(full_blob_path);
        blob_metadata.save(&blob_metadata_path)?;
        Ok(Some(blob_metadata_path))
    }

    fn blob_metadata_path(full_blob_path: &Path) -> PathBuf {
        let mut path = full_blob_path.to_path_buf().into_os_string();
        path.push(NYDUS_BLOB_METADATA_SUFFIX);
        path.into()
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
    /// file when that digest already exists (dedup). An explicit id is not a
    /// content digest, so `replace` makes the rename overwrite instead.
    fn finalize(
        self,
        full_blob_digest: &[u8; EROFS_BLOB_ID_SIZE],
        replace: bool,
    ) -> Result<PathBuf> {
        match self {
            Self::File(path) => Ok(path),
            Self::Store { dir, temp } => {
                let full_blob_path = dir.join(hex_string(full_blob_digest));
                if !replace && full_blob_path.exists() {
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
    blob_metadata: Option<&'a BlobMetadata>,
    blob_footer: &'a BlobFooter,
    full_blob_path: &'a Path,
    blob_metadata_path: Option<&'a Path>,
    bootstrap_path: Option<&'a Path>,
    native: Option<NativeLayout>,
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
        #[tabled(rename = "DATA LAYOUT")]
        data_layout: String,
        #[tabled(rename = "CHUNK SIZE")]
        chunk_size: String,
        #[tabled(rename = "CHUNK GROUP THRESHOLD")]
        chunk_group_threshold: String,
        #[tabled(rename = "CHUNK GROUP COUNT")]
        chunk_group_count: String,
        #[tabled(rename = "CHUNK COUNT")]
        chunk_count: String,
        #[tabled(rename = "DIGEST COUNT")]
        digest_count: String,
        #[tabled(rename = "CHUNK COMPRESSOR")]
        chunk_compressor: String,
        #[tabled(rename = "BLOB PAYLOAD SIZE")]
        blob_payload_size: String,
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

    // Native layers carry no blob meta: their table shows the footer only.
    let meta = |field: fn(&BlobMetadata) -> String| {
        summary
            .blob_metadata
            .map(field)
            .unwrap_or_else(|| "-".to_string())
    };
    let row = BlobRow {
        blob_index: summary.index.to_string(),
        data_blob_digest: hex_string(summary.data_blob_digest),
        full_blob_digest: hex_string(summary.full_blob_digest),
        data_layout: match summary.native {
            Some(NativeLayout::Plain) => "erofs plain device".to_string(),
            Some(NativeLayout::Compressed(algorithm)) => format!("z_erofs {algorithm} device"),
            None => "chunk-based".to_string(),
        },
        chunk_size: meta(|meta| meta.chunk_size().to_string()),
        chunk_group_threshold: meta(|meta| {
            meta.chunk_group_threshold()
                .map_or_else(|| "-".to_string(), |threshold| threshold.to_string())
        }),
        chunk_group_count: meta(|meta| meta.chunk_group_count().to_string()),
        chunk_count: meta(|meta| meta.chunk_count().to_string()),
        digest_count: meta(|meta| meta.digest_count().to_string()),
        chunk_compressor: meta(|meta| meta.compressor().to_string()),
        blob_payload_size: meta(|meta| meta.payload_total().to_string()),
        blob_compressed_size: meta(|meta| meta.compressed_end().to_string()),
        blob_uncompressed_size: meta(|meta| meta.uncompressed_size().to_string()),
        compressed_data_offset: summary.blob_footer.compressed_data_offset().to_string(),
        compressed_data_size: summary.blob_footer.compressed_data_size().to_string(),
        bootstrap_offset: summary.blob_footer.bootstrap_offset().to_string(),
        bootstrap_blocks: summary.blob_footer.bootstrap_blocks().to_string(),
        blob_metadata_offset: summary.blob_footer.blob_metadata_offset().to_string(),
        blob_metadata_blocks: summary.blob_footer.blob_metadata_blocks().to_string(),
        full_blob_path: summary.full_blob_path.display().to_string(),
        blob_metadata_path: summary
            .blob_metadata_path
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string()),
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
    use std::io::{Read, Write};
    use std::os::unix::fs::{symlink, FileTypeExt};
    use tempfile::tempdir;

    fn tar_contents() -> Vec<u8> {
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        let contents = b"original layer contents";
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        archive
            .append_data(&mut header, "hello.txt", &contents[..])
            .unwrap();
        archive.into_inner().unwrap()
    }

    fn tar_command(source: &Path, blob: &Path) -> BuildCommand {
        BuildCommand::try_parse_from([
            "build",
            source.to_str().unwrap(),
            "--source-type",
            "tar",
            "--blob",
            blob.to_str().unwrap(),
        ])
        .unwrap()
    }

    fn link_alias(target: &Path, alias: &Path, kind: &str) {
        match kind {
            "symlink" => symlink(target, alias).unwrap(),
            "hardlink" => fs::hard_link(target, alias).unwrap(),
            _ => unreachable!(),
        }
    }

    fn assert_collision(result: Result<()>) {
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("must point to different files"),
            "{err}"
        );
    }

    #[test]
    fn build_uses_cli_defaults_when_options_are_omitted() {
        let cmd = BuildCommand::try_parse_from(["build", "/tmp/source", "--blob", "/tmp/out.blob"])
            .unwrap();
        assert_eq!(cmd.chunk_size, None);
        assert_eq!(cmd.compressor, Compressor::Zstd);
    }

    #[test]
    fn erofs_compressors_select_native_layouts() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        for (value, layout) in [
            ("erofs-none", NativeLayout::Plain),
            ("erofs-lz4", NativeLayout::Compressed(ZAlgorithm::Lz4)),
            ("erofs-zstd", NativeLayout::Compressed(ZAlgorithm::Zstd)),
        ] {
            let cmd = BuildCommand::try_parse_from([
                "build",
                source.to_str().unwrap(),
                "--blob",
                "/tmp/out.blob",
                "--compressor",
                value,
                "--erofs-data-alignment",
                "2MiB",
            ])
            .unwrap();
            cmd.validate_output_paths(Some(Path::new("/tmp/out.blob")))
                .unwrap();
            let options = cmd.prepare().unwrap();
            assert_eq!(options.native(), Some(layout), "{value}");
            assert_eq!(options.blob_id(), None);
        }
        for (value, compressor) in [
            ("none", BlobMetadataCompressor::None),
            ("zstd", BlobMetadataCompressor::Zstd),
            ("lz4", BlobMetadataCompressor::Lz4Block),
        ] {
            let cmd = BuildCommand::try_parse_from([
                "build",
                source.to_str().unwrap(),
                "--blob",
                "/tmp/out.blob",
                "--compressor",
                value,
            ])
            .unwrap();
            assert_eq!(cmd.compressor.native(), None, "{value}");
            assert_eq!(BlobMetadataCompressor::from(cmd.compressor), compressor);
        }
        assert!(BuildCommand::try_parse_from([
            "build",
            source.to_str().unwrap(),
            "--blob",
            "/tmp/out.blob",
            "--compressor",
            "lz4-block",
        ])
        .is_err());

        let cmd = BuildCommand::try_parse_from([
            "build",
            source.to_str().unwrap(),
            "--blob",
            "/tmp/out.blob",
            "--erofs-data-alignment",
            "2MiB",
        ])
        .unwrap();
        let err = cmd.validate().unwrap_err();
        assert!(err.to_string().contains("erofs-* compressor"), "{err}");
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
    fn validate_rejects_tar_output_aliases_without_changing_contents() {
        for store in [false, true] {
            for output in ["blob", "bootstrap", "sidecar"] {
                for alias in ["direct", "symlink", "hardlink"] {
                    let dir = tempdir().unwrap();
                    let blob_id = [0xab; EROFS_BLOB_ID_SIZE];
                    let blob = dir.path().join(hex_string(&blob_id));
                    let bootstrap = dir.path().join("bootstrap");
                    let sidecar = BuildCommand::blob_metadata_path(&blob);
                    let target = match output {
                        "blob" => &blob,
                        "bootstrap" => &bootstrap,
                        "sidecar" => &sidecar,
                        _ => unreachable!(),
                    };
                    let source = if alias == "direct" {
                        target.clone()
                    } else {
                        dir.path().join("layer.tar")
                    };
                    let contents = tar_contents();
                    fs::write(&source, &contents).unwrap();
                    if alias != "direct" {
                        link_alias(&source, target, alias);
                    }
                    for artifact in [&blob, &bootstrap, &sidecar] {
                        if artifact != target {
                            fs::write(artifact, b"existing artifact").unwrap();
                        }
                    }
                    let mut cmd = tar_command(&source, &blob);
                    cmd.bootstrap = Some(bootstrap.clone());
                    if store {
                        cmd.blob = None;
                        cmd.blob_dir = Some(dir.path().to_path_buf());
                        cmd.blob_id = Some(blob_id);
                    }
                    let before: Vec<_> = [&source, &blob, &bootstrap, &sidecar]
                        .into_iter()
                        .map(|path| (path, fs::read(path).unwrap()))
                        .collect();

                    assert_collision(cmd.validate());
                    assert_collision(cmd.run(&cmd.prepare().unwrap()));
                    for (path, contents) in before {
                        assert_eq!(
                            fs::read(path).unwrap(),
                            contents,
                            "{store}/{output}/{alias}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn validate_rejects_output_collisions_without_changing_contents() {
        for source_type in [SourceType::Dir, SourceType::Tar] {
            for store in [false, true] {
                for pair in ["bootstrap-blob", "bootstrap-sidecar", "sidecar-blob"] {
                    for alias in ["direct", "symlink", "hardlink"] {
                        if pair == "sidecar-blob" && alias == "direct" {
                            continue;
                        }
                        let dir = tempdir().unwrap();
                        let source = dir.path().join("source");
                        if source_type == SourceType::Dir {
                            fs::create_dir(&source).unwrap();
                        } else {
                            fs::write(&source, tar_contents()).unwrap();
                        }
                        let blob_id = [0xcd; EROFS_BLOB_ID_SIZE];
                        let blob = dir.path().join(hex_string(&blob_id));
                        let sidecar = BuildCommand::blob_metadata_path(&blob);
                        let mut cmd = tar_command(&source, &blob);
                        cmd.source_type = source_type;
                        if store {
                            cmd.blob = None;
                            cmd.blob_dir = Some(dir.path().to_path_buf());
                            cmd.blob_id = Some(blob_id);
                        }
                        fs::write(&blob, b"existing blob").unwrap();
                        if pair == "sidecar-blob" {
                            link_alias(&blob, &sidecar, alias);
                        } else {
                            fs::write(&sidecar, b"existing sidecar").unwrap();
                            let target = if pair == "bootstrap-blob" {
                                &blob
                            } else {
                                &sidecar
                            };
                            cmd.bootstrap = Some(if alias == "direct" {
                                target.clone()
                            } else {
                                let bootstrap = dir.path().join("bootstrap");
                                link_alias(target, &bootstrap, alias);
                                bootstrap
                            });
                        }
                        let before = [fs::read(&blob).unwrap(), fs::read(&sidecar).unwrap()];

                        assert_collision(cmd.validate());
                        assert_collision(cmd.run(&cmd.prepare().unwrap()));
                        assert_eq!(fs::read(&blob).unwrap(), before[0]);
                        assert_eq!(fs::read(&sidecar).unwrap(), before[1]);
                    }
                }
            }
        }
    }

    #[test]
    fn validate_resolves_missing_outputs_and_dangling_symlinks() {
        for alias in ["parent", "dangling", "relative-dangling"] {
            let dir = tempdir().unwrap();
            let source = dir.path().join("layer.tar");
            fs::write(&source, tar_contents()).unwrap();
            let blob = dir.path().join("missing").join("out.blob");
            let mut cmd = tar_command(&source, &blob);
            let bootstrap = dir.path().join("alias");
            match alias {
                "parent" => {
                    symlink(dir.path(), &bootstrap).unwrap();
                    cmd.bootstrap = Some(bootstrap.join("missing/./out.blob"));
                }
                "dangling" => {
                    symlink(&blob, &bootstrap).unwrap();
                    cmd.bootstrap = Some(bootstrap);
                }
                "relative-dangling" => {
                    symlink("missing/out.blob", &bootstrap).unwrap();
                    cmd.bootstrap = Some(bootstrap);
                }
                _ => unreachable!(),
            }

            assert_collision(cmd.validate());
            assert_collision(cmd.run(&cmd.prepare().unwrap()));
            assert!(!blob.exists());
            assert!(!dir.path().join("missing").exists());
            assert_eq!(fs::read(&source).unwrap(), tar_contents());
        }
    }

    #[test]
    fn run_rejects_computed_digest_collisions_without_changing_contents() {
        for pair in [
            "tar-blob",
            "tar-sidecar",
            "bootstrap-blob",
            "bootstrap-sidecar",
            "sidecar-blob",
        ] {
            for alias in ["direct", "symlink", "hardlink"] {
                if pair == "sidecar-blob" && alias == "direct" {
                    continue;
                }
                let dir = tempdir().unwrap();
                let source = dir.path().join("layer.tar");
                let contents = tar_contents();
                fs::write(&source, &contents).unwrap();
                let store = dir.path().join("store");
                fs::create_dir(&store).unwrap();
                let mut cmd = tar_command(&source, &dir.path().join("unused"));
                cmd.blob = None;
                cmd.blob_dir = Some(store.clone());
                cmd.bootstrap = Some(dir.path().join("bootstrap"));
                let image =
                    build_image_from_tar_layer(&cmd.prepare().unwrap(), &source, Vec::new())
                        .unwrap();
                let blob = store.join(hex_string(&image.full_blob_digest));
                let sidecar = BuildCommand::blob_metadata_path(&blob);
                fs::write(&blob, b"existing blob").unwrap();
                fs::write(&sidecar, b"existing sidecar").unwrap();
                fs::write(cmd.bootstrap.as_ref().unwrap(), b"existing bootstrap").unwrap();
                let target = if pair.ends_with("sidecar") {
                    &sidecar
                } else {
                    &blob
                };
                if pair.starts_with("tar-") {
                    if alias == "direct" {
                        cmd.source = target.clone();
                        fs::write(target, &contents).unwrap();
                    } else {
                        fs::remove_file(target).unwrap();
                        link_alias(&source, target, alias);
                    }
                } else if pair.starts_with("bootstrap-") {
                    if alias == "direct" {
                        cmd.bootstrap = Some(target.clone());
                    } else {
                        let bootstrap = cmd.bootstrap.as_ref().unwrap();
                        fs::remove_file(bootstrap).unwrap();
                        link_alias(target, bootstrap, alias);
                    }
                } else {
                    fs::remove_file(&sidecar).unwrap();
                    link_alias(&blob, &sidecar, alias);
                }
                let before: Vec<_> = [&source, &blob, &sidecar, cmd.bootstrap.as_ref().unwrap()]
                    .into_iter()
                    .map(|path| (path, fs::read(path).unwrap()))
                    .collect();

                cmd.validate().unwrap();
                assert_collision(cmd.run(&cmd.prepare().unwrap()));
                for (path, contents) in before {
                    assert_eq!(fs::read(path).unwrap(), contents, "{pair}/{alias}");
                }
                assert_eq!(fs::read_dir(&store).unwrap().count(), 2);
            }
        }
    }

    #[test]
    fn run_rejects_bootstrap_at_new_digest_paths_before_finalize() {
        for sidecar in [false, true] {
            let dir = tempdir().unwrap();
            let source = dir.path().join("layer.tar");
            fs::write(&source, tar_contents()).unwrap();
            let store = dir.path().join("store");
            let mut cmd = tar_command(&source, &dir.path().join("unused"));
            cmd.blob = None;
            cmd.blob_dir = Some(store.clone());
            cmd.bootstrap = Some(dir.path().join("bootstrap"));
            let image =
                build_image_from_tar_layer(&cmd.prepare().unwrap(), &source, Vec::new()).unwrap();
            let blob = store.join(hex_string(&image.full_blob_digest));
            cmd.bootstrap = Some(if sidecar {
                BuildCommand::blob_metadata_path(&blob)
            } else {
                blob
            });

            cmd.validate().unwrap();
            assert_collision(cmd.run(&cmd.prepare().unwrap()));
            assert_eq!(fs::read(&source).unwrap(), tar_contents());
            assert_eq!(fs::read_dir(&store).unwrap().count(), 0);
        }
    }

    #[test]
    fn run_allows_distinct_tar_and_directory_outputs() {
        for source_type in [SourceType::Dir, SourceType::Tar] {
            for output in ["file", "explicit", "hashed"] {
                let dir = tempdir().unwrap();
                let source = dir.path().join("source");
                let original = if source_type == SourceType::Dir {
                    fs::create_dir(&source).unwrap();
                    let original = source.join("hello.txt");
                    fs::write(&original, b"original contents").unwrap();
                    original
                } else {
                    fs::write(&source, tar_contents()).unwrap();
                    source.clone()
                };
                let before = fs::read(&original).unwrap();
                let blob = dir.path().join("out.blob");
                let mut cmd = tar_command(&source, &blob);
                cmd.source_type = source_type;
                cmd.bootstrap = Some(dir.path().join("bootstrap"));
                if output != "file" {
                    cmd.blob = None;
                    cmd.blob_dir = Some(dir.path().join("store"));
                    if output == "explicit" {
                        cmd.blob_id = Some([0xab; EROFS_BLOB_ID_SIZE]);
                    }
                }

                cmd.validate().unwrap();
                cmd.run(&cmd.prepare().unwrap()).unwrap();
                assert_eq!(fs::read(&original).unwrap(), before);
                assert!(cmd.bootstrap.unwrap().is_file());
                if output == "file" {
                    assert!(blob.is_file());
                    assert!(BuildCommand::blob_metadata_path(&blob).is_file());
                } else {
                    assert_eq!(fs::read_dir(cmd.blob_dir.unwrap()).unwrap().count(), 2);
                }
            }
        }
    }

    #[test]
    fn run_allows_fifo_tar_source_and_blob_output() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("layer.fifo");
        let blob = dir.path().join("blob.fifo");
        assert!(std::process::Command::new("mkfifo")
            .args([&source, &blob])
            .status()
            .unwrap()
            .success());
        let mut cmd = tar_command(&source, &blob);
        cmd.bootstrap = Some(dir.path().join("bootstrap"));
        cmd.validate().unwrap();
        let input_path = source.clone();
        let input = std::thread::spawn(move || {
            File::create(input_path)
                .unwrap()
                .write_all(&tar_contents())
                .unwrap();
        });
        let output_path = blob.clone();
        let output = std::thread::spawn(move || {
            let mut contents = Vec::new();
            File::open(output_path)
                .unwrap()
                .read_to_end(&mut contents)
                .unwrap();
            contents
        });

        cmd.run(&cmd.prepare().unwrap()).unwrap();
        input.join().unwrap();
        assert!(!output.join().unwrap().is_empty());
        assert!(fs::metadata(&source).unwrap().file_type().is_fifo());
        assert!(fs::metadata(&blob).unwrap().file_type().is_fifo());
        assert!(BuildCommand::blob_metadata_path(&blob).is_file());
        assert!(cmd.bootstrap.unwrap().is_file());
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
    fn prepare_applies_and_validates_the_chunk_group_threshold() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        let parse = |extra: &[&str]| {
            let mut args = vec!["build", source.to_str().unwrap(), "--blob", "/tmp/out.blob"];
            args.extend_from_slice(extra);
            BuildCommand::try_parse_from(args).unwrap().prepare()
        };
        assert_eq!(parse(&[]).unwrap().chunk_group_threshold(), 64 * 1024);
        assert_eq!(
            parse(&["--chunk-group-threshold", "256kib"])
                .unwrap()
                .chunk_group_threshold(),
            256 * 1024
        );
        // A chunk size below the default caps the threshold at the chunk size.
        assert_eq!(
            parse(&["--chunk-size", "16kib"])
                .unwrap()
                .chunk_group_threshold(),
            16 * 1024
        );
        for bad in ["3kib", "2mib"] {
            assert!(parse(&["--chunk-group-threshold", bad])
                .unwrap_err()
                .to_string()
                .contains("power of two of at most"));
        }
    }

    #[test]
    fn blob_output_store_finalizes_temp_under_its_digest() {
        let dir = tempdir().unwrap();
        let store = dir.path().join("store");
        let output = BlobOutput::new(None, Some(&store)).unwrap();
        fs::write(output.path(), b"blob bytes").unwrap();
        let digest = [0xab_u8; EROFS_BLOB_ID_SIZE];

        let final_path = output.finalize(&digest, false).unwrap();

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

        let final_path = output.finalize(&digest, false).unwrap();

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

        let cmd = BuildCommand::try_parse_from([
            "build",
            source.to_str().unwrap(),
            "--blob-dir",
            blob_dir.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            "--compressor",
            "zstd",
        ])
        .unwrap();
        cmd.validate().unwrap();
        cmd.run(&cmd.prepare().unwrap()).unwrap();

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
