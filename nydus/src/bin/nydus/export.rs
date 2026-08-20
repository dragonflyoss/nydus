use clap::Parser;
use nydus::error::{Context, Error, Result};
use nydus::export::write_tar;
use nydus_core::ErofsReader;
use nydus_telemetry::logging::{init_command_tracing, init_command_tracing_stderr};
use std::fs::File;
use std::io::{self, BufWriter};
use std::path::{Path, PathBuf};
use tracing::Level;

/// The subcommand of export.
#[derive(Debug, Clone, Parser)]
pub struct ExportCommand {
    #[arg(help = "Specify the nydus full blob to export the OCI layer tar stream from")]
    source: PathBuf,

    #[arg(
        long,
        default_value = "-",
        env = "NYDUS_EXPORT_OUTPUT",
        help = "Specify the file path to save the exported tar stream, or `-` for stdout"
    )]
    output: PathBuf,

    #[arg(
        short = 'l',
        long,
        default_value = "info",
        env = "NYDUS_EXPORT_LOG_LEVEL",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    log_level: Level,

    #[arg(
        long,
        hide = true,
        default_value_t = true,
        env = "NYDUS_EXPORT_CONSOLE",
        help = "Specify whether to print log"
    )]
    console: bool,
}

/// Implement the execute for ExportCommand.
impl ExportCommand {
    /// Executes the export sub command, writing the source blob's OCI layer
    /// tar stream to the output.
    pub fn execute(&self) -> Result<()> {
        let tar_to_stdout = self.output == Path::new("-");
        // Logging to stdout would corrupt a tar stream written to stdout.
        let _guards = if tar_to_stdout {
            init_command_tracing_stderr(self.log_level, self.console)
        } else {
            init_command_tracing(self.log_level, self.console)
        };

        if !self.source.is_file() {
            return Err(Error::InvalidParameter(format!(
                "source {} is not a nydus blob file",
                self.source.display()
            )));
        }

        let reader = ErofsReader::open_blob(&self.source)
            .with_context(|| format!("failed to open nydus blob: {}", self.source.display()))?;

        if tar_to_stdout {
            let stdout = io::stdout();
            write_tar(&reader, BufWriter::new(stdout.lock()))?;
        } else {
            let file = File::create(&self.output)
                .with_context(|| format!("failed to create output: {}", self.output.display()))?;
            write_tar(&reader, BufWriter::new(file))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nydus::build::{build_image, BuildImageOptions};
    use nydus_format::blob::BlobMetadataCompressor;
    use nydus_format::erofs::EROFS_BLOCK_SIZE;
    use std::collections::{BTreeMap, HashSet};
    use std::fs;
    use std::io::Read;
    use tempfile::tempdir;

    fn build_and_export(source: &Path, blob: &Path, tar_path: &Path) {
        let options = BuildImageOptions::new(
            source.to_path_buf(),
            EROFS_BLOCK_SIZE,
            1 << 20,
            BlobMetadataCompressor::Zstd,
            HashSet::new(),
            false,
        )
        .unwrap();
        build_image(&options, File::create(blob).unwrap()).unwrap();

        let reader = ErofsReader::open_blob(blob).unwrap();
        let tar_file = File::create(tar_path).unwrap();
        write_tar(&reader, BufWriter::new(tar_file)).unwrap();
    }

    #[test]
    fn export_writes_to_stdout_by_default() {
        let cmd = ExportCommand::try_parse_from(["export", "/tmp/layer.blob"]).unwrap();
        assert_eq!(cmd.output, PathBuf::from("-"));
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
}
