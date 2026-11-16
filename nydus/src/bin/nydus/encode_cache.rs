use clap::Parser;
use nydus::error::{Error, Result};
use nydus_format::blob::BlobMetadataCompressor;
use std::fs::File;
use std::io::BufWriter;
use std::io::ErrorKind;
use std::path::PathBuf;

#[derive(Debug, Clone, Parser)]
pub struct EncodeCacheCommand {
    #[arg(long)]
    cache: PathBuf,
    #[arg(long)]
    prune: bool,
    #[arg(long, default_value_t = 0)]
    compact_max_layers: usize,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_parser = ["none", "zstd", "lz4"])]
    compressor: Option<String>,
}

impl EncodeCacheCommand {
    pub fn execute(&self) -> Result<()> {
        let directory = self
            .cache
            .parent()
            .ok_or_else(|| Error::InvalidParameter("capture has no directory".to_string()))?;
        let data = match File::open(directory.join("capture.data")) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let stdout = std::io::stdout();
        let output = BufWriter::with_capacity(256 * 1024, stdout.lock());
        let options = nydus_core::EncodeCacheOptions {
            compressor: self.compressor.as_deref().map(|name| match name {
                "none" => BlobMetadataCompressor::None,
                "zstd" => BlobMetadataCompressor::Zstd,
                "lz4" => BlobMetadataCompressor::Lz4Block,
                _ => unreachable!("clap validates compressor"),
            }),
            prune: self.prune,
            compact_max_layers: self.compact_max_layers,
            config: self
                .config
                .as_ref()
                .map(|path| nydus_config::Config::load(path))
                .transpose()?,
        };
        nydus_core::encode_cache(&self.cache, data.as_ref(), output, options)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compressor_is_optional_and_accepts_only_chunk_group_codecs() {
        let command =
            EncodeCacheCommand::try_parse_from(["encode-cache", "--cache", "capture.json"])
                .unwrap();
        assert_eq!(command.compressor, None);
        for compressor in ["none", "zstd", "lz4"] {
            let command = EncodeCacheCommand::try_parse_from([
                "encode-cache",
                "--cache",
                "capture.json",
                "--compressor",
                compressor,
            ])
            .unwrap();
            assert_eq!(command.compressor.as_deref(), Some(compressor));
        }
        for compressor in ["lz4hc", "deflate", "zlib", "unknown"] {
            assert!(EncodeCacheCommand::try_parse_from([
                "encode-cache",
                "--cache",
                "capture.json",
                "--compressor",
                compressor,
            ])
            .is_err());
        }
    }
}
