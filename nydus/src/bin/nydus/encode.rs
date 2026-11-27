use clap::{Parser, ValueEnum};
use nydus::error::Result;
use nydus_format::blob::BlobMetadataCompressor;
use nydus_telemetry::logging::init_command_tracing;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use tracing::Level;

#[derive(Debug, Copy, Clone, ValueEnum)]
enum Compressor {
    None,
    Zstd,
    Lz4,
}

impl From<Compressor> for BlobMetadataCompressor {
    fn from(value: Compressor) -> Self {
        match value {
            Compressor::None => Self::None,
            Compressor::Zstd => Self::Zstd,
            Compressor::Lz4 => Self::Lz4Block,
        }
    }
}

#[derive(Debug, Clone, Parser)]
pub struct EncodeCommand {
    #[arg(
        long,
        env = "NYDUS_ENCODE_CACHE_DIR",
        help = "Specify the cache layout directory holding the bootstrap and the decoded data of the blob to encode"
    )]
    cache_dir: PathBuf,
    #[arg(long, env = "NYDUS_ENCODE_PRUNE", help = "Remove unreferenced blobs")]
    prune: bool,
    #[arg(
        long,
        default_value_t = 0,
        env = "NYDUS_ENCODE_COMPACT_MAX_LAYERS",
        help = "Compact when the number of live data blobs exceeds this limit; zero disables compaction"
    )]
    compact_max_layers: usize,
    #[arg(
        long,
        env = "NYDUS_ENCODE_CONFIG",
        help = "Specify the parent reader configuration, including storage.dir"
    )]
    config: Option<PathBuf>,
    #[arg(
        long,
        value_enum,
        env = "NYDUS_ENCODE_COMPRESSOR",
        help = "Override the recorded chunk group compressor"
    )]
    compressor: Option<Compressor>,
    #[arg(
        short = 'l',
        long,
        default_value = "info",
        env = "NYDUS_ENCODE_LOG_LEVEL",
        help = "Specify the logging level [trace, debug, info, warn, error]"
    )]
    log_level: Level,
    #[arg(long, action = clap::ArgAction::Set, default_value_t = true, env = "NYDUS_ENCODE_CONSOLE", help = "Print logs to stderr")]
    console: bool,
}

impl EncodeCommand {
    pub fn execute(&self) -> Result<()> {
        let _guards = init_command_tracing(self.log_level, self.console);
        let stdout = std::io::stdout();
        let mut output = BufWriter::with_capacity(256 * 1024, stdout.lock());
        let options = nydus_core::EncodeOptions {
            compressor: self.compressor.map(Into::into),
            prune: self.prune,
            compact_max_layers: self.compact_max_layers,
            config: self
                .config
                .as_deref()
                .map(nydus_config::Config::load)
                .transpose()?,
        };
        nydus_core::CacheLayout::open(&self.cache_dir)?.encode(&mut output, options)?;
        output.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_uses_cache_layout_and_accepts_only_chunk_group_compressors() {
        let command = EncodeCommand::try_parse_from([
            "encode",
            "--cache-dir",
            "layout",
            "--config",
            "reader.yaml",
            "--compressor",
            "lz4",
        ])
        .unwrap();
        assert_eq!(command.cache_dir, PathBuf::from("layout"));
        assert_eq!(command.config, Some(PathBuf::from("reader.yaml")));
        assert!(matches!(command.compressor, Some(Compressor::Lz4)));
        for args in [
            ["--compressor", "erofs-zstd"],
            ["--parent-cache-dir", "cache"],
        ] {
            assert!(EncodeCommand::try_parse_from(
                ["encode", "--cache-dir", "layout"].into_iter().chain(args)
            )
            .is_err());
        }
    }
}
