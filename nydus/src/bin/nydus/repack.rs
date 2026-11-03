use clap::Parser;
use nydus::error::{Error, Result};
use nydus_config::Config;
use nydus_core::{IncrementalWriterOptions, NydusCore, RepackResult};
use nydus_format::blob::BlobMetadataCompressor;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Parser)]
pub struct RepackCommand {
    #[arg(long)]
    bootstrap: PathBuf,
    #[arg(long)]
    blob_dir: PathBuf,
    #[arg(long)]
    output_dir: PathBuf,
    #[arg(long, hide = true)]
    config: Option<PathBuf>,
    #[arg(long)]
    prune: bool,
    #[arg(long, default_value_t = 0)]
    compact_max_layers: usize,
    #[arg(long, default_value = "zstd", value_parser = ["none", "lz4", "zstd"])]
    compressor: String,
    // nydusify supplies blobs between the plan and result records. Holding
    // the process open avoids serializing/reloading an intermediate image.
    #[arg(long, hide = true)]
    prepare_stdio: bool,
}

impl RepackCommand {
    pub fn execute(&self) -> Result<()> {
        let core = if let Some(path) = &self.config {
            let config = nydus_config::Config::load(path)?;
            nydus_core::NydusCore::new(&self.bootstrap, config, None)?
        } else {
            local_core(&self.bootstrap, &self.blob_dir, &self.output_dir)?
        };
        let mut options = writer_options(&self.output_dir, &self.compressor)?;
        options.prune = self.prune;
        let result = core.repack(options, self.compact_max_layers, |plan| {
            if self.prepare_stdio {
                report("plan", plan)?;
                let mut response = String::new();
                std::io::stdin().lock().read_line(&mut response)?;
                if response.trim() != "ready" {
                    return Err(Error::InvalidParameter(
                        "repack input closed or invalid preparation acknowledgement".to_string(),
                    ));
                }
            }
            Ok(())
        })?;
        report("result", &result)
    }
}

fn report(phase: &str, result: &RepackResult) -> Result<()> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(
        &mut out,
        &serde_json::json!({
            "version": 1,
            "phase": phase,
            "pruned": result.pruned,
            "compacted": result.compacted,
            "blobs": result.blobs.iter().map(ToString::to_string).collect::<Vec<_>>(),
        }),
    )?;
    out.write_all(b"\n")?;
    out.flush()?;
    Ok(())
}

fn local_core(bootstrap: &Path, blobs: &Path, output: &Path) -> Result<NydusCore> {
    let config = Config::from_yaml(&format!(
        "backend:\n  type: local\n  config:\n    dir: {}\nstorage:\n  dir: {}\nprefetch:\n  scope: none\n",
        serde_json::to_string(blobs)?,
        serde_json::to_string(&output.join("cache"))?,
    ))?;
    NydusCore::new(bootstrap, config, None)
}

fn writer_options(output: &Path, compressor: &str) -> Result<IncrementalWriterOptions> {
    let mut options = IncrementalWriterOptions::new(output.to_path_buf());
    options.compressor = match compressor {
        "none" => BlobMetadataCompressor::None,
        "lz4" => BlobMetadataCompressor::Lz4Block,
        "zstd" => BlobMetadataCompressor::Zstd,
        _ => {
            return Err(Error::InvalidParameter(
                "unsupported repack compressor".to_string(),
            ))
        }
    };
    Ok(options)
}
