use clap::Parser;
use nydus::error::{Error, Result};
use std::fs::File;
use std::io::BufWriter;
use std::io::ErrorKind;
use std::path::PathBuf;

#[derive(Debug, Clone, Parser)]
pub struct EncodeCacheCommand {
    #[arg(long)]
    cache: PathBuf,
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
        nydus_core::encode_cache(&self.cache, data.as_ref(), output)
    }
}
