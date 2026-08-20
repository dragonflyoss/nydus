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

    #[test]
    fn export_writes_to_stdout_by_default() {
        let cmd = ExportCommand::try_parse_from(["export", "/tmp/layer.blob"]).unwrap();
        assert_eq!(cmd.output, PathBuf::from("-"));
    }
}
