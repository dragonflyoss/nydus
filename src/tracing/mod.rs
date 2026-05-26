use rolling_file::*;
use std::fs;
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    filter::LevelFilter,
    fmt::{time::ChronoLocal, Layer},
    prelude::*,
    EnvFilter, Registry,
};

/// Initialize tracing initializes the tracing system for the service, which logs to both stdout
/// and
#[allow(clippy::too_many_arguments)]
pub fn init_tracing(
    name: &str,
    log_dir: PathBuf,
    log_level: Level,
    log_max_files: usize,
    console: bool,
) -> Vec<WorkerGuard> {
    let mut guards = vec![];

    // Setup stdout layer.
    let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
    guards.push(stdout_guard);

    // Initialize stdout layer.
    let stdout_filter = if console {
        LevelFilter::DEBUG
    } else {
        LevelFilter::OFF
    };
    let stdout_logging_layer = Layer::new()
        .with_writer(stdout_writer)
        .with_file(true)
        .with_line_number(true)
        .with_target(false)
        .with_thread_names(false)
        .with_thread_ids(false)
        .with_timer(ChronoLocal::rfc_3339())
        .pretty()
        .with_filter(stdout_filter);

    // Setup file layer.
    fs::create_dir_all(log_dir.clone()).expect("failed to create log directory");
    let rolling_appender = BasicRollingFileAppender::new(
        log_dir.join(name).with_extension("log"),
        RollingConditionBasic::new().hourly(),
        log_max_files,
    )
    .expect("failed to create rolling file appender");

    let (rolling_writer, rolling_writer_guard) = tracing_appender::non_blocking(rolling_appender);
    guards.push(rolling_writer_guard);

    let file_logging_layer = Layer::new()
        .with_writer(rolling_writer)
        .with_ansi(false)
        .with_file(true)
        .with_line_number(true)
        .with_target(false)
        .with_thread_names(false)
        .with_thread_ids(false)
        .with_timer(ChronoLocal::rfc_3339())
        .compact();

    // Setup env filter for log level.
    let env_filter = EnvFilter::from_default_env().add_directive(log_level.into());
    let subscriber = Registry::default()
        .with(env_filter)
        .with(file_logging_layer)
        .with(stdout_logging_layer);
    subscriber.init();

    std::panic::set_hook(Box::new(tracing_panic::panic_hook));
    info!(
        "tracing initialized directory: {}, level: {}",
        log_dir.as_path().display(),
        log_level
    );

    guards
}

/// Initialize command tracing initializes the tracing system for command line tools, which only
/// logs to stdout and does not log to files.
#[allow(clippy::too_many_arguments)]
pub fn init_command_tracing(log_level: Level, console: bool) -> Vec<WorkerGuard> {
    let mut guards = vec![];

    // Setup stdout layer.
    let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
    guards.push(stdout_guard);

    // Initialize stdout layer.
    let stdout_filter = if console {
        LevelFilter::DEBUG
    } else {
        LevelFilter::OFF
    };
    let stdout_logging_layer = Layer::new()
        .with_writer(stdout_writer)
        .with_file(true)
        .with_line_number(true)
        .with_target(false)
        .with_thread_names(false)
        .with_thread_ids(false)
        .with_timer(ChronoLocal::rfc_3339())
        .pretty()
        .with_filter(stdout_filter);

    // Setup env filter for log level.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::default().add_directive(log_level.into()));

    let subscriber = Registry::default()
        .with(env_filter)
        .with(stdout_logging_layer);
    subscriber.init();

    std::panic::set_hook(Box::new(tracing_panic::panic_hook));

    guards
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_init_tracing_comprehensive() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let log_dir = temp_dir.path().join("logs");
        assert!(!log_dir.exists());

        let guards = init_tracing("test-service", log_dir.clone(), Level::INFO, 10, false);
        assert!(log_dir.exists());
        assert!(log_dir.is_dir());
        assert!(!guards.is_empty());
        assert_eq!(guards.len(), 2);
    }
}
