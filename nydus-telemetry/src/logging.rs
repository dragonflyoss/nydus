use rolling_file::*;
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::iter;
use std::path::PathBuf;
use tracing::{error, info, Level};
pub use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::non_blocking::{NonBlocking, NonBlockingBuilder};
use tracing_subscriber::{
    filter::LevelFilter,
    fmt::{time::ChronoLocal, Layer},
    prelude::*,
    EnvFilter, Registry,
};

/// Lines queued per appender before the writer thread drains them. The
/// crate default of 128k lines pins about 4 MiB per appender at startup.
const QUEUED_LOG_LINES: usize = 8192;

/// The size a log file is rolled at, between two hourly rolls. A daemon that
/// logs a line per failed request would otherwise fill the disk within the
/// hour; with it the log files take `log_max_files + 1` times this at most.
const LOG_FILE_MAX_SIZE: u64 = 10 * 1024 * 1024;

fn non_blocking<T: Write + Send + 'static>(writer: T) -> (NonBlocking, WorkerGuard) {
    NonBlockingBuilder::default()
        .buffered_lines_limit(QUEUED_LOG_LINES)
        .finish(writer)
}

/// Initializes the tracing system for the service, which logs to both stdout
/// and files under `log_dir` rolled every hour and at 10 MiB, an error when
/// the directory or the log file cannot be created.
pub fn init_tracing(
    name: &str,
    log_dir: PathBuf,
    log_level: Level,
    log_max_files: usize,
    console: bool,
) -> io::Result<Vec<WorkerGuard>> {
    // Setup file appender first, the one step that can fail.
    fs::create_dir_all(&log_dir).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "failed to create log directory {}: {err}",
                log_dir.display()
            ),
        )
    })?;
    let log_file = log_dir.join(name).with_extension("log");
    let rolling_appender = BasicRollingFileAppender::new(
        &log_file,
        RollingConditionBasic::new()
            .hourly()
            .max_size(LOG_FILE_MAX_SIZE),
        log_max_files,
    )
    .map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to open log file {}: {err}", log_file.display()),
        )
    })?;

    let mut guards = vec![];

    // Setup stdout layer.
    let (stdout_writer, stdout_guard) = non_blocking(std::io::stdout());
    guards.push(stdout_guard);

    // Initialize stdout layer.
    let stdout_filter = if console {
        LevelFilter::from_level(log_level)
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
    let (rolling_writer, rolling_writer_guard) = non_blocking(rolling_appender);
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
    // try_init: a process only installs one global subscriber; tolerate an
    // existing one so repeated init calls (e.g. tests sharing a binary) work.
    let _ = subscriber.try_init();

    std::panic::set_hook(Box::new(tracing_panic::panic_hook));
    info!(
        "tracing initialized directory: {}, level: {}",
        log_dir.as_path().display(),
        log_level
    );

    Ok(guards)
}

/// Logs the error the daemon `name` stops with, its causes included, and
/// returns `result` as it is. Call it while the guards of [`init_tracing`]
/// are alive: the error is otherwise printed only on stderr, which whoever
/// starts a daemon in the background drops.
pub fn log_failure<T, E: Error + 'static>(name: &str, result: Result<T, E>) -> Result<T, E> {
    result.inspect_err(|err| {
        let causes: Vec<String> = iter::successors(Some(err as &dyn Error), |&err| err.source())
            .map(ToString::to_string)
            .collect();
        error!("nydus {name} failed: {}", causes.join(": "));
    })
}

/// Initializes the tracing system for command line tools, which logs to
/// stderr and does not log to files. Diagnostics stay off stdout so command
/// payloads and reports (tar streams, tables) remain clean.
pub fn init_command_tracing(log_level: Level, console: bool) -> Vec<WorkerGuard> {
    let mut guards = vec![];

    // Setup console layer.
    let (console_writer, console_guard) = non_blocking(std::io::stderr());
    guards.push(console_guard);

    // Initialize console layer.
    let console_filter = if console {
        LevelFilter::from_level(log_level)
    } else {
        LevelFilter::OFF
    };
    let console_logging_layer = Layer::new()
        .with_writer(console_writer)
        .with_file(true)
        .with_line_number(true)
        .with_target(false)
        .with_thread_names(false)
        .with_thread_ids(false)
        .with_timer(ChronoLocal::rfc_3339())
        .pretty()
        .with_filter(console_filter);

    // Setup env filter for log level.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::default().add_directive(log_level.into()));

    let subscriber = Registry::default()
        .with(env_filter)
        .with(console_logging_layer);
    // try_init: a process only installs one global subscriber; tolerate an
    // existing one so repeated init calls (e.g. tests sharing a binary) work.
    let _ = subscriber.try_init();

    std::panic::set_hook(Box::new(tracing_panic::panic_hook));

    guards
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn init_tracing_creates_log_dir_and_returns_guards() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let log_dir = temp_dir.path().join("logs");
        assert!(!log_dir.exists());

        let guards = init_tracing("test-service", log_dir.clone(), Level::INFO, 10, false).unwrap();
        assert!(log_dir.exists());
        assert!(log_dir.is_dir());
        assert!(!guards.is_empty());
        assert_eq!(guards.len(), 2);
    }

    #[test]
    fn init_tracing_fails_when_the_log_dir_cannot_be_created() {
        let temp_dir = TempDir::new().expect("failed to create temp dir");
        let file = temp_dir.path().join("file");
        fs::write(&file, b"").unwrap();

        let err = init_tracing("test-service", file.join("logs"), Level::INFO, 10, false)
            .err()
            .unwrap();

        assert!(err.to_string().contains("failed to create log directory"));
    }

    #[test]
    fn log_failure_logs_an_error_with_its_causes_and_returns_the_result() {
        #[derive(Debug)]
        struct Failure(&'static str, Option<Box<Failure>>);
        impl std::fmt::Display for Failure {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.0)
            }
        }
        impl Error for Failure {
            fn source(&self) -> Option<&(dyn Error + 'static)> {
                self.1.as_deref().map(|cause| cause as _)
            }
        }

        let log = tempfile::NamedTempFile::new().unwrap();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.reopen().unwrap())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            assert!(log_failure("fuse", Ok::<_, Failure>(())).is_ok());
            assert!(fs::read_to_string(log.path()).unwrap().is_empty());

            let cause = Failure("device busy", None);
            let err = Failure("failed to mount", Some(Box::new(cause)));
            assert!(log_failure("fuse", Err::<(), _>(err)).is_err());
        });

        let logged = fs::read_to_string(log.path()).unwrap();
        assert!(
            logged.contains("ERROR")
                && logged.contains("nydus fuse failed: failed to mount: device busy"),
            "{logged}"
        );
    }
}
