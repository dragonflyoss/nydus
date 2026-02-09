// Copyright 2020 Ant Group. All rights reserved.
// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::env::current_dir;
use std::io::Result;
use std::path::PathBuf;

use flexi_logger::{
    self, style, Cleanup, Criterion, DeferredNow, FileSpec, Logger, Naming,
    TS_DASHES_BLANK_COLONS_DOT_BLANK,
};
use log::{Level, LevelFilter, Record};

pub fn log_level_to_verbosity(level: log::LevelFilter) -> usize {
    if level == log::LevelFilter::Off {
        0
    } else {
        level as usize - 1
    }
}

fn get_file_name<'a>(record: &'a Record) -> Option<&'a str> {
    record.file().map(|v| match v.rfind("/src/") {
        None => v,
        Some(pos) => match v[..pos].rfind('/') {
            None => &v[pos..],
            Some(p) => &v[p..],
        },
    })
}

fn opt_format(
    w: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> std::result::Result<(), std::io::Error> {
    let level = record.level();
    if level == Level::Info {
        write!(
            w,
            "[{}] {} {}",
            now.format(TS_DASHES_BLANK_COLONS_DOT_BLANK),
            record.level(),
            &record.args()
        )
    } else {
        write!(
            w,
            "[{}] {} [{}:{}] {}",
            now.format(TS_DASHES_BLANK_COLONS_DOT_BLANK),
            record.level(),
            get_file_name(record).unwrap_or("<unnamed>"),
            record.line().unwrap_or(0),
            &record.args()
        )
    }
}

fn colored_opt_format(
    w: &mut dyn std::io::Write,
    now: &mut DeferredNow,
    record: &Record,
) -> std::result::Result<(), std::io::Error> {
    let level = record.level();
    if level == Level::Info {
        write!(
            w,
            "[{}] {} {}",
            style(level).paint(now.format(TS_DASHES_BLANK_COLONS_DOT_BLANK).to_string()),
            style(level).paint(level.to_string()),
            style(level).paint(record.args().to_string())
        )
    } else {
        write!(
            w,
            "[{}] {} [{}:{}] {}",
            style(level).paint(now.format(TS_DASHES_BLANK_COLONS_DOT_BLANK).to_string()),
            style(level).paint(level.to_string()),
            get_file_name(record).unwrap_or("<unnamed>"),
            record.line().unwrap_or(0),
            style(level).paint(record.args().to_string())
        )
    }
}

/// Setup logging infrastructure for application.
///
/// `log_file_path` is an absolute path to logging files or relative path from current working
/// directory to logging file.
/// Flexi logger always appends a suffix to file name whose default value is ".log"
/// unless we set it intentionally. I don't like this passion. When the basename of `log_file_path`
/// is "bar", the newly created log file will be "bar.log"
pub fn setup_logging(
    log_file_path: Option<PathBuf>,
    level: LevelFilter,
    rotation_size: u64,
) -> Result<()> {
    if let Some(ref path) = log_file_path {
        // Do not try to canonicalize the path since the file may not exist yet.
        let mut spec = FileSpec::default().suppress_timestamp();

        // Parse log file to get the `basename` and `suffix`(extension) because `flexi_logger`
        // will automatically add `.log` suffix if we don't set explicitly, see:
        // https://github.com/emabee/flexi_logger/issues/74
        let basename = path
            .file_stem()
            .ok_or_else(|| {
                eprintln!("invalid file name input {:?}", path);
                einval!()
            })?
            .to_str()
            .ok_or_else(|| {
                eprintln!("invalid file name input {:?}", path);
                einval!()
            })?;
        spec = spec.basename(basename);

        // `flexi_logger` automatically add `.log` suffix if the file name has no extension.
        if let Some(suffix) = path.extension() {
            let suffix = suffix.to_str().ok_or_else(|| {
                eprintln!("invalid file extension {:?}", suffix);
                einval!()
            })?;
            spec = spec.suffix(suffix);
        }

        // Set log directory
        let parent_dir = path.parent();
        if let Some(p) = parent_dir {
            let cwd = current_dir()?;
            let dir = if !p.has_root() {
                cwd.join(p)
            } else {
                p.to_path_buf()
            };
            spec = spec.directory(dir);
        }

        // We rely on rust `log` macro to limit current log level rather than `flexi_logger`
        // So we set `flexi_logger` log level to "trace" which is High enough. Otherwise, we
        // can't change log level to a higher level than what is passed to `flexi_logger`.
        let mut logger = Logger::try_with_env_or_str("trace")
            .map_err(|_e| enosys!())?
            .log_to_file(spec)
            .append()
            .format(opt_format);

        // Set log rotation
        if rotation_size > 0 {
            let log_rotation_size_byte: u64 = rotation_size * 1024 * 1024;
            logger = logger.rotate(
                Criterion::Size(log_rotation_size_byte),
                Naming::Timestamps,
                Cleanup::KeepCompressedFiles(10),
            );
        }

        logger.start().map_err(|e| {
            eprintln!("{:?}", e);
            eother!(e)
        })?;
    } else {
        // We rely on rust `log` macro to limit current log level rather than `flexi_logger`
        // So we set `flexi_logger` log level to "trace" which is High enough. Otherwise, we
        // can't change log level to a higher level than what is passed to `flexi_logger`.
        Logger::try_with_env_or_str("trace")
            .map_err(|_e| enosys!())?
            .format(colored_opt_format)
            .start()
            .map_err(|e| eother!(e))?;
    }

    log::set_max_level(level);

    // Dump panic info and backtrace to logger.
    log_panics::Config::new()
        .backtrace_mode(log_panics::BacktraceMode::Resolved)
        .install_panic_hook();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_to_verbosity() {
        assert_eq!(log_level_to_verbosity(log::LevelFilter::Off), 0);
        assert_eq!(log_level_to_verbosity(log::LevelFilter::Error), 0);
        assert_eq!(log_level_to_verbosity(log::LevelFilter::Warn), 1);
        assert_eq!(log_level_to_verbosity(log::LevelFilter::Info), 2);
        assert_eq!(log_level_to_verbosity(log::LevelFilter::Debug), 3);
        assert_eq!(log_level_to_verbosity(log::LevelFilter::Trace), 4);
    }

    #[test]
    fn test_get_file_name_with_src() {
        let record = log::RecordBuilder::new()
            .file(Some("/home/user/project/src/main.rs"))
            .build();
        let file_name = get_file_name(&record);
        assert_eq!(file_name, Some("/project/src/main.rs"));
    }

    #[test]
    fn test_get_file_name_without_src() {
        let record = log::RecordBuilder::new()
            .file(Some("/home/user/main.rs"))
            .build();
        let file_name = get_file_name(&record);
        assert_eq!(file_name, Some("/home/user/main.rs"));
    }

    #[test]
    fn test_get_file_name_none() {
        let record = log::RecordBuilder::new().build();
        let file_name = get_file_name(&record);
        assert_eq!(file_name, None);
    }

    #[test]
    fn test_get_file_name_edge_case() {
        let record = log::RecordBuilder::new().file(Some("src/main.rs")).build();
        let file_name = get_file_name(&record);
        // Without a leading slash before "src", it should return the whole path
        assert_eq!(file_name, Some("src/main.rs"));
    }

    #[test]
    fn test_opt_format_info_level() {
        let mut output = Vec::new();
        let mut now = DeferredNow::new();
        let record = log::RecordBuilder::new()
            .level(Level::Info)
            .args(format_args!("test message"))
            .file(Some("test.rs"))
            .line(Some(42))
            .build();

        let result = opt_format(&mut output, &mut now, &record);
        assert!(result.is_ok());
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("INFO"));
        assert!(output_str.contains("test message"));
        // Info level should not include file, but may include other content
        assert!(!output_str.contains("test.rs"));
    }

    #[test]
    fn test_opt_format_debug_level() {
        let mut output = Vec::new();
        let mut now = DeferredNow::new();
        let record = log::RecordBuilder::new()
            .level(Level::Debug)
            .args(format_args!("debug message"))
            .file(Some("/home/user/project/src/test.rs"))
            .line(Some(99))
            .build();

        let result = opt_format(&mut output, &mut now, &record);
        assert!(result.is_ok());
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("DEBUG"));
        assert!(output_str.contains("debug message"));
        // Debug level should include file/line
        assert!(output_str.contains("test.rs"));
        assert!(output_str.contains("99"));
    }

    #[test]
    fn test_opt_format_without_file_info() {
        let mut output = Vec::new();
        let mut now = DeferredNow::new();
        let record = log::RecordBuilder::new()
            .level(Level::Error)
            .args(format_args!("error message"))
            .build();

        let result = opt_format(&mut output, &mut now, &record);
        assert!(result.is_ok());
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("ERROR"));
        assert!(output_str.contains("error message"));
        assert!(output_str.contains("<unnamed>"));
        assert!(output_str.contains(":0"));
    }

    #[test]
    fn test_colored_opt_format_info_level() {
        let mut output = Vec::new();
        let mut now = DeferredNow::new();
        let record = log::RecordBuilder::new()
            .level(Level::Info)
            .args(format_args!("test message"))
            .file(Some("test.rs"))
            .line(Some(42))
            .build();

        let result = colored_opt_format(&mut output, &mut now, &record);
        assert!(result.is_ok());
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("INFO"));
        assert!(output_str.contains("test message"));
    }

    #[test]
    fn test_colored_opt_format_warn_level() {
        let mut output = Vec::new();
        let mut now = DeferredNow::new();
        let record = log::RecordBuilder::new()
            .level(Level::Warn)
            .args(format_args!("warning message"))
            .file(Some("/home/user/project/src/test.rs"))
            .line(Some(123))
            .build();

        let result = colored_opt_format(&mut output, &mut now, &record);
        assert!(result.is_ok());
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("WARN"));
        assert!(output_str.contains("warning message"));
        assert!(output_str.contains("test.rs"));
        assert!(output_str.contains("123"));
    }

    #[test]
    fn test_log_rotation() {
        // Test path parsing logic without actually initializing logger multiple times
        let log_file = PathBuf::from("/tmp/test_log_rotation.log");

        // Verify the path components can be extracted
        assert_eq!(
            log_file.file_stem(),
            Some(std::ffi::OsStr::new("test_log_rotation"))
        );
        assert_eq!(log_file.extension(), Some(std::ffi::OsStr::new("log")));
        assert_eq!(log_file.parent(), Some(std::path::Path::new("/tmp")));
    }

    #[test]
    fn test_path_components_no_extension() {
        let log_file = PathBuf::from("/var/log/myapp");

        assert_eq!(log_file.file_stem(), Some(std::ffi::OsStr::new("myapp")));
        assert_eq!(log_file.extension(), None);
    }

    #[test]
    fn test_path_components_with_extension() {
        let log_file = PathBuf::from("/tmp/myapp.txt");

        assert_eq!(log_file.file_stem(), Some(std::ffi::OsStr::new("myapp")));
        assert_eq!(log_file.extension(), Some(std::ffi::OsStr::new("txt")));
    }
}
