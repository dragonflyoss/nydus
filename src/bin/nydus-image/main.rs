// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use(crate_version, crate_authors)]
extern crate clap;
extern crate stderrlog;

mod builder;
mod node;
mod stargz;
mod tree;
mod validator;

#[macro_use]
extern crate log;
extern crate serde;

const BLOB_ID_MAXIMUM_LENGTH: usize = 1024;

use clap::{App, Arg, SubCommand};
use vmm_sys_util::tempfile::TempFile;

use std::collections::BTreeMap;
use std::fs::metadata;
use std::fs::rename;
use std::io::{self, Result, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use builder::SourceType;
use nydus_utils::einval;
use nydus_utils::log_level_to_verbosity;
use rafs::metadata::digest;
use rafs::storage::{backend, compress, factory};
use validator::Validator;

fn upload_blob(
    backend: Arc<dyn backend::BlobBackendUploader>,
    blob_id: &str,
    blob_path: &Path,
) -> Result<()> {
    backend
        .upload(blob_id, blob_path, |(current, total)| {
            io::stdout().flush().unwrap();
            print!("\r");
            print!(
                "Backend blob uploading: {}/{} bytes ({}%)",
                current,
                total,
                current * 100 / total,
            );
        })
        .map_err(|e| {
            error!("upload_blob backend.upload {:?}", e);
            e
        })?;

    print!("\r");
    io::stdout().flush().unwrap();

    Ok(())
}

/// Get readahead file paths line by line from stdin
fn get_readahead_files(source: &Path) -> Result<BTreeMap<PathBuf, Option<u64>>> {
    let stdin = io::stdin();
    let mut files = BTreeMap::new();

    // Can't fail since source must be a legal input option.
    let source_path = source.canonicalize().unwrap();

    loop {
        let mut file = String::new();
        // Files' names as input must exist within source rootfs no matter its relative path or absolute path.
        // Hint path that does not correspond to an existed file will be discarded and throw warn logs.
        // Absolute path must point to a file in source rootfs.
        // Relative path must point to a file in source rootfs.
        // All paths must conform to format `/rootfs/dir/file` when added to BTree.
        let ret = stdin.read_line(&mut file);
        match ret {
            Ok(size) => {
                if size == 0 {
                    break;
                }
                let file_name = file.trim();
                if file_name.is_empty() {
                    continue;
                }
                let path = Path::new(file_name);
                // Will follow symlink.
                if !path.exists() {
                    warn!("{} does not exist, ignore it!", path.to_str().unwrap());
                    continue;
                }

                let canonicalized_name;
                match path.canonicalize() {
                    Ok(p) => {
                        if !p.starts_with(&source_path) {
                            continue;
                        }
                        canonicalized_name = p;
                    }
                    Err(_) => continue,
                }

                let file_name_trimmed = Path::new("/").join(
                    canonicalized_name
                        .strip_prefix(&source_path)
                        .unwrap()
                        .to_path_buf(),
                );

                // FIXME: Temporarily raise log level up, for devel/debug sake.
                debug!(
                    "readahead file: {}, trimmed file name {}",
                    file_name,
                    file_name_trimmed.to_str().unwrap()
                );
                // The inode index is not decided yet, but will do during fs-walk.
                files.insert(file_name_trimmed, None);
            }
            Err(err) => {
                error!("Failed to parse readahead files: {}", err);
            }
        }
    }

    Ok(files)
}

fn main() -> Result<()> {
    let cmd = App::new("nydus image builder")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Build image using nydus format.")
        .subcommand(
            SubCommand::with_name("create")
                .about("dump image bootstrap and upload blob to storage backend")
                .arg(
                    Arg::with_name("SOURCE")
                        .help("source directory")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("source-type")
                        .long("source-type")
                        .help("source type")
                        .takes_value(true)
                        .default_value("directory")
                        .possible_values(&["directory", "stargz_index"])
                )
                .arg(
                    Arg::with_name("blob")
                        .long("blob")
                        .help("blob file path")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .help("bootstrap file path (required)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("blob-id")
                        .long("blob-id")
                        .help("blob id (as object id in backend)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("compressor")
                        .long("compressor")
                        .help("how blob will be compressed: none, lz4_block (default)")
                        .takes_value(true)
                        .required(false)
                        .default_value("lz4_block"),
                )
                .arg(
                    Arg::with_name("digester")
                        .long("digester")
                        .help("how inode and blob chunk will be digested: blake3 (default), sha256")
                        .takes_value(true)
                        .required(false)
                        .default_value("blake3"),
                )
                .arg(
                    Arg::with_name("parent-bootstrap")
                        .long("parent-bootstrap")
                        .help("bootstrap file path of parent (optional)")
                        .takes_value(true)
                        .required(false),
                )
                .arg(
                    Arg::with_name("backend-type")
                        .long("backend-type")
                        .help("blob storage backend type (enable backend upload if specified)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("backend-config")
                        .long("backend-config")
                        .help("blob storage backend config (json)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("prefetch-policy")
                        .long("prefetch-policy")
                        .help("Prefetch policy: fs(issued from Fs layer), blob(issued from backend/blob layer), none(no readahead is needed)")
                        .takes_value(true)
                        .required(false)
                        .default_value("none"),
                )
                .arg(
                    Arg::with_name("repeatable")
                    .long("repeatable")
                    .help("Produce environment independent image")
                    .takes_value(false)
                    .required(false),
                )
                .arg(
                    Arg::with_name("disable-check")
                    .long("disable-check")
                    .help("Disable to validate bootstrap file after building")
                    .takes_value(false)
                    .required(false)
                )
        )
        .subcommand(
            SubCommand::with_name("check")
                .about("validate image bootstrap")
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .help("bootstrap file path (required)")
                        .takes_value(true),
                )
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .default_value("info")
                .help("Specify log level: trace, debug, info, warn, error")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .get_matches();

    let v = cmd
        .value_of("log-level")
        .unwrap()
        .parse()
        .unwrap_or(log::LevelFilter::Warn);

    stderrlog::new()
        .quiet(false)
        .verbosity(log_level_to_verbosity(v))
        .timestamp(stderrlog::Timestamp::Second)
        .init()
        .unwrap();

    if let Some(matches) = cmd.subcommand_matches("create") {
        let source_path = Path::new(matches.value_of("SOURCE").expect("SOURCE is required"));
        let source_type: SourceType = matches
            .value_of("source-type")
            .expect("source-type is required")
            .parse()?;

        let source_file = metadata(source_path)
            .map_err(|e| einval!(format!("failed to get source path {:?}", e)))?;

        let mut blob_id = String::new();
        if let Some(p_blob_id) = matches.value_of("blob-id") {
            blob_id = String::from(p_blob_id);
            if blob_id.len() > BLOB_ID_MAXIMUM_LENGTH {
                return Err(einval!(format!(
                    "blob id is limited to length {}",
                    BLOB_ID_MAXIMUM_LENGTH
                )));
            }
        }

        let mut compressor = matches.value_of("compressor").unwrap_or_default().parse()?;
        let mut digester = matches.value_of("digester").unwrap_or_default().parse()?;
        let repeatable = matches.is_present("repeatable");

        match source_type {
            SourceType::Directory => {
                if !source_file.is_dir() {
                    return Err(einval!("source must be a directory"));
                }
            }
            SourceType::StargzIndex => {
                if !source_file.is_file() {
                    return Err(einval!("source must be a JSON file"));
                }
                if blob_id.trim() == "" {
                    return Err(einval!("blob-id can't be empty"));
                }
                if compressor != compress::Algorithm::GZip {
                    trace!("compressor set to {}", compress::Algorithm::GZip);
                }
                compressor = compress::Algorithm::GZip;
                if digester != digest::Algorithm::Sha256 {
                    trace!("digester set to {}", digest::Algorithm::Sha256);
                }
                digester = digest::Algorithm::Sha256;
            }
        }

        let bootstrap_path = Path::new(
            matches
                .value_of("bootstrap")
                .expect("bootstrap is required"),
        );

        let temp_file = TempFile::new_with_prefix("").unwrap();

        let mut blob_path = matches
            .value_of("blob")
            .map(|p| Path::new(p))
            .unwrap_or_else(|| temp_file.as_path());

        let mut parent_bootstrap = Path::new("");
        if let Some(_parent_bootstrap) = matches.value_of("parent-bootstrap") {
            parent_bootstrap = Path::new(_parent_bootstrap);
        }

        let prefetch_policy = matches
            .value_of("prefetch-policy")
            .unwrap_or_default()
            .parse()?;

        let hint_readahead_files = if prefetch_policy != builder::PrefetchPolicy::None {
            get_readahead_files(source_path)?
        } else {
            BTreeMap::new()
        };

        let mut ib = builder::Builder::new(
            source_type,
            source_path,
            blob_path,
            bootstrap_path,
            parent_bootstrap,
            blob_id,
            compressor,
            digester,
            hint_readahead_files,
            prefetch_policy,
            !repeatable,
        )?;
        let (blob_ids, blob_size) = ib.build()?;

        // Validate output bootstrap file
        if !matches.is_present("disable-check") {
            let mut validator = Validator::new(&bootstrap_path)?;
            match validator.check(false) {
                Ok(valid) => {
                    if !valid {
                        return Err(einval!("Failed to build bootstrap from source"));
                    }
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }

        // Upload blob file
        if blob_size > 0 {
            let blob_id = blob_ids.last().unwrap();
            let mut uploaded = false;
            if let Some(backend_type) = matches.value_of("backend-type") {
                if let Some(backend_config) = matches.value_of("backend-config") {
                    let config = factory::BackendConfig {
                        backend_type: backend_type.to_owned(),
                        backend_config: serde_json::from_str(backend_config).map_err(|e| {
                            error!("failed to parse backend_config json: {}", e);
                            e
                        })?,
                    };
                    let blob_backend = factory::new_uploader(config).unwrap();
                    upload_blob(blob_backend, blob_id.as_str(), blob_path)?;
                    uploaded = true;
                }
            }
            // blob not uploaded to backend, let's save it to local file system
            if !uploaded && blob_path == temp_file.as_path() {
                trace!("rename {:?} to {}", blob_path, blob_id);
                rename(blob_path, blob_id)?;
                blob_path = Path::new(blob_id);
            }
        }

        if blob_size > 0 {
            info!(
                "build finished, blob id: {:?}, blob file: {:?}",
                blob_ids, blob_path
            );
        } else {
            info!("build finished, blob id: {:?}", blob_ids);
        }
    }

    if let Some(matches) = cmd.subcommand_matches("check") {
        let bootstrap_path = Path::new(
            matches
                .value_of("bootstrap")
                .expect("bootstrap is required"),
        );
        let mut validator = Validator::new(bootstrap_path)?;
        match validator.check(true) {
            Ok(valid) => {
                if valid {
                    info!("Bootstrap is valid");
                } else {
                    return Err(einval!("Bootstrap is invalid"));
                }
            }
            Err(err) => {
                return Err(err);
            }
        }
    }

    Ok(())
}
