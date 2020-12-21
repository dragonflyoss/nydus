// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use(crate_authors, crate_version)]
extern crate clap;
extern crate stderrlog;

mod builder;
mod node;
mod stargz;
mod tree;
mod uploader;
mod validator;

#[macro_use]
extern crate log;
extern crate serde;

const BLOB_ID_MAXIMUM_LENGTH: usize = 1024;

use anyhow::{anyhow, bail, Context, Result};
use clap::{App, Arg, SubCommand};

use std::collections::BTreeMap;
use std::fs::metadata;
use std::io;
use std::path::{Path, PathBuf};

use builder::SourceType;
use node::WhiteoutSpec;
use nydus_utils::{log_level_to_verbosity, BuildTimeInfo};
use rafs::metadata::digest;
use rafs::storage::compress;
use uploader::Uploader;
use validator::Validator;

/// Get readahead file paths line by line from stdin
fn get_readahead_files(source: &Path) -> Result<BTreeMap<PathBuf, Option<u64>>> {
    let stdin = io::stdin();
    let mut files = BTreeMap::new();

    // Can't fail since source must be a legal input option.
    let source_path = source.canonicalize()?;

    loop {
        let mut file = String::new();
        // Files' names as input must exist within source rootfs no matter its relative path or absolute path.
        // Hint path that does not correspond to an existed file will be discarded and throw warn logs.
        // Absolute path must point to a file in source rootfs.
        // Relative path must point to a file in source rootfs.
        // All paths must conform to format `/rootfs/dir/file` when added to BTree.
        let size = stdin
            .read_line(&mut file)
            .context(format!("failed to parse readahead files from {:?}", source))?;
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

        debug!(
            "readahead file: {}, trimmed file name {}",
            file_name,
            file_name_trimmed.to_str().unwrap()
        );
        // The inode index is not decided yet, but will do during fs-walk.
        files.insert(file_name_trimmed, None);
    }

    Ok(files)
}

fn main() -> Result<()> {
    let bti: String = BuildTimeInfo::dump(crate_version!());

    let cmd = App::new("nydus image builder")
        .version(bti.as_str())
        .author(crate_authors!())
        .about("Build image using nydus format.")
        .subcommand(
            SubCommand::with_name("create")
                .about("dump image bootstrap and upload blob to storage backend")
                .arg(
                    Arg::with_name("SOURCE")
                        .help("source path")
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
                        .takes_value(true)
                        .conflicts_with("backend-type"),
                )
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .required(true)
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
                        .help("blob storage backend type (enable blob upload if specified)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("backend-config")
                        .long("backend-config")
                        .help("blob storage backend config (JSON string)")
                        .takes_value(true)
                        .conflicts_with("backend-config-file"),
                )
                .arg(
                    Arg::with_name("backend-config-file")
                        .long("backend-config-file")
                        .help("blob storage backend config (JSON file)")
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
                .arg(
                    Arg::with_name("whiteout-spec")
                    .long("whiteout-spec")
                    .help("decide which whiteout spec to follow: \"oci\" or \"overlayfs\"")
                    .takes_value(true)
                    .required(true)
                    .possible_values(&["oci", "overlayfs"])
                    .default_value("oci")
                )
        )
        .subcommand(
            SubCommand::with_name("check")
                .about("validate image bootstrap")
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .help("bootstrap file path (required)")
                        .required(true)
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
        .context("failed to init logger")?;

    if let Some(matches) = cmd.subcommand_matches("create") {
        let source_path = Path::new(matches.value_of("SOURCE").unwrap());
        let source_type: SourceType = matches.value_of("source-type").unwrap().parse()?;

        let source_file = metadata(source_path)
            .context(format!("failed to get source path {:?}", source_path))?;

        let mut blob_id = String::new();
        if let Some(p_blob_id) = matches.value_of("blob-id") {
            blob_id = String::from(p_blob_id);
            if blob_id.len() > BLOB_ID_MAXIMUM_LENGTH {
                bail!("blob id is limited to length {}", BLOB_ID_MAXIMUM_LENGTH);
            }
        }

        let mut compressor = matches.value_of("compressor").unwrap_or_default().parse()?;
        let mut digester = matches.value_of("digester").unwrap_or_default().parse()?;
        let repeatable = matches.is_present("repeatable");

        match source_type {
            SourceType::Directory => {
                if !source_file.is_dir() {
                    bail!("source {:?} must be a directory", source_path);
                }
            }
            SourceType::StargzIndex => {
                if !source_file.is_file() {
                    bail!("source {:?} must be a JSON file", source_path);
                }
                if blob_id.trim() == "" {
                    bail!("blob-id can't be empty");
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

        let bootstrap_path = Path::new(matches.value_of("bootstrap").unwrap());

        let mut uploader = None;
        let mut blob_path = match matches.value_of("blob") {
            Some(p) => Some(PathBuf::from(p)),
            None => {
                if source_type == SourceType::Directory {
                    let backend_type = matches
                        .value_of("backend-type")
                        .ok_or_else(|| anyhow!("blob or backend-type must be specified"))?;

                    let real_uploader =
                        if let Some(backend_config) = matches.value_of("backend-config") {
                            Uploader::from_config_str(backend_type, backend_config)?
                        } else if let Some(backend_config_file) =
                            matches.value_of("backend-config-file")
                        {
                            Uploader::from_config_file(backend_type, backend_config_file)?
                        } else {
                            bail!("backend-config or backend-config-file must be specified")
                        };

                    let blob_path = Some(real_uploader.blob_path.clone());
                    uploader = Some(real_uploader);
                    blob_path
                } else {
                    None
                }
            }
        };

        let mut parent_bootstrap = Path::new("");
        if let Some(_parent_bootstrap) = matches.value_of("parent-bootstrap") {
            parent_bootstrap = Path::new(_parent_bootstrap);
        }

        let prefetch_policy = matches
            .value_of("prefetch-policy")
            .unwrap_or_default()
            .parse()?;

        let hint_readahead_files = if prefetch_policy != builder::PrefetchPolicy::None {
            get_readahead_files(source_path).context("failed to get readahead files")?
        } else {
            BTreeMap::new()
        };

        let whiteout_spec: WhiteoutSpec = matches
            .value_of("whiteout-spec")
            .unwrap_or_default()
            .parse()?;

        let mut ib = builder::Builder::new(
            source_type,
            source_path,
            blob_path.as_deref(),
            bootstrap_path,
            parent_bootstrap,
            blob_id,
            compressor,
            digester,
            hint_readahead_files,
            prefetch_policy,
            !repeatable,
            whiteout_spec,
        )?;
        let (blob_ids, blob_size) = ib.build().context("build failed")?;

        // Validate output bootstrap file
        if !matches.is_present("disable-check") {
            let mut validator = Validator::new(&bootstrap_path)?;
            let valid = validator
                .check(false)
                .context("failed to validate bootstrap")?;
            if !valid {
                bail!("failed to build bootstrap");
            }
        }

        if blob_size > 0 {
            // Upload blob file
            if let Some(uploader) = uploader {
                let blob_id = blob_ids.last().unwrap();
                blob_path = uploader.upload(blob_id)?;
            }
            if let Some(blob_path) = blob_path.as_ref() {
                info!(
                    "build finished, blob id: {:?}, blob file: {:?}",
                    blob_ids, blob_path,
                );
            } else {
                info!("build finished, blob id: {:?}", blob_ids);
            }
        } else {
            info!("build finished, no blob output");
        }
    }

    if let Some(matches) = cmd.subcommand_matches("check") {
        let bootstrap_path = Path::new(matches.value_of("bootstrap").unwrap());
        let mut validator = Validator::new(bootstrap_path)?;
        let valid = validator
            .check(true)
            .with_context(|| format!("failed to check bootstrap {:?}", bootstrap_path))?;
        if valid {
            info!("bootstrap is valid");
        } else {
            bail!("bootstrap is invalid");
        }
    }

    Ok(())
}
