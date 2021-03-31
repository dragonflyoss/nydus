// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use(crate_authors, crate_version)]
extern crate clap;

#[macro_use]
mod trace;

mod builder;
mod node;
mod stargz;
mod tree;
mod validator;

#[macro_use]
extern crate log;
extern crate serde;
#[macro_use]
extern crate lazy_static;

const BLOB_ID_MAXIMUM_LENGTH: usize = 1024;

use anyhow::{bail, Context, Result};
use clap::{App, Arg, SubCommand};

use std::collections::BTreeMap;
use std::fs::metadata;
use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};

use nix::unistd::{getegid, geteuid};
use serde::Serialize;

use builder::SourceType;
use node::WhiteoutSpec;
use nydus_utils::{digest, setup_logging, BuildTimeInfo};
use storage::compress;
use trace::{EventTracerClass, TimingTracerClass, TraceClass};
use validator::Validator;

#[derive(Serialize, Default)]
pub struct ResultOutput {
    blobs: Vec<String>,
    trace: serde_json::Map<String, serde_json::Value>,
}

impl ResultOutput {
    fn dump<W>(&self, writer: W) -> Result<()>
    where
        W: io::Write,
    {
        serde_json::to_writer(writer, &self).context("Write output file failed")
    }
}

fn dump_result_output(matches: &clap::ArgMatches, blob_ids: Vec<String>) -> Result<()> {
    let output_json: Option<PathBuf> = matches
        .value_of("output-json")
        .map(|o| o.to_string().into());

    if let Some(ref f) = output_json {
        let w = OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .open(f)
            .with_context(|| format!("{:?} can't be opened", f))?;

        let trace = root_tracer!().dump_summary_map().unwrap_or_default();

        ResultOutput {
            trace,
            blobs: blob_ids,
        }
        .dump(w)?;
    }

    Ok(())
}

/// Gather readahead file paths line by line from stdin
/// Input format:
///    printf "/relative/path/to/rootfs/1\n/relative/path/to/rootfs/1"
/// This routine does not guarantee that specified file must exist in local filesystem,
/// this is because we can't guarantee that source rootfs directory of parent bootstrap
/// is located in local file system.
fn gather_readahead_files() -> Result<BTreeMap<PathBuf, Option<u64>>> {
    let stdin = io::stdin();
    let mut files = BTreeMap::new();

    loop {
        let mut file = String::new();

        let size = stdin
            .read_line(&mut file)
            .context("failed to parse readahead files")?;
        if size == 0 {
            break;
        }
        let file_trimmed: PathBuf = file.trim().into();
        // Sanity check for the list format.
        if !file_trimmed.starts_with(Path::new("/")) {
            warn!(
                "Illegal file path specified. It {:?} must start with '/'",
                file
            );
            continue;
        }

        debug!(
            "readahead file: {}, trimmed file name {:?}",
            file, file_trimmed
        );
        // The inode index is not decided yet, but will do during fs-walk.
        files.insert(file_trimmed, None);
    }

    Ok(files)
}

fn main() -> Result<()> {
    let (bti_string, _) = BuildTimeInfo::dump(crate_version!());

    let cmd = App::new("nydus image builder")
        .version(bti_string.as_str())
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
                        .required(true)
                        .takes_value(true)
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
                        .help("blob id (as object id in backend/oss)")
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
                .arg(
                    Arg::with_name("output-json")
                        .long("output-json")
                        .help("JSON output path for build result")
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("aligned-chunk")
                        .long("aligned-chunk")
                        .help("Whether to align chunks into blobcache")
                        .takes_value(false)
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
                .arg(
                    Arg::with_name("output-json")
                        .long("output-json")
                        .help("JSON output path for check result")
                        .takes_value(true)
                )
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .default_value("info")
                .help("Specify log level: trace, debug, info, warn, error")
                .takes_value(true)
                .possible_values(&["trace", "debug", "info", "warn", "error"])
                .required(false)
                .global(true),
        )
        .get_matches();

    // Safe to unwrap because it has default value and possible values are defined.
    let level = cmd.value_of("log-level").unwrap().parse().unwrap();
    setup_logging(None, level)?;

    // FIXME: only register tracer in `create` subcommand.
    register_tracer!(TraceClass::Timing, TimingTracerClass);
    register_tracer!(TraceClass::Event, EventTracerClass);

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

        // Must specify a path to blob file.
        // Safe to unwrap because it is marked as required parameter.
        let blob_path: PathBuf = matches.value_of("blob").map(|b| b.into()).unwrap();

        let mut parent_bootstrap = Path::new("");
        if let Some(_parent_bootstrap) = matches.value_of("parent-bootstrap") {
            parent_bootstrap = Path::new(_parent_bootstrap);
        }

        let prefetch_policy = matches
            .value_of("prefetch-policy")
            .unwrap_or_default()
            .parse()?;

        let hint_readahead_files = if prefetch_policy != builder::PrefetchPolicy::None {
            gather_readahead_files().context("failed to get readahead files")?
        } else {
            BTreeMap::new()
        };

        let whiteout_spec: WhiteoutSpec = matches
            .value_of("whiteout-spec")
            .unwrap_or_default()
            .parse()?;

        let aligned_chunk = matches.is_present("aligned-chunk");

        // External tool like `nydusify` might rename the blob to a OCI distribution compatible one.
        let mut ib = builder::Builder::new(
            source_type,
            source_path,
            &blob_path,
            bootstrap_path,
            parent_bootstrap,
            blob_id,
            compressor,
            digester,
            hint_readahead_files,
            prefetch_policy,
            !repeatable,
            whiteout_spec,
            aligned_chunk,
        )?;

        // Some operations like listing xattr pairs of certain namespace need the process
        // to be privileged. Therefore, trace what euid and egid are
        event_tracer!("euid", "{}", geteuid());
        event_tracer!("egid", "{}", getegid());

        let (blob_ids, blob_size) =
            timing_tracer!({ ib.build().context("build failed") }, "total_build")?;

        // Validate output bootstrap file
        if !matches.is_present("disable-check") {
            let mut validator = Validator::new(&bootstrap_path)?;
            timing_tracer!(
                {
                    validator
                        .check(false)
                        .context("failed to validate bootstrap")
                },
                "validate_bootstrap"
            )?;
        }

        dump_result_output(matches, blob_ids.clone())?;

        if blob_size > 0 {
            info!(
                "build finished, blob id: {:?}, blob file: {:?}",
                blob_ids, blob_path,
            );
        } else {
            info!("build finished, no blob output");
        }
    }

    if let Some(matches) = cmd.subcommand_matches("check") {
        let bootstrap_path = Path::new(matches.value_of("bootstrap").unwrap());
        let mut validator = Validator::new(bootstrap_path)?;
        let blob_ids = validator
            .check(true)
            .with_context(|| format!("failed to check bootstrap {:?}", bootstrap_path))?;

        info!("bootstrap is valid, blobs: {:?}", blob_ids);

        dump_result_output(matches, blob_ids)?;
    }

    Ok(())
}
