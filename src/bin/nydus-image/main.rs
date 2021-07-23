// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#[macro_use(crate_authors, crate_version)]
extern crate clap;
#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate nydus_utils;

#[macro_use]
mod trace;

mod builder;
mod core;
mod inspect;
mod validator;

#[macro_use]
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate lazy_static;

const BLOB_ID_MAXIMUM_LENGTH: usize = 1024;

use anyhow::{bail, Context, Result};
use clap::{App, Arg, SubCommand};

use std::collections::HashMap;
use std::fs::metadata;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use nix::unistd::{getegid, geteuid};
use serde::Serialize;

use crate::builder::directory::DirectoryBuilder;
use crate::builder::stargz::StargzBuilder;
use crate::builder::Builder;

use crate::core::blob::BlobStorage;
use crate::core::context::BuildContext;
use crate::core::context::SourceType;
use crate::core::context::BUF_WRITER_CAPACITY;
use crate::core::node::{self, ChunkCountMap, WhiteoutSpec};
use crate::core::prefetch::Prefetch;
use crate::core::tree;

use nydus_utils::{digest, setup_logging, BuildTimeInfo};
use rafs::metadata::layout::OndiskBlobTable;
use rafs::RafsIoReader;
use storage::compress;
use trace::{EventTracerClass, TimingTracerClass, TraceClass};
use validator::Validator;

#[derive(Serialize, Default)]
pub struct ResultOutput {
    version: String,
    blobs: Vec<String>,
    trace: serde_json::Map<String, serde_json::Value>,
}

impl ResultOutput {
    fn dump(
        matches: &clap::ArgMatches,
        build_info: &BuildTimeInfo,
        blob_ids: Vec<String>,
    ) -> Result<()> {
        let output_json: Option<PathBuf> = matches
            .value_of("output-json")
            .map(|o| o.to_string().into());

        if let Some(ref f) = output_json {
            let w = OpenOptions::new()
                .truncate(true)
                .create(true)
                .write(true)
                .open(f)
                .with_context(|| format!("Output file {:?} can't be opened", f))?;

            let trace = root_tracer!().dump_summary_map().unwrap_or_default();
            let version = format!("{}-{}", build_info.package_ver, build_info.git_commit);
            let output = Self {
                version,
                trace,
                blobs: blob_ids,
            };

            serde_json::to_writer(w, &output).context("Write output file failed")?;
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    let (bti_string, build_info) = BuildTimeInfo::dump(crate_version!());

    // TODO: Try to use yaml to define below options
    let cmd = App::new("")
        .version(bti_string.as_str())
        .author(crate_authors!())
        .about("Build image using nydus format.")
        .subcommand(
            SubCommand::with_name("create")
                .about("Create a nydus format accelerated container image")
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
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .required(true)
                        .help("A path to bootstrap file which stores nydus image metadata portion")
                        .takes_value(true),
                ).arg(
                    Arg::with_name("blob")
                        .long("blob")
                        .help("A path to blob file which stores nydus image data portion")
                        .required_unless("backend-type")
                        .required_unless("source-type")
                        .required_unless("blob-dir")
                        .takes_value(true)
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
                .arg(
                    Arg::with_name("blob-dir")
                        .long("blob-dir")
                        .help("A directory where blob files are saved named as their sha256 digest. It's very useful when multiple layers are built at the same time.")
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("backend-type")
                        .long("backend-type")
                        .help("[deprecated!] Blob storage backend type, only support localfs for compatibility. Try use --blob instead.")
                        .takes_value(true)
                        .requires("backend-config")
                        .possible_values(&["localfs"]),
                )
                .arg(
                    Arg::with_name("backend-config")
                        .long("backend-config")
                        .help("[deprecated!] Blob storage backend config - JSON string, only support localfs for compatibility")
                        .takes_value(true)
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
        .subcommand(
            SubCommand::with_name("inspect")
                .about("Inspect nydus format")
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .help("bootstrap path")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("request")
                        .long("request")
                        .short("R")
                        .help("Inspect image in request mode")
                        .required(false)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("blob-dir").help("A directory holding all layers related to a single image")
                        .long("blob-dir").required(false)
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
        let source_path = PathBuf::from(matches.value_of("SOURCE").unwrap());
        let source_type: SourceType = matches.value_of("source-type").unwrap().parse()?;

        let source_file = metadata(&source_path)
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
        // For cli/binary interface compatibility sake, keep option `backend-config`, but
        // it only receives "localfs" backend type and it will be REMOVED in the future
        let blob_stor = if source_type == SourceType::Directory {
            Some(
                if let Some(p) = matches
                    .value_of("blob")
                    .map(|b| BlobStorage::SingleFile(b.into()))
                {
                    p
                } else if let Some(d) = matches.value_of("blob-dir").map(PathBuf::from) {
                    if !d.exists() {
                        bail!("Directory holding blobs is not existed")
                    }
                    BlobStorage::BlobsDir(d)
                } else {
                    // Safe because `backend-type` must be specified if `blob` is not with `Directory` source
                    // and `backend-config` must be provided as per clap restriction.
                    // This branch is majorly for compatibility. Hopefully, we can remove this branch.
                    let config_json = matches
                        .value_of("backend-config")
                        .ok_or_else(|| anyhow!("backend-config is not provided"))?;
                    let config: serde_json::Value = serde_json::from_str(config_json).unwrap();
                    warn!("Using --backend-type=localfs is DEPRECATED. Use --blob instead.");
                    if let Some(bf) = config.get("blob_file") {
                        // Even unwrap, it is caused by invalid json. Image creation just can't start.
                        let b: PathBuf = bf.as_str().unwrap().to_string().into();
                        BlobStorage::SingleFile(b)
                    } else {
                        error!("Wrong backend config input!");
                        return Err(anyhow!("invalid backend config"));
                    }
                },
            )
        } else {
            None
        };

        let mut parent_bootstrap_path = Path::new("");
        if let Some(_parent_bootstrap_path) = matches.value_of("parent-bootstrap") {
            parent_bootstrap_path = Path::new(_parent_bootstrap_path);
        }

        let whiteout_spec: WhiteoutSpec = matches
            .value_of("whiteout-spec")
            .unwrap_or_default()
            .parse()?;

        let prefetch_policy = matches
            .value_of("prefetch-policy")
            .unwrap_or_default()
            .parse()?;
        let prefetch = Prefetch::new(prefetch_policy)?;

        let aligned_chunk = matches.is_present("aligned-chunk");

        let f_bootstrap = Box::new(BufWriter::with_capacity(
            BUF_WRITER_CAPACITY,
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(bootstrap_path)
                .with_context(|| format!("failed to create bootstrap file {:?}", bootstrap_path))?,
        ));

        let f_parent_bootstrap: Option<RafsIoReader> = if parent_bootstrap_path != Path::new("") {
            Some(Box::new(
                OpenOptions::new()
                    .read(true)
                    .write(false)
                    .open(parent_bootstrap_path)
                    .with_context(|| {
                        format!(
                            "failed to open parent bootstrap file {:?}",
                            parent_bootstrap_path
                        )
                    })?,
            ))
        } else {
            None
        };

        let mut ctx = BuildContext {
            source_type,
            source_path,
            blob_id,
            f_bootstrap,
            f_parent_bootstrap,
            compressor,
            digester,
            explicit_uidgid: !repeatable,
            whiteout_spec,
            aligned_chunk,
            prefetch,

            lower_inode_map: HashMap::new(),
            upper_inode_map: HashMap::new(),
            chunk_cache: HashMap::new(),
            chunk_count_map: ChunkCountMap::default(),
            blob_table: OndiskBlobTable::new(),
            nodes: Vec::new(),
        };

        let mut builder: Box<dyn Builder> = match source_type {
            SourceType::Directory => {
                Box::new(DirectoryBuilder::new(blob_stor.as_ref().unwrap().clone()))
            }
            SourceType::StargzIndex => Box::new(StargzBuilder::new()),
        };
        let (blob_ids, blob_size) = timing_tracer!(
            { builder.build(&mut ctx).context("build failed") },
            "total_build"
        )?;

        // Some operations like listing xattr pairs of certain namespace need the process
        // to be privileged. Therefore, trace what euid and egid are
        event_tracer!("euid", "{}", geteuid());
        event_tracer!("egid", "{}", getegid());

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

        ResultOutput::dump(matches, &build_info, blob_ids.clone())?;

        info!(
            "Image build(size={}Bytes) successfully. Blobs table: {:?}",
            blob_size, blob_ids
        );
    }

    if let Some(matches) = cmd.subcommand_matches("check") {
        let bootstrap_path = Path::new(matches.value_of("bootstrap").unwrap());
        let mut validator = Validator::new(bootstrap_path)?;
        let blob_ids = validator
            .check(true)
            .with_context(|| format!("failed to check bootstrap {:?}", bootstrap_path))?;

        info!("bootstrap is valid, blobs: {:?}", blob_ids);

        ResultOutput::dump(matches, &build_info, blob_ids)?;
    }

    if let Some(matches) = cmd.subcommand_matches("inspect") {
        // Safe to unwrap since `bootstrap` has default value.
        let bootstrap_path = Path::new(matches.value_of("bootstrap").unwrap());
        let cmd = matches.value_of("request");

        let mut inspector =
            inspect::RafsInspector::new(bootstrap_path, cmd.is_some()).map_err(|e| {
                error!("Failed to instantiate inspector, {:?}", e);
                e
            })?;

        if let Some(c) = cmd {
            let o = inspect::Executor::execute(&mut inspector, c.to_string()).unwrap();
            serde_json::to_writer(std::io::stdout(), &o)
                .unwrap_or_else(|e| error!("Failed to serialize, {:?}", e));
        } else {
            inspect::Prompt::run(inspector);
        }
    }

    Ok(())
}
