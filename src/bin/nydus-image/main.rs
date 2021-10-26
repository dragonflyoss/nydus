// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]
#[macro_use(crate_authors, crate_version)]
extern crate clap;
#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate log;
extern crate serde;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate lazy_static;

use std::fs::metadata;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{App, Arg, SubCommand};
use nix::unistd::{getegid, geteuid};
use serde::Serialize;

use nydus_app::{setup_logging, BuildTimeInfo};
use nydus_utils::digest;
use rafs::RafsIoReader;
use storage::{compress, RAFS_DEFAULT_CHUNK_SIZE};

use crate::builder::{Builder, DirectoryBuilder, StargzBuilder};
use crate::core::chunk_dict::import_chunk_dict;
use crate::core::context::{
    BlobManager, BlobStorage, BootstrapContext, BuildContext, RafsVersion, SourceType,
    BUF_WRITER_CAPACITY,
};
use crate::core::node::{self, WhiteoutSpec};
use crate::core::prefetch::Prefetch;
use crate::core::tree;
use crate::trace::{EventTracerClass, TimingTracerClass, TraceClass};
use crate::validator::Validator;

#[macro_use]
mod trace;
mod builder;
mod core;
mod inspect;
mod validator;

const BLOB_ID_MAXIMUM_LENGTH: usize = 255;

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
        .about("Build or inspect RAFS filesystems for nydus accelerated container images.")
        .subcommand(
            SubCommand::with_name("create")
                .about("Creates a nydus image from source")
                .arg(
                    Arg::with_name("SOURCE")
                        .help("source path to build the nydus image from")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("source-type")
                        .long("source-type")
                        .short("t")
                        .help("type of the source:")
                        .takes_value(true)
                        .default_value("directory")
                        .possible_values(&["directory", "stargz_index"])
                )
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .short("B")
                        .help("path to store the nydus image's metadata blob")
                        .required(true)
                        .takes_value(true),
                ).arg(
                    Arg::with_name("blob")
                        .long("blob")
                        .short("b")
                        .help("path to store nydus image's data blob")
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
                        .short("c")
                        .help("algorithm to compress image data blob:")
                        .takes_value(true)
                        .required(false)
                        .default_value("lz4_block")
                        .possible_values(&["none", "lz4_block", "gzip"]),
                )
                .arg(
                    Arg::with_name("digester")
                        .long("digester")
                        .short("d")
                        .help("algorithm to digest inodes and data chunks:")
                        .takes_value(true)
                        .required(false)
                        .default_value("blake3")
                        .possible_values(&["blake3", "sha256"]),
                )
                .arg(
                    Arg::with_name("parent-bootstrap")
                        .long("parent-bootstrap")
                        .short("p")
                        .help("path to parent/referenced image's metadata blob (optional)")
                        .takes_value(true)
                        .required(false),
                )
                .arg(
                    Arg::with_name("prefetch-policy")
                        .long("prefetch-policy")
                        .short("P")
                        .help("Prefetch policy:")
                        .takes_value(true)
                        .required(false)
                        .default_value("none")
                        .possible_values(&["fs", "blob", "none"]),
                )
                .arg(
                    Arg::with_name("repeatable")
                        .long("repeatable")
                        .short("R")
                        .help("Generate reproducible nydus image")
                        .takes_value(false)
                        .required(false),
                )
                .arg(
                    Arg::with_name("disable-check")
                        .long("disable-check")
                        .help("Disable validation of metadata after building")
                        .takes_value(false)
                        .required(false)
                )
                .arg(
                    Arg::with_name("whiteout-spec")
                        .long("whiteout-spec")
                        .short("W")
                        .help("Type of whiteout specification:")
                        .takes_value(true)
                        .required(true)
                        .default_value("oci")
                        .possible_values(&["oci", "overlayfs"])
                )
                .arg(
                    Arg::with_name("output-json")
                        .long("output-json")
                        .short("J")
                        .help("JSON output path for build result")
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("aligned-chunk")
                        .long("aligned-chunk")
                        .short("A")
                        .help("Align data chunks to 4K")
                        .takes_value(false)
                )
                .arg(
                    Arg::with_name("blob-dir")
                        .long("blob-dir")
                        .short("D")
                        .help("Directory to store nydus image's metadata and data blob")
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("chunk-dict")
                        .long("chunk-dict")
                        .short("M")
                        .help("Specify a chunk dictionary for chunk deduplication")
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
                .about("Validates nydus image's filesystem metadata")
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .short("B")
                        .help("path to nydus image's metadata blob (required)")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("verbose")
                        .long("verbose")
                        .short("V")
                        .help("verbose output")
                        .required(false),
                )
                .arg(
                    Arg::with_name("output-json")
                        .long("output-json")
                        .short("J")
                        .help("path to JSON output file")
                        .takes_value(true)
                )
        )
        .subcommand(
            SubCommand::with_name("inspect")
                .about("Inspects nydus image's filesystem metadata")
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .short("B")
                        .help("path to nydus image's metadata blob (required)")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("request")
                        .long("request")
                        .short("R")
                        .help("Inspect nydus image's filesystem metadata in request mode")
                        .required(false)
                        .takes_value(true),
                )
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .short("l")
                .help("Specify log level:")
                .default_value("info")
                .possible_values(&["trace", "debug", "info", "warn", "error"])
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .get_matches();

    // Safe to unwrap because it has a default value and possible values are defined.
    let level = cmd.value_of("log-level").unwrap().parse().unwrap();
    setup_logging(None, level)?;

    register_tracer!(TraceClass::Timing, TimingTracerClass);
    register_tracer!(TraceClass::Event, EventTracerClass);

    if let Some(matches) = cmd.subcommand_matches("create") {
        Command::create(matches, &build_info)
    } else if let Some(matches) = cmd.subcommand_matches("check") {
        Command::check(matches, &build_info)
    } else if let Some(matches) = cmd.subcommand_matches("inspect") {
        Command::inspect(matches)
    } else {
        println!("{}", cmd.usage());
        Ok(())
    }
}

struct Command {}

impl Command {
    fn create(matches: &clap::ArgMatches, build_info: &BuildTimeInfo) -> Result<()> {
        let aligned_chunk = matches.is_present("aligned-chunk");
        let blob_id = Self::get_blob_id(&matches)?;
        let bootstrap_path = Self::get_bootstrap(&matches)?;
        let parent_bootstrap = Self::get_parent_bootstrap(&matches)?;
        let source_path = PathBuf::from(matches.value_of("SOURCE").unwrap());
        let source_type: SourceType = matches.value_of("source-type").unwrap().parse()?;
        let blob_stor = Self::get_blob_storage(&matches, source_type)?;
        let repeatable = matches.is_present("repeatable");
        let whiteout_spec: WhiteoutSpec = matches
            .value_of("whiteout-spec")
            .unwrap_or_default()
            .parse()?;

        let mut compressor = matches.value_of("compressor").unwrap_or_default().parse()?;
        let mut digester = matches.value_of("digester").unwrap_or_default().parse()?;
        match source_type {
            SourceType::Directory => {
                let source_file = metadata(&source_path)
                    .context(format!("failed to get source path {:?}", source_path))?;
                if !source_file.is_dir() {
                    bail!("source {:?} must be a directory", source_path);
                }
            }
            SourceType::StargzIndex => {
                let source_file = metadata(&source_path)
                    .context(format!("failed to get source path {:?}", source_path))?;
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

        let prefetch_policy = matches
            .value_of("prefetch-policy")
            .unwrap_or_default()
            .parse()?;
        let prefetch = Prefetch::new(prefetch_policy)?;

        let bootstrap = Box::new(BufWriter::with_capacity(
            BUF_WRITER_CAPACITY,
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(bootstrap_path)
                .with_context(|| format!("failed to create bootstrap file {:?}", bootstrap_path))?,
        ));
        let mut bootstrap_ctx = BootstrapContext::new(bootstrap, parent_bootstrap);

        let mut build_ctx = BuildContext::new(
            blob_id,
            aligned_chunk,
            compressor,
            digester,
            !repeatable,
            whiteout_spec,
            source_type,
            source_path,
            prefetch,
            blob_stor,
        );
        build_ctx.set_fs_version(RafsVersion::V5);
        build_ctx.set_chunk_size(RAFS_DEFAULT_CHUNK_SIZE as u32);

        let mut blob_mgr = BlobManager::new();

        if let Some(chunk_dict_arg) = matches.value_of("chunk-dict") {
            blob_mgr.set_chunk_dict(timing_tracer!(
                { import_chunk_dict(chunk_dict_arg) },
                "import_chunk_dict"
            )?);
        }

        let mut builder: Box<dyn Builder> = match source_type {
            SourceType::Directory => Box::new(DirectoryBuilder::new()),
            SourceType::StargzIndex => Box::new(StargzBuilder::new()),
        };
        let (blob_ids, blob_size) = timing_tracer!(
            {
                builder
                    .build(&mut build_ctx, &mut bootstrap_ctx, &mut blob_mgr)
                    .context("build failed")
            },
            "total_build"
        )?;

        // Some operations like listing xattr pairs of certain namespace need the process
        // to be privileged. Therefore, trace what euid and egid are
        event_tracer!("euid", "{}", geteuid());
        event_tracer!("egid", "{}", getegid());

        // Validate output bootstrap file
        Self::validate_image(&matches, &bootstrap_path)?;
        ResultOutput::dump(matches, &build_info, blob_ids.clone())?;
        info!(
            "Image build(size={}Bytes) successfully. Blobs table: {:?}",
            blob_size, blob_ids
        );

        Ok(())
    }

    fn check(matches: &clap::ArgMatches, build_info: &BuildTimeInfo) -> Result<()> {
        let bootstrap_path = Self::get_bootstrap(matches)?;
        let verbose = matches.is_present("verbose");
        let mut validator = Validator::new(bootstrap_path)?;
        let blob_ids = validator
            .check(verbose)
            .with_context(|| format!("failed to check bootstrap {:?}", bootstrap_path))?;

        info!("bootstrap is valid, blobs: {:?}", blob_ids);
        ResultOutput::dump(matches, &build_info, blob_ids)?;

        Ok(())
    }

    fn inspect(matches: &clap::ArgMatches) -> Result<()> {
        let bootstrap_path = Self::get_bootstrap(matches)?;
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

        Ok(())
    }

    fn get_bootstrap<'a>(matches: &'a clap::ArgMatches) -> Result<&'a Path> {
        match matches.value_of("bootstrap") {
            None => bail!("missing parameter `bootstrap`"),
            Some(s) => Ok(Path::new(s)),
        }
    }

    // Must specify a path to blob file.
    // For cli/binary interface compatibility sake, keep option `backend-config`, but
    // it only receives "localfs" backend type and it will be REMOVED in the future
    fn get_blob_storage(
        matches: &clap::ArgMatches,
        source_type: SourceType,
    ) -> Result<Option<BlobStorage>> {
        // Must specify a path to blob file.
        // For cli/binary interface compatibility sake, keep option `backend-config`, but
        // it only receives "localfs" backend type and it will be REMOVED in the future
        let blob_stor = if source_type == SourceType::Directory {
            if let Some(p) = matches
                .value_of("blob")
                .map(|b| BlobStorage::SingleFile(b.into()))
            {
                Some(p)
            } else if let Some(d) = matches.value_of("blob-dir").map(PathBuf::from) {
                if !d.exists() {
                    bail!("Directory holding blobs is not existed")
                }
                Some(BlobStorage::BlobsDir(d))
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
                    Some(BlobStorage::SingleFile(b))
                } else {
                    error!("Wrong backend config input!");
                    return Err(anyhow!("invalid backend config"));
                }
            }
        } else {
            None
        };

        Ok(blob_stor)
    }

    fn get_parent_bootstrap(matches: &clap::ArgMatches) -> Result<Option<RafsIoReader>> {
        let mut parent_bootstrap_path = Path::new("");
        if let Some(_parent_bootstrap_path) = matches.value_of("parent-bootstrap") {
            parent_bootstrap_path = Path::new(_parent_bootstrap_path);
        }

        if parent_bootstrap_path != Path::new("") {
            Ok(Some(Box::new(
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
            )))
        } else {
            Ok(None)
        }
    }

    fn get_blob_id(matches: &clap::ArgMatches) -> Result<String> {
        let mut blob_id = String::new();

        if let Some(p_blob_id) = matches.value_of("blob-id") {
            blob_id = String::from(p_blob_id);
            if blob_id.len() > BLOB_ID_MAXIMUM_LENGTH {
                bail!("blob id is limited to length {}", BLOB_ID_MAXIMUM_LENGTH);
            }
        }

        Ok(blob_id)
    }

    fn validate_image(matches: &clap::ArgMatches, bootstrap_path: &Path) -> Result<()> {
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

        Ok(())
    }
}
