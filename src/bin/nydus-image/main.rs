// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]
#[macro_use(crate_authors)]
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

use std::fs::{self, metadata, DirEntry, File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{App, Arg, ArgMatches, SubCommand};
use nix::unistd::{getegid, geteuid};
use nydus_api::http::BackendConfig;
use nydus_app::{setup_logging, BuildTimeInfo};
use nydus_rafs::metadata::RafsVersion;
use nydus_rafs::RafsIoReader;
use nydus_storage::factory::BlobFactory;
use nydus_storage::{RAFS_DEFAULT_CHUNK_SIZE, RAFS_MAX_CHUNK_SIZE};
use nydus_utils::{compress, digest};
use serde::{Deserialize, Serialize};

use crate::builder::{Builder, DirectoryBuilder, StargzBuilder};
use crate::core::blob_compact::BlobCompactor;
use crate::core::chunk_dict::{import_chunk_dict, parse_chunk_dict_arg};
use crate::core::context::{
    ArtifactStorage, BlobManager, BootstrapManager, BuildContext, BuildOutput, ConversionType,
};
use crate::core::node::{self, WhiteoutSpec};
use crate::core::prefetch::Prefetch;
use crate::core::tree;
use crate::merge::Merger;
use crate::trace::{EventTracerClass, TimingTracerClass, TraceClass};
use crate::unpack::{OCIUnpacker, Unpacker};
use crate::validator::Validator;

#[macro_use]
mod trace;
mod builder;
mod core;
mod inspect;
mod merge;
mod stat;
mod unpack;
mod validator;

const BLOB_ID_MAXIMUM_LENGTH: usize = 255;

#[derive(Serialize, Deserialize, Default)]
pub struct OutputSerializer {
    /// The binary version of builder (nydus-image).
    version: String,
    /// Represents all blob in blob table ordered by blob index, this field
    /// only include the layer that does have a blob, and should be deprecated
    /// in future, use `artifacts` field to replace.
    blobs: Vec<String>,
    /// Performance trace info for current build.
    trace: serde_json::Map<String, serde_json::Value>,
}

impl OutputSerializer {
    fn dump(
        matches: &clap::ArgMatches,
        build_output: BuildOutput,
        build_info: &BuildTimeInfo,
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
                .with_context(|| format!("can not open output file {}", f.display()))?;
            let trace = root_tracer!().dump_summary_map().unwrap_or_default();
            let version = format!("{}-{}", build_info.package_ver, build_info.git_commit);
            let output = Self {
                version,
                blobs: build_output.blobs,
                trace,
            };

            serde_json::to_writer(w, &output).context("failed to write result to output file")?;
        }

        Ok(())
    }

    fn dump_with_check(
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
                .with_context(|| format!("can not open output file {}", f.display()))?;
            let trace = root_tracer!().dump_summary_map().unwrap_or_default();
            let version = format!("{}-{}", build_info.package_ver, build_info.git_commit);
            let output = Self {
                version,
                blobs: blob_ids,
                trace,
            };

            serde_json::to_writer(w, &output).context("failed to write result to output file")?;
        }

        Ok(())
    }
}

fn prepare_cmd_args(bti_string: String) -> ArgMatches<'static> {
    let arg_chunk_dict = Arg::with_name("chunk-dict")
        .long("chunk-dict")
        .short("M")
        .help("specify a chunk dictionary for chunk deduplication")
        .takes_value(true);
    let arg_prefetch_policy = Arg::with_name("prefetch-policy")
        .long("prefetch-policy")
        .short("P")
        .help("specify policy for blob data prefetch")
        .takes_value(true)
        .required(false)
        .default_value("none")
        .possible_values(&["fs", "blob", "none"]);
    let arg_output_json = Arg::with_name("output-json")
        .long("output-json")
        .short("J")
        .help("output file to store result in JSON format")
        .takes_value(true);

    App::new("")
        .version(bti_string.as_str())
        .author(crate_authors!())
        .about("Build or inspect RAFS filesystems for Nydus accelerated container images.")
        .subcommand(
            SubCommand::with_name("create")
                .about("Create a RAFS filesystem from a directory, a tarball or an stargz ToC")
                .arg(
                    Arg::with_name("SOURCE")
                        .help("source to build the RAFS filesystem from")
                        .required(true)
                        .multiple(false),
                )
                .arg(
                    Arg::with_name("type")
                        .long("type")
                        .short("t")
                        .alias("source-type")
                        .help("image conversion type:")
                        .takes_value(true)
                        .default_value("directory")
                        .possible_values(&["directory", "stargz_index"])
                )
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .short("B")
                        .help("path to store generated RAFS filesystem metadata blob")
                        .required_unless_one(&["blob-dir", "inline-bootstrap"])
                        .conflicts_with("inline-bootstrap")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("inline-bootstrap")
                        .long("inline-bootstrap")
                        .help("append RAFS metadata to the data blob")
                        .takes_value(false)
                        .required(false),
                )
                .arg(
                    Arg::with_name("blob-dir")
                        .long("blob-dir")
                        .short("D")
                        .help("directory to store RAFS filesystem metadata and data blobs")
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("blob")
                        .long("blob")
                        .short("b")
                        .help("path to store generated RAFS filesystem data blob")
                        .required_unless_one(&["backend-type", "type", "blob-dir"])
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("blob-id")
                        .long("blob-id")
                        .help("specify blob id (as object id in backend/oss)")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("blob-meta")
                        .long("blob-meta")
                        .help("path to store generated data blob compression information")
                        .conflicts_with("inline-bootstrap")
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("blob-offset")
                        .long("blob-offset")
                        .help("add an offset for compressed blob (used to put the blob in the tarball)")
                        .default_value("0")
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("blob-data-size")
                        .long("blob-data-size")
                        .help("specify blob data size of stargz conversion")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("chunk-size")
                        .long("chunk-size")
                        .short("S")
                        .help("size of data chunk, must be power of two and between 0x1000-0x1000000:")
                        .required(false)
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
                        .possible_values(&["none", "lz4_block", "gzip", "zstd"]),
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
                    Arg::with_name("fs-version")
                        .long("fs-version")
                        .short("v")
                        .help("RAFS filesystem format version number:")
                        .required(true)
                        .default_value("5")
                        .possible_values(&["5", "6"]),
                )
                .arg(
                    arg_chunk_dict.clone(),
                )
                .arg(
                    Arg::with_name("parent-bootstrap")
                        .long("parent-bootstrap")
                        .short("p")
                        .help("path to parent/referenced RAFS filesystem metadata blob (optional)")
                        .takes_value(true)
                        .required(false),
                )
                .arg(
                    Arg::with_name("aligned-chunk")
                        .long("aligned-chunk")
                        .short("A")
                        .help("Align uncompressed data chunk to 4K")
                        .takes_value(false)
                )
                .arg(
                    Arg::with_name("repeatable")
                        .long("repeatable")
                        .short("R")
                        .help("generate reproducible RAFS filesystem")
                        .takes_value(false)
                        .required(false),
                )
                .arg(
                    Arg::with_name("disable-check")
                        .long("disable-check")
                        .help("disable validation of metadata after building")
                        .takes_value(false)
                        .required(false)
                )
                .arg(
                    Arg::with_name("whiteout-spec")
                        .long("whiteout-spec")
                        .short("W")
                        .help("type of whiteout specification:")
                        .takes_value(true)
                        .required(true)
                        .default_value("oci")
                        .possible_values(&["oci", "overlayfs", "none"])
                )
                .arg(
                    arg_prefetch_policy.clone(),
                )
                .arg(
                    arg_output_json.clone(),
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
            SubCommand::with_name("merge")
                .about("Merge multiple bootstraps into a overlaid bootstrap")
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .short("B")
                        .help("output path of nydus overlaid bootstrap")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    arg_chunk_dict,
                )
                .arg(
                    arg_prefetch_policy,
                )
                .arg(
                    arg_output_json.clone(),
                )
                .arg(
                    Arg::with_name("SOURCE")
                        .help("bootstrap paths (allow one or more)")
                        .required(true)
                        .multiple(true),
                )
        )
        .subcommand(
            SubCommand::with_name("check")
                .about("Validate RAFS filesystem metadata")
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .short("B")
                        .help("path to RAFS metadata blob (required)")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("verbose")
                        .long("verbose")
                        .short("v")
                        .help("verbose output")
                        .required(false),
                )
                .arg(
                    arg_output_json.clone(),
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
                        .help("inspect nydus image's filesystem metadata in request mode")
                        .required(false)
                        .takes_value(true),
                )
        )
        .subcommand(
            SubCommand::with_name("stat")
                .about("Generate statistics information from a group of RAFS bootstraps")
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .short("B")
                        .help("generate statistics information from the RAFS bootstrap")
                        .required(false)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("blob-dir")
                        .long("blob-dir")
                        .short("D")
                        .help("generate statistics information from all RAFS bootstraps in the directory")
                        .required(false)
                        .takes_value(true)
                )
                .arg(
                    Arg::with_name("target")
                        .long("target")
                        .short("T")
                        .help("generate statistics information for the target RAFS bootstrap after deduplicating data chunks available in other bootstraps")
                        .required(false)
                        .takes_value(true),
                )
                .arg(
                    arg_output_json.clone(),
                )
        )
        .subcommand(
            SubCommand::with_name("compact")
                .about("(experimental)Compact specific nydus image, remove unused chunks in blobs, merge small blobs")
                .arg(
                    Arg::with_name("bootstrap")
                        .long("bootstrap")
                        .short("B")
                        .help("bootstrap to compact")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("config")
                        .long("config")
                        .short("C")
                        .help("config to compactor")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("backend-type")
                        .long("backend-type")
                        .help("type of backend")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("backend-config-file")
                        .long("backend-config-file")
                        .help("config file of backend")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("chunk-dict")
                        .long("chunk-dict")
                        .short("M")
                        .help("Specify a chunk dictionary for chunk deduplication")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("output-bootstrap")
                        .long("output-bootstrap")
                        .short("O")
                        .help("bootstrap to output, default is source bootstrap add suffix .compact")
                        .takes_value(true),
                )
                .arg(
                    arg_output_json,
                )
        )
        .subcommand(
            SubCommand::with_name("unpack")
            .about("Unpack a RAFS filesystem to a tar file")
            .arg(
                Arg::with_name("bootstrap")
                .long("bootstrap")
                .short("B")
                .help("path to RAFS bootstrap file")
                .required(true)
                .takes_value(true))
            .arg(
                Arg::with_name("blob")
                .long("blob")
                .short("b")
                .help("path to RAFS data blob file")
                .required(false)
                .takes_value(true)
                )
            .arg(
                Arg::with_name("output")
                .long("output")
                .help("path for output tar file")
                .required(true)
                .takes_value(true)
                )
        )
        .arg(
            Arg::with_name("log-file")
                .long("log-file")
                .short("o")
                .help("specify log file")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .short("l")
                .help("specify log level:")
                .default_value("info")
                .possible_values(&["trace", "debug", "info", "warn", "error"])
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .get_matches()
}

fn init_log(matches: &ArgMatches) -> Result<()> {
    let mut log_file = None;
    if let Some(file) = matches.value_of("log-file") {
        let path = PathBuf::from(file);
        log_file = Some(path);
    }

    // Safe to unwrap because it has a default value and possible values are defined.
    let level = matches.value_of("log-level").unwrap().parse().unwrap();

    setup_logging(log_file, level, 0).context("failed to setup logging")
}

fn main() -> Result<()> {
    let (bti_string, build_info) = BuildTimeInfo::dump();

    let cmd = prepare_cmd_args(bti_string);

    init_log(&cmd)?;

    register_tracer!(TraceClass::Timing, TimingTracerClass);
    register_tracer!(TraceClass::Event, EventTracerClass);

    if let Some(matches) = cmd.subcommand_matches("create") {
        Command::create(matches, &build_info)
    } else if let Some(matches) = cmd.subcommand_matches("merge") {
        Command::merge(matches, &build_info)
    } else if let Some(matches) = cmd.subcommand_matches("check") {
        Command::check(matches, &build_info)
    } else if let Some(matches) = cmd.subcommand_matches("inspect") {
        Command::inspect(matches)
    } else if let Some(matches) = cmd.subcommand_matches("stat") {
        Command::stat(matches)
    } else if let Some(matches) = cmd.subcommand_matches("compact") {
        Command::compact(matches, &build_info)
    } else if let Some(matches) = cmd.subcommand_matches("unpack") {
        Command::unpack(matches)
    } else {
        println!("{}", cmd.usage());
        Ok(())
    }
}

struct Command {}

impl Command {
    fn create(matches: &clap::ArgMatches, build_info: &BuildTimeInfo) -> Result<()> {
        let blob_id = Self::get_blob_id(matches)?;
        let blob_offset = Self::get_blob_offset(matches)?;
        let parent_bootstrap = Self::get_parent_bootstrap(matches)?;
        let prefetch = Self::get_prefetch(matches)?;
        let source_path = PathBuf::from(matches.value_of("SOURCE").unwrap());
        let conversion_type: ConversionType = matches.value_of("type").unwrap().parse()?;
        let blob_stor = Self::get_blob_storage(matches, conversion_type)?;
        let blob_meta_stor = Self::get_blob_meta_storage(matches)?;
        let inline_bootstrap = matches.is_present("inline-bootstrap");
        let repeatable = matches.is_present("repeatable");
        let version = Self::get_fs_version(matches)?;
        let chunk_size = Self::get_chunk_size(matches, conversion_type)?;
        let aligned_chunk = if version.is_v6() {
            info!("v6 enforces to use \"aligned-chunk\".");
            true
        } else {
            // get_fs_version makes sure it's either v6 or v5.
            matches.is_present("aligned-chunk")
        };
        let whiteout_spec: WhiteoutSpec = matches
            .value_of("whiteout-spec")
            .unwrap_or_default()
            .parse()?;
        let mut compressor = matches.value_of("compressor").unwrap_or_default().parse()?;
        let mut digester = matches.value_of("digester").unwrap_or_default().parse()?;
        let blob_data_size = Self::get_blob_size(matches, conversion_type)?;

        match conversion_type {
            ConversionType::DirectoryToRafs => {
                Self::ensure_directory(&source_path)?;
                if blob_stor.is_none() {
                    bail!("both --blob and --blob-dir are not provided");
                } else if blob_meta_stor.is_some() {
                    bail!("'--input-type directory' conflicts with '--blob-meta'");
                }
            }
            ConversionType::DirectoryToTargz => unimplemented!(),
            ConversionType::DirectoryToStargz => unimplemented!(),
            ConversionType::StargzToRafs => unimplemented!(),
            ConversionType::StargzToRef => unimplemented!(),
            ConversionType::StargzIndexToRef => {
                Self::ensure_file(&source_path)?;
                if inline_bootstrap {
                    bail!("'--type stargz_index' conflicts with '--inline-bootstrap'");
                }
                if blob_id.trim() == "" {
                    bail!("'--blob-id' is missing for '--type stargz_index'");
                }
                if compressor != compress::Algorithm::GZip {
                    trace!(
                        "only gzip is supported for '--type stargz_index', compressor set to {}",
                        compress::Algorithm::GZip
                    );
                }
                compressor = compress::Algorithm::GZip;
                if digester != digest::Algorithm::Sha256 {
                    trace!(
                        "only sha256 is supported for '--type stargz_index', digester set to {}",
                        digest::Algorithm::Sha256
                    );
                }
                digester = digest::Algorithm::Sha256;
            }
            ConversionType::TargzToRafs => unimplemented!(),
            ConversionType::TargzToStargz => unimplemented!(),
            ConversionType::TarToRafs => unimplemented!(),
            ConversionType::TarToStargz => unimplemented!(),
            ConversionType::TargzToRef => unimplemented!(),
        }

        let mut build_ctx = BuildContext::new(
            blob_id,
            aligned_chunk,
            blob_offset,
            compressor,
            digester,
            !repeatable,
            whiteout_spec,
            conversion_type,
            source_path,
            prefetch,
            blob_stor,
            blob_meta_stor,
            inline_bootstrap,
        );
        build_ctx.set_fs_version(version);
        build_ctx.set_chunk_size(chunk_size);

        let mut blob_mgr = BlobManager::new();
        if let Some(chunk_dict_arg) = matches.value_of("chunk-dict") {
            blob_mgr.set_chunk_dict(timing_tracer!(
                { import_chunk_dict(chunk_dict_arg) },
                "import_chunk_dict"
            )?);
        }

        let mut bootstrap_mgr = if inline_bootstrap {
            BootstrapManager::new(None, parent_bootstrap)
        } else {
            let bootstrap_path = Self::get_bootstrap_storage(matches)?;
            BootstrapManager::new(Some(bootstrap_path), parent_bootstrap)
        };

        let mut builder: Box<dyn Builder> = match conversion_type {
            ConversionType::DirectoryToRafs => Box::new(DirectoryBuilder::new()),
            ConversionType::DirectoryToTargz => unimplemented!(),
            ConversionType::DirectoryToStargz => unimplemented!(),
            ConversionType::StargzToRafs => unimplemented!(),
            ConversionType::StargzToRef => unimplemented!(),
            ConversionType::StargzIndexToRef => Box::new(StargzBuilder::new(blob_data_size)),
            ConversionType::TargzToRafs => unimplemented!(),
            ConversionType::TargzToRef => unimplemented!(),
            ConversionType::TargzToStargz => unimplemented!(),
            ConversionType::TarToRafs => unimplemented!(),
            ConversionType::TarToStargz => unimplemented!(),
        };
        let build_output = timing_tracer!(
            {
                builder
                    .build(&mut build_ctx, &mut bootstrap_mgr, &mut blob_mgr)
                    .context("build failed")
            },
            "total_build"
        )?;

        // Some operations like listing xattr pairs of certain namespace need the process
        // to be privileged. Therefore, trace what euid and egid are
        event_tracer!("euid", "{}", geteuid());
        event_tracer!("egid", "{}", getegid());

        // Validate output bootstrap file
        if !inline_bootstrap {
            if let Some(ArtifactStorage::SingleFile(p)) = &bootstrap_mgr.bootstrap_storage {
                Self::validate_image(matches, p).context("failed to validate bootstrap")?;
            }
        }

        info!("build successfully: {:?}", build_output,);
        OutputSerializer::dump(matches, build_output, build_info)
    }

    fn merge(matches: &clap::ArgMatches, build_info: &BuildTimeInfo) -> Result<()> {
        let source_bootstrap_paths: Vec<PathBuf> = matches
            .values_of("SOURCE")
            .map(|paths| paths.map(PathBuf::from).collect())
            .unwrap();
        let target_bootstrap_path = Self::get_bootstrap_storage(matches)?;
        let chunk_dict_path = if let Some(arg) = matches.value_of("chunk-dict") {
            Some(parse_chunk_dict_arg(arg)?)
        } else {
            None
        };
        let mut ctx = BuildContext {
            prefetch: Self::get_prefetch(matches)?,
            ..Default::default()
        };
        let output = Merger::merge(
            &mut ctx,
            source_bootstrap_paths,
            target_bootstrap_path,
            chunk_dict_path,
        )?;
        OutputSerializer::dump(matches, output, build_info)
    }

    fn compact(matches: &clap::ArgMatches, build_info: &BuildTimeInfo) -> Result<()> {
        let bootstrap_path = PathBuf::from(Self::get_bootstrap(matches)?);
        let dst_bootstrap = match matches.value_of("output-bootstrap") {
            None => bootstrap_path.with_extension("bootstrap.compact"),
            Some(s) => PathBuf::from(s),
        };

        let chunk_dict = match matches.value_of("chunk-dict") {
            None => None,
            Some(args) => Some(import_chunk_dict(args)?),
        };

        let backend_type = matches.value_of("backend-type").unwrap();
        let backend_file = matches.value_of("backend-config-file").unwrap();
        let backend_config = BackendConfig::from_file(backend_type, backend_file)?;
        let backend = BlobFactory::new_backend(backend_config, "compactor")?;

        let config_file_path = matches.value_of("config").unwrap();
        let file = File::open(config_file_path)
            .with_context(|| format!("failed to open config file {}", config_file_path))?;
        let config = serde_json::from_reader(file)
            .with_context(|| format!("invalid config file {}", config_file_path))?;

        if let Some(build_output) =
            BlobCompactor::do_compact(bootstrap_path, dst_bootstrap, chunk_dict, backend, &config)?
        {
            OutputSerializer::dump(matches, build_output, build_info)?;
        }
        Ok(())
    }

    fn unpack(args: &clap::ArgMatches) -> Result<()> {
        let bootstrap = args.value_of("bootstrap").expect("pass in bootstrap");
        if bootstrap.is_empty() {
            return Err(anyhow!("invalid empty --bootstrap option"));
        }
        let output = args.value_of("output").expect("pass in output");
        if output.is_empty() {
            return Err(anyhow!("invalid empty --output option"));
        }

        let blob = args.value_of("blob");

        let unpacker =
            OCIUnpacker::new(bootstrap, blob, output).with_context(|| "fail to create unpacker")?;

        unpacker.unpack().with_context(|| "fail to unpack")
    }

    fn check(matches: &clap::ArgMatches, build_info: &BuildTimeInfo) -> Result<()> {
        let bootstrap_path = Self::get_bootstrap(matches)?;
        let verbose = matches.is_present("verbose");
        let mut validator = Validator::new(bootstrap_path)?;
        let blobs = validator
            .check(verbose)
            .with_context(|| format!("failed to check bootstrap {:?}", bootstrap_path))?;

        println!("RAFS metadata is valid, data blobs: ");
        let mut blob_ids = Vec::new();
        for (idx, blob) in blobs.iter().enumerate() {
            println!(
                "\t {}: {}, compressed size 0x{:x}, uncompressed size 0x{:x}",
                idx,
                blob.blob_id(),
                blob.compressed_size(),
                blob.uncompressed_size()
            );
            blob_ids.push(blob.blob_id().to_string());
        }

        OutputSerializer::dump_with_check(matches, build_info, blob_ids)?;

        Ok(())
    }

    fn inspect(matches: &clap::ArgMatches) -> Result<()> {
        let bootstrap_path = Self::get_bootstrap(matches)?;
        let cmd = matches.value_of("request");
        let mut inspector =
            inspect::RafsInspector::new(bootstrap_path, cmd.is_some()).map_err(|e| {
                error!("failed to create inspector, {:?}", e);
                e
            })?;

        if let Some(c) = cmd {
            let o = inspect::Executor::execute(&mut inspector, c.to_string()).unwrap();
            serde_json::to_writer(std::io::stdout(), &o)
                .unwrap_or_else(|e| error!("Failed to serialize result, {:?}", e));
        } else {
            inspect::Prompt::run(inspector);
        }

        Ok(())
    }

    fn stat(matches: &clap::ArgMatches) -> Result<()> {
        let mut stat = stat::ImageStat::new();
        let target = matches
            .value_of("target")
            .map(Path::new)
            .unwrap_or_else(|| Path::new(""));

        if let Some(blob) = matches.value_of("bootstrap").map(PathBuf::from) {
            stat.stat(&blob, true)?;
        } else if let Some(d) = matches.value_of("blob-dir").map(PathBuf::from) {
            Self::ensure_directory(d.clone())?;

            stat.dedup_enabled = true;

            let children = fs::read_dir(d.as_path())
                .with_context(|| format!("failed to read dir {:?}", d.as_path()))?;
            let children = children.collect::<Result<Vec<DirEntry>, std::io::Error>>()?;
            for child in children {
                let path = child.path();
                if path.is_file() && path != target {
                    if let Err(e) = stat.stat(&path, true) {
                        error!(
                            "failed to process {}, {}",
                            path.to_str().unwrap_or_default(),
                            e
                        );
                    };
                }
            }
        } else {
            bail!("one of `--bootstrap` and `--blob-dir` must be specified");
        }

        if let Some(blob) = matches.value_of("target").map(PathBuf::from) {
            stat.target_enabled = true;
            stat.stat(&blob, false)?;
        }

        stat.finalize();

        if let Some(path) = matches.value_of("output-json").map(PathBuf::from) {
            stat.dump_json(&path)?;
        } else {
            stat.dump();
        }

        Ok(())
    }

    fn get_bootstrap<'a>(matches: &'a clap::ArgMatches) -> Result<&'a Path> {
        match matches.value_of("bootstrap") {
            None => bail!("missing parameter `bootstrap`"),
            Some(s) => Ok(Path::new(s)),
        }
    }

    fn get_bootstrap_storage(matches: &clap::ArgMatches) -> Result<ArtifactStorage> {
        if let Some(s) = matches.value_of("bootstrap") {
            Ok(ArtifactStorage::SingleFile(s.into()))
        } else if let Some(d) = matches.value_of("blob-dir").map(PathBuf::from) {
            if !d.exists() {
                bail!("Directory to store blobs does not exist")
            }
            Ok(ArtifactStorage::FileDir(d))
        } else {
            bail!("both --bootstrap and --blob-dir are missing, please specify one to store the generated metadata blob file");
        }
    }

    // Must specify a path to blob file.
    // For cli/binary interface compatibility sake, keep option `backend-config`, but
    // it only receives "localfs" backend type and it will be REMOVED in the future
    fn get_blob_storage(
        matches: &clap::ArgMatches,
        conversion_type: ConversionType,
    ) -> Result<Option<ArtifactStorage>> {
        // Must specify a path to blob file.
        // For cli/binary interface compatibility sake, keep option `backend-config`, but
        // it only receives "localfs" backend type and it will be REMOVED in the future
        let blob_stor = if conversion_type == ConversionType::DirectoryToRafs {
            if let Some(p) = matches
                .value_of("blob")
                .map(|b| ArtifactStorage::SingleFile(b.into()))
            {
                Some(p)
            } else if let Some(d) = matches.value_of("blob-dir").map(PathBuf::from) {
                if !d.exists() {
                    bail!("Directory to store blobs does not exist")
                }
                Some(ArtifactStorage::FileDir(d))
            } else if let Some(config_json) = matches.value_of("backend-config") {
                let config: serde_json::Value = serde_json::from_str(config_json).unwrap();
                warn!("Using --backend-type=localfs is DEPRECATED. Use --blob instead.");
                if let Some(bf) = config.get("blob_file") {
                    // Even unwrap, it is caused by invalid json. Image creation just can't start.
                    let b: PathBuf = bf
                        .as_str()
                        .ok_or_else(|| anyhow!("backend-config is invalid"))?
                        .to_string()
                        .into();
                    Some(ArtifactStorage::SingleFile(b))
                } else {
                    error!("Wrong backend config input!");
                    return Err(anyhow!("invalid backend config"));
                }
            } else {
                bail!("both --blob and --blob-dir are missing, please specify one to store the generated data blob file");
            }
        } else {
            None
        };

        Ok(blob_stor)
    }

    fn get_blob_meta_storage(matches: &clap::ArgMatches) -> Result<Option<ArtifactStorage>> {
        let blob_meta_stor = matches
            .value_of("blob-meta")
            .map(|b| ArtifactStorage::SingleFile(b.into()));
        Ok(blob_meta_stor)
    }

    fn get_parent_bootstrap(matches: &clap::ArgMatches) -> Result<Option<RafsIoReader>> {
        let mut parent_bootstrap_path = Path::new("");
        if let Some(_parent_bootstrap_path) = matches.value_of("parent-bootstrap") {
            parent_bootstrap_path = Path::new(_parent_bootstrap_path);
        }

        if parent_bootstrap_path != Path::new("") {
            let file = OpenOptions::new()
                .read(true)
                .write(false)
                .open(parent_bootstrap_path)
                .with_context(|| {
                    format!(
                        "failed to open parent bootstrap file {:?}",
                        parent_bootstrap_path
                    )
                })?;
            Ok(Some(Box::new(file)))
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

    fn get_blob_size(matches: &clap::ArgMatches, ty: ConversionType) -> Result<u64> {
        if ty != ConversionType::StargzIndexToRef {
            return Ok(0);
        }

        match matches.value_of("blob-data-size") {
            None => bail!("no value specified for '--blob-data-size'"),
            Some(v) => {
                let param = v.trim_start_matches("0x").trim_start_matches("0X");
                let size = u64::from_str_radix(param, 16)
                    .context(format!("invalid blob data size {}", v))?;
                Ok(size)
            }
        }
    }

    fn validate_image(matches: &clap::ArgMatches, bootstrap_path: &Path) -> Result<()> {
        if !matches.is_present("disable-check") {
            let mut validator = Validator::new(bootstrap_path)?;
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

    fn get_chunk_size(matches: &clap::ArgMatches, ty: ConversionType) -> Result<u32> {
        match matches.value_of("chunk-size") {
            None => {
                if ty == ConversionType::StargzIndexToRef {
                    Ok(0x400000u32)
                } else {
                    Ok(RAFS_DEFAULT_CHUNK_SIZE as u32)
                }
            }
            Some(v) => {
                let param = v.trim_start_matches("0x").trim_start_matches("0X");
                let chunk_size =
                    u32::from_str_radix(param, 16).context(format!("invalid chunk size {}", v))?;
                if chunk_size as u64 > RAFS_MAX_CHUNK_SIZE
                    || chunk_size < 0x1000
                    || !chunk_size.is_power_of_two()
                {
                    bail!("invalid chunk size: {}", chunk_size);
                }
                Ok(chunk_size)
            }
        }
    }

    fn get_prefetch(matches: &clap::ArgMatches) -> Result<Prefetch> {
        let prefetch_policy = matches
            .value_of("prefetch-policy")
            .unwrap_or_default()
            .parse()?;
        Prefetch::new(prefetch_policy)
    }

    fn get_blob_offset(matches: &clap::ArgMatches) -> Result<u64> {
        match matches.value_of("blob-offset") {
            None => Ok(0),
            Some(v) => v
                .parse::<u64>()
                .context(format!("invalid blob offset {}", v)),
        }
    }

    fn get_fs_version(matches: &clap::ArgMatches) -> Result<RafsVersion> {
        match matches.value_of("fs-version") {
            None => Ok(RafsVersion::V6),
            Some(v) => {
                let version: u32 = v.parse().context(format!("invalid fs-version: {}", v))?;
                if version == 5 {
                    Ok(RafsVersion::V5)
                } else if version == 6 {
                    Ok(RafsVersion::V6)
                } else {
                    bail!("invalid fs-version: {}", v);
                }
            }
        }
    }

    fn ensure_file<P: AsRef<Path>>(path: P) -> Result<()> {
        let file = metadata(path.as_ref())
            .context(format!("failed to access path {:?}", path.as_ref()))?;
        ensure!(
            file.is_file(),
            "specified path must be a regular file: {:?}",
            path.as_ref()
        );
        Ok(())
    }

    fn ensure_directory<P: AsRef<Path>>(path: P) -> Result<()> {
        let dir = metadata(path.as_ref())
            .context(format!("failed to access path {:?}", path.as_ref()))?;
        ensure!(
            dir.is_dir(),
            "specified path must be a directory: {:?}",
            path.as_ref()
        );
        Ok(())
    }
}
