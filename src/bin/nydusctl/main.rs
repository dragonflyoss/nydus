// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]

#[macro_use(crate_authors)]
extern crate clap;
#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_json;
extern crate nydus_rafs as rafs;

use std::collections::HashMap;

use anyhow::Result;
use clap::{App, Arg, SubCommand};

mod client;
mod commands;

use commands::{
    CommandBackend, CommandCache, CommandDaemon, CommandFsStats, CommandMount, CommandUmount,
};
use nydus_app::BuildTimeInfo;

#[tokio::main]
async fn main() -> Result<()> {
    let (_, build_info) = BuildTimeInfo::dump();
    let app = App::new("A client to query and configure the nydusd daemon\n")
        .version(build_info.package_ver.as_str())
        .author(crate_authors!())
        .arg(
            Arg::with_name("sock")
                .help("Sets file path for the nydusd API socket")
                .short("S")
                .long("sock")
                .required(true)
                .takes_value(true)
                .global(false),
        )
        .arg(
            Arg::with_name("raw")
                .help("Outputs messages in plain json mode")
                .short("r")
                .long("raw")
                .takes_value(false)
                .global(true),
        )
        .subcommand(SubCommand::with_name("info").about("Gets information about the nydusd daemon"))
        .subcommand(
            SubCommand::with_name("set")
                .about("Configures parameters for the nydusd daemon")
                .help(
                    r#"Configurable parameters:
         <KIND>  : <VALUE>
        log-level: trace, debug, info, warn, error"#,
                )
                .arg(
                    Arg::with_name("KIND")
                        .help("the parameter to configure")
                        .required(true)
                        .takes_value(true)
                        .possible_values(&["log-level"])
                        .index(1),
                )
                .arg(
                    Arg::with_name("VALUE")
                        .help("the configuration value")
                        .required(true)
                        .takes_value(true)
                        .index(2),
                ),
        )
        .subcommand(
            SubCommand::with_name("metrics")
                .about("Gets runtime metrics about backend, cache and filesystems")
                .arg(
                    Arg::with_name("category")
                        .help("the metrics category to fetch")
                        .required(true)
                        .possible_values(&["backend", "cache", "fsstats"])
                        .takes_value(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("interval")
                        .help("interval to refresh the metrics")
                        .short("I")
                        .long("interval")
                        .required(false)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("mount")
                .about("Mounts a new filesystem instance")
                .arg(
                    Arg::with_name("source")
                        .help("Storage backend for the filesystem instance")
                        .short("s")
                        .long("source")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("config")
                        .help("Configuration file for the new filesystem instance")
                        .short("c")
                        .long("config")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("mountpoint")
                        .help("Mountpoint for the new filesystem instance")
                        .short("m")
                        .long("mountpoint")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("type")
                        .help("Type of the new filesystem instance")
                        .short("t")
                        .long("type")
                        .required(true)
                        .takes_value(true)
                        .possible_values(&["rafs", "passthrough_fs"]),
                ),
        )
        .subcommand(
            SubCommand::with_name("umount")
                .about("Umounts a filesystem instance")
                .arg(
                    Arg::with_name("mountpoint")
                        .help("Mountpoint of the filesystem instance")
                        .short("m")
                        .required(true)
                        .takes_value(true)
                        .index(1),
                ),
        );

    let cmd = app.get_matches();

    // Safe to unwrap because it is required by Clap
    let sock = cmd.value_of("sock").unwrap();
    let raw = cmd.is_present("raw");
    let client = client::NydusdClient::new(sock);

    if let Some(_matches) = cmd.subcommand_matches("info") {
        let cmd = CommandDaemon {};
        cmd.execute(raw, &client, None).await?;
    } else if let Some(matches) = cmd.subcommand_matches("set") {
        // Safe to unwrap since the below two arguments are required by clap.
        let kind = matches.value_of("KIND").unwrap().to_string();
        let value = matches.value_of("VALUE").unwrap().to_string();
        let mut items = HashMap::new();
        items.insert(kind, value);

        let cmd = CommandDaemon {};
        cmd.execute(raw, &client, Some(items)).await?;
    } else if let Some(matches) = cmd.subcommand_matches("metrics") {
        // Safe to unwrap as it is required by clap
        let category = matches.value_of("category").unwrap();
        let mut context = HashMap::new();
        matches
            .value_of("interval")
            .map(|i| context.insert("interval".to_string(), i.to_string()));

        match category {
            "backend" => {
                let cmd = CommandBackend {};
                cmd.execute(raw, &client, Some(context)).await?
            }
            "cache" => {
                let cmd = CommandCache {};
                cmd.execute(raw, &client, None).await?
            }
            "fsstats" => {
                let cmd = CommandFsStats {};
                cmd.execute(raw, &client, None).await?
            }
            _ => println!("Illegal category"),
        }
    } else if let Some(matches) = cmd.subcommand_matches("mount") {
        // Safe to unwrap as it is required by clap
        let mut context = HashMap::new();
        context.insert(
            "source".to_string(),
            matches.value_of("source").unwrap().to_string(),
        );
        context.insert(
            "mountpoint".to_string(),
            matches.value_of("mountpoint").unwrap().to_string(),
        );
        context.insert(
            "config".to_string(),
            matches.value_of("config").unwrap().to_string(),
        );
        context.insert(
            "type".to_string(),
            matches.value_of("type").unwrap().to_string(),
        );

        let cmd = CommandMount {};
        cmd.execute(raw, &client, Some(context)).await?
    } else if let Some(matches) = cmd.subcommand_matches("umount") {
        // Safe to unwrap as it is required by clap
        let mut context = HashMap::new();
        context.insert(
            "mountpoint".to_string(),
            matches.value_of("mountpoint").unwrap().to_string(),
        );

        let cmd = CommandUmount {};
        cmd.execute(raw, &client, Some(context)).await?
    }

    Ok(())
}
