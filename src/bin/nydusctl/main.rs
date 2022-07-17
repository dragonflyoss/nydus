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
use clap::{Arg, ArgAction, Command};

mod client;
mod commands;

use commands::{
    CommandBackend, CommandCache, CommandDaemon, CommandFsStats, CommandMount, CommandUmount,
};
use nydus_app::BuildTimeInfo;

lazy_static! {
    static ref BTI: BuildTimeInfo = BuildTimeInfo::dump().1;
}

#[tokio::main]
async fn main() -> Result<()> {
    let app = Command::new("A client to query and configure the nydusd daemon\n")
        .version(BTI.package_ver.as_str())
        .author(crate_authors!())
        .arg(
            Arg::new("sock")
                .help("Sets file path for the nydusd API socket")
                .short('S')
                .long("sock")
                .required(true)
                .global(false),
        )
        .arg(
            Arg::new("raw")
                .help("Outputs messages in plain json mode")
                .short('r')
                .long("raw")
                .action(ArgAction::SetTrue)
                .global(true),
        )
        .subcommand(Command::new("info").about("Gets information about the nydusd daemon"))
        .subcommand(
            Command::new("set")
                .about("Configures parameters for the nydusd daemon")
                .override_help(
                    r#"Configurable parameters:
         <KIND>  : <VALUE>
        log-level: trace, debug, info, warn, error"#,
                )
                .arg(
                    Arg::new("KIND")
                        .help("the parameter to configure")
                        .required(true)
                        .value_parser(["log-level"])
                        .index(1),
                )
                .arg(
                    Arg::new("VALUE")
                        .help("the configuration value")
                        .required(true)
                        .index(2),
                ),
        )
        .subcommand(
            Command::new("metrics")
                .about("Gets runtime metrics about backend, cache and filesystems")
                .arg(
                    Arg::new("category")
                        .help("the metrics category to fetch")
                        .required(true)
                        .value_parser(["backend", "cache", "fsstats"])
                        .index(1),
                )
                .arg(
                    Arg::new("interval")
                        .help("interval to refresh the metrics")
                        .short('I')
                        .long("interval")
                        .required(false),
                ),
        )
        .subcommand(
            Command::new("mount")
                .about("Mounts a new filesystem instance")
                .arg(
                    Arg::new("source")
                        .help("Storage backend for the filesystem instance")
                        .short('s')
                        .long("source")
                        .required(true),
                )
                .arg(
                    Arg::new("config")
                        .help("Configuration file for the new filesystem instance")
                        .short('c')
                        .long("config")
                        .required(true),
                )
                .arg(
                    Arg::new("mountpoint")
                        .help("Mountpoint for the new filesystem instance")
                        .short('m')
                        .long("mountpoint")
                        .required(true),
                )
                .arg(
                    Arg::new("type")
                        .help("Type of the new filesystem instance")
                        .short('t')
                        .long("type")
                        .required(true)
                        .value_parser(["rafs", "passthrough_fs"]),
                ),
        )
        .subcommand(
            Command::new("umount")
                .about("Umounts a filesystem instance")
                .arg(
                    Arg::new("mountpoint")
                        .help("Mountpoint of the filesystem instance")
                        .short('m')
                        .required(true)
                        .index(1),
                ),
        );

    let cmd = app.get_matches();

    // Safe to unwrap because it is required by Clap
    let sock = cmd.get_one::<String>("sock").map(|s| s.as_str()).unwrap();
    let raw = cmd.get_flag("raw");
    let client = client::NydusdClient::new(sock);

    if let Some(_matches) = cmd.subcommand_matches("info") {
        let cmd = CommandDaemon {};
        cmd.execute(raw, &client, None).await?;
    } else if let Some(matches) = cmd.subcommand_matches("set") {
        // Safe to unwrap since the below two arguments are required by clap.
        let kind = matches.get_one::<String>("KIND").unwrap().to_owned();
        let value = matches.get_one::<String>("VALUE").unwrap().to_owned();
        let mut items = HashMap::new();
        items.insert(kind, value);

        let cmd = CommandDaemon {};
        cmd.execute(raw, &client, Some(items)).await?;
    } else if let Some(matches) = cmd.subcommand_matches("metrics") {
        // Safe to unwrap as it is required by clap
        let category = matches
            .get_one::<String>("category")
            .map(|s| s.as_str())
            .unwrap();
        let mut context = HashMap::new();
        matches
            .get_one::<String>("interval")
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
            matches.get_one::<String>("source").unwrap().to_string(),
        );
        context.insert(
            "mountpoint".to_string(),
            matches.get_one::<String>("mountpoint").unwrap().to_string(),
        );
        context.insert(
            "config".to_string(),
            matches.get_one::<String>("config").unwrap().to_string(),
        );
        context.insert(
            "type".to_string(),
            matches.get_one::<String>("type").unwrap().to_string(),
        );

        let cmd = CommandMount {};
        cmd.execute(raw, &client, Some(context)).await?
    } else if let Some(matches) = cmd.subcommand_matches("umount") {
        // Safe to unwrap as it is required by clap
        let mut context = HashMap::new();
        context.insert(
            "mountpoint".to_string(),
            matches.get_one::<String>("mountpoint").unwrap().to_string(),
        );

        let cmd = CommandUmount {};
        cmd.execute(raw, &client, Some(context)).await?
    }

    Ok(())
}
