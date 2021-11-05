// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

#![deny(warnings)]
#[macro_use(crate_authors, crate_version)]
extern crate clap;
#[macro_use]
extern crate anyhow;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_json;

use std::collections::HashMap;

use anyhow::Result;
use clap::{App, Arg, SubCommand};

mod client;
mod commands;

use commands::{
    CommandBackend, CommandBlobcache, CommandDaemon, CommandFsStats, CommandMount, CommandUmount,
};

#[tokio::main]
async fn main() -> Result<()> {
    let app = App::new("A client to query and configure nydusd")
        .version(crate_version!())
        .author(crate_authors!())
        .arg(
            Arg::with_name("sock")
                .long("sock")
                .help("Unix domain socket path")
                .takes_value(true)
                .required(true)
                .global(false),
        )
        .arg(
            Arg::with_name("raw")
                .long("raw")
                .help("Output plain json")
                .takes_value(false)
                .global(false),
        )
        .subcommand(SubCommand::with_name("info").about("Get nydusd working status"))
        .subcommand(
            SubCommand::with_name("set")
                .about(
                    "Configure nydusd parameters in format: set KIND VALUE where KIND can be \"log-level\"",
                )
                .help(
                    r#"Acceptable Items:
        log-level: trace, debug, info, warn, error"#,
                )
                .arg(
                    Arg::with_name("KIND")
                        .help("what item to configure")
                        .required(true)
                        .possible_values(&["log-level"])
                        .takes_value(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("VALUE")
                        .help("what item to configure")
                        .required(true)
                        .takes_value(true)
                        .index(2),
                ),
        )
        .subcommand(
            SubCommand::with_name("metrics")
                .about(
                    "Query nydus metrics. Possible metrics category: fsstats; blobcache; backend",
                )
                .arg(
                    Arg::with_name("category")
                        .help("Show the category of metrics: blobcache, backend, fsstats")
                        .required(true)
                        .possible_values(&["blobcache", "backend", "fsstats"])
                        .takes_value(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("interval")
                        .long("interval")
                        .short("I")
                        .required(false)
                        .takes_value(true),
                ),
        );

    let app = app
        .subcommand(
            SubCommand::with_name("mount")
                .about("Attach a file system backend")
                .arg(
                    Arg::with_name("source")
                        .help("From what to attach the file system backend")
                        .long("source")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("config")
                        .help("File system backend configuration file")
                        .long("config")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("mountpoint")
                        .long("mountpoint")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("type")
                        .possible_values(&["rafs", "passthrough_fs"])
                        .long("type")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("umount")
                .about("Detach a file system backend")
                .arg(
                    Arg::with_name("mountpoint")
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

    if cmd.subcommand_matches("info").is_some() {
        let cmd = CommandDaemon {};
        cmd.execute(raw, &client, None).await?;
    }

    if let Some(matches) = cmd.subcommand_matches("set") {
        // Safe to unwrap since the below two arguments are required by clap.
        let kind = matches.value_of("KIND").unwrap().to_string();
        let value = matches.value_of("VALUE").unwrap().to_string();
        let mut items = HashMap::new();
        items.insert(kind, value);

        let cmd = CommandDaemon {};
        cmd.execute(raw, &client, Some(items)).await?;
    }

    if let Some(matches) = cmd.subcommand_matches("metrics") {
        // Safe to unwrap as it is required by clap
        let category = matches.value_of("category").unwrap();
        let mut context = HashMap::new();

        matches
            .value_of("interval")
            .map(|i| context.insert("interval".to_string(), i.to_string()));

        match category {
            "blobcache" => {
                let cmd = CommandBlobcache {};
                cmd.execute(raw, &client, None).await?
            }
            "backend" => {
                let cmd = CommandBackend {};
                cmd.execute(raw, &client, Some(context)).await?
            }
            "fsstats" => {
                let cmd = CommandFsStats {};
                cmd.execute(raw, &client, None).await?
            }
            _ => println!("Illegal category"),
        }
    }

    if let Some(matches) = cmd.subcommand_matches("mount") {
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
    }

    if let Some(matches) = cmd.subcommand_matches("umount") {
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
