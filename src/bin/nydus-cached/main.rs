// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[macro_use(crate_version)]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

use std::io::Result;
use std::os::unix::prelude::AsRawFd;
use std::sync::{atomic::AtomicBool, Mutex};

use clap::{App, Arg};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use nydus_app::{dump_program_info, setup_logging, BuildTimeInfo};
use storage::remote::{RemoteBlobMgr, Server};
use vmm_sys_util::eventfd::EventFd;

const CLIENT_TOKEN: Token = Token(1);

lazy_static! {
    static ref EVENT_MANAGER_RUN: AtomicBool = AtomicBool::new(true);
    static ref EXIT_EVTFD: Mutex::<Option<EventFd>> = Mutex::<Option<EventFd>>::default();
}

fn main() -> Result<()> {
    let (bti_string, _bti) = BuildTimeInfo::dump(crate_version!());

    let cmd_arguments = App::new("")
        .version(bti_string.as_str())
        .about("Nydus Storage Cache Daemon")
        .arg(
            Arg::with_name("sock")
                .long("sock")
                .short("S")
                .help("Service API socket")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("C")
                .help("Configuration file")
                .takes_value(true)
                .required(false)
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .short("l")
                .help("Log level:")
                .default_value("info")
                .possible_values(&["trace", "debug", "info", "warn", "error"])
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("log-file")
                .long("log-file")
                .short("L")
                .help("Log messages to the file. If file extension is not specified, the default extenstion \".log\" will be appended.")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("test")
                .long("test")
                .short("T")
                .help("run as client for tests")
                .takes_value(false)
                .required(false),
        )
        .arg(
            Arg::with_name("workdir")
                .long("workdir")
                .short("W")
                .help("working directory")
                .takes_value(true)
                .required(true),
        )
        ;

    let cmd_arguments_parsed = cmd_arguments.get_matches();

    let logging_file = cmd_arguments_parsed.value_of("log-file").map(|l| l.into());
    // Safe to unwrap because it has default value and possible values are defined
    let level = cmd_arguments_parsed
        .value_of("log-level")
        .unwrap()
        .parse()
        .unwrap();
    setup_logging(logging_file, level)?;
    dump_program_info(crate_version!());

    let sock = cmd_arguments_parsed
        .value_of("sock")
        .unwrap_or("/tmp/nydus-cached.sock");
    let workdir = cmd_arguments_parsed
        .value_of("workdir")
        .unwrap_or("/tmp/nydus-cached");

    if cmd_arguments_parsed.is_present("test") {
        return run_test_cases(workdir, sock);
    }

    let mut cached_subscriber = CachedServerSubscriber::new(sock)?;
    cached_subscriber.listen();

    /*
    let mut http_thread: Option<thread::JoinHandle<Result<()>>> = None;
    let http_exit_evtfd = EventFd::new(0).unwrap();
    if let Some(apisock) = apisock {
        let (to_api, from_http) = channel();
        let (to_http, from_api) = channel();

        let api_server = ApiServer::new(to_http, daemon.clone())?;

        let api_server_subscriber = Arc::new(ApiSeverSubscriber::new(api_server, from_http)?);
        let evtfd = api_server_subscriber.get_event_fd()?;
        event_manager.add_subscriber(api_server_subscriber);
        let ret = start_http_thread(
            apisock,
            evtfd,
            to_api,
            from_api,
            http_exit_evtfd.try_clone().unwrap(),
        )?;
        http_thread = Some(ret);
        info!("api server running at {}", apisock);
    }
    */

    /*
    if let Some(t) = http_thread {
        http_exit_evtfd.write(1).unwrap();
        if t.join()
            .map(|r| r.map_err(|e| error!("Thread execution error. {:?}", e)))
            .is_err()
        {
            error!("Join http thread failed.");
        }
    }
     */

    cached_subscriber.server.stop();
    info!("nydus-cached quits");

    Ok(())
}

pub struct CachedServerSubscriber {
    server: Server,
    receiver: Poll,
}

impl CachedServerSubscriber {
    pub fn new(sock: &str) -> Result<Self> {
        let receiver = Poll::new()?;
        let server = Server::new(sock)?;
        receiver.registry().register(
            &mut SourceFd(&server.as_raw_fd()),
            CLIENT_TOKEN,
            Interest::READABLE | Interest::WRITABLE,
        )?;
        let subscriber = Self { server, receiver };
        Ok(subscriber)
    }

    pub fn listen(&mut self) {
        let mut events = Events::with_capacity(64);

        loop {
            if let Err(e) = self.receiver.poll(&mut events, None) {
                error!("Cached server poll events failed, {}", e);
                break;
            }
            for event in &events {
                match event.token() {
                    CLIENT_TOKEN => match self.server.handle_incoming_connection() {
                        Err(e) => error!("failed to handle incoming connection, {}", e),
                        Ok(None) => {}
                        Ok(Some(client)) => {
                            let id = client.id();
                            self.receiver
                                .registry()
                                .register(
                                    &mut SourceFd(&client.clone().as_raw_fd()),
                                    Token(id as usize),
                                    Interest::READABLE | Interest::WRITABLE,
                                )
                                .unwrap_or_else(|e| {
                                    error!("client connection is failed to register, {}", e);
                                });
                        }
                    },
                    token => {
                        let id = token.0 as u32;
                        if let Err(e) = self.server.handle_event(id) {
                            error!("failed to handle client request, {}", e);
                            self.server.close_connection(id);
                        }
                    }
                }
            }
        }
    }
}

fn run_test_cases(workdir: &str, sock: &str) -> Result<()> {
    let blobmgr = RemoteBlobMgr::new(workdir.to_owned(), sock)?;

    println!("run nydus-cached in test mode...");
    blobmgr.connect()?;
    blobmgr.start()?;
    blobmgr.ping()?;
    blobmgr.shutdown();
    println!("nydus-cached test finished");

    Ok(())
}
