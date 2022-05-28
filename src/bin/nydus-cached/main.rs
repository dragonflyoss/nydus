// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[macro_use(crate_version)]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate nydus_storage as storage;

use std::io::Result;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use clap::{App, Arg};
use event_manager::{EventManager, EventOps, EventSubscriber, Events, SubscriberOps};
use nydus_app::{dump_program_info, setup_logging, BuildTimeInfo};
use storage::remote::{RemoteBlobMgr, Server};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

const LISTERNER_EVENT_IDX: u32 = 1;

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

    let server = Arc::new(CachedServer::new(sock)?);
    let mut event_manager = EventManager::<Arc<dyn EventSubscriber>>::new().unwrap();
    event_manager.add_subscriber(server.clone());

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

    //*EXIT_EVTFD.lock().unwrap().deref_mut() = Some(exit_evtfd);
    while EVENT_MANAGER_RUN.load(Ordering::Relaxed) {
        // If event manager dies, so does nydusd
        event_manager.run().unwrap();
    }

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

    server.server.stop();
    info!("nydus-cached quits");

    Ok(())
}

struct CachedServer {
    server: Server,
}

impl CachedServer {
    fn new(sock: &str) -> Result<Self> {
        let server = Server::new(sock)?;

        Ok(Self { server })
    }

    fn handle_incoming_connection(&self, events: Events, event_ops: &mut EventOps) {
        match events.event_set() {
            EventSet::IN => match self.server.handle_incoming_connection() {
                Err(e) => error!("failed to handle incoming connection, {}", e),
                Ok(None) => {}
                Ok(Some(client)) => {
                    let id = client.id();
                    debug_assert!(id != LISTERNER_EVENT_IDX);
                    let event = Events::with_data(client.as_ref(), id, EventSet::IN);
                    if let Err(e) = event_ops.add(event) {
                        error!(
                            "failed to register event handler for client connection, {}",
                            e
                        );
                        client.close();
                    }
                }
            },
            EventSet::ERROR => error!("failed to accept incoming connection."),
            EventSet::HANG_UP => {
                event_ops
                    .remove(events)
                    .unwrap_or_else(|e| error!("failed to unregister handler for listener, {}", e));
            }
            _ => {}
        }
    }

    fn handle_event(&self, events: Events, event_ops: &mut EventOps) {
        let id = events.data();
        let event_set = events.event_set();

        if event_set.contains(EventSet::HANG_UP) || event_set.contains(EventSet::READ_HANG_UP) {
            event_ops
                .remove(events)
                .unwrap_or_else(|e| error!("failed to unregister handler for listener, {}", e));
            self.server.close_connection(id);
        } else if event_set.contains(EventSet::ERROR) {
            error!("epoll from client connection returns error");
            event_ops
                .remove(events)
                .unwrap_or_else(|e| error!("failed to unregister handler for listener, {}", e));
            self.server.close_connection(id);
        } else if event_set.contains(EventSet::IN) {
            if let Err(e) = self.server.handle_event(id) {
                error!("failed to handle client request, {}", e);
                event_ops
                    .remove(events)
                    .unwrap_or_else(|e| error!("failed to unregister handler for listener, {}", e));
                self.server.close_connection(id);
            }
        } else {
            error!(
                "unknown epoll event from client connection {}",
                events.event_set().bits()
            );
            event_ops
                .remove(events)
                .unwrap_or_else(|e| error!("failed to unregister handler for listener, {}", e));
            self.server.close_connection(id);
        }
    }
}

impl EventSubscriber for CachedServer {
    fn process(&self, events: Events, event_ops: &mut EventOps) {
        let data = events.data();

        if data == LISTERNER_EVENT_IDX {
            self.handle_incoming_connection(events, event_ops);
        } else {
            self.handle_event(events, event_ops);
        }
    }

    fn init(&self, ops: &mut EventOps) {
        let event = Events::with_data(&self.server, LISTERNER_EVENT_IDX, EventSet::IN);

        ops.add(event)
            .expect("Cannot register event handler for listener");
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
