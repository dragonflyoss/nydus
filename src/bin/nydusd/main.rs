// Copyright 2020 Ant Group. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[macro_use(crate_authors, crate_version)]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate rafs;
extern crate serde_json;

#[cfg(feature = "fusedev")]
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Result};
use std::ops::DerefMut;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::channel,
    Arc, Mutex,
};
use std::thread;
use std::{io, process};

use nix::sys::signal;
use rlimit::{rlim, Resource};

use clap::{App, Arg};
use fuse_rs::api::{Vfs, VfsOptions};

use event_manager::{EventManager, EventSubscriber, SubscriberOps};
use vmm_sys_util::eventfd::EventFd;

use nydus_api::http::start_http_thread;
use nydus_utils::{dump_program_info, setup_logging, BuildTimeInfo};

mod daemon;
use daemon::{DaemonError, FsBackendMountCmd, FsBackendType, NydusDaemonSubscriber};

#[cfg(feature = "virtiofs")]
mod virtiofs;
#[cfg(feature = "virtiofs")]
use virtiofs::create_nydus_daemon;
#[cfg(feature = "fusedev")]
mod fusedev;
#[cfg(feature = "fusedev")]
use fusedev::create_nydus_daemon;

mod api_server_glue;
mod upgrade;
use api_server_glue::{ApiServer, ApiSeverSubscriber};

lazy_static! {
    static ref EVENT_MANAGER_RUN: AtomicBool = AtomicBool::new(true);
    static ref EXIT_EVTFD: Mutex::<Option<EventFd>> = Mutex::<Option<EventFd>>::default();
}

fn get_default_rlimit_nofile() -> Result<rlim> {
    // Our default RLIMIT_NOFILE target.
    let mut max_fds: rlim = 1_000_000;
    // leave at least this many fds free
    let reserved_fds: rlim = 16_384;

    // Reduce max_fds below the system-wide maximum, if necessary.
    // This ensures there are fds available for other processes so we
    // don't cause resource exhaustion.
    let mut file_max = String::new();
    let mut f = File::open("/proc/sys/fs/file-max")?;
    f.read_to_string(&mut file_max)?;
    let file_max = file_max
        .trim()
        .parse::<rlim>()
        .map_err(|_| DaemonError::InvalidArguments("read fs.file-max sysctl wrong".to_string()))?;
    if file_max < 2 * reserved_fds {
        return Err(io::Error::from(DaemonError::InvalidArguments(
            "The fs.file-max sysctl is too low to allow a reasonable number of open files."
                .to_string(),
        )));
    }

    max_fds = std::cmp::min(file_max - reserved_fds, max_fds);

    Resource::NOFILE
        .get()
        .map(|(curr, _)| if curr >= max_fds { 0 } else { max_fds })
}

pub fn exit_event_manager() {
    EXIT_EVTFD
        .lock()
        .expect("Not poisoned lock!")
        .as_ref()
        .unwrap()
        .write(1)
        .unwrap_or_else(|e| error!("Write event fd failed when exiting event manager, {}", e))
}

extern "C" fn sig_exit(_sig: std::os::raw::c_int) {
    if cfg!(feature = "virtiofs") {
        // In case of virtiofs, mechanism to unblock recvmsg() from VMM is lacked.
        // Given the fact that we have nothing to clean up, directly exit seems fine.
        process::exit(0);
    } else {
        // Can't directly exit here since we want to umount rafs reflecting the signal.
        exit_event_manager();
    }
}

fn main() -> Result<()> {
    let (bti_string, bti) = BuildTimeInfo::dump(crate_version!());

    let cmd_arguments = App::new("")
        .version(bti_string.as_str())
        .author(crate_authors!())
        .about("Nydus image service")
        .arg(
            Arg::with_name("bootstrap")
                .long("bootstrap")
                .help("rafs bootstrap file")
                .takes_value(true)
                .min_values(1)
                .conflicts_with("shared-dir"),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .help("config file")
                .takes_value(true)
                .required(false)
                .min_values(1),
        )
        .arg(
            Arg::with_name("apisock")
                .long("apisock")
                .help("admin api socket path")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("shared-dir")
                .long("shared-dir")
                .help("Shared directory path")
                .takes_value(true)
                .min_values(1)
                .conflicts_with("bootstrap"),
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
        .arg(
            Arg::with_name("log-file")
                .long("log-file")
                .help("Specify the path to log file. If log filename has not extension, the default \".log\" will be added.")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("rlimit-nofile")
                .long("rlimit-nofile")
                .default_value("1,000,000")
                .help("set maximum number of file descriptors (0 leaves rlimit unchanged)")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("prefetch-files")
                .long("prefetch-files")
                .help("Specify a files list hinting which files should be prefetched.")
                .takes_value(true)
                .required(false)
                .multiple(true)
                .global(true),
        )
        .arg(
            Arg::with_name("supervisor")
                .long("supervisor")
                .help("A socket by which communicate to external supervisor")
                .takes_value(true)
                .required(false)
                .requires("id")
                .global(true),
        )
        .arg(
            Arg::with_name("id")
                .long("id")
                .help("Assigned ID to identify a daemon")
                .takes_value(true)
                .required(false)
                .requires("supervisor")
                .global(true),
        )
        .arg(
            Arg::with_name("upgrade")
                .long("upgrade")
                .help("Start nydusd in Upgrade mode")
                .takes_value(false)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("failover-policy")
                .long("failover-policy")
                .default_value("resend")
                .help("`flush` or `resend`")
                .takes_value(true)
                .required(false)
                .global(true),
        );

    #[cfg(feature = "fusedev")]
    let cmd_arguments = cmd_arguments
        .arg(
            Arg::with_name("mountpoint")
                .long("mountpoint")
                .help("fuse mount point")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("threads")
                .long("thread-num")
                .default_value("1")
                .help("Specify the number of fuse service threads")
                .takes_value(true)
                .required(false)
                .global(true)
                .validator(|v| {
                    if let Ok(t) = v.parse::<i32>() {
                        if t > 0 {
                            Ok(())
                        } else {
                            Err("Zero thread count is not allowed".to_string())
                        }
                    } else {
                        Err("Input thread number is not legal".to_string())
                    }
                }),
        );

    #[cfg(feature = "virtiofs")]
    let cmd_arguments = cmd_arguments.arg(
        Arg::with_name("sock")
            .long("sock")
            .help("vhost-user socket path")
            .takes_value(true)
            .min_values(1),
    );

    let cmd_arguments_parsed = cmd_arguments.get_matches();

    let logging_file = cmd_arguments_parsed.value_of("log-file").map(|l| l.into());
    // Safe to unwrap because it has default value and possible values are defined
    let level = cmd_arguments_parsed
        .value_of("log-level")
        .unwrap()
        .parse()
        .unwrap();

    setup_logging(logging_file, level)?;

    dump_program_info();

    // Retrieve arguments
    // shared-dir means fs passthrough
    let shared_dir = cmd_arguments_parsed.value_of("shared-dir");
    // bootstrap means rafs only
    let bootstrap = cmd_arguments_parsed.value_of("bootstrap");
    // apisock means admin api socket support
    let apisock = cmd_arguments_parsed.value_of("apisock");
    let rlimit_nofile_default = get_default_rlimit_nofile()?;
    let rlimit_nofile: rlim = cmd_arguments_parsed
        .value_of("rlimit-nofile")
        .map(|n| n.parse().unwrap_or(rlimit_nofile_default))
        .unwrap_or(rlimit_nofile_default);

    let vfs = Vfs::new(VfsOptions::default());
    let mount_cmd = if let Some(shared_dir) = shared_dir {
        info!(
            "set rlimit {}, default {}",
            rlimit_nofile, rlimit_nofile_default
        );

        if rlimit_nofile != 0 {
            Resource::NOFILE.set(rlimit_nofile, rlimit_nofile)?;
        }

        let cmd = FsBackendMountCmd {
            fs_type: FsBackendType::PassthroughFs,
            source: shared_dir.to_string(),
            config: "".to_string(),
            mountpoint: "/".to_string(),
            prefetch_files: None,
        };

        Some(cmd)
    } else if let Some(b) = bootstrap {
        let config = cmd_arguments_parsed.value_of("config").ok_or_else(|| {
            DaemonError::InvalidArguments("config file is not provided".to_string())
        })?;

        let prefetch_files: Option<Vec<String>> =
            if let Some(files) = cmd_arguments_parsed.values_of("prefetch-files") {
                Some(files.map(|s| s.to_string()).collect())
            } else {
                None
            };

        let cmd = FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            source: b.to_string(),
            config: std::fs::read_to_string(config)?,
            mountpoint: "/".to_string(),
            prefetch_files,
        };

        Some(cmd)
    } else {
        None
    };

    let mut event_manager = EventManager::<Arc<dyn EventSubscriber>>::new().unwrap();

    let vfs = Arc::new(vfs);
    let daemon_subscriber = Arc::new(NydusDaemonSubscriber::new()?);
    // Send an event to exit from Event Manager so as to exit from nydusd
    let exit_evtfd = daemon_subscriber.get_event_fd()?;
    event_manager.add_subscriber(daemon_subscriber);

    // Basically, below two arguments are essential for live-upgrade/failover/ and external management.
    let daemon_id = cmd_arguments_parsed.value_of("id").map(|id| id.to_string());
    let supervisor = cmd_arguments_parsed
        .value_of("supervisor")
        .map(|s| s.to_string());

    #[cfg(feature = "virtiofs")]
    let daemon = {
        // sock means vhost-user-backend only
        let vu_sock = cmd_arguments_parsed.value_of("sock").ok_or_else(|| {
            DaemonError::InvalidArguments("vhost socket must be provided!".to_string())
        })?;
        create_nydus_daemon(daemon_id, supervisor, vu_sock, vfs, mount_cmd, bti)?
    };
    #[cfg(feature = "fusedev")]
    let daemon = {
        // threads means number of fuse service threads
        let threads: u32 = cmd_arguments_parsed
            .value_of("threads")
            .map(|n| n.parse().unwrap_or(1))
            .unwrap_or(1);

        let p = cmd_arguments_parsed
            .value_of("failover-policy")
            .unwrap_or("flush")
            .try_into()
            .map_err(|e| {
                error!("Invalid failover policy");
                e
            })?;

        // mountpoint means fuse device only
        let mountpoint = cmd_arguments_parsed.value_of("mountpoint").ok_or_else(|| {
            DaemonError::InvalidArguments("Mountpoint must be provided!".to_string())
        })?;

        create_nydus_daemon(
            mountpoint,
            vfs,
            supervisor,
            daemon_id,
            threads,
            apisock,
            cmd_arguments_parsed.is_present("upgrade"),
            p,
            mount_cmd,
            bti,
        )
        .map(|d| {
            info!("Fuse daemon started!");
            d
        })?
    };

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

    *EXIT_EVTFD.lock().unwrap().deref_mut() = Some(exit_evtfd);
    nydus_utils::signal::register_signal_handler(signal::SIGINT, sig_exit);
    nydus_utils::signal::register_signal_handler(signal::SIGTERM, sig_exit);

    while EVENT_MANAGER_RUN.load(Ordering::Relaxed) {
        // If event manager dies, so does nydusd
        event_manager.run().unwrap();
    }

    if let Some(t) = http_thread {
        http_exit_evtfd.write(1).unwrap();
        if t.join()
            .map(|r| r.map_err(|e| error!("Thread execution error. {:?}", e)))
            .is_err()
        {
            error!("Join http thread failed.");
        }
    }

    daemon.stop().unwrap_or_else(|e| error!("{}", e));
    daemon.wait().unwrap_or_else(|e| error!("{}", e));
    info!("nydusd quits");
    Ok(())
}
