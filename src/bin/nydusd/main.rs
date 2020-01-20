// Copyright 2020 Ant Financial. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#[macro_use(crate_version, crate_authors)]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate rafs;
extern crate serde_json;
extern crate stderrlog;

use std::fs::File;
use std::io::{Read, Result};
use std::ops::{Deref, DerefMut};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::channel,
    Arc, Mutex,
};
use std::{io, process};

use nix::sys::signal;
use rlimit::{rlim, Resource};

use clap::{App, Arg};
use fuse_rs::{
    api::{Vfs, VfsOptions},
    passthrough::{Config, PassthroughFs},
};

use event_manager::{EventManager, EventSubscriber, SubscriberOps};
use vmm_sys_util::eventfd::EventFd;

use nydus_api::http::start_http_thread;
use nydus_utils::{einval, log_level_to_verbosity};
use rafs::fs::{Rafs, RafsConfig};

mod daemon;
use daemon::{Error, NydusDaemonSubscriber};

#[cfg(feature = "virtiofsd")]
mod virtiofs;
#[cfg(feature = "virtiofsd")]
use virtiofs::create_nydus_daemon;
#[cfg(feature = "fusedev")]
mod fusedev;
#[cfg(feature = "fusedev")]
use fusedev::create_nydus_daemon;

mod api_server_glue;
use api_server_glue::{ApiServer, ApiSeverSubscriber};

lazy_static! {
    static ref EVENT_MANAGER_RUN: AtomicBool = AtomicBool::new(true);
    static ref EXIT_EVTFD: Mutex::<Option<EventFd>> = Mutex::<Option<EventFd>>::default();
}

pub trait SubscriberWrapper: EventSubscriber {
    fn get_event_fd(&self) -> Result<EventFd>;
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
        .map_err(|_| Error::InvalidArguments("read fs.file-max sysctl wrong".to_string()))?;
    if file_max < 2 * reserved_fds {
        return Err(io::Error::from(Error::InvalidArguments(
            "The fs.file-max sysctl is too low to allow a reasonable number of open files."
                .to_string(),
        )));
    }

    max_fds = std::cmp::min(file_max - reserved_fds, max_fds);

    Resource::NOFILE
        .get()
        .map(|(curr, _)| if curr >= max_fds { 0 } else { max_fds })
}

extern "C" fn sig_exit(_sig: std::os::raw::c_int) {
    if cfg!(feature = "virtiofsd") {
        // In case of virtiofsd, mechanism to unblock recvmsg() from VMM is lacked.
        // Given the fact that we have nothing to clean up, directly exit seems fine.
        // TODO: But it might be possible to use libc::pthread_kill to unblock it.
        process::exit(0);
    } else {
        // Can't directly exit here since we want to umount rafs reflecting the signal.
        EXIT_EVTFD
            .lock()
            .unwrap()
            .deref()
            .as_ref()
            .unwrap()
            .write(1)
            .unwrap_or_else(|e| error!("Write event fd failed, {}", e))
    }
}

fn main() -> Result<()> {
    let cmd_arguments = App::new("vhost-user-fs backend")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Launch a vhost-user-fs backend.")
        .arg(
            Arg::with_name("bootstrap")
                .long("bootstrap")
                .help("rafs bootstrap file")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("sock")
                .long("sock")
                .help("vhost-user socket path")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("mountpoint")
                .long("mountpoint")
                .help("fuse mount point")
                .takes_value(true)
                .min_values(1),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .help("config file")
                .takes_value(true)
                .required(true)
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
                .min_values(1),
        )
        .arg(
            Arg::with_name("log-level")
                .long("log-level")
                .default_value("warn")
                .help("Specify log level: trace, debug, info, warn, error")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("threads")
                .long("thread-num")
                .default_value("1")
                .help("Specify the number of fuse service threads")
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
        .get_matches();

    let v = cmd_arguments
        .value_of("log-level")
        .unwrap()
        .parse()
        .unwrap_or(log::LevelFilter::Warn);

    stderrlog::new()
        .quiet(false)
        .verbosity(log_level_to_verbosity(log::LevelFilter::Trace))
        .timestamp(stderrlog::Timestamp::Second)
        .init()
        .unwrap();
    // We rely on `log` macro to limit current log level rather than `stderrlog`
    // So we set stderrlog verbosity to TRACE which is High enough. Otherwise, we
    // can't change log level to a higher level than what is passed to `stderrlog`.
    log::set_max_level(v);
    // A string including multiple directories and regular files should be separated by white-space, e.g.
    //      <path1> <path2> <path3>
    // And each path should be relative to rafs root, e.g.
    //      /foo1/bar1 /foo2/bar2
    // Specifying both regular file and directory are supported.
    let prefetch_files: Vec<&Path>;
    if let Some(files) = cmd_arguments.values_of("prefetch-files") {
        prefetch_files = files.map(|s| Path::new(s)).collect();
        // Sanity check
        for d in &prefetch_files {
            if !d.starts_with(Path::new("/")) {
                return Err(einval!(format!("Illegal prefetch files input {:?}", d)));
            }
        }
    } else {
        prefetch_files = Vec::new();
    }

    // Retrieve arguments
    // sock means vhost-user-backend only
    let vu_sock = cmd_arguments.value_of("sock").unwrap_or_default();
    // mountpoint means fuse device only
    let mountpoint = cmd_arguments.value_of("mountpoint").unwrap_or_default();
    // shared-dir means fs passthrough
    let shared_dir = cmd_arguments.value_of("shared-dir").unwrap_or_default();
    let config = cmd_arguments
        .value_of("config")
        .ok_or_else(|| Error::InvalidArguments("config file is not provided".to_string()))?;
    // bootstrap means rafs only
    let bootstrap = cmd_arguments.value_of("bootstrap").unwrap_or_default();
    // apisock means admin api socket support
    let apisock = cmd_arguments.value_of("apisock").unwrap_or_default();
    // threads means number of fuse service threads
    let threads: u32 = cmd_arguments
        .value_of("threads")
        .map(|n| n.parse().unwrap_or(1))
        .unwrap_or(1);
    let rlimit_nofile_default = get_default_rlimit_nofile()?;
    let rlimit_nofile: rlim = cmd_arguments
        .value_of("rlimit-nofile")
        .map(|n| n.parse().unwrap_or(rlimit_nofile_default))
        .unwrap_or(rlimit_nofile_default);

    // Some basic validation
    if !shared_dir.is_empty() && !bootstrap.is_empty() {
        return Err(einval!(
            "shared-dir and bootstrap cannot be set at the same time"
        ));
    }
    if vu_sock.is_empty() && mountpoint.is_empty() {
        return Err(einval!("either sock or mountpoint must be set".to_string()));
    }
    if !vu_sock.is_empty() && !mountpoint.is_empty() {
        return Err(einval!(
            "sock and mountpoint must not be set at the same time".to_string()
        ));
    }

    let content =
        std::fs::read_to_string(config).map_err(|e| Error::InvalidConfig(e.to_string()))?;
    let rafs_conf: RafsConfig =
        serde_json::from_str(&content).map_err(|e| Error::InvalidConfig(e.to_string()))?;
    let vfs = Vfs::new(VfsOptions::default());
    if !shared_dir.is_empty() {
        // Vfs by default enables no_open and writeback, passthroughfs
        // needs to specify them explicitly.
        // TODO(liubo): enable no_open_dir.
        let fs_cfg = Config {
            root_dir: shared_dir.to_string(),
            do_import: false,
            writeback: true,
            no_open: true,
            ..Default::default()
        };
        let passthrough_fs = PassthroughFs::new(fs_cfg).map_err(Error::FsInitFailure)?;
        passthrough_fs.import()?;
        vfs.mount(Box::new(passthrough_fs), "/")?;
        info!("vfs mounted");

        info!(
            "set rlimit {}, default {}",
            rlimit_nofile, rlimit_nofile_default
        );
        if rlimit_nofile != 0 {
            Resource::NOFILE.set(rlimit_nofile, rlimit_nofile)?;
        }
    } else if !bootstrap.is_empty() {
        let mut file = Box::new(File::open(bootstrap)?) as Box<dyn rafs::RafsIoRead>;
        let mut rafs = Rafs::new(rafs_conf.clone(), &"/".to_string(), &mut file)?;
        rafs.import(&mut file, Some(prefetch_files))?;
        info!("rafs mounted: {}", rafs_conf);
        vfs.mount(Box::new(rafs), "/")?;
        info!("vfs mounted");
    }

    let mut event_manager = EventManager::<Arc<dyn SubscriberWrapper>>::new().unwrap();

    let vfs = Arc::new(vfs);
    if apisock != "" {
        let vfs = Arc::clone(&vfs);

        let (to_api, from_http) = channel();
        let (to_http, from_api) = channel();

        let api_server = ApiServer::new(
            "nydusd".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
            to_http,
        )?;

        let api_server_subscriber = Arc::new(ApiSeverSubscriber::new(vfs, api_server, from_http)?);
        let api_server_id = event_manager.add_subscriber(api_server_subscriber);
        let evtfd = event_manager
            .subscriber_mut(api_server_id)
            .unwrap()
            .get_event_fd()?;
        start_http_thread(apisock, evtfd, to_api, from_api)?;
        info!("api server running at {}", apisock);
    }

    let daemon_subscriber = Arc::new(NydusDaemonSubscriber::new()?);
    let daemon_subscriber_id = event_manager.add_subscriber(daemon_subscriber);
    let evtfd = event_manager
        .subscriber_mut(daemon_subscriber_id)
        .unwrap()
        .get_event_fd()?;
    let exit_evtfd = evtfd.try_clone()?;
    let mut daemon = {
        if !vu_sock.is_empty() {
            create_nydus_daemon(vu_sock, vfs, evtfd, !bootstrap.is_empty())
        } else {
            create_nydus_daemon(mountpoint, vfs, evtfd, !bootstrap.is_empty())
        }
    }?;
    info!("starting fuse daemon");

    *EXIT_EVTFD.lock().unwrap().deref_mut() = Some(exit_evtfd);
    nydus_utils::signal::register_signal_handler(signal::SIGINT, sig_exit);
    nydus_utils::signal::register_signal_handler(signal::SIGTERM, sig_exit);

    if let Err(e) = daemon.start(threads) {
        error!("Failed to start daemon: {:?}", e);
        process::exit(1);
    }

    while EVENT_MANAGER_RUN.load(Ordering::Relaxed) {
        // If event manager dies, so does nydusd
        event_manager.run().unwrap();
    }

    if let Err(e) = daemon.stop() {
        error!("Error shutting down worker thread: {:?}", e)
    }

    if let Err(e) = daemon.wait() {
        error!("Waiting for daemon failed: {:?}", e);
    }

    info!("nydusd quits");
    Ok(())
}
