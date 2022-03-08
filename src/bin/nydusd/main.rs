// Copyright 2020 Ant Group. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

#![deny(warnings)]
#[macro_use(crate_version)]
extern crate clap;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
extern crate rafs;
extern crate serde_json;
#[macro_use]
extern crate nydus_error;

#[cfg(feature = "fusedev")]
use std::convert::TryInto;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "macos")]
use std::io::Result;
#[cfg(target_os = "linux")]
use std::io::{Read, Result};
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::{mpsc::channel, Arc, Mutex};
use std::thread;
use std::{io, process};

use clap::{App, Arg};
use fuse_backend_rs::api::{Vfs, VfsOptions};
use mio::Waker;
use nix::sys::signal;
use rlimit::{rlim, Resource};

use nydus::FsBackendType;
use nydus_api::http::start_http_thread;
use nydus_app::{dump_program_info, setup_logging, BuildTimeInfo};

use self::api_server_glue::{ApiServer, ApiSeverSubscriber};
use self::daemon::{DaemonError, FsBackendMountCmd, NydusDaemon};

#[cfg(feature = "virtiofs")]
mod virtiofs;
#[cfg(feature = "virtiofs")]
use self::virtiofs::create_nydus_daemon;
#[cfg(feature = "fusedev")]
mod fusedev;
#[cfg(feature = "fusedev")]
use self::fusedev::create_nydus_daemon;

mod api_server_glue;
mod daemon;
mod upgrade;

lazy_static! {
    static ref FUSE_DAEMON: Mutex::<Option<Arc<dyn NydusDaemon + Send + Sync>>> = Mutex::default();
}

#[cfg(target_os = "macos")]
fn get_default_rlimit_nofile() -> Result<rlim> {
    // Our default RLIMIT_NOFILE target.
    let mut max_fds: rlim = 1_000_000;
    // leave at least this many fds free
    let reserved_fds: rlim = 16_384;

    let mut mib = [nix::libc::CTL_KERN, nix::libc::KERN_MAXFILES];

    // Reduce max_fds below the system-wide maximum, if necessary.
    // This ensures there are fds available for other processes so we
    // don't cause resource exhaustion.
    let file_max = unsafe {
        let mut file_max: rlim = 0;
        let mut size = std::mem::size_of::<rlim>();
        let res = nix::libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&mut file_max) as *mut u64 as *mut nix::libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        nix::errno::Errno::result(res)?;
        file_max
    };

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

#[cfg(target_os = "linux")]
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

pub fn exit_daemon() {
    let daemon = FUSE_DAEMON.lock().expect("Not posioned lock");
    if let Some(daemon) = daemon.deref() {
        daemon
            .disconnect()
            .unwrap_or_else(|e| error!("disconnect daemon failed, {}", e));
    }
}

extern "C" fn sig_exit(_sig: std::os::raw::c_int) {
    if cfg!(feature = "virtiofs") {
        // In case of virtiofs, mechanism to unblock recvmsg() from VMM is lacked.
        // Given the fact that we have nothing to clean up, directly exit seems fine.
        process::exit(0);
    } else {
        // Can't directly exit here since we want to umount rafs reflecting the signal.
        exit_daemon();
    }
}

fn main() -> Result<()> {
    let (bti_string, bti) = BuildTimeInfo::dump(crate_version!());

    let cmd_arguments = App::new("")
        .version(bti_string.as_str())
        .about("Nydus Image Service")
        .arg(
            Arg::with_name("apisock")
                .long("apisock")
                .short("A")
                .help("Administration API socket")
                .takes_value(true)
                .required(false),
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
            Arg::with_name("failover-policy")
                .long("failover-policy")
                .default_value("resend")
                .help("Nydus image service failover policy")
                .possible_values(&["resend", "flush"])
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("id")
                .long("id")
                .help("Nydus image service identifier")
                .takes_value(true)
                .required(false)
                .requires("supervisor")
                .global(true),
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
                .help("Log messages to the file. If file extension is not specified, the default extension \".log\" will be appended.")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("prefetch-files")
                .long("prefetch-files")
                .help("List of file/directory to prefetch")
                .takes_value(true)
                .required(false)
                .multiple(true)
                .global(true),
        )
        .arg(
            Arg::with_name("rlimit-nofile")
                .long("rlimit-nofile")
                .default_value("1,000,000")
                .help("Tune the maximum number of file descriptors (0 leaves rlimit unchanged)")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("supervisor")
                .long("supervisor")
                .short("S")
                .help("Supervisor API socket")
                .takes_value(true)
                .required(false)
                .requires("id")
                .global(true),
        )
        .arg(
            Arg::with_name("upgrade")
                .long("upgrade")
                .short("U")
                .help("Start in upgrade mode")
                .takes_value(false)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("virtual-mountpoint")
                .long("virtual-mountpoint")
                .short("V")
                .help("Virtual mountpoint for the filesystem")
                .takes_value(true)
                .default_value("/")
                .required(false)
                .global(true),
        ).arg(
            Arg::with_name("bootstrap")
                .long("bootstrap")
                .short("B")
                .help("Rafs filesystem bootstrap/metadata file")
                .takes_value(true)
                .conflicts_with("shared-dir")
        )
        .arg(
            Arg::with_name("shared-dir")
                .long("shared-dir")
                .short("s")
                .help("Directory to pass through to the guest VM")
                .takes_value(true)
                .conflicts_with("bootstrap"),
        )
        .arg(
            Arg::with_name("hybrid-mode").long("hybrid-mode")
            .help("run nydusd in rafs and passthroughfs hybrid mode")
            .required(false)
            .takes_value(false)
            .global(true)
        );

    #[cfg(feature = "fusedev")]
    let cmd_arguments = cmd_arguments
        .arg(
            Arg::with_name("mountpoint")
                .long("mountpoint")
                .short("M")
                .help("Fuse mount point")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("threads")
                .long("thread-num")
                .short("T")
                .default_value("1")
                .help("Number of working threads to serve IO requests")
                .takes_value(true)
                .required(false)
                .global(true)
                .validator(|v| {
                    if let Ok(t) = v.parse::<i32>() {
                        if t > 0 && t <= 1024 {
                            Ok(())
                        } else {
                            Err("Invalid working thread number {}, valid values: [1-1024]"
                                .to_string())
                        }
                    } else {
                        Err("Input thread number is not legal".to_string())
                    }
                }),
        )
        .arg(
            Arg::with_name("writable")
                .long("writable")
                .help("set fuse mountpoint non-readonly")
                .takes_value(false),
        );

    #[cfg(feature = "virtiofs")]
    let cmd_arguments = cmd_arguments.arg(
        Arg::with_name("sock")
            .long("sock")
            .help("Vhost-user API socket")
            .takes_value(true)
            .required(true),
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

    dump_program_info(crate_version!());

    // Retrieve arguments
    // shared-dir means fs passthrough
    let shared_dir = cmd_arguments_parsed.value_of("shared-dir");
    // bootstrap means rafs only
    let bootstrap = cmd_arguments_parsed.value_of("bootstrap");
    // safe as virtual_mountpoint default to "/"
    let virtual_mnt = cmd_arguments_parsed.value_of("virtual-mountpoint").unwrap();
    // apisock means admin api socket support
    let apisock = cmd_arguments_parsed.value_of("apisock");
    let rlimit_nofile_default = get_default_rlimit_nofile()?;
    let rlimit_nofile: rlim = cmd_arguments_parsed
        .value_of("rlimit-nofile")
        .map(|n| n.parse().unwrap_or(rlimit_nofile_default))
        .unwrap_or(rlimit_nofile_default);

    let mut opts = VfsOptions::default();
    let mount_cmd = if let Some(shared_dir) = shared_dir {
        if rlimit_nofile != 0 {
            info!(
                "set rlimit {}, default {}",
                rlimit_nofile, rlimit_nofile_default
            );
            Resource::NOFILE.set(rlimit_nofile, rlimit_nofile)?;
        }

        let cmd = FsBackendMountCmd {
            fs_type: FsBackendType::PassthroughFs,
            source: shared_dir.to_string(),
            config: "".to_string(),
            mountpoint: virtual_mnt.to_string(),
            prefetch_files: None,
        };

        // passthroughfs requires !no_open
        opts.no_open = false;
        opts.killpriv_v2 = true;

        Some(cmd)
    } else if let Some(b) = bootstrap {
        let config = cmd_arguments_parsed.value_of("config").ok_or_else(|| {
            DaemonError::InvalidArguments("config file is not provided".to_string())
        })?;

        let prefetch_files: Option<Vec<String>> = cmd_arguments_parsed
            .values_of("prefetch-files")
            .map(|files| files.map(|s| s.to_string()).collect());

        let cmd = FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            source: b.to_string(),
            config: std::fs::read_to_string(config)?,
            mountpoint: virtual_mnt.to_string(),
            prefetch_files,
        };

        // rafs can be readonly and skip open
        opts.no_open = true;

        Some(cmd)
    } else {
        None
    };

    // Enable all options required by passthroughfs
    if cmd_arguments_parsed.is_present("hybrid-mode") {
        opts.no_open = false;
        opts.killpriv_v2 = true;
    }

    let vfs = Vfs::new(opts);

    let vfs = Arc::new(vfs);
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
            !cmd_arguments_parsed.is_present("writable"),
            p,
            mount_cmd,
            bti,
        )
        .map(|d| {
            info!("Fuse daemon started!");
            d
        })
        .map_err(|e| {
            error!("Failed in starting daemon: {}", e);
            e
        })?
    };

    #[allow(clippy::type_complexity)]
    let mut http_thread_and_waker: Option<(
        thread::JoinHandle<Result<()>>,
        thread::JoinHandle<()>,
        Arc<Waker>,
    )> = None;
    if let Some(apisock) = apisock {
        let (to_api, from_http) = channel();
        let (to_http, from_api) = channel();

        let api_server = ApiServer::new(to_http, daemon.clone())?;

        let api_server_subscriber = ApiSeverSubscriber::new(api_server, from_http)?;
        let api_notifier = api_server_subscriber.get_waker();
        let api_server_thread = api_server_subscriber.run()?;

        let (ret, thread_exit_waker) = start_http_thread(apisock, api_notifier, to_api, from_api)?;
        http_thread_and_waker = Some((ret, api_server_thread, thread_exit_waker));
        info!("api server running at {}", apisock);
    }

    *FUSE_DAEMON.lock().unwrap().deref_mut() = Some(daemon.clone());
    nydus_app::signal::register_signal_handler(signal::SIGINT, sig_exit);
    nydus_app::signal::register_signal_handler(signal::SIGTERM, sig_exit);

    daemon
        .wait()
        .unwrap_or_else(|e| error!("failed to wait daemon {}", e));

    if let Some((http_server_thread, api_server_thread, waker)) = http_thread_and_waker {
        info!("wake http_thread.");
        if waker.wake().is_err() {
            error!("wake http thread failed.");
        }
        if http_server_thread
            .join()
            .map(|r| r.map_err(|e| error!("Http server thread execution error. {:?}", e)))
            .is_err()
        {
            error!("Join http server thread failed.");
        }
        if api_server_thread.join().is_err() {
            error!("Join api server thread failed.");
        }
    }

    info!("nydusd quits");

    Ok(())
}
