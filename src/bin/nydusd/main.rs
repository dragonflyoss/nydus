// Copyright 2022 Alibaba Cloud. All rights reserved.
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
#[macro_use]
extern crate nydus_error;

#[cfg(feature = "fusedev")]
use std::convert::TryInto;
use std::io::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use clap::{App, Arg, ArgMatches, SubCommand, Values};
use fuse_backend_rs::api::{Vfs, VfsOptions};
use mio::{Events, Poll, Token, Waker};
use nix::sys::signal;
use rlimit::{rlim, Resource};

use nydus::FsBackendType;
use nydus_app::{dump_program_info, setup_logging, BuildTimeInfo};

use crate::api_server_glue::ApiServerController;
use crate::daemon::{DaemonError, NydusDaemon};
use crate::fs_service::{FsBackendMountCmd, FsService};
use crate::service_controller::create_daemon;

#[cfg(feature = "fusedev")]
mod fusedev;
#[cfg(feature = "virtiofs")]
mod virtiofs;

mod api_server_glue;
mod daemon;
mod fs_cache;
mod fs_service;
mod service_controller;
mod upgrade;

/// Minimal number of file descriptors reserved for system.
const RLIMIT_NOFILE_RESERVED: rlim = 16384;
/// Default number of file descriptors.
const RLIMIT_NOFILE_MAX: rlim = 1_000_000;

lazy_static! {
    static ref DAEMON_CONTROLLER: DaemonController = DaemonController::new();
}

/// Controller to manage registered filesystem/blobcache/fscache services.
pub struct DaemonController {
    active: AtomicBool,
    singleton_mode: AtomicBool,
    daemon: Mutex<Option<Arc<dyn NydusDaemon>>>,
    // For backward compatibility to support singleton fusedev/virtiofs server.
    fs_service: Mutex<Option<Arc<dyn FsService>>>,
    waker: Arc<Waker>,
    poller: Mutex<Poll>,
}

impl DaemonController {
    fn new() -> Self {
        let poller = Poll::new().expect("Failed to create `ServiceController` instance");
        let waker = Waker::new(poller.registry(), Token(1))
            .expect("Failed to create waker for ServiceController");

        Self {
            active: AtomicBool::new(true),
            singleton_mode: AtomicBool::new(true),
            daemon: Mutex::new(None),
            fs_service: Mutex::new(None),
            waker: Arc::new(waker),
            poller: Mutex::new(poller),
        }
    }

    /// Check whether the service controller is still in active/working state.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    /// Allocate a waker to notify stop events.
    pub fn alloc_waker(&self) -> Arc<Waker> {
        self.waker.clone()
    }

    /// Enable/disable singleton mode, which will shutdown the process when any working thread exits.
    pub fn set_singleton_mode(&self, enabled: bool) {
        self.singleton_mode.store(enabled, Ordering::Release);
    }

    /// Set the daemon service object.
    pub fn set_daemon(&self, daemon: Arc<dyn NydusDaemon>) -> Option<Arc<dyn NydusDaemon>> {
        self.daemon.lock().unwrap().replace(daemon)
    }

    /// Get the daemon service object.
    ///
    /// Panic if called before `set_daemon()` has been called.
    pub fn get_daemon(&self) -> Arc<dyn NydusDaemon> {
        self.daemon.lock().unwrap().clone().unwrap()
    }

    /// Set the default fs service object.
    pub fn set_fs_service(&self, service: Arc<dyn FsService>) -> Option<Arc<dyn FsService>> {
        self.fs_service.lock().unwrap().replace(service)
    }

    /// Get the default fs service object.
    pub fn get_fs_service(&self) -> Option<Arc<dyn FsService>> {
        self.fs_service.lock().unwrap().clone()
    }

    fn shutdown(&self) {
        // Marking exiting state.
        self.active.store(false, Ordering::Release);
        // Signal the `run_loop()` working thread to exit.
        let _ = self.waker.wake();

        let daemon = self.daemon.lock().unwrap().take();
        if let Some(d) = daemon {
            /*
            // TODO: fix the behavior
            if cfg!(feature = "virtiofs") {
                // In case of virtiofs, mechanism to unblock recvmsg() from VMM is lacked.
                // Given the fact that we have nothing to clean up, directly exit seems fine.
                process::exit(0);
            }
             */
            if let Err(e) = d.stop() {
                error!("failed to stop daemon: {}", e);
            }
            if let Err(e) = d.wait() {
                error!("failed to wait daemon: {}", e)
            }
        }
    }

    fn run_loop(&self) {
        let mut events = Events::with_capacity(8);

        loop {
            match self.poller.lock().unwrap().poll(&mut events, None) {
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => error!("failed to receive notification from waker: {}", e),
                Ok(_) => {}
            }

            for event in events.iter() {
                if event.is_error() {
                    error!("Got error on the monitored event.");
                    continue;
                }

                if event.is_readable() && event.token() == Token(1) {
                    if self.active.load(Ordering::Acquire) {
                        return;
                    } else if self.singleton_mode.load(Ordering::Acquire) {
                        self.active.store(false, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }
    }
}

extern "C" fn sig_exit(_sig: std::os::raw::c_int) {
    DAEMON_CONTROLLER.shutdown();
}

#[cfg(any(feature = "fusedev", feature = "virtiofs"))]
fn append_fs_options(app: App<'static, 'static>) -> App<'static, 'static> {
    app.arg(
        Arg::with_name("bootstrap")
            .long("bootstrap")
            .short("B")
            .help("Bootstrap/metadata file for rafs filesystem, which also enables rafs mode")
            .takes_value(true)
            .requires("config")
            .conflicts_with("shared-dir"),
    )
    .arg(
        Arg::with_name("prefetch-files")
            .long("prefetch-files")
            .short("P")
            .help("List of file/directory to prefetch")
            .takes_value(true)
            .required(false)
            .requires("bootstrap")
            .multiple(true),
    )
    .arg(
        Arg::with_name("virtual-mountpoint")
            .long("virtual-mountpoint")
            .short("m")
            .help("Path inside FUSE/virtiofs virtual filesystem to mount the rafs/passthroughfs instance")
            .takes_value(true)
            .default_value("/")
            .required(false),
    )
}

#[cfg(feature = "fusedev")]
fn append_fuse_options(app: App<'static, 'static>) -> App<'static, 'static> {
    app.arg(
        Arg::with_name("mountpoint")
            .long("mountpoint")
            .short("M")
            .help("Path to mount the FUSE filesystem, target for `mount.fuse`")
            .takes_value(true)
            .required(false),
    )
    .arg(
        Arg::with_name("failover-policy")
            .long("failover-policy")
            .short("F")
            .default_value("resend")
            .help("FUSE server failover policy")
            .possible_values(&["resend", "flush"])
            .takes_value(true)
            .required(false),
    )
    .arg(
        Arg::with_name("threads")
            .long("thread-num")
            .short("T")
            .default_value("1")
            .help("Number of working threads to serve FUSE IO requests")
            .takes_value(true)
            .required(false)
            .validator(|v| {
                if let Ok(t) = v.parse::<i32>() {
                    if t > 0 && t <= 1024 {
                        Ok(())
                    } else {
                        Err("Invalid working thread number {}, valid values: [1-1024]".to_string())
                    }
                } else {
                    Err("Input thread number is invalid".to_string())
                }
            }),
    )
    .arg(
        Arg::with_name("writable")
            .long("writable")
            .short("W")
            .help("Mount FUSE filesystem in rw mode")
            .takes_value(false),
    )
}

#[cfg(feature = "fusedev")]
fn append_fuse_subcmd_options(app: App<'static, 'static>) -> App<'static, 'static> {
    let subcmd = SubCommand::with_name("fuse").about("Run as a dedicated FUSE server");
    let subcmd = append_fuse_options(subcmd);
    let subcmd = append_fs_options(subcmd);
    app.subcommand(subcmd)
}

#[cfg(feature = "virtiofs")]
fn append_virtiofs_options(app: App<'static, 'static>) -> App<'static, 'static> {
    app.arg(
        Arg::with_name("hybrid-mode")
            .long("hybrid-mode")
            .short("H")
            .help("Enable support for both rafs and passthroughfs modes")
            .required(false)
            .takes_value(false),
    )
    .arg(
        Arg::with_name("shared-dir")
            .long("shared-dir")
            .short("s")
            .help("Directory shared by host and guest for passthroughfs, which also enables pathroughfs mode")
            .takes_value(true)
            .conflicts_with("bootstrap"),
    )
    .arg(
        Arg::with_name("sock")
            .long("sock")
            .short("v")
            .help("Vhost-user API socket")
            .takes_value(true)
            .required(false),
    )
}

#[cfg(feature = "virtiofs")]
fn append_virtiofs_subcmd_options(app: App<'static, 'static>) -> App<'static, 'static> {
    let subcmd = SubCommand::with_name("virtiofs").about("Run as a dedicated virtiofs server");
    let subcmd = append_virtiofs_options(subcmd);
    let subcmd = append_fs_options(subcmd);
    app.subcommand(subcmd)
}

fn append_services_subcmd_options(app: App<'static, 'static>) -> App<'static, 'static> {
    let subcmd = SubCommand::with_name("daemon")
        .about("Run as a global daemon hosting multiple blobcache/fscache/virtiofs services.")
        .arg(
            Arg::with_name("fscache")
                .long("fscache")
                .short("F")
                .help("Control device for fscache, which also enables fscache service")
                .takes_value(true)
                .default_value("/dev/cachefiles"),
        );

    app.subcommand(subcmd)
}

fn prepare_commandline_options() -> App<'static, 'static> {
    let cmdline = App::new("nydusd")
        .about("Nydus BlobCache/FsCache/Image Service")
        .arg(
            Arg::with_name("apisock")
                .long("apisock")
                .short("A")
                .help("Administration API socket")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("config")
                .long("config")
                .short("C")
                .help("Configuration file")
                .required(false)
                .global(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("id")
                .long("id")
                .short("I")
                .help("Service instance identifier")
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
                .help("Log messages to the file. Default extension \".log\" will be used if no extension specified.")
                .takes_value(true)
                .required(false)
                .global(true),
        )
        .arg(
            Arg::with_name("rlimit-nofile")
                .long("rlimit-nofile")
                .short("R")
                .default_value("1000000")
                .help("Set rlimit for maximum file descriptor number (0 leaves it unchanged)")
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
        );

    #[cfg(feature = "fusedev")]
    let cmdline = append_fuse_subcmd_options(cmdline);
    #[cfg(feature = "virtiofs")]
    let cmdline = append_virtiofs_subcmd_options(cmdline);

    #[cfg(feature = "fusedev")]
    let cmdline = append_fuse_options(cmdline);
    #[cfg(feature = "virtiofs")]
    let cmdline = append_virtiofs_options(cmdline);
    #[cfg(any(feature = "fusedev", feature = "virtiofs"))]
    let cmdline = append_fs_options(cmdline);

    append_services_subcmd_options(cmdline)
}

#[cfg(target_os = "macos")]
fn get_max_rlimit_nofile() -> Result<rlim> {
    let mut mib = [nix::libc::CTL_KERN, nix::libc::KERN_MAXFILES];
    let mut file_max: rlim = 0;
    let mut size = std::mem::size_of::<rlim>();
    // Safe because the arguments are valid and we have checked the result.
    let res = unsafe {
        nix::libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&mut file_max) as *mut u64 as *mut nix::libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    nix::errno::Errno::result(res)?;
    Ok(file_max)
}

#[cfg(target_os = "linux")]
fn get_max_rlimit_nofile() -> Result<rlim> {
    let file_max = std::fs::read_to_string("/proc/sys/fs/file-max")?;
    file_max
        .trim()
        .parse::<rlim>()
        .map_err(|_| eother!("invalid content from fs.file-max"))
}

/// Handle command line option to tune rlimit for maximum file descriptor number.
fn handle_rlimit_nofile_option(args: &ArgMatches, option_name: &str) -> Result<()> {
    // `rlimit-nofile` has a default value, so safe to unwrap().
    let rlimit_nofile: rlim = args.value_of(option_name).unwrap().parse().map_err(|_e| {
        Error::new(
            ErrorKind::InvalidInput,
            "invalid value for option `rlimit-nofile`",
        )
    })?;

    if rlimit_nofile != 0 {
        // Ensures there are fds available for other processes so we don't cause resource exhaustion.
        let rlimit_nofile_max = get_max_rlimit_nofile()?;
        if rlimit_nofile_max < 2 * RLIMIT_NOFILE_RESERVED {
            return Err(eother!(
                "The fs.file-max sysctl is too low to allow a reasonable number of open files."
            ));
        }

        // Reduce max_fds below the system-wide maximum, if necessary.
        let rlimit_nofile_max = std::cmp::min(
            rlimit_nofile_max - RLIMIT_NOFILE_RESERVED,
            RLIMIT_NOFILE_MAX,
        );
        let rlimit_nofile_max = Resource::NOFILE.get().map(|(curr, _)| {
            if curr >= rlimit_nofile_max {
                curr
            } else {
                rlimit_nofile_max
            }
        })?;
        let rlimit_nofile = std::cmp::min(rlimit_nofile, rlimit_nofile_max);
        info!(
            "Set rlimit-nofile to {}, maximum {}",
            rlimit_nofile, rlimit_nofile_max
        );
        Resource::NOFILE.set(rlimit_nofile, rlimit_nofile)?;
    }

    Ok(())
}

pub struct SubCmdArgs<'a> {
    args: &'a ArgMatches<'a>,
    subargs: &'a ArgMatches<'a>,
}

impl<'a> SubCmdArgs<'a> {
    fn new(args: &'a ArgMatches, subargs: &'a ArgMatches) -> Self {
        SubCmdArgs { args, subargs }
    }

    pub fn value_of(&self, key: &str) -> Option<&str> {
        if let Some(v) = self.subargs.value_of(key) {
            Some(v)
        } else {
            self.args.value_of(key)
        }
    }

    pub fn values_of(&self, key: &str) -> Option<Values> {
        if let Some(v) = self.subargs.values_of(key) {
            Some(v)
        } else {
            self.args.values_of(key)
        }
    }

    pub fn is_present(&self, key: &str) -> bool {
        self.subargs.is_present(key) || self.args.is_present(key)
    }
}

fn process_default_fs_service(
    args: SubCmdArgs,
    bti: BuildTimeInfo,
    apisock: Option<&str>,
    is_fuse: bool,
) -> Result<()> {
    // shared-dir means fs passthrough
    let shared_dir = args.value_of("shared-dir");
    // bootstrap means rafs only
    let bootstrap = args.value_of("bootstrap");
    // safe as virtual_mountpoint default to "/"
    let virtual_mnt = args.value_of("virtual-mountpoint").unwrap();

    let mut opts = VfsOptions::default();
    let mount_cmd = if let Some(shared_dir) = shared_dir {
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
        let config = args.value_of("config").ok_or_else(|| {
            DaemonError::InvalidArguments("config file is not provided".to_string())
        })?;

        let prefetch_files: Option<Vec<String>> = args
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
    if args.is_present("hybrid-mode") {
        opts.no_open = false;
        opts.killpriv_v2 = true;
    }

    let vfs = Vfs::new(opts);
    let vfs = Arc::new(vfs);
    // Basically, below two arguments are essential for live-upgrade/failover/ and external management.
    let daemon_id = args.value_of("id").map(|id| id.to_string());
    let supervisor = args.value_of("supervisor").map(|s| s.to_string());

    #[cfg(feature = "fusedev")]
    if is_fuse {
        // threads means number of fuse service threads
        let threads: u32 = args
            .value_of("threads")
            .map(|n| n.parse().unwrap_or(1))
            .unwrap_or(1);

        let p = args
            .value_of("failover-policy")
            .unwrap_or("flush")
            .try_into()
            .map_err(|e| {
                error!("Invalid failover policy");
                e
            })?;

        // mountpoint means fuse device only
        let mountpoint = args.value_of("mountpoint").ok_or_else(|| {
            DaemonError::InvalidArguments(
                "Mountpoint must be provided for FUSE server!".to_string(),
            )
        })?;

        let daemon = {
            fusedev::create_fuse_daemon(
                mountpoint,
                vfs,
                supervisor,
                daemon_id,
                threads,
                apisock,
                args.is_present("upgrade"),
                !args.is_present("writable"),
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
        DAEMON_CONTROLLER.set_daemon(daemon);
    }

    #[cfg(feature = "virtiofs")]
    if !is_fuse {
        let vu_sock = args.value_of("sock").ok_or_else(|| {
            DaemonError::InvalidArguments("vhost socket must be provided!".to_string())
        })?;
        let _ = apisock.as_ref();
        DAEMON_CONTROLLER.set_daemon(virtiofs::create_virtiofs_daemon(
            daemon_id, supervisor, vu_sock, vfs, mount_cmd, bti,
        )?);
    }

    Ok(())
}

fn process_daemon_arguments(
    subargs: &SubCmdArgs,
    _apisock: Option<&str>,
    bti: BuildTimeInfo,
) -> Result<()> {
    let daemon = create_daemon(subargs, bti)?;
    DAEMON_CONTROLLER.set_daemon(daemon);
    Ok(())
}

fn main() -> Result<()> {
    let (bti_string, bti) = BuildTimeInfo::dump(crate_version!());
    let cmd_options = prepare_commandline_options().version(bti_string.as_str());
    let args = cmd_options.clone().get_matches();
    let logging_file = args.value_of("log-file").map(|l| l.into());
    // Safe to unwrap because it has default value and possible values are defined
    let level = args.value_of("log-level").unwrap().parse().unwrap();
    let apisock = args.value_of("apisock");

    setup_logging(logging_file, level)?;
    dump_program_info(crate_version!());
    handle_rlimit_nofile_option(&args, "rlimit-nofile")?;

    match args.subcommand_name() {
        Some("daemon") => {
            // Safe to unwrap because the subcommand is `daemon`.
            let subargs = args.subcommand_matches("daemon").unwrap();
            let subargs = SubCmdArgs::new(&args, subargs);
            process_daemon_arguments(&subargs, apisock, bti)?;
        }
        Some("fuse") => {
            // Safe to unwrap because the subcommand is `fuse`.
            let subargs = args.subcommand_matches("fuse").unwrap();
            let subargs = SubCmdArgs::new(&args, subargs);
            process_default_fs_service(subargs, bti, apisock, true)?;
        }
        Some("virtiofs") => {
            // Safe to unwrap because the subcommand is `virtiofs`.
            let subargs = args.subcommand_matches("virtiofs").unwrap();
            let subargs = SubCmdArgs::new(&args, subargs);
            process_default_fs_service(subargs, bti, apisock, false)?;
        }
        _ => {
            let subargs = SubCmdArgs::new(&args, &args);
            #[cfg(feature = "fusedev")]
            process_default_fs_service(subargs, bti, apisock, true)?;
            #[cfg(feature = "virtiofs")]
            process_default_fs_service(subargs, bti, apisock, false)?;
        }
    }

    let daemon = DAEMON_CONTROLLER.get_daemon();
    if let Some(fs) = daemon.get_default_fs_service() {
        DAEMON_CONTROLLER.set_fs_service(fs);
    }

    // Start the HTTP Administration API server
    let mut api_controller = ApiServerController::new(apisock);
    api_controller.start()?;

    // Initialize and run the daemon controller event loop.
    nydus_app::signal::register_signal_handler(signal::SIGINT, sig_exit);
    nydus_app::signal::register_signal_handler(signal::SIGTERM, sig_exit);

    // Run the main event loop
    if DAEMON_CONTROLLER.is_active() {
        DAEMON_CONTROLLER.run_loop();
    }

    // Gracefully shutdown system.
    info!("nydusd quits");
    api_controller.stop();
    DAEMON_CONTROLLER.shutdown();

    Ok(())
}
