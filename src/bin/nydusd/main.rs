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
use std::fs::File;
use std::io::{self, Read, Result};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use clap::{App, Arg, ArgMatches, SubCommand};
use event_manager::{EventManager, EventSubscriber};
use fuse_backend_rs::api::{Vfs, VfsOptions};
use mio::{Events, Poll, Token, Waker};
use nix::sys::signal;
use rlimit::{rlim, Resource};

use nydus::FsBackendType;
use nydus_app::{dump_program_info, setup_logging, BuildTimeInfo};

use self::api_server_glue::ApiServerController;
use self::daemon::{DaemonError, FsBackendMountCmd, NydusDaemon};

#[cfg(feature = "fusedev")]
mod fusedev;
#[cfg(feature = "virtiofs")]
mod virtiofs;

mod api_server_glue;
mod daemon;
mod fscache;
mod upgrade;

/// Minimal number of file descriptors reserved for system.
const RLIMIT_NOFILE_RESERVED: rlim = 16384;
/// Default number of file descriptors.
const RLIMIT_NOFILE_MAX: rlim = 1_000_000;

lazy_static! {
    static ref SERVICE_CONTROLLER: ServiceController = ServiceController::new();
}

/// Controller to manage registered filesystem/blobcache/fscache services.
pub struct ServiceController {
    active: AtomicBool,
    singleton_mode: AtomicBool,
    // For backward compatibility to support singleton fusedev/virtiofs server.
    default_fs_service: Mutex<Option<Arc<dyn NydusDaemon>>>,
    waker: Arc<Waker>,
    poller: Mutex<Poll>,
}

impl ServiceController {
    fn new() -> Self {
        let poller = Poll::new().expect("Failed to create `ServiceController` instance");
        let waker = Waker::new(poller.registry(), Token(1))
            .expect("Failed to create waker for ServiceController");

        Self {
            active: AtomicBool::new(true),
            singleton_mode: AtomicBool::new(true),
            default_fs_service: Mutex::new(None),
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

    /// Set the default file system service instance.
    pub fn set_default_fs_service(
        &self,
        fs_service: Arc<dyn NydusDaemon>,
    ) -> Option<Arc<dyn NydusDaemon>> {
        self.default_fs_service.lock().unwrap().replace(fs_service)
    }

    /// Get the default file system service instance.
    pub fn get_default_fs_service(&self) -> Option<Arc<dyn NydusDaemon>> {
        self.default_fs_service.lock().unwrap().clone()
    }

    fn shutdown(&self) {
        // Marking exiting state.
        self.active.store(false, Ordering::Release);
        // Signal the `run_loop()` working thread to exit.
        let _ = self.waker.wake();

        let fs_service = self.default_fs_service.lock().unwrap().take();
        if let Some(service) = fs_service {
            // TODO: fix the behavior
            if cfg!(feature = "virtiofs") {
                // In case of virtiofs, mechanism to unblock recvmsg() from VMM is lacked.
                // Given the fact that we have nothing to clean up, directly exit seems fine.
                process::exit(0);
            }
            if let Err(e) = service.stop() {
                error!("failed to stop default fs service: {}", e);
            }
            if let Err(e) = service.wait() {
                error!("failed to wait for default fs service: {}", e)
            }
        }
    }

    fn run_loop(&self) {
        let mut events = Events::with_capacity(8);

        loop {
            self.poller
                .lock()
                .unwrap()
                .poll(&mut events, None)
                .unwrap_or_else(|e| error!("failed to receive notification from waker: {}", e));

            for event in events.iter() {
                if event.is_error() {
                    error!("Got error on the monitored event.");
                    continue;
                }

                if event.is_readable()
                    && event.token() == Token(1)
                    && self.singleton_mode.load(Ordering::Acquire)
                {
                    self.active.store(false, Ordering::Relaxed);
                    return;
                }
            }
        }
    }
}

extern "C" fn sig_exit(_sig: std::os::raw::c_int) {
    SERVICE_CONTROLLER.shutdown();
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
        Arg::with_name("config")
            .long("config")
            .short("C")
            .help("Configuration file")
            .required(false)
            .takes_value(true),
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
            .required(true),
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

#[cfg(feature = "fusedev1")]
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
            .required(true),
    )
}

#[cfg(feature = "virtiofs1")]
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
                .help("Log file, \".log\" will be appended if no file extension specified")
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

    //#[cfg(feature = "fusedev")]
    //let cmdline = append_fuse_subcmd_options(cmdline);
    //#[cfg(feature = "virtiofs")]
    //let cmdline = append_virtiofs_subcmd_options(cmdline);

    #[cfg(feature = "fusedev")]
    let cmdline = append_fuse_options(cmdline);
    #[cfg(feature = "virtiofs")]
    let cmdline = append_virtiofs_options(cmdline);
    #[cfg(any(feature = "fusedev", feature = "virtiofs"))]
    let cmdline = append_fs_options(cmdline);

    append_services_subcmd_options(cmdline)
}

fn get_max_rlimit_nofile() -> std::io::Result<rlim> {
    let mut f = File::open("/proc/sys/fs/file-max")?;
    let mut file_max = String::new();
    f.read_to_string(&mut file_max)?;
    let file_max = file_max.trim().parse::<rlim>().map_err(|_| {
        DaemonError::InvalidArguments("invalid content from fs.file-max".to_string())
    })?;

    // Ensures there are fds available for other processes so we don't cause resource exhaustion.
    if file_max < 2 * RLIMIT_NOFILE_RESERVED {
        return Err(io::Error::from(DaemonError::InvalidArguments(
            "The fs.file-max sysctl is too low to allow a reasonable number of open files."
                .to_string(),
        )));
    }

    // Reduce max_fds below the system-wide maximum, if necessary.
    let max_fds = std::cmp::min(file_max - RLIMIT_NOFILE_RESERVED, RLIMIT_NOFILE_MAX);

    Resource::NOFILE
        .get()
        .map(|(curr, _)| if curr >= max_fds { curr } else { max_fds })
}

/// Handle command line option to tune rlimit for maximum file descriptor number.
fn handle_rlimit_nofile_option(args: &ArgMatches, option_name: &str) -> Result<()> {
    // `rlimit-nofile` has a default value, so safe to unwrap().
    let rlimit_nofile: rlim = args.value_of(option_name).unwrap().parse().map_err(|_e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid value for option rlimit-nofile",
        )
    })?;

    if rlimit_nofile != 0 {
        let rlimit_nofile_max = get_max_rlimit_nofile()?;
        let rlimit_nofile_max = std::cmp::min(rlimit_nofile_max, RLIMIT_NOFILE_MAX);
        let rlimit_nofile = std::cmp::min(rlimit_nofile, rlimit_nofile_max);
        info!(
            "Set rlimit-nofile to {}, maximum {}",
            rlimit_nofile, rlimit_nofile_max
        );
        Resource::NOFILE.set(rlimit_nofile, rlimit_nofile)?;
    }

    Ok(())
}

fn process_default_fs_service(
    args: &ArgMatches,
    subargs: &ArgMatches,
    bti: BuildTimeInfo,
    apisock: Option<&str>,
    is_fuse: bool,
) -> Result<()> {
    // shared-dir means fs passthrough
    let shared_dir = subargs.value_of("shared-dir");
    // bootstrap means rafs only
    let bootstrap = subargs.value_of("bootstrap");
    // safe as virtual_mountpoint default to "/"
    let virtual_mnt = subargs.value_of("virtual-mountpoint").unwrap();

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
        SERVICE_CONTROLLER.set_default_fs_service(daemon);
    }

    #[cfg(feature = "virtiofs")]
    if !is_fuse {
        let vu_sock = args.value_of("sock").ok_or_else(|| {
            DaemonError::InvalidArguments("vhost socket must be provided!".to_string())
        })?;
        let _ = apisock.as_ref();
        SERVICE_CONTROLLER.set_default_fs_service(virtiofs::create_virtiofs_daemon(
            daemon_id, supervisor, vu_sock, vfs, mount_cmd, bti,
        )?);
    }

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
    let mut event_manager = EventManager::<Arc<dyn EventSubscriber>>::new().unwrap();

    setup_logging(logging_file, level)?;
    dump_program_info(crate_version!());
    handle_rlimit_nofile_option(&args, "rlimit-nofile")?;

    // Initialize and run the daemon controller event loop.
    nydus_app::signal::register_signal_handler(signal::SIGINT, sig_exit);
    nydus_app::signal::register_signal_handler(signal::SIGTERM, sig_exit);
    std::thread::spawn(|| SERVICE_CONTROLLER.run_loop());

    match args.subcommand_name() {
        Some("daemon") => {
            todo!("surppot services");
        }
        Some("fuse") => {
            // Safe to unwrap because the subcommand is `fuse`.
            let subargs = args.subcommand_matches("fuse").unwrap();
            process_default_fs_service(&args, subargs, bti, apisock, true)?;
        }
        Some("virtiofs") => {
            // Safe to unwrap because the subcommand is `virtiofs`.
            let subargs = args.subcommand_matches("virtiofs").unwrap();
            process_default_fs_service(&args, subargs, bti, apisock, false)?;
        }
        _ => {
            #[cfg(feature = "fusedev")]
            process_default_fs_service(&args, &args, bti, apisock, true)?;
            #[cfg(feature = "virtiofs")]
            process_default_fs_service(&args, &args, bti, apisock, false)?;
            /*
            cmd_options
                .print_help()
                .map_err(|_e| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
             */
        }
    }

    // Start the HTTP Administration API server
    let mut api_controller = ApiServerController::new(apisock);
    api_controller.start(&mut event_manager)?;

    // Run the main event loop
    while SERVICE_CONTROLLER.is_active() {
        // If event manager dies, so does nydusd
        if event_manager.run().is_err() {
            break;
        }
    }

    // Gracefully shutdown system.
    info!("nydusd quits");
    api_controller.stop();
    SERVICE_CONTROLLER.shutdown();

    Ok(())
}
