// Copyright 2022 Alibaba Cloud. All rights reserved.
// Copyright 2020 Ant Group. All rights reserved.
// Copyright 2019 Intel Corporation. All Rights Reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)
#![deny(warnings)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate nydus_api;

use std::convert::TryInto;
use std::io::{Error, ErrorKind, Result};

use clap::{Arg, ArgAction, ArgMatches, Command};
use nix::sys::signal;
use rlimit::Resource;

use nydus::{dump_program_info, get_build_time_info, setup_logging, SubCmdArgs};
use nydus_api::{BuildTimeInfo, ConfigV2};
use nydus_service::daemon::DaemonController;
use nydus_service::{
    create_daemon, create_fuse_daemon, create_vfs_backend, validate_threads_configuration,
    Error as NydusError, FsBackendMountCmd, FsBackendType, ServiceArgs,
};

use crate::api_server_glue::ApiServerController;

#[cfg(feature = "virtiofs")]
mod virtiofs;

mod api_server_glue;

/// Minimal number of file descriptors reserved for system.
const RLIMIT_NOFILE_RESERVED: u64 = 16384;
/// Default number of file descriptors.
const RLIMIT_NOFILE_MAX: u64 = 1_000_000;

lazy_static! {
    static ref DAEMON_CONTROLLER: DaemonController = DaemonController::new();
    static ref BTI_STRING: String = get_build_time_info().0;
    static ref BTI: BuildTimeInfo = get_build_time_info().1;
}

fn thread_validator(v: &str) -> std::result::Result<String, String> {
    validate_threads_configuration(v).map(|s| s.to_string())
}

fn append_fs_options(app: Command) -> Command {
    app.arg(
        Arg::new("bootstrap")
            .long("bootstrap")
            .short('B')
            .help("Path to the RAFS filesystem metadata file")
            .conflicts_with("shared-dir"),
    )
    .arg(
        Arg::new("localfs-dir")
            .long("localfs-dir")
            .short('D')
            .help(
                "Path to the `localfs` working directory, which also enables the `localfs` storage backend"
            )
            .conflicts_with("config"),
    )
    .arg(
        Arg::new("shared-dir")
            .long("shared-dir")
            .short('s')
            .help("Path to the directory to be shared via the `passthroughfs` FUSE driver")
    )
    .arg(
        Arg::new("prefetch-files")
            .long("prefetch-files")
            .help("Path to the prefetch configuration file containing a list of directories/files separated by newlines")
            .required(false)
            .requires("bootstrap")
            .num_args(1),
    )
    .arg(
        Arg::new("virtual-mountpoint")
            .long("virtual-mountpoint")
            .short('m')
            .help("Mountpoint within the FUSE/virtiofs device to mount the RAFS/passthroughfs filesystem")
            .default_value("/")
            .required(false),
    )
}

fn append_fuse_options(app: Command) -> Command {
    app.arg(
        Arg::new("mountpoint")
            .long("mountpoint")
            .short('M')
            .help("Mountpoint for the FUSE filesystem, target for `mount.fuse`")
            .required(true),
    )
    .arg(
        Arg::new("failover-policy")
            .long("failover-policy")
            .default_value("resend")
            .help("FUSE server failover policy")
            .value_parser(["resend", "flush"])
            .required(false),
    )
    .arg(
        Arg::new("fuse-threads")
            .long("fuse-threads")
            .alias("thread-num")
            .default_value("4")
            .help("Number of worker threads to serve FUSE I/O requests")
            .value_parser(thread_validator)
            .required(false),
    )
    .arg(
        Arg::new("writable")
            .long("writable")
            .action(ArgAction::SetTrue)
            .help("Mounts FUSE filesystem in rw mode"),
    )
}

fn append_fuse_subcmd_options(cmd: Command) -> Command {
    let subcmd = Command::new("fuse").about("Run the Nydus daemon as a dedicated FUSE server");
    let subcmd = append_fuse_options(subcmd);
    let subcmd = append_fs_options(subcmd);
    cmd.subcommand(subcmd)
}

#[cfg(feature = "virtiofs")]
fn append_virtiofs_options(cmd: Command) -> Command {
    cmd.arg(
        Arg::new("hybrid-mode")
            .long("hybrid-mode")
            .help("Enables both `RAFS` and `passthroughfs` filesystem drivers")
            .action(ArgAction::SetFalse)
            .required(false),
    )
    .arg(
        Arg::new("sock")
            .long("sock")
            .help("Path to the vhost-user API socket")
            .required(true),
    )
}

#[cfg(feature = "virtiofs")]
fn append_virtiofs_subcmd_options(cmd: Command) -> Command {
    let subcmd =
        Command::new("virtiofs").about("Run the Nydus daemon as a dedicated virtio-fs server");
    let subcmd = append_virtiofs_options(subcmd);
    let subcmd = append_fs_options(subcmd);
    cmd.subcommand(subcmd)
}

fn append_fscache_options(app: Command) -> Command {
    app.arg(
        Arg::new("fscache")
            .long("fscache")
            .short('F')
            .help("Working directory for Linux fscache driver to store cache files"),
    )
    .arg(
        Arg::new("fscache-tag")
            .long("fscache-tag")
            .help("Tag to identify the fscache daemon instance")
            .requires("fscache"),
    )
    .arg(
        Arg::new("fscache-threads")
            .long("fscache-threads")
            .default_value("4")
            .help("Number of working threads to serve fscache requests")
            .required(false)
            .value_parser(thread_validator),
    )
}

fn append_singleton_subcmd_options(cmd: Command) -> Command {
    let subcmd = Command::new("singleton")
        .about("Run the Nydus daemon to host multiple blobcache/fscache/fuse/virtio-fs services");
    let subcmd = append_fscache_options(subcmd);

    // TODO: enable support of fuse service
    /*
    let subcmd = subcmd.arg(
        Arg::new("fuse")
            .long("fuse")
            .short("f")
            .help("Run as a shared FUSE server"),
    );
    let subcmd = append_fuse_options(subcmd);
    let subcmd = append_fs_options(subcmd);
    */

    cmd.subcommand(subcmd)
}

fn prepare_commandline_options() -> Command {
    let cmdline = Command::new("nydusd")
        .about("Nydus daemon to provide BlobCache, FsCache, FUSE, Virtio-fs and container image services")
        .arg(
            Arg::new("apisock")
                .long("apisock")
                .short('A')
                .help("Path to the Nydus daemon administration API socket")
                .required(false)
                .global(true),
        )
        .arg(
            Arg::new("config")
                .long("config")
                .short('C')
                .help("Path to the Nydus daemon configuration file")
                .required(false)
                .global(true),
        )
        .arg(
            Arg::new("id")
                .long("id")
                .help("Service instance identifier")
                .required(false)
                .requires("supervisor")
                .global(true),
        )
        .arg(
            Arg::new("log-level")
                .long("log-level")
                .short('l')
                .help("Log level:")
                .default_value("info")
                .value_parser(["trace", "debug", "info", "warn", "error"])
                .required(false)
                .global(true),
        )
        .arg(
            Arg::new("log-file")
                .long("log-file")
                .short('L')
                .help("Log messages to the file. Default extension \".log\" will be used if no extension specified.")
                .required(false)
                .global(true),
        )
        .arg(
            Arg::new("log-rotation-size")
                .long("log-rotation-size")
                .help("Specify log rotation size(MB), 0 to disable")
                .default_value("0")
                .required(false)
                .global(true),
        )
        .arg(
            Arg::new("rlimit-nofile")
                .long("rlimit-nofile")
                .default_value("1000000")
                .help("Set rlimit for maximum file descriptor number (0 leaves it unchanged)")
                .required(false)
                .global(true),
        )
        .arg(
            Arg::new("supervisor")
                .long("supervisor")
                .help("Path to the Nydus daemon supervisor API socket")
                .required(false)
                .requires("id")
                .global(true),
        )
        .arg(
            Arg::new("upgrade")
                .long("upgrade")
                .help("Start Nydus daemon in upgrade mode")
                .action(ArgAction::SetTrue)
                .required(false)
                .global(true),
        )
        .args_conflicts_with_subcommands(true);

    let cmdline = append_fuse_options(cmdline);
    let cmdline = append_fs_options(cmdline);
    let cmdline = append_fuse_subcmd_options(cmdline);
    #[cfg(feature = "virtiofs")]
    let cmdline = append_virtiofs_subcmd_options(cmdline);
    #[cfg(feature = "block-nbd")]
    let cmdline = self::nbd::append_nbd_subcmd_options(cmdline);
    append_singleton_subcmd_options(cmdline)
}

#[cfg(target_os = "macos")]
fn get_max_rlimit_nofile() -> Result<u64> {
    let mut mib = [nix::libc::CTL_KERN, nix::libc::KERN_MAXFILES];
    let mut file_max: u64 = 0;
    let mut size = std::mem::size_of::<u64>();
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
fn get_max_rlimit_nofile() -> Result<u64> {
    let file_max = std::fs::read_to_string("/proc/sys/fs/file-max")?;
    file_max
        .trim()
        .parse::<u64>()
        .map_err(|_| eother!("invalid content from fs.file-max"))
}

/// Handle command line option to tune rlimit for maximum file descriptor number.
fn handle_rlimit_nofile_option(args: &ArgMatches, option_name: &str) -> Result<()> {
    // `rlimit-nofile` has a default value, so safe to unwrap().
    let rlimit_nofile: u64 = args
        .get_one::<String>(option_name)
        .unwrap()
        .parse()
        .map_err(|_e| {
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

fn process_fs_service(
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

    let mut fs_type = FsBackendType::PassthroughFs;
    let mount_cmd = if let Some(shared_dir) = shared_dir {
        let cmd = FsBackendMountCmd {
            fs_type: FsBackendType::PassthroughFs,
            source: shared_dir.to_string(),
            config: "".to_string(),
            mountpoint: virtual_mnt.to_string(),
            prefetch_files: None,
        };

        Some(cmd)
    } else if let Some(b) = bootstrap {
        let config = match args.value_of("localfs-dir") {
            Some(v) => {
                format!(
                    r###"
        {{
            "device": {{
                "backend": {{
                    "type": "localfs",
                    "config": {{
                        "dir": {:?},
                        "readahead": true
                    }}
                }},
                "cache": {{
                    "type": "blobcache",
                    "config": {{
                        "compressed": false,
                        "work_dir": {:?}
                    }}
                }}
            }},
            "mode": "direct",
            "digest_validate": false,
            "iostats_files": false
        }}
        "###,
                    v, v
                )
            }
            None => match args.value_of("config") {
                Some(v) => {
                    let auth = std::env::var("IMAGE_PULL_AUTH").ok();
                    if auth.is_some() {
                        let mut config = ConfigV2::from_file(v)?;
                        config.update_registry_auth_info(&auth);
                        serde_json::to_string(&config)?
                    } else {
                        std::fs::read_to_string(v)?
                    }
                }
                None => {
                    let e = NydusError::InvalidArguments(
                        "both --config and --localfs-dir are missing".to_string(),
                    );
                    return Err(e.into());
                }
            },
        };

        // read the prefetch list of files from prefetch-files
        let prefetch_files: Option<Vec<String>> = match args.value_of("prefetch-files") {
            Some(v) => {
                let content = match std::fs::read_to_string(v) {
                    Ok(v) => v,
                    Err(_) => {
                        let e = NydusError::InvalidArguments(
                            "the prefetch-files arg is not a file path".to_string(),
                        );
                        return Err(e.into());
                    }
                };
                let mut prefetch_files: Vec<String> = Vec::new();
                for line in content.lines() {
                    if line.is_empty() || line.trim().is_empty() {
                        continue;
                    }
                    prefetch_files.push(line.trim().to_string());
                }
                Some(prefetch_files)
            }
            None => None,
        };

        let cmd = FsBackendMountCmd {
            fs_type: FsBackendType::Rafs,
            source: b.to_string(),
            config,
            mountpoint: virtual_mnt.to_string(),
            prefetch_files,
        };

        fs_type = FsBackendType::Rafs;

        Some(cmd)
    } else {
        None
    };

    let vfs = create_vfs_backend(fs_type, is_fuse, args.is_present("hybrid-mode"))?;
    // Basically, below two arguments are essential for live-upgrade/failover/ and external management.
    let daemon_id = args.value_of("id").map(|id| id.to_string());
    let supervisor = args.value_of("supervisor").map(|s| s.to_string());

    if is_fuse {
        // threads means number of fuse service threads
        let threads: u32 = args
            .value_of("fuse-threads")
            .map(|n| n.parse().unwrap_or(1))
            .unwrap_or(1);

        let p = args
            .value_of("failover-policy")
            .unwrap_or(&"flush".to_string())
            .try_into()
            .map_err(|e| {
                error!("Invalid failover policy");
                e
            })?;

        // mountpoint means fuse device only
        let mountpoint = args.value_of("mountpoint").ok_or_else(|| {
            NydusError::InvalidArguments("Mountpoint must be provided for FUSE server!".to_string())
        })?;

        let daemon = {
            create_fuse_daemon(
                mountpoint,
                vfs,
                supervisor,
                daemon_id,
                threads,
                DAEMON_CONTROLLER.alloc_waker(),
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
    } else {
        #[cfg(feature = "virtiofs")]
        {
            let vu_sock = args.value_of("sock").ok_or_else(|| {
                NydusError::InvalidArguments("vhost socket must be provided!".to_string())
            })?;
            let _ = apisock.as_ref();
            DAEMON_CONTROLLER.set_daemon(virtiofs::create_virtiofs_daemon(
                daemon_id, supervisor, vu_sock, vfs, mount_cmd, bti,
            )?);
        }
    }

    Ok(())
}

fn process_singleton_arguments(
    subargs: &SubCmdArgs,
    _apisock: Option<&str>,
    bti: BuildTimeInfo,
) -> Result<()> {
    let id = subargs.value_of("id").map(|id| id.to_string());
    let supervisor = subargs.value_of("supervisor").map(|s| s.to_string());
    let config = match subargs.value_of("config") {
        None => None,
        Some(path) => {
            let config = std::fs::read_to_string(path)?;
            let config: serde_json::Value = serde_json::from_str(&config)
                .map_err(|_e| einval!("invalid configuration file"))?;
            Some(config)
        }
    };
    let fscache = subargs.value_of("fscache").map(|s| s.as_str());
    let tag = subargs.value_of("fscache-tag").map(|s| s.as_str());
    let threads = subargs.value_of("fscache-threads").map(|s| s.as_str());
    info!("Start Nydus daemon in singleton mode!");
    let daemon = create_daemon(
        id,
        supervisor,
        fscache,
        tag,
        threads,
        config,
        bti,
        DAEMON_CONTROLLER.alloc_waker(),
    )
    .map_err(|e| {
        error!("Failed to start singleton daemon: {}", e);
        e
    })?;
    DAEMON_CONTROLLER.set_singleton_mode(true);
    if let Some(blob_mgr) = daemon.get_blob_cache_mgr() {
        DAEMON_CONTROLLER.set_blob_cache_mgr(blob_mgr);
    }
    DAEMON_CONTROLLER.set_daemon(daemon);
    Ok(())
}

#[cfg(feature = "block-nbd")]
mod nbd {
    use super::*;
    use nydus_api::BlobCacheEntry;
    use nydus_service::block_nbd::create_nbd_daemon;
    use std::str::FromStr;

    pub(super) fn append_nbd_subcmd_options(cmd: Command) -> Command {
        let subcmd = Command::new("nbd")
            .about("Export a RAFS v6 image as a block device through NBD (Experiment)");
        let subcmd = subcmd
            .arg(
                Arg::new("DEVICE")
                    .help("NBD device node to attach the block device")
                    .required(true)
                    .num_args(1),
            )
            .arg(
                Arg::new("bootstrap")
                    .long("bootstrap")
                    .short('B')
                    .help("Path to the RAFS filesystem metadata file")
                    .requires("localfs-dir")
                    .conflicts_with("config"),
            )
            .arg(
                Arg::new("localfs-dir")
                    .long("localfs-dir")
                    .requires("bootstrap")
                    .short('D')
                    .help(
                        "Path to the `localfs` working directory, which also enables the `localfs` storage backend"
                    )
                    .conflicts_with("config"),
            )
            .arg(
                Arg::new("threads")
                    .long("threads")
                    .default_value("4")
                    .help("Number of worker threads to serve NBD requests")
                    .value_parser(thread_validator)
                    .required(false),
            );
        cmd.subcommand(subcmd)
    }

    pub(super) fn process_nbd_service(
        args: SubCmdArgs,
        bti: BuildTimeInfo,
        _apisock: Option<&str>,
    ) -> Result<()> {
        let mut entry = if let Some(bootstrap) = args.value_of("bootstrap") {
            let dir = args.value_of("localfs-dir").ok_or_else(|| {
                einval!("option `-D/--localfs-dir` is required by `--boootstrap`")
            })?;
            let config = r#"
            {
                "type": "bootstrap",
                "id": "disk-default",
                "domain_id": "block-nbd",
                "config_v2": {
                    "version": 2,
                    "id": "block-nbd-factory",
                    "backend": {
                        "type": "localfs",
                        "localfs": {
                            "dir": "LOCAL_FS_DIR"
                        }
                    },
                    "cache": {
                        "type": "filecache",
                        "filecache": {
                            "work_dir": "LOCAL_FS_DIR"
                        }
                    },
                    "metadata_path": "META_FILE_PATH"
                }
            }"#;
            let config = config
                .replace("LOCAL_FS_DIR", dir)
                .replace("META_FILE_PATH", bootstrap);
            BlobCacheEntry::from_str(&config)?
        } else if let Some(v) = args.value_of("config") {
            BlobCacheEntry::from_file(v)?
        } else {
            return Err(einval!(
                "both option `-C/--config` and `-B/--bootstrap` are missing"
            ));
        };
        if !entry.prepare_configuration_info() {
            return Err(einval!(
                "invalid blob cache entry configuration information"
            ));
        }
        if entry.validate() == false {
            return Err(einval!(
                "invalid blob cache entry configuration information"
            ));
        }

        // Safe to unwrap because `DEVICE` is mandatory option.
        let device = args.value_of("DEVICE").unwrap().to_string();
        let id = args.value_of("id").map(|id| id.to_string());
        let supervisor = args.value_of("supervisor").map(|s| s.to_string());
        let threads: u32 = args
            .value_of("threads")
            .map(|n| n.parse().unwrap_or(1))
            .unwrap_or(1);

        let daemon = create_nbd_daemon(
            device,
            threads,
            entry,
            bti,
            id,
            supervisor,
            DAEMON_CONTROLLER.alloc_waker(),
        )
        .map(|d| {
            info!("NBD daemon started!");
            d
        })
        .map_err(|e| {
            error!("Failed in starting NBD daemon: {}", e);
            e
        })?;
        DAEMON_CONTROLLER.set_daemon(daemon);

        Ok(())
    }
}

extern "C" fn sig_exit(_sig: std::os::raw::c_int) {
    DAEMON_CONTROLLER.shutdown();
}

fn main() -> Result<()> {
    let bti = BTI.to_owned();
    let cmd_options = prepare_commandline_options().version(BTI_STRING.as_str());
    let args = cmd_options.get_matches();
    let logging_file = args.get_one::<String>("log-file").map(|l| l.into());
    // Safe to unwrap because it has default value and possible values are defined
    let level = args
        .get_one::<String>("log-level")
        .unwrap()
        .parse()
        .unwrap();
    let apisock = args.get_one::<String>("apisock").map(|s| s.as_str());
    let rotation_size = args
        .get_one::<String>("log-rotation-size")
        .unwrap()
        .parse::<u64>()
        .map_err(|e| einval!(format!("Invalid log rotation size: {}", e)))?;

    setup_logging(logging_file, level, rotation_size)?;

    // Initialize and run the daemon controller event loop.
    nydus::register_signal_handler(signal::SIGINT, sig_exit);
    nydus::register_signal_handler(signal::SIGTERM, sig_exit);

    dump_program_info();
    handle_rlimit_nofile_option(&args, "rlimit-nofile")?;

    match args.subcommand_name() {
        Some("singleton") => {
            // Safe to unwrap because the subcommand is `singleton`.
            let subargs = args.subcommand_matches("singleton").unwrap();
            let subargs = SubCmdArgs::new(&args, subargs);
            process_singleton_arguments(&subargs, apisock, bti)?;
        }
        Some("fuse") => {
            // Safe to unwrap because the subcommand is `fuse`.
            let subargs = args.subcommand_matches("fuse").unwrap();
            let subargs = SubCmdArgs::new(&args, subargs);
            process_fs_service(subargs, bti, apisock, true)?;
        }
        Some("virtiofs") => {
            // Safe to unwrap because the subcommand is `virtiofs`.
            let subargs = args.subcommand_matches("virtiofs").unwrap();
            let subargs = SubCmdArgs::new(&args, subargs);
            process_fs_service(subargs, bti, apisock, false)?;
        }
        #[cfg(feature = "block-nbd")]
        Some("nbd") => {
            // Safe to unwrap because the subcommand is `nbd`.
            let subargs = args.subcommand_matches("nbd").unwrap();
            let subargs = SubCmdArgs::new(&args, subargs);
            self::nbd::process_nbd_service(subargs, bti, apisock)?;
        }
        _ => {
            let subargs = SubCmdArgs::new(&args, &args);
            process_fs_service(subargs, bti, apisock, true)?;
        }
    }

    let daemon = DAEMON_CONTROLLER.get_daemon();
    if let Some(fs) = daemon.get_default_fs_service() {
        DAEMON_CONTROLLER.set_fs_service(fs);
    }

    // Start the HTTP Administration API server
    let mut api_controller = ApiServerController::new(apisock);
    api_controller.start()?;

    // Run the main event loop
    if DAEMON_CONTROLLER.is_active() {
        DAEMON_CONTROLLER.run_loop();
    }

    // Gracefully shutdown system.
    info!("nydusd quits");
    api_controller.stop();
    DAEMON_CONTROLLER.set_singleton_mode(false);
    DAEMON_CONTROLLER.shutdown();

    Ok(())
}
