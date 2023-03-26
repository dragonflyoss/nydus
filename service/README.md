# nydus-service

The `nydus-service` crate helps to reuse the core services of nydus, allowing you to integrate nydus services into your project elegantly and easily. It provides:

* fuse service
* virtio-fs service
* fscache service
* blobcache service

It also supplies the nydus daemon and the daemon controller to help manage these services.

## Why you need

You're supposed to know that `nydusd` running as daemon to expose a [FUSE](https://www.kernel.org/doc/html/latest/filesystems/fuse.html) mountpoint, a [Virtio-FS](https://virtio-fs.gitlab.io/) mountpoint or an [EROFS](https://docs.kernel.org/filesystems/erofs.html) mountpoint inside guest for containers to access, and it provides key features include:

- Container images are downloaded on demand
- Chunk level data deduplication
- Flatten image metadata and data to remove all intermediate layers
- Only usable image data is saved when building a container image
- Only usable image data is downloaded when running a container
- End-to-end image data integrity
- Compatible with the OCI artifacts spec and distribution spec
- Integrated with existing CNCF project Dragonfly to support image distribution in large clusters
- Different container image storage backends are supported

If you want to use these features as native in your project without preparing and invoking `nydusd` deliberately, `nydus-service` is just born for this.

## How to use

For example, reuse the fuse service with `nydus-service` in three steps.

**prepare the config**:

```rust
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "scheme": "",
        "skip_verify": true,
        "timeout": 5,
        "connect_timeout": 5,
        "retry_limit": 4,
        "auth": "YOUR_LOGIN_AUTH="
      }
    },
    "cache": {
      "type": "blobcache",
      "config": {
        "work_dir": "cache"
      }
    }
  },
  "mode": "direct",
  "digest_validate": false,
  "iostats_files": false,
  "enable_xattr": true,
  "fs_prefetch": {
    "enable": true,
    "threads_count": 4
  }
}
```

**create a daemon**:

```Rust
static ref DAEMON_CONTROLLER: DaemonController = DaemonController::default()

let cmd = FsBackendMountCmd {
    fs_type: FsBackendType::Rafs,
    // Bootstrap path
    source: bootstrap,
    // Backend config
    config,
    // Virutal mountpoint
    mountpoint: "/".to_string(),
    // Prefetch files
    prefetch_files: None,
};

let daemon = {
    create_fuse_daemon(
        // Mountpoint for the FUSE filesystem, target for `mount.fuse`
        mountpoint,
        // Vfs associated with the filesystem service object
        vfs,
        // Supervisor
        None,
      	// Service instance identifier
        id,
        // Number of working threads to serve fuse requests
        fuse_threads,
      	// daemon controller's waker
        waker,
      	// Path to the Nydus daemon administration API socket
        Some("api_sock"),
      	// Start Nydus daemon in upgrade mode
        upgrade,
      	// Mounts FUSE filesystem in rw mode
        !writable,
        // FUSE server failover policy
        failvoer-policy,
        // Request structure to mount a backend filesystem instance
        Some(cmd),
        BTI.to_owned(),
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
```

**start daemon controller**:

```rust
thread::spawn(move || {
 	 let daemon = DAEMON_CONTROLLER.get_daemon();
 	 if let Some(fs) = daemon.get_default_fs_service() {
 	   	DAEMON_CONTROLLER.set_fs_service(fs);
 	 }

 	 // Run the main event loop
 	 if DAEMON_CONTROLLER.is_active() {
 	   	DAEMON_CONTROLLER.run_loop();
	 }

 	 // Gracefully shutdown system.
 	 info!("nydusd quits");
 	 DAEMON_CONTROLLER.shutdown();
});
```

Then, you can make the most of nydus services in your project.

## Support

**Platforms**:

- x86_64
- aarch64

**Operating Systems**:

- Linux

## License

This code is licensed under [Apache-2.0](LICENSE-APACHE) or [BSD-3-Clause](LICENSE-BSD-3-Clause).
