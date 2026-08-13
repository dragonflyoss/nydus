//! ublk target exposing a nydus image as `/dev/ublkbN`.
//!
//! The device is read-only: the kernel EROFS driver mounts it and issues plain
//! block reads, which are served from the bootstrap mapping and the blob caches
//! (fetched from the backend on demand). Write-side operations are rejected.

use std::rc::Rc;
use std::sync::Arc;

use libublk::ctrl::{UblkCtrl, UblkCtrlBuilder};
use libublk::io::{BufDescList, UblkDev, UblkIOCtx, UblkQueue};
use libublk::{BufDesc, UblkError, UblkFlags, UblkIORes};
use nydus_error::{Error, Result};
use tracing::{error, info};

use super::core::{UblkCore, UBLK_LOGICAL_BLOCK_SIZE};

/// Default per-queue depth, i.e. the number of in-flight block requests.
pub const DEFAULT_QUEUE_DEPTH: u16 = 128;
/// Default size of the per-request I/O buffer.
pub const DEFAULT_IO_BUF_BYTES: u32 = 512 * 1024;
/// Upper bound for the queue count picked by [`default_queues`].
pub const MAX_DEFAULT_QUEUES: u16 = 4;

/// Number of queues to use when the caller does not pick one.
///
/// Each queue is served by a dedicated thread that reads synchronously, so a
/// single queue serialises every block request and concurrent readers queue up
/// behind each other. Scale with the CPU count instead, capped so that large
/// hosts do not spawn a thread and its I/O buffers per core.
pub fn default_queues() -> u16 {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    (cpus as u16).clamp(1, MAX_DEFAULT_QUEUES)
}

/// Tunables for the ublk device.
#[derive(Clone, Debug)]
pub struct UblkOptions {
    /// Device id, `-1` lets the driver allocate one.
    pub dev_id: i32,
    /// Number of hardware queues; each queue gets its own serving thread.
    pub queues: u16,
    /// Per-queue depth.
    pub depth: u16,
    /// Maximum bytes transferred by a single request.
    pub io_buf_bytes: u32,
    /// Create the device in unprivileged mode (`UBLK_F_UNPRIVILEGED_DEV`).
    pub unprivileged: bool,
}

impl Default for UblkOptions {
    fn default() -> Self {
        Self {
            dev_id: -1,
            queues: default_queues(),
            depth: DEFAULT_QUEUE_DEPTH,
            io_buf_bytes: DEFAULT_IO_BUF_BYTES,
            unprivileged: false,
        }
    }
}

/// A running ublk device serving a nydus image.
pub struct UblkService {
    ctrl: Arc<UblkCtrl>,
    core: Arc<UblkCore>,
}

impl UblkService {
    /// Create the ublk device. The device is added to the driver here but does
    /// not serve I/O until [`UblkService::run`] is called.
    pub fn new(core: Arc<UblkCore>, options: &UblkOptions) -> Result<Self> {
        let ctrl_flags = if options.unprivileged {
            libublk::sys::UBLK_F_UNPRIVILEGED_DEV as u64
        } else {
            0
        };
        let ctrl = UblkCtrlBuilder::default()
            .name("nydus")
            .id(options.dev_id)
            .nr_queues(options.queues)
            .depth(options.depth)
            .io_buf_bytes(options.io_buf_bytes)
            .ctrl_flags(ctrl_flags)
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .build()
            .map_err(|err| Error::Runtime(format!("failed to create ublk device: {err}")))?;

        Ok(Self {
            ctrl: Arc::new(ctrl),
            core,
        })
    }

    /// Path of the block device, e.g. `/dev/ublkb0`.
    pub fn dev_path(&self) -> String {
        format!("/dev/ublkb{}", self.ctrl.dev_info().dev_id)
    }

    /// Handle used to stop the device from another thread.
    pub fn handle(&self) -> UblkHandle {
        UblkHandle {
            ctrl: self.ctrl.clone(),
        }
    }

    /// Serve I/O until the device is stopped or removed. Blocks the caller.
    pub fn run(&self) -> Result<()> {
        let device_size = self.core.device_size();
        let core = self.core.clone();
        let dev_path = self.dev_path();

        self.ctrl
            .run_target(
                |dev| init_target(dev, device_size),
                move |qid, dev| serve_queue(qid, dev, core.clone()),
                move |_ctrl| info!("nydus ublk device ready at {dev_path}"),
            )
            .map_err(|err| Error::Runtime(format!("ublk device failed: {err}")))?;

        Ok(())
    }

    /// Remove the device from the driver. Safe to call after [`Self::run`]
    /// returned; the driver reports `ENOENT` when it is already gone.
    pub fn delete(&self) {
        let _ = self.ctrl.del_dev();
    }
}

/// Thread-safe handle for stopping a running [`UblkService`].
#[derive(Clone)]
pub struct UblkHandle {
    ctrl: Arc<UblkCtrl>,
}

impl UblkHandle {
    /// Stop the device, which makes [`UblkService::run`] return.
    pub fn stop(&self) {
        if let Err(err) = self.ctrl.kill_dev() {
            error!("failed to stop ublk device: {err}");
        }
    }
}

/// Describe the device to the driver: read-only, EROFS-block-sized.
fn init_target(dev: &mut UblkDev, device_size: u64) -> std::result::Result<(), UblkError> {
    let block_shift = UBLK_LOGICAL_BLOCK_SIZE.trailing_zeros() as u8;
    let tgt = &mut dev.tgt;
    tgt.dev_size = device_size;
    tgt.params = libublk::sys::ublk_params {
        types: libublk::sys::UBLK_PARAM_TYPE_BASIC,
        basic: libublk::sys::ublk_param_basic {
            attrs: libublk::sys::UBLK_ATTR_READ_ONLY,
            logical_bs_shift: block_shift,
            physical_bs_shift: block_shift,
            io_opt_shift: block_shift,
            io_min_shift: block_shift,
            max_sectors: dev.dev_info.max_io_buf_bytes >> 9,
            dev_sectors: device_size >> 9,
            ..Default::default()
        },
        ..Default::default()
    };

    Ok(())
}

/// Serve one hardware queue. Runs on its own thread until the queue is down.
fn serve_queue(qid: u16, dev: &UblkDev, core: Arc<UblkCore>) {
    let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
    let bufs = bufs_rc.clone();

    let handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
        let slice = bufs_rc[tag as usize].as_slice();
        let res = handle_io(q, tag, slice, &core);
        if let Err(err) =
            q.complete_io_cmd_unified(tag, BufDesc::Slice(slice), Ok(UblkIORes::Result(res)))
        {
            error!("ublk queue {qid} failed to complete tag {tag}: {err}");
        }
    };

    let queue = match UblkQueue::new(qid, dev)
        .and_then(|q| q.submit_fetch_commands_unified(BufDescList::Slices(Some(&bufs))))
    {
        Ok(queue) => queue,
        Err(err) => {
            error!("failed to set up ublk queue {qid}: {err}");
            return;
        }
    };

    queue.wait_and_handle_io(handler);
}

/// Handle a single block request, returning the ublk result: transferred bytes
/// on success, a negative errno on failure.
fn handle_io(q: &UblkQueue, tag: u16, buf: &[u8], core: &UblkCore) -> i32 {
    let iod = q.get_iod(tag);
    let op = iod.op_flags & 0xff;
    let offset = iod.start_sector << 9;
    let bytes = (iod.nr_sectors as usize) << 9;

    match op {
        libublk::sys::UBLK_IO_OP_READ => {
            if bytes > buf.len() {
                return -libc::EINVAL;
            }
            // SAFETY: `buf` is this queue's I/O buffer for `tag`. The buffer is
            // owned by the queue and only ever touched by the handler serving
            // that tag, so no other reference to it is live here.
            let dst = unsafe { std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, bytes) };
            match core.read_at(offset, dst) {
                Ok(()) => bytes as i32,
                Err(err) => {
                    error!("ublk read at {offset} ({bytes} bytes) failed: {err}");
                    -err.raw_os_error().unwrap_or(libc::EIO)
                }
            }
        }
        // The device is read-only, so a flush has nothing to write back.
        libublk::sys::UBLK_IO_OP_FLUSH => 0,
        _ => -libc::EOPNOTSUPP,
    }
}
