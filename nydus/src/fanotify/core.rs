//! Fanotify fill engine, multi-device model.
//!
//! Unlike the flat model (one sparse image = bootstrap + blobs), nydus's native
//! shape is multi-device EROFS: the **bootstrap is a real local EROFS image**
//! (superblock + all inode/dirent metadata + a device table) that the operator
//! mounts directly, and each data **blob is a separate EROFS device** backed by
//! the core's per-blob sparse cache file (`BlobInfo::cache_path`).
//!
//! Consequences:
//! - The daemon marks each blob's cache file (the device), not the bootstrap.
//!   Mount and metadata reads (`ls`, `stat`) hit the real local bootstrap and do
//!   not involve fanotify at all; only cold blob-data reads fault.
//! - Filling is `Blobs::fetch(id, off, len)`, which decodes + validates +
//!   writes the blob's cache file *in place* (the same file the kernel reads) and
//!   is idempotent — so no hand-rolled pwrite/dedup/fsync is needed here; that
//!   I/O lives in (and is tested by) `nydus-core`.
//!
//! Kernel-independent logic here (device lookup, RANGE decision, fetch-range
//! alignment) is unit-tested; the core fetch and the event loop are not
//! (they need a real image / kernel).

use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tracing::{debug, warn};

use nydus_config::{BackendConfig, Config};
use nydus_core::{BlobId, NydusCore};
use nydus_error::{Context, Error, Result};

use super::proto::{PreContentEvent, Range, FAN_PRE_ACCESS};

/// EROFS block size as u64 — reuses the canonical constant from the core.
const BLOCK_SIZE: u64 = nydus_format::erofs::EROFS_BLOCK_SIZE as u64;

/// `fanotify_init(2)` flag: close-on-exec on the group descriptor.
pub(crate) const FAN_CLOEXEC: u32 = 0x0000_0001;
/// `fanotify_init(2)` flag: non-blocking reads on the group descriptor.
pub(crate) const FAN_NONBLOCK: u32 = 0x0000_0002;
/// `fanotify_init(2)` class: pre-content permission events (Linux 6.15+).
pub(crate) const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
/// `fanotify_mark(2)` flag: add a mark.
pub(crate) const FAN_MARK_ADD: u32 = 0x0000_0001;
/// `fanotify_mark(2)` flag: remove a mark instead of adding one.
pub(crate) const FAN_MARK_REMOVE: u32 = 0x0000_0002;

/// Why an event was denied, kept distinct so metrics and logs can separate a
/// client/kernel range problem from a backend/data failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenyReason {
    /// The event carried no fillable range (missing/zero/out-of-device/overflow).
    InvalidRange,
    /// The event is not a pre-access (FAN_PRE_ACCESS) permission event.
    NotPreAccess,
    /// The event fd did not resolve to a known source blob device.
    UnknownDevice,
    /// A read targeted a redirect slot, which the guest must never read.
    RedirectRead,
    /// The backend fetch, decode, CRC, or cache write failed.
    BackendFailure,
}

/// Decision derived purely from the parsed event, before any I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Deny(DenyReason),
    Fill(Range),
}

/// A range that cannot be turned into a valid, non-empty, in-device fetch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RangeError {
    #[error("range count is zero")]
    ZeroCount,
    #[error("range offset is past the device end")]
    OffsetPastEnd,
    #[error("range end overflows")]
    Overflow,
    #[error("range is empty after alignment")]
    EmptyAfterAlign,
}

/// One blob exposed as an EROFS device (the backing file the kernel reads).
///
/// Slots are kept in original device-table order, including redirect slots, so
/// the EROFS `device=` index is never renumbered. A read routed to a redirect
/// slot is an invariant violation and is denied.
#[derive(Clone, Debug)]
pub struct BlobDevice {
    /// 1-based device-table index, preserved from the bootstrap.
    pub index: u16,
    pub id: BlobId,
    /// True for an "ondemand" redirect blob the guest must never read directly.
    pub is_redirect: bool,
    /// Host path of the blob's sparse cache file = the EROFS `device=` target.
    pub cache_path: PathBuf,
    /// Device size in bytes (block-aligned).
    pub cache_size: u64,
}

#[cfg(test)]
impl BlobDevice {
    pub(crate) fn for_test(
        index: u16,
        id: BlobId,
        is_redirect: bool,
        cache_path: PathBuf,
        cache_size: u64,
    ) -> Self {
        Self {
            index,
            id,
            is_redirect,
            cache_path,
            cache_size,
        }
    }
}

/// Read-side handle for the fanotify pre-content service.
pub struct FanotifyCore {
    core: Arc<NydusCore>,
    devices: Vec<BlobDevice>,
    /// File identity → `devices` vec position, for O(1) event-fd lookup.
    slot_by_identity: HashMap<FileId, usize>,
    /// `BlobId` → `devices` vec position, for O(1) lookup by blob identity.
    slot_by_blob_id: HashMap<BlobId, usize>,
    /// Per-device-slot sticky flag: true once the fanotify mark has been removed
    /// (or was never added because the blob was already fully ready at startup).
    /// Prevents redundant `is_all_ready` probes and duplicate `FAN_MARK_REMOVE`
    /// syscalls across concurrent fetch workers.
    unmarked: Vec<AtomicBool>,
}

impl FanotifyCore {
    /// Build the core and enumerate the blob devices. `entries()` also
    /// prepares (creates + sizes) each blob's cache file, so the device files
    /// exist and can be marked/mounted immediately after this returns.
    ///
    /// Every device-table slot is preserved in order (including redirect slots),
    /// the indices are validated to run contiguously from 1, every device size
    /// is validated block-aligned (`align_fetch_range` relies on it), and each
    /// cache file is confirmed to be a regular file whose size matches the slot
    /// before its `(dev, ino)` identity is recorded from that same opened
    /// descriptor.
    pub fn new(bootstrap: &Path, config: Config) -> Result<Self> {
        validate_bounded_backend_timeout(&config)?;
        let core = Arc::new(NydusCore::new(bootstrap, config)?);
        let entries = core
            .blobs
            .prepare_all()
            .context("failed to enumerate blob devices")?;

        let mut devices = Vec::with_capacity(entries.len());
        let mut slot_by_identity = HashMap::with_capacity(entries.len());
        let mut slot_by_blob_id = HashMap::with_capacity(entries.len());
        for (slot, b) in entries.into_iter().enumerate() {
            let expected_index = u16::try_from(slot + 1).map_err(|err| {
                Error::InvalidImage(format!(
                    "blob device table has more slots than the EROFS index space: {err}"
                ))
            })?;
            if b.index != expected_index {
                return Err(Error::InvalidImage(format!(
                    "blob device index {} is not contiguous from 1 (expected {} at slot {})",
                    b.index, expected_index, slot
                )));
            }
            if b.cache_size % BLOCK_SIZE != 0 {
                return Err(Error::InvalidImage(format!(
                    "blob device {} size {} is not a multiple of the {} B EROFS block size",
                    b.cache_path.display(),
                    b.cache_size,
                    BLOCK_SIZE
                )));
            }

            let identity = cache_identity(&b.cache_path, b.cache_size).with_context(|| {
                format!("failed to validate blob device {}", b.cache_path.display())
            })?;
            slot_by_blob_id.insert(b.id, slot);
            devices.push(BlobDevice {
                index: b.index,
                id: b.id,
                is_redirect: b.is_redirect,
                cache_path: b.cache_path,
                cache_size: b.cache_size,
            });
            slot_by_identity.insert(identity, slot);
        }

        let unmarked: Vec<AtomicBool> = devices.iter().map(|_| AtomicBool::new(false)).collect();
        Ok(Self {
            core,
            devices,
            slot_by_identity,
            slot_by_blob_id,
            unmarked,
        })
    }

    /// The blob devices, in device-table order (the order they must be passed as
    /// EROFS `-o device=` options). Includes redirect slots as placeholders.
    pub fn devices(&self) -> &[BlobDevice] {
        &self.devices
    }

    /// Find the blob device an event fd refers to, by its file identity.
    /// O(1) HashMap lookup.
    pub fn device_for(&self, identity: FileId) -> Option<&BlobDevice> {
        self.slot_by_identity
            .get(&identity)
            .map(|&idx| &self.devices[idx])
    }

    /// Return true when the authoritative block_group_map already covers the complete
    /// aligned range. This never triggers backend I/O.
    pub fn is_range_ready(&self, id: &BlobId, offset: u64, len: u64) -> Result<bool> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| Error::Overflow("ready range overflow".to_string()))?;
        let ready = self
            .core
            .blobs
            .ready_ranges(id, offset, len)
            .context("failed to inspect blob ready ranges")?;
        Ok(ready.len() == 1 && ready[0].start == offset && ready[0].end == end)
    }

    /// Fill `[offset, offset + count)` of blob `id`'s device by fetching it into
    /// the blob's cache file (the same file the kernel reads).
    pub fn fetch(
        &self,
        id: &BlobId,
        cache_size: u64,
        offset: u64,
        count: u64,
    ) -> std::result::Result<(), FetchError> {
        debug_assert!(count > 0);
        debug_assert!(offset % BLOCK_SIZE == 0);
        debug_assert!(count % BLOCK_SIZE == 0);
        debug_assert!(offset <= cache_size && offset + count <= cache_size);
        self.core.blobs.fetch(id, offset, count).map_err(|err| {
            FetchError::Backend(
                err.context(format!("failed to fetch blob range [{offset}, +{count})")),
            )
        })
    }

    /// Record that the mark for device `slot` was never added (the blob was
    /// already fully ready at startup), so `try_unmark` skips it at runtime.
    pub fn set_unmarked(&self, slot: usize) {
        if let Some(flag) = self.unmarked.get(slot) {
            flag.store(true, Ordering::Release);
        }
    }

    /// Remove the fanotify mark on a blob whose block_group_map is fully ready.
    ///
    /// Called from fetch worker threads after a successful fetch. The per-slot
    /// [`AtomicBool`] ensures the readiness probe and the `FAN_MARK_REMOVE`
    /// syscall execute at most once per blob across all concurrent workers.
    /// Returns `true` if this call won the per-slot CAS and attempted
    /// `FAN_MARK_REMOVE`; the syscall itself may still fail (logged), in
    /// which case the latched flag prevents any retry.
    ///
    /// # Safety (syscall)
    ///
    /// `fan_fd` must be a live fanotify group descriptor. `fanotify_mark` is
    /// thread-safe; concurrent calls with `FAN_MARK_REMOVE` on the same path
    /// are harmless (the loser gets `ENOENT`).
    pub fn try_unmark(&self, fan_fd: RawFd, id: &BlobId) -> bool {
        let Some(&slot) = self.slot_by_blob_id.get(id) else {
            return false;
        };
        // Fast path: the mark was already removed by an earlier successful
        // unmark, or was never added because the blob was fully ready at
        // startup.
        if self.unmarked[slot].load(Ordering::Acquire) {
            return false;
        }
        // O(1) probe: single atomic load on the block_group_map's shared ALL_READY flag.
        if !self.core.blobs.is_all_ready(id).unwrap_or(false) {
            return false;
        }
        // Claim the unmark: exactly one thread wins the CAS.
        if self.unmarked[slot]
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let path = match CString::new(self.devices[slot].cache_path.as_os_str().as_bytes()) {
            Ok(p) => p,
            Err(_) => return false, // interior NUL: cannot happen for real paths
        };
        let ret = unsafe {
            libc::fanotify_mark(
                fan_fd,
                FAN_MARK_REMOVE,
                FAN_PRE_ACCESS,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOENT) {
                // Benign: the mark was already removed (e.g. by another path).
                debug!(
                    "fanotify: FAN_MARK_REMOVE for slot {} ({}): already gone (ENOENT)",
                    self.devices[slot].index,
                    self.devices[slot].cache_path.display()
                );
            } else {
                // Unexpected, but not fatal.
                warn!(
                    "fanotify: FAN_MARK_REMOVE for slot {} ({}) failed: {err}",
                    self.devices[slot].index,
                    self.devices[slot].cache_path.display()
                );
            }
        } else {
            debug!(
                "fanotify: unmarked fully-ready blob {} (slot {}) at {}",
                id,
                self.devices[slot].index,
                self.devices[slot].cache_path.display()
            );
        }
        true
    }
}

/// The failure mode of a fill attempt, so the service can deny with the right
/// reason instead of collapsing every failure into one response.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error(transparent)]
    Backend(Error),
}

/// Decide the response purely from the parsed event. A missing RANGE record is a
/// hard deny (without an offset we cannot bound the fetch); non-pre-access masks
/// are denied too.
pub fn decide(event: &PreContentEvent) -> Decision {
    if !event.is_pre_access() {
        return Decision::Deny(DenyReason::NotPreAccess);
    }
    match event.range {
        Some(range) => Decision::Fill(range),
        None => Decision::Deny(DenyReason::InvalidRange),
    }
}

/// Align `[offset, offset + count)` outward to whole 4 KiB blocks and clamp to
/// `cache_size` (`Blobs::fetch` requires block-aligned arguments), using
/// checked arithmetic throughout. Reports why the range is unusable instead of
/// silently producing an empty range that a caller might treat as success.
pub(crate) fn align_fetch_range(
    offset: u64,
    count: u64,
    cache_size: u64,
) -> std::result::Result<Range, RangeError> {
    if count == 0 {
        return Err(RangeError::ZeroCount);
    }
    if offset >= cache_size {
        return Err(RangeError::OffsetPastEnd);
    }
    let raw_end = offset.checked_add(count).ok_or(RangeError::Overflow)?;
    let end = raw_end.min(cache_size);

    let aligned_off = offset & !(BLOCK_SIZE - 1);
    let aligned_end =
        nydus_format::utils::align_up_u64(end, BLOCK_SIZE).ok_or(RangeError::Overflow)?;
    // `cache_size` is validated block-aligned at device enumeration, so rounding
    // `end` up never exceeds it; clamp as a safety net and verify the aligned
    // window stays inside the device.
    let aligned_end = aligned_end.min(cache_size);
    if aligned_off >= aligned_end {
        return Err(RangeError::EmptyAfterAlign);
    }
    Ok(Range {
        offset: aligned_off,
        count: aligned_end - aligned_off,
    })
}

/// The daemon's only fetch deadline is the backend's HTTP timeout plus its
/// bounded retry count — there is no per-event deadline. A registry
/// `timeout: 0s` disables the HTTP timeout entirely and would let a stalled
/// registry block readers indefinitely, so this mode rejects it up front.
/// Other consumers of the registry backend keep the historical
/// "0 = no timeout" behavior.
fn validate_bounded_backend_timeout(config: &Config) -> Result<()> {
    if let BackendConfig::Registry(registry) = &config.backend {
        if registry.http.timeout.is_zero() {
            return Err(Error::InvalidConfig(
                "fanotify mode requires a bounded registry `timeout`: `0s` disables HTTP \
                 timeouts and lets a stalled registry block readers indefinitely — set a \
                 large value (e.g. 600s) instead"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

/// The `(st_dev, st_ino)` identity of a file, matching event fds to devices.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
}

/// Read the file identity of an fd (the accessed blob device file).
pub fn fd_identity(fd: RawFd) -> Result<FileId> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let ret = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to stat event fd");
    }
    let st = unsafe { st.assume_init() };
    // st_dev/st_ino widths vary by platform (glibc/musl, 32/64-bit), so the cast
    // is intentional for portability even where it is a u64→u64 no-op.
    #[allow(clippy::unnecessary_cast)]
    Ok(FileId {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
    })
}

/// Open the cache file with `O_NOFOLLOW`, confirm it is a regular file of the
/// expected size, and take its `(dev, ino)` identity from that same descriptor.
/// Refusing symlinks and non-regular files closes the path-stat/mark/open race.
fn cache_identity(path: &Path, expected_size: u64) -> Result<FileId> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|err| {
        Error::InvalidParameter(format!(
            "blob device path contains an interior NUL byte: {err}"
        ))
    })?;
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_LARGEFILE,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to open blob cache file (O_NOFOLLOW)");
    }
    // SAFETY: open returned a fresh, owned descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let ret = unsafe { libc::fstat(owned.as_raw_fd(), st.as_mut_ptr()) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to stat blob cache file");
    }
    let st = unsafe { st.assume_init() };
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(Error::InvalidParameter(
            "blob cache file is not a regular file".to_string(),
        ));
    }
    #[allow(clippy::unnecessary_cast)]
    let size = st.st_size as u64;
    if size != expected_size {
        return Err(Error::InvalidParameter(format!(
            "blob cache file size {size} does not match device size {expected_size}"
        )));
    }
    #[allow(clippy::unnecessary_cast)]
    Ok(FileId {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn ev(mask: u64, range: Option<Range>) -> PreContentEvent {
        PreContentEvent {
            fd: 5,
            pid: 1,
            mask,
            range,
        }
    }

    #[test]
    fn missing_range_denies() {
        assert_eq!(
            decide(&ev(crate::fanotify::proto::FAN_PRE_ACCESS, None)),
            Decision::Deny(DenyReason::InvalidRange)
        );
    }

    #[test]
    fn present_range_fills() {
        let r = Range {
            offset: 4096,
            count: 8192,
        };
        assert_eq!(
            decide(&ev(crate::fanotify::proto::FAN_PRE_ACCESS, Some(r))),
            Decision::Fill(r)
        );
    }

    #[test]
    fn non_pre_access_denies() {
        let r = Range {
            offset: 0,
            count: 4096,
        };
        assert_eq!(
            decide(&ev(0, Some(r))),
            Decision::Deny(DenyReason::NotPreAccess)
        );
    }

    #[test]
    fn align_block_aligned_range_unchanged() {
        assert_eq!(
            align_fetch_range(4096, 8192, 65536),
            Ok(Range {
                offset: 4096,
                count: 8192
            })
        );
    }

    #[test]
    fn align_rounds_offset_down_and_len_up() {
        // offset 100 → down to 0; end 100+50=150 → up to 4096
        assert_eq!(
            align_fetch_range(100, 50, 65536),
            Ok(Range {
                offset: 0,
                count: 4096
            })
        );
        // offset 5000 (→4096), end 5000+100=5100 (→8192)
        assert_eq!(
            align_fetch_range(5000, 100, 65536),
            Ok(Range {
                offset: 4096,
                count: 4096
            })
        );
    }

    #[test]
    fn align_clamps_to_cache_size() {
        // end spills past the device → clamped to cache_size (block-aligned)
        assert_eq!(
            align_fetch_range(4096, 999_999, 8192),
            Ok(Range {
                offset: 4096,
                count: 4096
            })
        );
    }

    #[test]
    fn align_reports_reason_for_invalid_ranges() {
        assert_eq!(align_fetch_range(0, 0, 8192), Err(RangeError::ZeroCount));
        assert_eq!(
            align_fetch_range(8192, 4096, 8192),
            Err(RangeError::OffsetPastEnd)
        );
        assert_eq!(
            align_fetch_range(4096, u64::MAX, 65536),
            Err(RangeError::Overflow)
        );
    }

    #[test]
    fn zero_registry_timeout_is_rejected_for_fanotify() {
        let registry_yaml = |http_block: &str| {
            format!(
                "backend:\n  type: registry\n  config:\n    addr: http://127.0.0.1:5000\n    \
                 repository: a/b\n{http_block}storage:\n  dir: /cache\n"
            )
        };

        let zero = Config::from_yaml(&registry_yaml("    http:\n      timeout: 0s\n")).unwrap();
        assert!(validate_bounded_backend_timeout(&zero).is_err());

        // Omitted timeout falls back to the registry backend's positive default.
        let omitted = Config::from_yaml(&registry_yaml("")).unwrap();
        assert!(validate_bounded_backend_timeout(&omitted).is_ok());

        let local = Config::from_yaml(
            "backend:\n  type: local\n  config:\n    dir: /blobs\n\
             storage:\n  dir: /cache\n",
        )
        .unwrap();
        assert!(validate_bounded_backend_timeout(&local).is_ok());
    }

    #[test]
    fn cache_identity_accepts_regular_file_of_expected_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob.data");
        std::fs::write(&path, vec![0u8; 4096]).unwrap();
        let identity = cache_identity(&path, 4096).unwrap();
        let md = std::fs::metadata(&path).unwrap();
        assert_eq!((identity.dev, identity.ino), (md.dev(), md.ino()));
    }

    #[test]
    fn cache_identity_rejects_size_mismatch_and_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob.data");
        std::fs::write(&path, vec![0u8; 2048]).unwrap();
        assert!(cache_identity(&path, 4096).is_err());

        let link = dir.path().join("blob.link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(cache_identity(&link, 2048).is_err());
    }
}
