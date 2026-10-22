# Known issues

Bugs the e2e suites reproduce but that are not fixed yet. A test of the
correct behavior wraps its body in `env.KnownIssue(t, "KI-N", ...)`.
CI sets `NYDUS_TEST_FAIL_KNOWN_ISSUES=1`: known bugs fail, and correct
behavior passes. The marker does not hide failures in PR checks.
Without that variable, local runs retain the diagnostic mode: skip while
the bug reproduces and fail when the marker becomes stale.
Fixing a bug means deleting its row and the marker in the same change.

| ID | Behavior the tests expect | Where it goes wrong |
| --- | --- | --- |
| KI-1 | A registry answering a `Range` request with `200` and the whole blob is rejected (or the right slice is used); the reader never serves bytes from the wrong offset. | `nydus-backend/src/registry/mod.rs` accepts any successful status; `response.rs` takes the body's first bytes. |
| KI-2 | Corrupted cached data and CRC-preserving corruption must not silently return wrong bytes. CRC32C is now verified by default, but cache hits are not verified and stored group digests are not checked. | `nydus-storage/src/cache/local.rs`, `nydus-storage/src/cache/mod.rs` |
| KI-3 | A cache map reset by one daemon never makes a peer read a group that is not ready. | `nydus-storage/src/chunk_group_map.rs` (`reset` vs `set_ready`) |
| KI-4 | A daemon never writes into a cache data file another process deleted, and waiting on a peer's cache lock is bounded. | `nydus-storage/src/cache` |
| KI-6 | `nydus merge` gives each inode the link count of the merged tree. | `nydus/src/build/merge.rs` (`nlink` copied from the layer) |
| KI-7 | `nydus check` exits non-zero on every structural error it reports. | `nydus/src/bin/nydus/check.rs` |
| KI-8 | A daemon that mounts kernel EROFS itself (`fileio`, and the experimental `nbd` and `fanotify`) notices its mount being unmounted from outside and exits, as the FUSE daemon does. | `nydus/src/bin/nydus/fileio.rs` waits for a signal only; likewise `nbd.rs`, `fanotify.rs`. |
| KI-9 | With Dragonfly configured but its scheduler unreachable at startup, the mount still comes up and reads fall back to the origin. | `nydus-backend/src/registry/dragonfly.rs` (`Dragonfly::new` fails the backend) |
| KI-10 | SIGTERM while files on the mount are open still unmounts (lazily if need be) and exits 0. | `nydus/src/fuse/mount.rs` (`finish_session` tries one plain unmount) |
| KI-12 | Through `fileio`, a registry that never answers fails a read within a few request timeouts, as it does through FUSE. Instead the kernel keeps issuing export reads that nydus fails one after another; the replies find the requests gone (`ENOENT`), and read(2) does not return within 30s. Not yet reproduced outside CI (needs kernel >= 6.12). | `nydus/src/fileio` export read path, or kernel EROFS file-backed reads over FUSE |

The Rust tests pin KI-1, KI-2 and KI-9 in process as well, with
`nydus_test_utils::known_issue::assert_known_issue` (the same strict CI
policy; locally a reproduced bug is an expected failure). KI-3 has a deterministic
cross-process reproducer in
[`group_map_process.rs`](../../nydus-storage/tests/group_map_process.rs):
an x86-64 hardware watchpoint pauses `set_ready` after its bitmap write,
another process resets the map, and the stale counter update resumes.
It needs Linux x86-64 and ptrace permission; the privileged CI lane sets
`NYDUS_TEST_REQUIRE_PTRACE=1` so an unavailable prerequisite fails.

KI-5 (process-global cache options) and KI-11 (Dragonfly 404/401 handling)
were resolved upstream. Their intended behavior is now tested without a
known-issue marker.
