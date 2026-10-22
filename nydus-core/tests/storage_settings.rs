//! `storage.skip_verify_checksums` and `storage.fetch_size` as cores see
//! them. Each core keeps its own cache options, even when another core
//! uses different settings.

mod common;

use std::fs;
use std::ops::Range;
use std::os::unix::fs::FileExt;

use common::{read_flat, Image};
use nydus_core::NydusCore;
use nydus_test_utils::known_issue::assert_known_issue;
use tempfile::tempdir;

const VERIFY: &str = "skip_verify_checksums: false";
const SKIP_VERIFY: &str = "skip_verify_checksums: true";
const ONE_GROUP: &str = "fetch_size: 0";
const WHOLE_BLOB: &str = "fetch_size: 1048576";

/// Fetch group `group` of the core's one blob through the flat view.
fn fetch_group(core: &NydusCore, image: &Image, group: usize) -> nydus_error::Result<Vec<u8>> {
    let blob = &core.blobs.flat_layout()?[0];
    let range = image.logical(group);
    read_flat(
        core,
        blob.mapped_offset + range.start,
        range.end - range.start,
    )
}

/// The blob's resident ranges, without fetching.
fn ready(core: &NydusCore) -> Vec<Range<u64>> {
    let blob = &core.blobs.flat_layout().unwrap()[0];
    core.blobs
        .ready_ranges(&blob.id, 0, blob.cache_size)
        .unwrap()
}

/// Verification rejects a mismatched checksum; explicitly disabling it
/// serves the same data.
#[test]
fn verification_rejects_a_wrong_chunk_group_checksum() {
    let image = Image::build();
    image.tamper_chunk_group_checksum(1);

    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[VERIFY, ONE_GROUP]);
    let err = fetch_group(&core, &image, 1).expect_err("a wrong checksum must fail the read");
    let io = err.io_error().expect("an I/O error");
    assert_eq!(io.kind(), std::io::ErrorKind::InvalidData, "{err:?}");
    assert!(
        nydus_storage::cache::is_chunk_group_crc_mismatch(io),
        "{err:?}"
    );
    let group = image.logical(0);
    assert_eq!(
        fetch_group(&core, &image, 0).unwrap(),
        image.dense[group.start as usize..group.end as usize]
    );
    assert_eq!(ready(&core), [group]);
    drop(core);

    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[SKIP_VERIFY, ONE_GROUP]);
    let group = image.logical(1);
    assert_eq!(
        fetch_group(&core, &image, 1).unwrap(),
        image.dense[group.start as usize..group.end as usize]
    );
}

/// A second core does not disable the first core's verification.
#[test]
fn a_second_core_preserves_the_first_cores_verification() {
    let image = Image::build();
    image.tamper_chunk_group_checksum(1);

    let verifying_dir = tempdir().unwrap();
    let verifying = image.core(verifying_dir.path(), &[VERIFY, ONE_GROUP]);
    let skipping_dir = tempdir().unwrap();
    let _skipping = image.core(skipping_dir.path(), &[SKIP_VERIFY, ONE_GROUP]);

    let err = fetch_group(&verifying, &image, 1).unwrap_err();
    assert!(nydus_storage::cache::is_chunk_group_crc_mismatch(
        err.io_error().unwrap()
    ));
    assert!(ready(&verifying).is_empty());
}

/// A second core does not enlarge the first core's fetch window.
#[test]
fn a_second_core_preserves_the_first_cores_fetch_size() {
    let image = Image::build();

    // Alone, the core fetches the missed group only.
    let alone_dir = tempdir().unwrap();
    let alone = image.core(alone_dir.path(), &[ONE_GROUP]);
    fetch_group(&alone, &image, 0).unwrap();
    assert_eq!(ready(&alone), [image.logical(0)]);
    drop(alone);

    let narrow_dir = tempdir().unwrap();
    let narrow = image.core(narrow_dir.path(), &[ONE_GROUP]);
    let wide_dir = tempdir().unwrap();
    let _wide = image.core(wide_dir.path(), &[WHOLE_BLOB]);
    fetch_group(&narrow, &image, 0).unwrap();

    assert_eq!(ready(&narrow), [image.logical(0)]);
}

/// KI-2: cache hits are never verified, not even with verification on: a
/// group corrupted in the cache file after it was filled reads back
/// corrupted instead of failing.
#[test]
fn ki2_cache_hits_are_served_unverified() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[VERIFY, ONE_GROUP]);
    let blob = core.blobs.prepare_all().unwrap().remove(0);
    let group = image.logical(1);
    let good = image.dense[group.start as usize..group.end as usize].to_vec();
    assert_eq!(fetch_group(&core, &image, 1).unwrap(), good);

    let cache = fs::OpenOptions::new()
        .write(true)
        .open(&blob.cache_path)
        .unwrap();
    let at = group.start + 100;
    cache
        .write_all_at(&[image.dense[at as usize] ^ 0xff], at)
        .unwrap();

    let node = core.fs.open(common::FILE_NAME).unwrap();
    let mut buf = vec![0u8; 16];
    let result = node.read_at(at, &mut buf).map(|_| buf.clone());
    let wrong_bytes = result
        .as_ref()
        .is_ok_and(|bytes| bytes[..] != image.dense[at as usize..at as usize + 16]);
    assert_known_issue("KI-2", &result, result.is_err(), wrong_bytes);
}
