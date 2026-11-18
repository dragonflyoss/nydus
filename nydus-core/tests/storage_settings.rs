mod common;

use std::fs;
use std::io;
use std::ops::Range;
use std::os::unix::fs::FileExt;

use common::{read_flat, Image, FILE_NAME};
use nydus_core::NydusCore;
use nydus_storage::cache::is_chunk_group_crc_mismatch;
use nydus_storage::chunk_group_map::current_boot_tag;
use tempfile::tempdir;

const VERIFY: &str = "skip_verify_checksums: false";
const SKIP_VERIFY: &str = "skip_verify_checksums: true";
const ONE_GROUP: &str = "fetch_size: 0";
const WHOLE_BLOB: &str = "fetch_size: 1048576";
const GROUP_MAP_BOOT_TAG_OFFSET: u64 = 28;

fn fetch_group(core: &NydusCore, image: &Image, group: usize) -> nydus_error::Result<Vec<u8>> {
    let blob = &core.blobs.flat_layout()?[0];
    let range = image.logical(group);
    read_flat(
        core,
        blob.mapped_offset + range.start,
        range.end - range.start,
    )
}

fn ready(core: &NydusCore) -> Vec<Range<u64>> {
    let blob = &core.blobs.flat_layout().unwrap()[0];
    core.blobs
        .ready_ranges(&blob.id, 0, blob.cache_size)
        .unwrap()
}

#[test]
fn skip_verify_checksums_false_rejects_a_wrong_checksum_even_beside_a_skipping_core() {
    let image = Image::build();
    image.tamper_chunk_group_checksum(1);
    let group = image.logical(0);
    let test_cases = vec![None, Some(SKIP_VERIFY)];

    for second_core_setting in test_cases {
        let cache_dir = tempdir().unwrap();
        let core = image.core(cache_dir.path(), &[VERIFY, ONE_GROUP]);
        let second_cache_dir = tempdir().unwrap();
        let _second_core = second_core_setting
            .map(|storage| image.core(second_cache_dir.path(), &[storage, ONE_GROUP]));

        let err = fetch_group(&core, &image, 1).unwrap_err();
        let io_err = err.io_error().unwrap();
        assert_eq!(
            io_err.kind(),
            io::ErrorKind::InvalidData,
            "second_core_setting={second_core_setting:?}"
        );
        assert!(
            is_chunk_group_crc_mismatch(io_err),
            "second_core_setting={second_core_setting:?}"
        );
        assert!(
            ready(&core).is_empty(),
            "second_core_setting={second_core_setting:?}"
        );

        assert_eq!(
            fetch_group(&core, &image, 0).unwrap(),
            image.dense[group.start as usize..group.end as usize],
            "second_core_setting={second_core_setting:?}"
        );
        assert_eq!(
            ready(&core),
            [group.clone()],
            "second_core_setting={second_core_setting:?}"
        );
    }
}

#[test]
fn skip_verify_checksums_true_serves_a_group_with_a_wrong_checksum() {
    let image = Image::build();
    image.tamper_chunk_group_checksum(1);
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[SKIP_VERIFY, ONE_GROUP]);
    let group = image.logical(1);

    let data = fetch_group(&core, &image, 1).unwrap();

    assert_eq!(data, image.dense[group.start as usize..group.end as usize]);
}

#[test]
fn fetch_size_zero_fetches_only_the_missed_group_even_beside_a_wide_core() {
    let image = Image::build();
    let test_cases = vec![None, Some(WHOLE_BLOB)];

    for second_core_setting in test_cases {
        let cache_dir = tempdir().unwrap();
        let core = image.core(cache_dir.path(), &[ONE_GROUP]);
        let second_cache_dir = tempdir().unwrap();
        let _second_core =
            second_core_setting.map(|storage| image.core(second_cache_dir.path(), &[storage]));

        fetch_group(&core, &image, 0).unwrap();

        assert_eq!(
            ready(&core),
            [image.logical(0)],
            "second_core_setting={second_core_setting:?}"
        );
    }
}

#[test]
fn read_at_refetches_a_corrupted_cache_group_after_a_restart() {
    let image = Image::build();
    let cache_dir = tempdir().unwrap();
    let core = image.core(cache_dir.path(), &[VERIFY, ONE_GROUP]);
    let blob = core.blobs.prepare_all().unwrap().remove(0);
    let group = image.logical(1);
    assert_eq!(
        fetch_group(&core, &image, 1).unwrap(),
        image.dense[group.start as usize..group.end as usize]
    );
    drop(core);

    let corrupted_offset = group.start + 100;
    fs::OpenOptions::new()
        .write(true)
        .open(&blob.cache_path)
        .unwrap()
        .write_all_at(
            &[image.dense[corrupted_offset as usize] ^ 0xff],
            corrupted_offset,
        )
        .unwrap();
    let map = blob
        .cache_path
        .with_extension("")
        .with_extension("group.map");
    let boot_tag = current_boot_tag().unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&map)
        .unwrap()
        .write_all_at(
            &boot_tag.wrapping_add(1).max(1).to_le_bytes(),
            GROUP_MAP_BOOT_TAG_OFFSET,
        )
        .unwrap();

    let core = image.core(cache_dir.path(), &[VERIFY, ONE_GROUP]);
    assert!(ready(&core).is_empty());
    let mut buf = vec![0u8; 16];
    core.fs
        .open(FILE_NAME)
        .unwrap()
        .read_at(corrupted_offset, &mut buf)
        .unwrap();
    assert_eq!(
        buf,
        image.dense[corrupted_offset as usize..corrupted_offset as usize + 16]
    );
}
