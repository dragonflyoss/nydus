mod common;

use std::sync::Arc;

use common::{Image, CHUNK_SIZE, FILE_NAME};
use nydus_core::NydusCore;

fn cached_bytes(core: &NydusCore) -> f64 {
    core.metrics()
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.get_name() == "nydus_cache_bytes")
        .unwrap()
        .get_metric()
        .iter()
        .find(|metric| {
            metric
                .get_label()
                .iter()
                .any(|label| label.get_name() == "status" && label.get_value() == "cached")
        })
        .unwrap()
        .get_gauge()
        .get_value()
}

fn read_group(core: &NydusCore, image: &Image, group: usize) {
    let mut bytes = [0; 17];
    let offset = image.logical(group).start;
    core.fs
        .open(FILE_NAME)
        .unwrap()
        .read_at(offset, &mut bytes)
        .unwrap();
    assert_eq!(
        bytes.as_slice(),
        &image.file[offset as usize..offset as usize + 17]
    );
}

#[test]
fn new_gives_each_core_its_own_metrics_and_trace_for_identical_blobs() {
    let image = Image::build();
    let first_dir = image.dir.path().join("first");
    let second_dir = image.dir.path().join("second");
    let first = image.core(&first_dir, &["fetch_size: 0"]);
    let second = image.core(&second_dir, &["fetch_size: 0"]);

    read_group(&first, &image, 2);
    read_group(&first, &image, 2);
    read_group(&second, &image, 4);
    assert!(!Arc::ptr_eq(first.metrics(), second.metrics()));
    assert!(!Arc::ptr_eq(
        first.ondemand_recorder(),
        second.ondemand_recorder()
    ));
    assert_eq!(first.ondemand_snapshot().entries.len(), 1);
    assert_eq!(first.ondemand_snapshot().entries[0].chunk_group_index, 2);
    assert_eq!(second.ondemand_snapshot().entries.len(), 1);
    assert_eq!(second.ondemand_snapshot().entries[0].chunk_group_index, 4);
    assert_eq!(cached_bytes(&first), f64::from(CHUNK_SIZE));
    assert_eq!(cached_bytes(&second), f64::from(CHUNK_SIZE));
}

#[test]
fn drop_releases_the_core_state_and_leaves_the_others_counting() {
    let image = Image::build();
    let first_dir = image.dir.path().join("first");
    let second_dir = image.dir.path().join("second");
    let first = image.core(&first_dir, &["fetch_size: 0"]);
    let second = image.core(&second_dir, &["fetch_size: 0"]);
    read_group(&first, &image, 2);
    read_group(&second, &image, 4);

    let old_metrics = first.metrics().clone();
    let old_trace = Arc::downgrade(first.ondemand_recorder());
    drop(first);
    assert!(old_trace.upgrade().is_none());
    assert!(!old_metrics
        .registry()
        .gather()
        .iter()
        .any(|family| family.get_name() == "nydus_cache_bytes"));
    read_group(&second, &image, 1);
    assert_eq!(second.ondemand_snapshot().entries.len(), 2);
    assert_eq!(cached_bytes(&second), f64::from(2 * CHUNK_SIZE));

    let reopened = image.core(&first_dir, &["fetch_size: 0"]);
    assert!(reopened.ondemand_snapshot().entries.is_empty());
    read_group(&reopened, &image, 2);
    assert_eq!(reopened.ondemand_snapshot().entries.len(), 1);
    assert_eq!(cached_bytes(&reopened), f64::from(CHUNK_SIZE));
    assert_eq!(second.ondemand_snapshot().entries.len(), 2);
}
