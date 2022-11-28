import pytest
import tempfile
from distributor import Distributor
from rafs import Backend, NydusDaemon, RafsConf, RafsImage
from workload_gen import WorkloadGen
from nydus_anchor import NydusAnchor
from utils import logging_setup, Size, Unit
import utils
from nydusd_client import NydusAPIClient
import nydusd_client
import os
import logging
import time
import random

logging_setup()


def test_daemon_info(nydus_anchor, nydus_image, rafs_conf: RafsConf):
    nydus_image.set_backend(Backend.BACKEND_PROXY).create_image()
    rafs_conf.set_rafs_backend(Backend.BACKEND_PROXY)
    rafs = NydusDaemon(nydus_anchor, nydus_image, rafs_conf)
    rafs.mount()
    nc = NydusAPIClient(rafs.get_apisock())
    nc.get_wait_daemon()


def test_iostats(
    nydus_anchor: NydusAnchor, nydus_image: RafsImage, rafs_conf: RafsConf
):
    rafs_id = "/"
    rafs_conf.enable_files_iostats().enable_latest_read_files().set_rafs_backend(
        Backend.BACKEND_PROXY
    )
    nydus_image.set_backend(Backend.BACKEND_PROXY).create_image()
    rafs = NydusDaemon(nydus_anchor, nydus_image, rafs_conf)

    rafs.mount()
    assert rafs.is_mounted()

    nc = NydusAPIClient(rafs.get_apisock())

    duration = 5

    wg = WorkloadGen(nydus_anchor.mountpoint, nydus_image.rootfs())
    wg.setup_workload_generator()
    wg.torture_read(4, duration)

    while duration:
        time.sleep(1)
        duration -= 1
        nc.get_global_metrics()
        nc.get_files_metrics(rafs_id)
        nc.get_backend_metrics(rafs_id)

    wg.finish_torture_read()

    duration = 7
    wg.torture_read(4, duration)
    # Disable it firstly and then enable it.
    # TODO: files metrics can't be toggled dynamically now. Try to implement it.
    # nc.disable_files_metrics(rafs_id)
    # nc.enable_files_metrics(rafs_id)

    r = nc.get_latest_files_metrics(rafs_id)
    print(r)

    while duration:
        time.sleep(1)
        duration -= 1
        nc.get_files_metrics(rafs_id)

    wg.finish_torture_read()
    rafs.umount()


def test_global_metrics(
    nydus_anchor: NydusAnchor, nydus_image: RafsImage, rafs_conf: RafsConf
):
    rafs_id = "/"

    rafs_conf.enable_files_iostats().set_rafs_backend(Backend.BACKEND_PROXY)
    nydus_image.set_backend(Backend.BACKEND_PROXY).create_image()

    rafs = NydusDaemon(nydus_anchor, nydus_image, rafs_conf)
    rafs.mount()

    nc = NydusAPIClient(rafs.get_apisock())

    gm = nc.get_global_metrics()
    assert gm["files_account_enabled"] == True
    assert gm["measure_latency"] == True

    file_counters = nc.get_files_metrics(rafs_id)
    assert len(file_counters)

    logging.info("There are %d file counters created.", len(file_counters))

    wg = WorkloadGen(nydus_anchor.mountpoint, nydus_image.rootfs())
    wg.setup_workload_generator()

    wg.io_read(4)

    file_counters = nc.get_files_metrics(rafs_id)
    assert file_counters is not None and len(file_counters)
    logging.info(
        "There are %d file counters created after some read.", len(file_counters)
    )

    if len(file_counters):
        k = random.choice(list(file_counters))
        logging.info("ino: %s, stats: %s", k, file_counters[k])

    gm_old = nc.get_global_metrics()

    wg.io_read(4)

    gm_new = nc.get_global_metrics()
    assert gm_new["data_read"] > gm_old["data_read"]
    assert (
        gm_new["fop_hits"][nydusd_client.Fop.Read.get_value()]
        > gm_old["fop_hits"][nydusd_client.Fop.Read.get_value()]
    )

    rafs.umount()


def test_backend_swap(
    nydus_anchor, nydus_scratch_image: RafsImage, rafs_conf: RafsConf
):

    dist = Distributor(nydus_scratch_image.rootfs(), 5, 4)
    dist.generate_tree()
    dist.put_multiple_files(100, Size(2, Unit.MB))

    nydus_scratch_image.set_backend(Backend.BACKEND_PROXY).create_image(
        readahead_policy="fs", readahead_files="/".encode()
    )
    rafs_conf.set_rafs_backend(
        Backend.BACKEND_PROXY
    ).enable_rafs_blobcache().enable_fs_prefetch(
        threads_count=7, bandwidth_rate=Size(2, Unit.MB).B
    )
    rafs_conf.dump_rafs_conf()

    rafs = NydusDaemon(nydus_anchor, None, rafs_conf, with_defaults=False)
    rafs.thread_num(4).set_mountpoint(nydus_anchor.mountpoint).apisock(
        "api_sock"
    ).mount()

    nc = NydusAPIClient(rafs.get_apisock())
    nc.pseudo_fs_mount(nydus_scratch_image.bootstrap_path, "/", rafs_conf.path(), None)
    nc.umount_rafs("/")
    assert len(os.listdir(nydus_anchor.mountpoint)) == 0

    mp = "/pseudo1"
    nc.pseudo_fs_mount(nydus_scratch_image.bootstrap_path, mp, rafs_conf.path(), None)

    rafs_conf_2nd = RafsConf(nydus_anchor, nydus_scratch_image)
    rafs_conf_2nd.set_rafs_backend(
        Backend.LOCALFS, image=nydus_scratch_image
    ).enable_rafs_blobcache().enable_fs_prefetch(
        threads_count=3, bandwidth_rate=Size(1, Unit.MB).B
    )
    rafs_conf_2nd.dump_rafs_conf()

    new_image = (
        RafsImage(nydus_anchor, nydus_scratch_image.rootfs())
        .set_backend(Backend.LOCALFS)
        .create_image(readahead_policy="fs", readahead_files="/".encode())
    )

    # TODO: Once upon a time, more than one fd are open. Check why this happens.
    wg = WorkloadGen(
        os.path.join(nydus_anchor.mountpoint, mp.strip("/")),
        nydus_scratch_image.rootfs(),
    )

    wg.setup_workload_generator()
    wg.torture_read(8, 8)

    for i in range(1, 50):
        logging.debug("swap for the %dth time", i)
        nc.swap_backend(mp, new_image.bootstrap_name, rafs_conf_2nd.path())
        # assert nc.get_blobcache_metrics(mp)["prefetch_workers"] == 3
        time.sleep(0.2)
        nc.swap_backend(mp, nydus_scratch_image.bootstrap_name, rafs_conf.path())
        utils.clean_pagecache()

    wg.finish_torture_read()

    assert wg.io_error == False

    nc.umount_rafs(mp)
    utils.clean_pagecache()


def test_access_pattern(
    nydus_anchor: NydusAnchor, nydus_image: RafsImage, rafs_conf: RafsConf
):
    rafs_id = "/"
    rafs_conf.enable_access_pattern().set_rafs_backend(Backend.BACKEND_PROXY)
    rafs_conf.dump_rafs_conf()

    nydus_image.set_backend(Backend.BACKEND_PROXY).create_image()

    rafs = NydusDaemon(nydus_anchor, nydus_image, rafs_conf)
    rafs.mount()

    nc = NydusAPIClient(rafs.get_apisock())

    wg = WorkloadGen(nydus_anchor.mountpoint, nydus_image.rootfs())
    wg.setup_workload_generator()
    wg.torture_read(4, 8)
    duration = 4
    while duration:
        time.sleep(1)
        duration -= 1
        global_metrics = nc.get_global_metrics()
        global_metrics["access_pattern_enabled"] == True

    patterns = nc.get_access_patterns(rafs_id)
    assert len(patterns) != 0
    patterns = nc.get_access_patterns()
    assert len(patterns) != 0
    nc.get_access_patterns("poison")

    wg.finish_torture_read()


def test_api_mount_with_prefetch(
    nydus_anchor, nydus_image: RafsImage, rafs_conf: RafsConf
):
    nydus_image.set_backend(Backend.BACKEND_PROXY).create_image()

    hint_files = ["/"]
    rafs = NydusDaemon(nydus_anchor, None, None, with_defaults=False)

    # Prefetch must enable blobcache
    rafs_conf.enable_rafs_blobcache()
    rafs_conf.set_rafs_backend(Backend.BACKEND_PROXY)
    rafs_conf.enable_fs_prefetch(threads_count=4)
    rafs_conf.dump_rafs_conf()
    rafs.set_mountpoint(nydus_anchor.mountpoint).apisock("api_sock").mount(
        dump_config=False,
    )

    nc = NydusAPIClient(rafs.get_apisock())
    nc.pseudo_fs_mount(
        nydus_image.bootstrap_path,
        "/pseudo_fs_1",
        rafs_conf.path(),
        hint_files,
        "rafs",
    )

    # Only one rafs mountpoint exists, so whether set rafs id or not is not important.
    time.sleep(0.5)
    m = nc.get_blobcache_metrics()
    assert m["prefetch_data_amount"] != 0

    wg = WorkloadGen(
        os.path.join(nydus_anchor.mountpoint, "pseudo_fs_1"), nydus_image.rootfs()
    )
    wg.setup_workload_generator()
    wg.torture_read(4, 8)
    wg.finish_torture_read()
    m = nc.get_blobcache_metrics("/pseudo_fs_1")


def test_detect_io_hang(nydus_anchor, nydus_image: RafsImage, rafs_conf: RafsConf):

    rafs_conf.enable_files_iostats().set_rafs_backend(Backend.BACKEND_PROXY)
    rafs_conf.dump_rafs_conf()

    nydus_image.set_backend(Backend.BACKEND_PROXY).create_image()

    rafs = NydusDaemon(nydus_anchor, nydus_image, rafs_conf)
    rafs.thread_num(5).mount()

    wg = WorkloadGen(nydus_anchor.mountpoint, nydus_image.rootfs())
    wg.setup_workload_generator()
    wg.torture_read(4, 8)

    nc = NydusAPIClient(rafs.get_apisock())

    for _ in range(0, 30):
        ops = nc.get_inflight_metrics()
        time.sleep(0.1)
        print(ops)

    wg.finish_torture_read()
