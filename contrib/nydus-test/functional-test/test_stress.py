from time import sleep
from conftest import ANCHOR
import pytest
from nydus_anchor import NydusAnchor
from rafs import RafsConf, RafsImage, RafsMount, Backend
import os
from fio import Fio
from utils import Size, Unit, clean_pagecache
from distributor import Distributor
from bot import Bot
from workload_gen import WorkloadGen
from utils import is_regular, timer, logging_setup, get_current_time, delta_time

RESULT = ""
SCRATCH_IMAGE = None
FILE_CNT = 500
TARGET_FILES = None

SUMMARY_FILE = open("stress.report", "w")


logging_setup()


def setup_module(module):
    ANCHOR.prepare_scratch_dir()
    global SCRATCH_IMAGE
    SCRATCH_IMAGE = RafsImage(
        ANCHOR,
        ANCHOR.scratch_dir,
        "boostrap_scratched",
        "blob_scratched",
        clear_from_oss=True,
    )

    dist = Distributor(SCRATCH_IMAGE.rootfs(), 8, 3)
    dist.generate_tree()
    dist.put_multiple_files(FILE_CNT, Size(16, Unit.KB))

    target_files = [os.path.join(ANCHOR.mount_point, f) for f in dist.files[-FILE_CNT:]]
    target_files = ":".join(target_files)
    global TARGET_FILES
    TARGET_FILES = target_files

    SCRATCH_IMAGE.set_backend(Backend.OSS).create_image()


def teardown_module(module):
    """teardown any state that was previously setup with a setup_module
    method.
    """
    try:
        bot = Bot()
        if bot is not None:
            bot.send(RESULT)
    except ValueError:
        pass

    SCRATCH_IMAGE.clean_up()


def test_file_read_with_cache(nydus_anchor, rafs_conf: RafsConf):

    rafs_conf.enable_rafs_blobcache().enable_fs_prefetch(
        threads_count=4,
        merging_size=Size(128, Unit.KB).B,
    ).set_rafs_backend(Backend.OSS)

    rafs = RafsMount(nydus_anchor, SCRATCH_IMAGE, rafs_conf).prefetch_files("/").mount()

    sleep(8)

    rafs.umount()

    rafs = RafsMount(nydus_anchor, SCRATCH_IMAGE, rafs_conf).prefetch_files("/").mount()

    wg = WorkloadGen(rafs.mount_point, None)
    total_files = 0

    def read_file(t):
        try:
            with open(t, "rb") as f:
                try:
                    if is_regular(t):
                        f.read(1024)
                        nonlocal total_files
                        total_files += 1
                except OSError:
                    pass
        except FileNotFoundError:
            pass
        except PermissionError:
            pass
        except OSError:
            pass

    start = get_current_time()
    wg.iter_all_files(read_file)
    end = get_current_time()
    sec, usec = delta_time(end, start)

    clean_pagecache()

    r = {"total files": total_files, "elapse/s": sec}

    print(r)


@pytest.mark.parametrize("blk_size", ["4k"])
@pytest.mark.parametrize("direct", ["1"])
@pytest.mark.parametrize("readwrite", ["read", "randread"])
def test_stress_fio(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    blk_size,
    direct,
    readwrite,
):
    rafs_conf.enable_rafs_blobcache().enable_fs_prefetch(
        threads_count=4,
        merging_size=Size(1, Unit.MB).B,
        bandwidth_rate=Size(10, Unit.MB).B,
    ).set_rafs_backend(Backend.OSS)

    RafsMount(nydus_anchor, SCRATCH_IMAGE, rafs_conf).prefetch_files("/").mount()
    fio = Fio()

    fio.create_command(blk_size, readwrite).block_size(blk_size).direct(direct).numjobs(
        4
    ).ioengine("psync").read_write(readwrite).filename(TARGET_FILES)

    fio.run()
    title_line = f"Blobcache and prefetch limited at 10M, block size: {blk_size}, direct: {direct}, readwrite: {readwrite}"
    r = fio.get_result(title_line)
    global RESULT
    RESULT += r

    SUMMARY_FILE.write(r)
    SUMMARY_FILE.flush()

    clean_pagecache()


@pytest.mark.parametrize("blk_size", ["4k", "16k", "256k"])
@pytest.mark.parametrize("direct", ["1"])
@pytest.mark.parametrize("readwrite", ["read", "randread"])
def test_stress_fio_higher_limit(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    blk_size,
    direct,
    readwrite,
):
    rafs_conf.enable_rafs_blobcache().enable_fs_prefetch(
        threads_count=4,
        merging_size=Size(1, Unit.MB).B,
        bandwidth_rate=Size(50, Unit.MB).B,
    ).set_rafs_backend(Backend.OSS)

    RafsMount(nydus_anchor, SCRATCH_IMAGE, rafs_conf).prefetch_files("/").mount()

    fio = Fio()

    fio.create_command(blk_size, readwrite).block_size(blk_size).direct(direct).numjobs(
        4
    ).ioengine("psync").read_write(readwrite).filename(TARGET_FILES)

    fio.run()
    title_line = f"Blobcache and prefetch limited ad 50M, block size: {blk_size}, direct: {direct}, readwrite: {readwrite}"
    r = fio.get_result(title_line)
    global RESULT
    RESULT += r

    SUMMARY_FILE.write(r)
    SUMMARY_FILE.flush()

    clean_pagecache()


@pytest.mark.parametrize("blk_size", ["4k", "16k", "256k"])
@pytest.mark.parametrize("direct", ["1"])
@pytest.mark.parametrize("readwrite", ["read", "randread"])
def test_stress_fio_no_prefetch(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    blk_size,
    direct,
    readwrite,
):
    rafs_conf.enable_rafs_blobcache().set_rafs_backend(Backend.OSS).amplify_io(
        128 * 1024
    )

    RafsMount(nydus_anchor, SCRATCH_IMAGE, rafs_conf).mount()

    fio = Fio()

    fio.create_command(blk_size, readwrite).block_size(blk_size).direct(direct).numjobs(
        4
    ).ioengine("psync").read_write(readwrite).filename(TARGET_FILES)

    fio.run()
    title_line = f"With blobcache but disable prefetch, block size: {blk_size}, direct: {direct}, readwrite: {readwrite}"
    r = fio.get_result(title_line)
    global RESULT
    RESULT += r

    SUMMARY_FILE.write(r)
    SUMMARY_FILE.flush()

    clean_pagecache()
