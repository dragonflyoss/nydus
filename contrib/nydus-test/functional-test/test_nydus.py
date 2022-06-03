import os
import tempfile
import time
import random
import signal
import stat
import shutil
import uuid
from fallocate import fallocate, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_KEEP_SIZE

import pytest
import utils
from rafs import RafsMount, RafsConf, RafsImage, Backend, Compressor
from nydus_anchor import NydusAnchor
from workload_gen import WorkloadGen
from distributor import Distributor
from utils import logging_setup, Size, Unit
import verifier
from nydusd_client import NydusAPIClient
from whiteout import Whiteout
import platform

logging_setup()

# Specify nydusd and its tools build target directory.
# Let test script fill test environment variables.


# TODO: Test if nydusd is compatible with early version of image
# We want to test every kind of images
def test_build_image(nydus_anchor, nydus_scratch_image, rafs_conf: RafsConf):
    """
    title: Build nydus image
    description: Build nydus image from rootfs generating proper bootstrap and
    blob
    pass_criteria:
      - Image can successfully builded and mounted
      - Rafs can be unmounted and do a small account of read io and attr
        operation
      - Try let image builder upload blob itself.
    """

    dist = Distributor(nydus_scratch_image.rootfs(), 80, 1)
    dist.generate_tree()
    dist.put_directories(100)
    dist.put_hardlinks(90)
    dist.put_symlinks(200)
    dist.put_multiple_files(random.randint(20, 28), Size(10, Unit.MB))
    dist.put_multiple_chinese_files(random.randint(20, 28), Size(20, Unit.KB))

    Whiteout().whiteout_one_file(nydus_scratch_image.rootfs(), "i/am/troublemaker/foo")

    nydus_scratch_image.set_backend(Backend.OSS).create_image(oss_uploader="util")

    rafs_conf.set_rafs_backend(backend_type=Backend.OSS)
    rafs_conf.dump_rafs_conf()

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    wg = WorkloadGen(nydus_anchor.mount_point, nydus_scratch_image.rootfs())

    rafs.mount()
    assert wg.verify_entire_fs()
    rafs.umount()


@pytest.mark.parametrize("io_duration", [5])
@pytest.mark.parametrize("fs_version", ["5"])
@pytest.mark.parametrize("backend", [Backend.OSS, Backend.LOCALFS])
def test_basic(
    nydus_anchor,
    nydus_image: RafsImage,
    io_duration,
    backend,
    rafs_conf: RafsConf,
    fs_version,
):
    """
    title: Basic functionality test
    description: Mount rafs with different mount options
    pass_criteria:
      - Rafs can be mounted.
      - Rafs can be unmounted.
    """
    nydus_image.set_backend(backend, blob_dir=()).create_image(fs_version=fs_version)
    rafs_conf.set_rafs_backend(backend)

    rafs = RafsMount(nydus_anchor, nydus_image, rafs_conf)
    rafs.mount()
    assert rafs.is_mounted()

    workload_gen = WorkloadGen(nydus_anchor.mount_point, nydus_image.rootfs())

    workload_gen.setup_workload_generator()
    workload_gen.io_read(io_duration)

    nydus_anchor.check_nydusd_health()
    assert workload_gen.io_error == False
    assert workload_gen.verify_entire_fs()

    assert rafs.is_mounted()
    rafs.umount()


def test_prefetch_without_cache(
    nydus_anchor: NydusAnchor, nydus_scratch_image: RafsImage, rafs_conf: RafsConf
):
    """Files prefetch test

    1. relative hinted prefetch files
    2. absolute hinted prefetch files
    3. source rootfs root dir.
    """

    rafs_conf.enable_fs_prefetch().set_rafs_backend(Backend.OSS)
    rafs_conf.dump_rafs_conf()

    dist = Distributor(nydus_scratch_image.rootfs(), 4, 4)
    dist.generate_tree()
    dist.put_directories(20)
    dist.put_multiple_files(40, Size(8, Unit.KB))
    dist.put_hardlinks(6)
    dist.put_multiple_chinese_files(random.randint(20, 28), Size(20, Unit.KB))

    hint_files = ["/"]
    hint_files.extend(dist.files)
    hint_files.extend(dist.dirs)
    hint_files.extend(dist.symlinks)
    hint_files.extend(dist.hardlinks)

    hint_files = [os.path.join("/", p) for p in hint_files]
    hint_files = "\n".join(hint_files)

    nydus_scratch_image.set_backend(Backend.OSS).create_image(
        readahead_policy="fs", readahead_files=hint_files.encode()
    )

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.mount()
    assert rafs.is_mounted()

    workload_gen = WorkloadGen(nydus_anchor.mount_point, nydus_scratch_image.rootfs())

    # TODO: Run several parallel read workers against the mount_point
    workload_gen.setup_workload_generator()
    workload_gen.torture_read(8, 5)
    workload_gen.finish_torture_read()

    assert NydusAnchor.check_nydusd_health()
    assert not workload_gen.io_error

    assert rafs.is_mounted()
    rafs.umount()


@pytest.mark.parametrize("thread_cnt", [3])
@pytest.mark.parametrize("compressor", [Compressor.LZ4_BLOCK, Compressor.NONE])
@pytest.mark.parametrize("is_cache_compressed", [False])
def test_prefetch_with_cache(
    nydus_anchor,
    nydus_scratch_image: RafsImage,
    rafs_conf: RafsConf,
    thread_cnt,
    compressor,
    is_cache_compressed,
):
    """
    title: Prefetch from various backend
    description:
      - Enable rafs backend blob cache, as it is disabled by default
    pass_criteria:
      - Rafs can be mounted.
      - Rafs can be unmounted.
    """
    rafs_conf.enable_rafs_blobcache(is_compressed=is_cache_compressed)
    rafs_conf.set_rafs_backend(Backend.OSS, prefix="object_prefix/")
    rafs_conf.enable_fs_prefetch(threads_count=4, bandwidth_rate=Size(40, Unit.MB).B)
    rafs_conf.dump_rafs_conf()

    dist = Distributor(nydus_scratch_image.rootfs(), 4, 4)
    dist.generate_tree()
    dist.put_directories(20)
    dist.put_multiple_files(40, Size(3, Unit.MB))
    dist.put_hardlinks(6)
    dist.put_multiple_chinese_files(random.randint(20, 28), Size(20, Unit.KB))

    nydus_scratch_image.set_backend(Backend.OSS, prefix="object_prefix/").create_image(
        compressor=compressor,
        readahead_policy="fs",
        readahead_files="/".encode(),
    )

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.thread_num(4).mount()

    nc = NydusAPIClient(rafs.get_apisock())
    workload_gen = WorkloadGen(nydus_anchor.mount_point, nydus_scratch_image.rootfs())
    m = nc.get_blobcache_metrics()
    time.sleep(0.3)
    assert m["prefetch_data_amount"] != 0

    workload_gen.setup_workload_generator()
    workload_gen.torture_read(thread_cnt, 10)

    assert NydusAnchor.check_nydusd_health()

    workload_gen.finish_torture_read()
    assert not workload_gen.io_error

    # In this way, we can check if nydusd is crashed.
    assert rafs.is_mounted()
    rafs.umount()


@pytest.mark.parametrize("compressor", [Compressor.NONE, Compressor.LZ4_BLOCK])
@pytest.mark.parametrize("backend", [Backend.OSS, Backend.LOCALFS])
@pytest.mark.parametrize("amplified_size", [Size(3, Unit.MB).B, Size(3, Unit.KB).B])
def test_large_file(nydus_anchor, compressor, backend, amplified_size):
    _tmp_dir = tempfile.TemporaryDirectory(dir=nydus_anchor.workspace)
    large_file_dir = _tmp_dir.name

    dist = Distributor(large_file_dir, 3, 3)
    dist.generate_tree()
    dist.put_single_file(Size(20, Unit.MB))
    dist.put_single_file(Size(10891, Unit.KB))
    dist.put_multiple_files(10, Size(2, Unit.MB))
    dist.put_multiple_files(10, Size(4, Unit.MB))

    image = RafsImage(nydus_anchor, large_file_dir, "bs_large", "blob_large")
    image.set_backend(backend).create_image(compressor=compressor)

    rafs_conf = (
        RafsConf(nydus_anchor, image)
        .enable_rafs_blobcache()
        .amplify_io(amplified_size)
        .set_rafs_backend(backend, image=image)
    )

    rafs = RafsMount(nydus_anchor, image, rafs_conf)
    rafs.thread_num(4).mount()

    workload_gen = WorkloadGen(nydus_anchor.mount_point, large_file_dir)

    workload_gen.setup_workload_generator()
    workload_gen.torture_read(8, 5)
    workload_gen.finish_torture_read()

    assert not workload_gen.io_error

    rafs.umount()
    image.clean_up()


def test_hardlink(nydus_anchor: NydusAnchor, nydus_scratch_image, rafs_conf: RafsConf):
    dist = Distributor(nydus_scratch_image.rootfs(), 8, 6)
    dist.generate_tree()

    hardlink_verifier = verifier.HardlinkVerifier(nydus_scratch_image.rootfs(), dist)
    hardlink_verifier.scratch()

    nydus_scratch_image.set_backend(Backend.OSS).create_image(clear_from_oss=True)
    rafs_conf.set_rafs_backend(Backend.OSS)
    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.mount()

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_scratch_image.rootfs())

    hardlink_verifier.verify(nydus_anchor.mount_point, nydus_scratch_image.rootfs())

    wg.setup_workload_generator()
    wg.io_read(3)
    nydus_anchor.check_nydusd_health()

    assert wg.io_error == False


def test_meta(
    nydus_anchor: NydusAnchor, rafs_conf: RafsConf, nydus_scratch_image: RafsImage
):
    anchor = nydus_anchor
    rafs_conf.set_rafs_backend(Backend.OSS).enable_rafs_blobcache()
    rafs_conf.dump_rafs_conf()

    dist = Distributor(nydus_scratch_image.rootfs(), 8, 5)
    dist.generate_tree()

    xattr_verifier = verifier.XattrVerifier(anchor.mount_point, dist)
    xattr_verifier.scratch(nydus_scratch_image.rootfs())

    symlink_verifier = verifier.SymlinkVerifier(anchor.mount_point, dist)
    symlink_verifier.scratch()

    # Do some meta operations on scratch dir before creating rafs image file.
    # Use scratch dir as image source dir as we just prepared test meta into it.
    nydus_scratch_image.set_backend(Backend.OSS).create_image(clear_from_oss=True)
    rafs = RafsMount(anchor, nydus_scratch_image, rafs_conf)
    rafs.thread_num(4).mount()
    assert rafs.is_mounted()

    xattr_verifier.verify(anchor.mount_point)
    symlink_verifier.verify(anchor.mount_point, nydus_scratch_image.rootfs())

    workload_gen = WorkloadGen(anchor.mount_point, nydus_scratch_image.rootfs())
    workload_gen.setup_workload_generator()

    workload_gen.torture_read(10, 3)
    workload_gen.finish_torture_read()

    assert workload_gen.io_error == False
    assert anchor.check_nydusd_health()


@pytest.mark.parametrize("backend", [Backend.OSS, Backend.LOCALFS])
def test_file_tail(nydus_anchor: NydusAnchor, nydus_scratch_image: RafsImage, backend):
    """
    description: Read data from file tail
        - Create several files of different sizes
        - Punch hole to each file of which some should have hole tail
        - Create rafs image from test scratch direcotry.
        - Mount rafs
        - Do some test.
    """
    file_size_list = [
        Size(1, Unit.KB),
        Size(6, Unit.KB),
        Size(2, Unit.MB),
        Size(10034, Unit.KB),
    ]
    file_list = []

    dist = Distributor(nydus_anchor.scratch_dir, 2, 2)
    dist.generate_tree()

    for f_s in file_size_list:
        f_name = dist.put_single_file(f_s)
        file_list.append(f_name)
        # Punch hole
        with utils.pushd(nydus_anchor.scratch_dir):
            with open(f_name, "a+b") as f:
                fallocate(
                    f,
                    f_s.B - 500,
                    1000,
                    mode=FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                )

    nydus_scratch_image.set_backend(backend).create_image()

    rafs_conf = RafsConf(nydus_anchor, nydus_scratch_image)
    rafs_conf.set_rafs_backend(backend, image=nydus_scratch_image)

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.mount()

    with utils.pushd(nydus_anchor.mount_point):
        for name in file_list:
            with open(name, "rb") as f:
                size = os.stat(name).st_size
                f.seek(size - 300)
                buf = f.read(1000)
                assert len(buf) == 300

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_scratch_image.rootfs())
    for f in file_list:
        wg.verify_single_file(os.path.join(nydus_anchor.mount_point, f))

    assert wg.io_error == False


def test_deep_direcotry(
    nydus_anchor, rafs_conf: RafsConf, nydus_scratch_image: RafsImage
):

    dist = Distributor(nydus_anchor.scratch_dir, 100, 1)
    dist.generate_tree()

    nydus_scratch_image.set_backend(Backend.OSS).create_image(clear_from_oss=True)

    rafs_conf.set_rafs_backend(Backend.OSS)
    rafs_conf.dump_rafs_conf()

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.mount()

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_scratch_image.rootfs())

    wg.setup_workload_generator()
    wg.torture_read(8, 5)

    wg.finish_torture_read()
    assert wg.verify_entire_fs()


def test_various_file_types(
    nydus_anchor: NydusAnchor, rafs_conf: RafsConf, nydus_scratch_image: RafsImage
):
    """
    description: Put various types of files into rootfs.
        - Regular, dir, char, block, fifo, sock, symlink
    """

    with utils.pushd(nydus_scratch_image.rootfs()):
        fd = os.open("regular", os.O_CREAT | os.O_RDWR)
        os.close(fd)

        os.mkfifo("fifo")
        os.mknod("blk", 0o600 | stat.S_IFBLK, device=random.randint(0, 2 ^ 64))
        os.mknod("char", 0o600 | stat.S_IFCHR, device=random.randint(0, 2 ^ 64))
        os.mknod("sock", 0o600 | stat.S_IFSOCK, device=random.randint(0, 2 ^ 64))
        os.symlink("regular", "symlink")

    nydus_scratch_image.set_backend(Backend.OSS).create_image()
    rafs_conf.set_rafs_backend(Backend.OSS)

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.mount()

    with utils.pushd(nydus_anchor.mount_point):
        assert os.path.exists("fifo")
        assert os.path.exists("blk")
        assert os.path.exists("char")
        assert os.path.exists("sock")
        assert os.path.exists("symlink")

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_scratch_image.rootfs())
    wg.setup_workload_generator()
    assert wg.verify_entire_fs()

    wg.torture_read(2, 4)
    wg.finish_torture_read()


def test_passthough_fs(nydus_anchor, nydus_image, rafs_conf):
    nydus_image.set_backend(Backend.OSS).create_image()
    rafs = RafsMount(nydus_anchor, None, rafs_conf, with_defaults=False)
    rafs.shared_dir(nydus_image.rootfs()).set_mountpoint(
        nydus_anchor.mount_point
    ).apisock("api_sock").mount()

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_image.rootfs())

    wg.setup_workload_generator()
    wg.torture_read(8, 5)
    wg.finish_torture_read()
    assert wg.verify_entire_fs()


def test_pseudo_fs(nydus_anchor, nydus_image, rafs_conf: RafsConf):
    nydus_image.set_backend(Backend.OSS).create_image()

    rafs_conf.set_rafs_backend(Backend.OSS)

    rafs = RafsMount(nydus_anchor, None, rafs_conf)
    rafs.mount()
    time.sleep(1)
    nc = NydusAPIClient(rafs.get_apisock())

    try:
        shutil.rmtree("pseudo_fs_scratch")
    except FileNotFoundError:
        pass

    scratch_rootfs = shutil.copytree(
        nydus_image.rootfs(), "pseudo_fs_scratch", symlinks=True
    )
    dist = Distributor(scratch_rootfs, 5, 5)
    dist.generate_tree()
    dist.put_multiple_files(20, Size(8, Unit.KB))

    ###
    suffix = "1"
    image = RafsImage(
        nydus_anchor,
        scratch_rootfs,
        "bs" + suffix,
        "blob" + suffix,
        clear_from_oss=True,
    )
    conf = RafsConf(nydus_anchor)
    conf.enable_fs_prefetch()
    conf.enable_validation()
    conf.set_rafs_backend(Backend.OSS)
    conf.dump_rafs_conf()

    image.set_backend(Backend.OSS).create_image()
    nc.pseudo_fs_mount(image.bootstrap_path, f"/pseudo{suffix}", conf.path(), None)
    ###
    suffix = "2"
    image = RafsImage(
        nydus_anchor,
        scratch_rootfs,
        "bs" + suffix,
        "blob" + suffix,
        clear_from_oss=True,
    )
    conf = RafsConf(nydus_anchor)
    conf.enable_rafs_blobcache()
    conf.enable_validation()
    conf.enable_records_readahead()
    conf.set_rafs_backend(Backend.OSS)
    conf.dump_rafs_conf()

    dist.put_multiple_files(20, Size(8, Unit.KB))

    image.set_backend(Backend.OSS).create_image()
    nc.pseudo_fs_mount(image.bootstrap_path, f"/pseudo{suffix}", conf.path(), None)
    ###
    suffix = "3"
    image = RafsImage(
        nydus_anchor,
        scratch_rootfs,
        "bs" + suffix,
        "blob" + suffix,
        clear_from_oss=True,
    )
    conf = RafsConf(nydus_anchor)
    conf.enable_rafs_blobcache()
    conf.enable_records_readahead()
    conf.set_rafs_backend(Backend.OSS)
    conf.dump_rafs_conf()

    dist.put_multiple_files(20, Size(8, Unit.KB))

    image.set_backend(Backend.OSS).create_image()
    nc.pseudo_fs_mount(image.bootstrap_path, f"/pseudo{suffix}", conf.path(), None)

    wg1 = WorkloadGen(os.path.join(nydus_anchor.mount_point, "pseudo1"), scratch_rootfs)
    wg2 = WorkloadGen(os.path.join(nydus_anchor.mount_point, "pseudo2"), scratch_rootfs)
    wg3 = WorkloadGen(os.path.join(nydus_anchor.mount_point, "pseudo3"), scratch_rootfs)

    time.sleep(2)
    wg1.setup_workload_generator()
    wg2.setup_workload_generator()
    wg3.setup_workload_generator()

    wg1.torture_read(4, 8)
    wg2.torture_read(4, 8)
    wg3.torture_read(4, 8)

    wg1.finish_torture_read()
    wg2.finish_torture_read()
    wg3.finish_torture_read()

    # TODO: Temporarily disable the verification as hard to select `verify dir`
    # assert wg1.verify_entire_fs()
    # assert wg2.verify_entire_fs()
    # assert wg3.verify_entire_fs()

    nc.umount_rafs("/pseudo1")
    nc.umount_rafs("/pseudo2")
    nc.umount_rafs("/pseudo3")


def test_shared_blobcache(nydus_anchor, nydus_image, rafs_conf: RafsConf):
    """
    description:
        Start more than one nydusd, let them share the same blobcache.
    """
    nydus_image.set_backend(Backend.LOCALFS, blob_dir=()).create_image()
    rafs_conf.enable_rafs_blobcache().set_rafs_backend(Backend.LOCALFS)
    rafs_conf.dump_rafs_conf()

    def make_rafs(mountpoint):
        rafs = (
            RafsMount(nydus_anchor, nydus_image, rafs_conf)
            .apisock(tempfile.NamedTemporaryFile().name)
            .prefetch_files("/")
            .set_mountpoint(mountpoint)
        )
        return rafs

    cases = []
    count = 10

    for num in range(0, count):
        mountpoint = tempfile.TemporaryDirectory(
            dir=nydus_anchor.workspace, suffix="root_" + str(num)
        )
        rafs = make_rafs(mountpoint.name)

        rafs.mount(dump_config=False)
        workload_gen = WorkloadGen(mountpoint.name, nydus_image.rootfs())
        workload_gen.setup_workload_generator()
        cases.append((rafs, workload_gen, mountpoint))

    for case in cases:
        utils.clean_pagecache()
        case[1].torture_read(4, 5)

    for case in cases:
        case[1].finish_torture_read()
        # Ensure that blob & bitmap files are included in blobcache dir.
        assert len(os.listdir(nydus_anchor.blobcache_dir)) == 2

    for case in cases:
        case[0].umount()


# @pytest.mark.skip(reason="ECS can't pass this case!")
@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_signal_handling(
    nydus_anchor: NydusAnchor, nydus_scratch_image: RafsImage, rafs_conf: RafsConf, sig
):

    dist = Distributor(nydus_scratch_image.rootfs(), 2, 2)
    dist.generate_tree()
    dist.put_multiple_files(5, Size(2, Unit.KB))

    nydus_scratch_image.set_backend(Backend.OSS).create_image()

    victim = os.path.join(nydus_anchor.mount_point, dist.files[-1])

    rafs_conf.set_rafs_backend(Backend.OSS)

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.mount()
    fd = os.open(victim, os.O_RDONLY)
    assert rafs.is_mounted()
    os.kill(rafs.p.pid, sig)
    time.sleep(3)

    assert not os.path.ismount(nydus_anchor.mount_point)

    rafs.p.wait()


def test_records_readahead(nydus_anchor, nydus_image):
    nydus_image.set_backend(Backend.OSS).create_image()

    rafs_conf = RafsConf(nydus_anchor, nydus_image)
    rafs_conf.enable_records_readahead(interval=1).set_rafs_backend(
        Backend.LOCALFS, image=nydus_image
    )

    rafs = RafsMount(nydus_anchor, nydus_image, rafs_conf)
    rafs.mount()

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_image.rootfs())

    # TODO: Run several parallel read workers against the mount_point
    wg.setup_workload_generator()
    wg.torture_read(8, 5)
    wg.finish_torture_read()

    rafs.umount()

    utils.clean_pagecache()

    rafs.mount()

    wg.torture_read(8, 5)
    wg.finish_torture_read()


@pytest.mark.parametrize("readahead_policy", ["blob"])
def test_blob_prefetch(
    nydus_anchor: NydusAnchor, nydus_scratch_image: RafsImage, readahead_policy
):
    """
    description:
        For rafs, there are two types of prefetching.
        1. Prefetch files from fs-layer, which means each file is prefetched one by one.
        2. Prefetch directly from backend/blob layer, which means a range will be fetched from blob
    """
    # Try to delete any access log since if it present, bootstrap blob prefetch won't work.
    utils.execute("rm -rf *.access", shell=True)

    dist = Distributor(nydus_scratch_image.rootfs(), 8, 2)
    dist.generate_tree()
    dist.put_directories(20)
    dist.put_multiple_files(100, Size(64, Unit.KB))
    dist.put_symlinks(30)
    dist.put_hardlinks(20)
    dist.put_multiple_files(40, Size(64, Unit.KB))

    utils.clean_pagecache()

    hint_files = dist.files[-40:]
    hint_files.extend(dist.symlinks[-20:])

    hint_files = [os.path.join("/", p) for p in hint_files]
    hint_files = "\n".join(hint_files)

    nydus_scratch_image.set_backend(Backend.LOCALFS).create_image(
        readahead_policy=readahead_policy,
        readahead_files=hint_files.encode(),
    )

    rafs_conf = RafsConf(nydus_anchor, nydus_scratch_image)
    rafs_conf.set_rafs_backend(Backend.LOCALFS, image=nydus_scratch_image)
    rafs_conf.enable_records_readahead(interval=1)
    rafs_conf.dump_rafs_conf()

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    with utils.timer("Mount elapse"):
        rafs.thread_num(7).mount()
    assert rafs.is_mounted()

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_scratch_image.rootfs())

    # TODO: Run several parallel read workers against the mount_point
    wg.setup_workload_generator()
    wg.torture_read(5, 5)
    wg.finish_torture_read()

    utils.clean_pagecache()


@pytest.mark.parametrize("compressor", [Compressor.NONE, Compressor.LZ4_BLOCK])
def test_digest_validate(
    nydus_anchor, rafs_conf: RafsConf, nydus_image: RafsImage, compressor
):

    rafs_conf.set_rafs_backend(Backend.LOCALFS)
    rafs_conf.enable_validation()
    rafs_conf.enable_rafs_blobcache()

    nydus_image.set_backend(Backend.LOCALFS, blob_dir=()).create_image(
        compressor=compressor
    )

    rafs = RafsMount(nydus_anchor, nydus_image, rafs_conf)
    rafs.mount()

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_image.rootfs())
    wg.setup_workload_generator()
    wg.torture_read(5, 5, verify=True)
    wg.finish_torture_read()


@pytest.mark.parametrize("backend", [Backend.OSS])
def test_specified_prefetch(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    nydus_scratch_image: RafsImage,
    backend,
):
    """
    description:
        Nydusd can have a list including files and directories input when started.
        Then it can prefetch files from backend per as to the list.
    """

    rafs_conf.set_rafs_backend(backend)
    rafs_conf.enable_fs_prefetch(prefetch_all=True)
    rafs_conf.enable_rafs_blobcache()
    rafs_conf.dump_rafs_conf()

    dist = Distributor(nydus_scratch_image.rootfs(), 8, 2)
    dist.generate_tree()
    dirs = dist.put_directories(20)
    dist.put_multiple_files(100, Size(64, Unit.KB))
    dist.put_symlinks(30)
    dist.put_hardlinks(20)
    dist.put_multiple_files(40, Size(64, Unit.KB))
    dist.put_single_file(Size(3, Unit.MB), name="test")

    nydus_scratch_image.set_backend(backend).create_image()

    prefetching_files = dirs
    prefetching_files += dist.files[:-10]
    prefetching_files += dist.dirs[:-5]
    prefetching_files += dist.symlinks[:-10]
    # Fuzz
    prefetching_files.append("/a/b/c/d")
    prefetching_files.append(os.path.join("/", "f/g/h/"))

    specified_dirs = " ".join([os.path.join("/", d) for d in prefetching_files])

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.prefetch_files(specified_dirs).mount()
    wg = WorkloadGen(nydus_anchor.mount_point, nydus_scratch_image.rootfs())

    nc = NydusAPIClient(rafs.get_apisock())
    wg.setup_workload_generator()
    blobcache_metrics = nc.get_blobcache_metrics()
    wg.torture_read(5, 10)

    while blobcache_metrics["prefetch_workers"] != 0:
        time.sleep(0.5)
        blobcache_metrics = nc.get_blobcache_metrics()

    begin = nc.get_backend_metrics()["read_amount_total"]
    time.sleep(1)
    end = nc.get_backend_metrics()["read_amount_total"]

    assert end == begin
    wg.finish_torture_read()


def test_build_image_param_blobid(
    nydus_anchor, nydus_image: RafsImage, rafs_conf: RafsConf
):
    """
    description:
        Test if nydus-image argument `--blob-id` works properly
    """
    # More strict id check?
    nydus_image.set_backend(Backend.OSS).set_param(
        "blob-id", uuid.uuid4()
    ).create_image()
    rafs_conf.set_rafs_backend(Backend.OSS)
    rafs = RafsMount(nydus_anchor, nydus_image, rafs_conf)
    rafs.mount()

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_image.rootfs())
    wg.setup_workload_generator()
    wg.torture_read(5, 5)
    wg.finish_torture_read()


@pytest.mark.skipif(
    platform.machine() != "x86_64", reason="Only supported x86 syscalls test"
)
def test_syscalls(
    nydus_anchor: NydusAnchor,
    nydus_scratch_image: RafsImage,
    rafs_conf: RafsConf,
):

    syscall_helper = "framework/test_syscalls"
    ret, _ = utils.execute(
        ["gcc", "framework/test_syscalls.c", "-o", syscall_helper],
        shell=False,
        print_output=True,
    )
    assert ret

    dist = Distributor(nydus_scratch_image.rootfs(), 2, 2)
    dist.generate_tree()
    dist.put_single_file(
        Size(8, Unit.KB), pos=nydus_scratch_image.rootfs(), name="xattr_no_kv"
    )
    dist.put_single_file_with_xattr(
        Size(8, Unit.KB),
        ("trusted.nydus.key", ""),
        pos=nydus_scratch_image.rootfs(),
        name="xattr_empty_value",
    )
    dist.put_single_file_with_xattr(
        Size(8, Unit.KB),
        ("trusted.nydus.key", "1234567890"),
        pos=nydus_scratch_image.rootfs(),
        name="xattr_insufficient_buffer",
    )

    nydus_scratch_image.set_backend(Backend.OSS).create_image()

    rafs_conf.enable_xattr().set_rafs_backend(Backend.OSS)
    rafs_conf.dump_rafs_conf()

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.mount()

    for no in [58]:
        ret, _ = utils.execute(
            [syscall_helper, nydus_anchor.mount_point, str(no)],
            shell=False,
            print_output=True,
        )
        assert ret


def test_blobcache_recovery(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    nydus_scratch_image: RafsImage,
):
    rafs_conf.set_rafs_backend(Backend.OSS)
    rafs_conf.enable_fs_prefetch()
    rafs_conf.enable_rafs_blobcache()
    rafs_conf.dump_rafs_conf()

    dist = Distributor(nydus_scratch_image.rootfs(), 8, 2)
    dist.generate_tree()
    dirs = dist.put_directories(20)
    dist.put_multiple_files(100, Size(64, Unit.KB))
    dist.put_symlinks(30)
    dist.put_hardlinks(20)
    dist.put_multiple_files(40, Size(64, Unit.KB))
    dist.put_single_file(Size(3, Unit.MB), name="test")

    nydus_scratch_image.set_backend(Backend.OSS).create_image()

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.prefetch_files("/").mount()
    wg = WorkloadGen(nydus_anchor.mount_point, nydus_scratch_image.rootfs())

    wg.setup_workload_generator()
    wg.torture_read(4, 4)

    # Hopefully, prefetch can be done in 5 secondes.
    time.sleep(5)

    wg.finish_torture_read()
    rafs.umount()

    rafs2 = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs2.mount()

    wg.torture_read(4, 4)
    time.sleep(0.5)

    nc = NydusAPIClient(rafs2.get_apisock())

    begin = nc.get_backend_metrics()["read_amount_total"]
    time.sleep(1)
    end = nc.get_backend_metrics()["read_amount_total"]

    assert end == begin == 0

    wg.finish_torture_read()
