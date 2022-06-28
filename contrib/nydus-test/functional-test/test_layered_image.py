import utils
from utils import logging_setup, Size, Unit
import pytest
from rafs import *
from workload_gen import WorkloadGen
from nydus_anchor import *
from distributor import Distributor
from verifier import XattrVerifier
from random import randint
import os
from nydusd_client import NydusAPIClient
from whiteout import WhiteoutSpec, Whiteout

logging_setup()


def test_verify_layers_images(nydus_anchor: NydusAnchor):
    """
    title: Verify if new image on top of parent image is properly built
    description: Use debugfs.rafs tool to inspect if new image is correct.
                 No need to mount rafs in this case.
    """
    pass


def test_basic_read(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    nydus_image: RafsImage,
    nydus_parent_image: RafsImage,
):
    """
    title: Build an image from parent image.
    description: Mount rafs to check if can act read correctly.
    """

    nydus_parent_image.set_backend(Backend.OSS).create_image()
    nydus_image.set_backend(Backend.OSS).create_image(parent_image=nydus_parent_image)

    nydus_anchor.mount_overlayfs([nydus_image.rootfs(), nydus_parent_image.rootfs()])

    rafs_conf.enable_rafs_blobcache().set_rafs_backend(Backend.OSS)
    rafs_conf.dump_rafs_conf()

    rafs = RafsMount(nydus_anchor, nydus_image, rafs_conf)
    rafs.mount()

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_anchor.overlayfs)
    wg.setup_workload_generator()

    wg.io_read(5)
    assert wg.verify_entire_fs()

    assert wg.io_error == False


def test_read_stress(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    nydus_image: RafsImage,
    nydus_parent_image: RafsImage,
):

    nydus_parent_image.set_backend(Backend.OSS).create_image()
    nydus_image.set_backend(Backend.OSS).create_image(parent_image=nydus_parent_image)

    nydus_anchor.mount_overlayfs([nydus_image.rootfs(), nydus_parent_image.rootfs()])

    rafs_conf.enable_rafs_blobcache().set_rafs_backend(Backend.OSS)
    rafs_conf.dump_rafs_conf()

    rafs = RafsMount(nydus_anchor, nydus_image, rafs_conf)
    rafs.thread_num(4).mount()

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_anchor.overlayfs)
    wg.setup_workload_generator()

    wg.torture_read(8, 10)
    wg.finish_torture_read()

    assert wg.io_error == False


def test_read_cache(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    nydus_image: RafsImage,
    nydus_parent_image: RafsImage,
):

    nydus_parent_image.set_backend(Backend.OSS).create_image()
    nydus_image.set_backend(Backend.OSS).create_image(parent_image=nydus_parent_image)

    nydus_anchor.mount_overlayfs([nydus_image.rootfs(), nydus_parent_image.rootfs()])

    rafs_conf.enable_rafs_blobcache().set_rafs_backend(Backend.OSS)
    rafs_conf.dump_rafs_conf()

    rafs = RafsMount(nydus_anchor, nydus_image, rafs_conf)
    rafs.mount()

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_anchor.overlayfs)
    wg.setup_workload_generator()

    wg.torture_read(12, 10)
    wg.finish_torture_read()

    assert wg.verify_entire_fs()


@pytest.mark.parametrize("thread_cnt", [5])
@pytest.mark.parametrize("io_duration", [5])
def test_blobcache(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    nydus_image: RafsImage,
    nydus_scratch_parent_image: RafsImage,
    thread_cnt,
    io_duration,
):
    dist_parent = Distributor(nydus_scratch_parent_image.rootfs(), 6, 4)
    dist_parent.generate_tree()
    dist_parent.put_multiple_files(20, Size(4, Unit.KB))

    hint_files_parent = [os.path.join("/", p) for p in dist_parent.files[-20:]]
    hint_files_parent = "\n".join(hint_files_parent[-1:])

    nydus_scratch_parent_image.set_backend(Backend.OSS).create_image()
    # shutil.rmtree(nydus_scratch_parent_image.rootfs())
    nydus_image.set_backend(Backend.OSS).create_image(
        readahead_policy="fs",
        parent_image=nydus_scratch_parent_image,
        readahead_files=hint_files_parent.encode(),
    )

    nydus_anchor.mount_overlayfs(
        [nydus_image.rootfs(), nydus_scratch_parent_image.rootfs()]
    )

    rafs_conf.enable_rafs_blobcache().set_rafs_backend(Backend.OSS)
    rafs_conf.enable_fs_prefetch()
    rafs_conf.dump_rafs_conf()

    rafs = RafsMount(nydus_anchor, nydus_image, rafs_conf)
    rafs.thread_num(4).mount()

    nc = NydusAPIClient(rafs.get_apisock())
    m = nc.get_blobcache_metrics()
    # TODO: Open this check when prefetch is fixed.
    time.sleep(1)
    assert m["prefetch_data_amount"] != 0

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_anchor.overlayfs)
    wg.setup_workload_generator()

    wg.torture_read(thread_cnt, io_duration)
    wg.finish_torture_read()


@pytest.mark.parametrize("backend", [Backend.OSS])
def test_layered_rebuild(
    nydus_anchor,
    nydus_scratch_image: RafsImage,
    nydus_scratch_parent_image: RafsImage,
    rafs_conf: RafsConf,
    backend,
):
    """
    title: Layered image rebuild
        description:
            - Parent and upper have files whose contents are exactly the same.
            - Use files stats to check if file is overlayed.
            - Files with the same name but different modes.
            - Files with xattr in parent should be shadowed.
        pass_criteria:
          - Mount successfully.
          - No data corruption.
    """
    rafs_conf.set_rafs_backend(backend)
    rafs_conf.enable_rafs_blobcache()
    rafs_conf.dump_rafs_conf()

    parent_rootfs = nydus_scratch_parent_image.rootfs()
    upper_rootfs = nydus_scratch_image.rootfs()

    nydus_anchor.mount_overlayfs(
        [nydus_scratch_image.rootfs(), nydus_scratch_parent_image.rootfs()]
    )

    shared_files = []

    dist_parent = Distributor(parent_rootfs, 6, 4)
    dist_parent.generate_tree()
    shared_files.extend(dist_parent.put_multiple_files(100, Size(64, Unit.KB)))
    shared_files.extend(dist_parent.put_symlinks(30))
    shared_files.extend(dist_parent.put_hardlinks(30))
    xattr_verifier = XattrVerifier(parent_rootfs, dist_parent)
    Whiteout.mirror_files(shared_files, parent_rootfs, upper_rootfs)

    xattr_verifier.scratch(parent_rootfs)

    nydus_scratch_parent_image.set_backend(backend).create_image()
    nydus_scratch_image.set_backend(backend).create_image(
        parent_image=nydus_scratch_parent_image
    )

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.mount()

    workload_gen = WorkloadGen(nydus_anchor.mount_point, nydus_anchor.overlayfs)
    workload_gen.setup_workload_generator()

    xattr_verifier.verify(nydus_anchor.mount_point)

    assert workload_gen.verify_entire_fs()
    workload_gen.torture_read(5, 4)

    workload_gen.finish_torture_read()


def test_layered_localfs(
    nydus_anchor, nydus_scratch_image: RafsImage, nydus_scratch_parent_image: RafsImage
):
    nydus_scratch_parent_image.set_backend(Backend.LOCALFS, blob_dir=()).create_image()
    nydus_scratch_image.set_backend(Backend.LOCALFS, blob_dir=()).create_image(
        parent_image=nydus_scratch_parent_image
    )

    nydus_anchor.mount_overlayfs(
        [nydus_scratch_image.rootfs(), nydus_scratch_parent_image.rootfs()]
    )

    rafs_conf = RafsConf(nydus_anchor).set_rafs_backend(Backend.LOCALFS)

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.mount()

    workload_gen = WorkloadGen(nydus_anchor.mount_point, nydus_anchor.overlayfs)
    workload_gen.setup_workload_generator()

    assert workload_gen.verify_entire_fs()
    workload_gen.torture_read(5, 4)

    workload_gen.finish_torture_read()


@pytest.mark.parametrize("whiteout_spec", [WhiteoutSpec.OCI, WhiteoutSpec.OVERLAY])
def test_whiteout(nydus_anchor, rafs_conf, whiteout_spec):
    _td_1 = tempfile.TemporaryDirectory(dir=nydus_anchor.workspace)
    _td_2 = tempfile.TemporaryDirectory(dir=nydus_anchor.workspace)
    parent_rootfs = _td_1.name
    upper_rootfs = _td_2.name

    whiteout = Whiteout(whiteout_spec)

    parent_image = RafsImage(nydus_anchor, parent_rootfs, "parent_bs", "parent_blob")

    dist_parent = Distributor(parent_rootfs, 6, 4)
    dist_parent.generate_tree()
    dist_parent.put_directories(20)
    dist_parent.put_multiple_files(50, Size(32, Unit.KB))
    dist_parent.put_symlinks(30)
    dist_parent.put_hardlinks(20)

    to_be_removed = dist_parent.put_single_file(Size(7, Unit.KB))

    layered_image = RafsImage(nydus_anchor, upper_rootfs, "bs", "blob")

    dist_upper = Distributor(upper_rootfs, 3, 5)
    dist_upper.generate_tree()
    dist_upper.put_multiple_files(27, Size(3, Unit.MB))
    dist_upper.put_symlinks(5)

    # `to_be_removed` should look like `a/b/c`
    whiteout.whiteout_one_file(upper_rootfs, to_be_removed)
    # Put a whiteout file that does not hide any file from lower layer
    whiteout.whiteout_one_file(upper_rootfs, "i/am/troublemaker/foo")

    dir_to_be_whiteout_opaque = dist_parent.dirs[randint(0, len(dist_parent.dirs) - 1)]
    # `dir_to_be_removed` should look like `a/b/c`
    whiteout.whiteout_opaque_directory(upper_rootfs, dir_to_be_whiteout_opaque)

    dist_parent.put_directories(1)
    dir_to_be_removed = dist_parent.dirs[-1]
    whiteout.whiteout_one_dir(upper_rootfs, dir_to_be_removed)

    parent_image.set_backend(Backend.OSS).create_image()
    layered_image.set_backend(Backend.OSS).whiteout_spec(whiteout_spec).create_image(
        parent_image=parent_image
    )

    rafs_conf.set_rafs_backend(Backend.OSS)

    nydus_anchor.mount_overlayfs([layered_image.rootfs(), parent_image.rootfs()])
    rafs = RafsMount(nydus_anchor, layered_image, rafs_conf)
    rafs.mount()

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_anchor.overlayfs)

    assert not os.path.exists(os.path.join(nydus_anchor.mount_point, to_be_removed))
    assert not os.path.exists(os.path.join(nydus_anchor.mount_point, dir_to_be_removed))

    files_under_opaque_dir = os.listdir(
        os.path.join(nydus_anchor.mount_point, dir_to_be_whiteout_opaque)
    )

    # If opaque dir has files, only file from lower layer will be hidden.
    if len(files_under_opaque_dir) != 0:
        upper_files = os.listdir(os.path.join(upper_rootfs, dir_to_be_whiteout_opaque))
        for f in files_under_opaque_dir:
            assert f in upper_files

    assert wg.verify_entire_fs()


def test_prefetch_with_cache(
    nydus_anchor: NydusAnchor,
    nydus_scratch_image: RafsImage,
    nydus_scratch_parent_image: RafsImage,
    rafs_conf: RafsConf,
):
    parent_rootfs = nydus_scratch_parent_image.rootfs()
    upper_rootfs = nydus_scratch_image.rootfs()

    rafs_conf.enable_validation()
    rafs_conf.set_rafs_backend(Backend.OSS)
    rafs_conf.enable_rafs_blobcache()
    rafs_conf.enable_fs_prefetch(threads_count=4, merging_size=512 * 1024)
    rafs_conf.dump_rafs_conf()

    dist_parent = Distributor(parent_rootfs, 6, 4)
    dist_parent.generate_tree()
    dist_parent.put_directories(20)
    dist_parent.put_multiple_files(100, Size(64, Unit.KB))
    dist_parent.put_symlinks(30)
    dist_parent.put_hardlinks(20)

    dist_upper = Distributor(upper_rootfs, 3, 8)
    dist_upper.generate_tree()
    dist_upper.put_multiple_files(27, Size(3, Unit.MB))
    dist_upper.put_symlinks(5)

    # hint_files_parent = dist_parent.put_multiple_files(1000, Size(8, Unit.KB))
    # hint_files_parent = [os.path.join(parent_rootfs, p) for p in hint_files_parent]
    # hint_files_parent = "\n".join(hint_files_parent)

    nydus_scratch_parent_image.set_backend(Backend.OSS).create_image(
        readahead_policy="fs", readahead_files="/".encode()
    )

    hint_files = dist_upper.put_multiple_files(1000, Size(8, Unit.KB))
    hint_files.extend(dist_upper.put_multiple_empty_files(200))

    hint_files = [os.path.join("/", p) for p in hint_files]
    hint_files = "\n".join(hint_files)

    nydus_scratch_image.set_backend(Backend.OSS).create_image(
        parent_image=nydus_scratch_parent_image,
        readahead_policy="fs",
        readahead_files=hint_files.encode(),
    )

    nydus_anchor.mount_overlayfs(
        [nydus_scratch_image.rootfs(), nydus_scratch_parent_image.rootfs()]
    )

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.thread_num(5).mount()

    workload_gen = WorkloadGen(nydus_anchor.mount_point, nydus_anchor.overlayfs)
    workload_gen.setup_workload_generator()

    assert workload_gen.verify_entire_fs()
    workload_gen.torture_read(5, 20)
    workload_gen.finish_torture_read()


def test_different_partitions(nydus_anchor: NydusAnchor, rafs_conf):
    loop_file_1 = tempfile.NamedTemporaryFile(suffix="loop")
    loop_file_2 = tempfile.NamedTemporaryFile(suffix="loop")
    loop_mnt_1 = tempfile.TemporaryDirectory(dir=nydus_anchor.workspace)
    loop_mnt_2 = tempfile.TemporaryDirectory(dir=nydus_anchor.workspace)

    os.posix_fallocate(loop_file_1.fileno(), 0, Size(400, Unit.MB).B)
    os.posix_fallocate(loop_file_2.fileno(), 0, Size(400, Unit.MB).B)

    utils.execute(["mkfs.ext4", "-F", loop_file_1.name])
    utils.execute(["mkfs.ext4", "-F", loop_file_2.name])
    utils.execute(["mount", loop_file_1.name, loop_mnt_1.name])
    utils.execute(["mount", loop_file_2.name, loop_mnt_2.name])

    # TODO: Put more special files into
    dist1 = Distributor(loop_mnt_1.name, 5, 7)
    dist1.generate_tree()
    dist1.put_multiple_files(100, Size(12, Unit.KB))

    dist2 = Distributor(loop_mnt_2.name, 5, 7)
    dist2.generate_tree()
    dist2.put_symlinks(20)
    dist2.put_multiple_files(50, Size(12, Unit.KB))

    Whiteout.mirror_files(dist2.files[:20], loop_mnt_2.name, loop_mnt_1.name)

    parent_image = (
        RafsImage(nydus_anchor, loop_mnt_1.name).set_backend(Backend.OSS).create_image()
    )

    image = RafsImage(nydus_anchor, loop_mnt_2.name)
    image.set_backend(Backend.OSS).create_image(parent_image=parent_image)

    rafs_conf.set_rafs_backend(Backend.OSS)
    rafs = RafsMount(nydus_anchor, image, rafs_conf)
    rafs.mount()

    nydus_anchor.mount_overlayfs([image.rootfs(), parent_image.rootfs()])

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_anchor.overlayfs)
    wg.setup_workload_generator()
    wg.torture_read(5, 5)
    wg.finish_torture_read()

    utils.execute(["umount", loop_mnt_1.name])
    utils.execute(["umount", loop_mnt_2.name])

    nydus_anchor.umount_overlayfs()
