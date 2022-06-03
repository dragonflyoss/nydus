import os
import utils
from utils import Size, Unit
import pytest
from workload_gen import WorkloadGen
from nydus_anchor import NydusAnchor
from rafs import RafsConf, RafsImage, RafsMount, Compressor


@pytest.mark.parametrize("compressor", [Compressor.NONE, Compressor.LZ4_BLOCK])
@pytest.mark.parametrize("backend", ["oss", "localfs"])
def test_blobcache(
    nydus_anchor: NydusAnchor,
    nydus_image: RafsImage,
    rafs_conf: RafsConf,
    compressor,
    backend,
):
    """
    Allocate a file with local test working directory.
    Loop the file so to get a small file system which is easy to get full.
    Change blob cache location the above test blobdir
    """

    blobdir = "/blobdir"

    blob_backend = "blob_backend"
    fd = os.open(blob_backend, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    os.posix_fallocate(fd, 0, 1024 * 1024 * 4)
    os.close(fd)

    utils.execute(["mkfs.ext4", "-F", blob_backend])
    utils.execute(["mount", blob_backend, blobdir])

    rafs_conf.enable_rafs_blobcache()
    rafs_conf.set_rafs_backend(backend)
    rafs_conf.dump_rafs_conf()

    cache_file = os.listdir(blobdir)
    assert len(cache_file) == 1

    rafs = RafsMount(nydus_anchor, nydus_image, rafs_conf)
    rafs.mount()
    assert rafs.is_mounted()

    workload_gen = WorkloadGen(nydus_anchor.mount_point, nydus_anchor.source_dir)

    workload_gen.setup_workload_generator()
    workload_gen.torture_read(4, 15)

    nydus_anchor.start_stats_checker()
    workload_gen.finish_torture_read()
    nydus_anchor.stop_stats_checker()

    cache_file = os.listdir(blobdir)
    assert len(cache_file) >= 2

    if workload_gen.io_error:
        warnings.warn(UserWarning("Rafs will return EIO if blobcache file is full"))

    rafs.umount()

    ret, _ = utils.execute(["umount", blobdir])
    assert ret

    os.unlink(blob_backend)


def test_limited_mem(nydus_anchor, rafs_conf, nydus_image):
    """
    description: Run nydusd in a memory limited environment.
        - Use `ulimit` to limit virtual memory nydusd can use.
        - Mount rafs
        - Torture rafs
    """

    rafs_conf.enable_rafs_blobcache()
    rafs_conf.dump_rafs_conf()

    rafs = RafsMount(nydus_anchor, nydus_image, rafs_conf)
    rafs.mount(limited_mem=Size(3, Unit.GB))

    wg = WorkloadGen(nydus_anchor.mount_point, nydus_image.rootfs())

    wg.setup_workload_generator()
    wg.torture_read(8, 10)

    nydus_anchor.start_stats_checker()
    wg.finish_torture_read()
    nydus_anchor.stop_stats_checker()

    assert wg.io_error == False
    assert nydus_anchor.check_nydusd_health()
