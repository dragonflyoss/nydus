import pytest
from rafs import RafsMount, RafsConf, RafsImage, Backend, Compressor
from nydus_anchor import NydusAnchor
from workload_gen import WorkloadGen
from distributor import Distributor
from utils import logging_setup, Size, Unit
import verifier
import random
from nydusd_client import NydusAPIClient
import time
import shutil
import utils
import uuid


logging_setup()


def test_stargz(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    nydus_scratch_image: RafsImage,
):
    """
    Example command:
        stargzify file:`pwd`/foo.tar.gz foo.stargz

    """
    intermediator = "tmp.tar.gz"
    stargz_image = "tmp.stargz"

    dist = Distributor(nydus_scratch_image.rootfs(), 4, 4)
    dist.generate_tree()
    dirs = dist.put_directories(20)
    dist.put_multiple_files(100, Size(64, Unit.KB))
    dist.put_symlinks(30)
    dist.put_multiple_files(10, Size(4, Unit.MB))
    dist.put_hardlinks(20)
    dist.put_single_file(Size(3, Unit.MB), name="test")
    try:
        shutil.rmtree("origin")
    except Exception:
        pass
    shutil.copytree(nydus_scratch_image.rootfs(), "origin", symlinks=True)
    utils.write_tar_gz(nydus_scratch_image.rootfs(), intermediator)

    cmd = ["framework/bin/stargzify", f"file:{intermediator}", stargz_image]
    utils.execute(cmd)

    toc = utils.parse_stargz(stargz_image)
    image = RafsImage(
        nydus_anchor,
        toc,
        "boostrap_scratched",
        "blob_scratched",
        clear_from_oss=True,
    )

    # This is a trick since blob name is usually a temp file created when RafsImage instantiated.
    # framework will upload stargz to oss.
    image.blob_abs_path = stargz_image
    image.set_backend(Backend.OSS).set_param("blob-id", uuid.uuid4()).create_image(
        from_stargz=True
    )

    rafs_conf.set_rafs_backend(Backend.OSS)
    rafs_conf.enable_rafs_blobcache(is_compressed=True)

    rafs = RafsMount(nydus_anchor, image, rafs_conf)
    rafs.mount()

    wg = WorkloadGen(nydus_anchor.mount_point, "origin")

    wg.verify_entire_fs()

    wg.setup_workload_generator()
    wg.torture_read(4, 4)

    wg.finish_torture_read()
    assert not wg.io_error