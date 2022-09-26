from nydus_anchor import NydusAnchor
from rafs import NydusDaemon, RafsImage, BlobEntryConf, Backend
import pytest
import uuid
from erofs import Erofs
from nydusd_client import NydusAPIClient
import time
from workload_gen import WorkloadGen
from distributor import Distributor
import random
from utils import logging_setup, Size, Unit


logging_setup()


def test_basic(nydus_anchor: NydusAnchor, nydus_image: RafsImage):

    nydus_image.set_backend(Backend.BACKEND_PROXY).create_image()
    daemon = NydusDaemon(nydus_anchor, None, None, mode="singleton")
    daemon.set_fscache().start()

    nc = NydusAPIClient(daemon.get_apisock())

    fsid = str(uuid.uuid4())

    blob_conf = (
        BlobEntryConf(nydus_anchor)
        .set_type("bootstrap")
        .set_metadata_path(nydus_image.bootstrap_path)
        .set_fsid(fsid)
        .set_backend()
    )
    time.sleep(1)
    nc.bind_fscache_blob(blob_conf)

    erofs = Erofs()
    erofs.mount(fsid=fsid, mountpoint=nydus_anchor.mountpoint)

    workload_gen = WorkloadGen(nydus_anchor.mountpoint, nydus_image.rootfs())
    workload_gen.setup_workload_generator()
    workload_gen.torture_read(4, 10)
    workload_gen.finish_torture_read()
    assert not workload_gen.io_error


def test_prefetch(nydus_anchor: NydusAnchor, nydus_scratch_image: RafsImage):
    dist = Distributor(nydus_scratch_image.rootfs(), 4, 4)
    dist.generate_tree()
    dist.put_directories(20)
    dist.put_multiple_files(40, Size(3, Unit.MB))
    dist.put_hardlinks(6)
    dist.put_multiple_chinese_files(random.randint(20, 28), Size(20, Unit.KB))

    nydus_scratch_image.set_backend(Backend.BACKEND_PROXY).create_image()

    daemon = NydusDaemon(nydus_anchor, None, None, mode="singleton")
    daemon.set_fscache().start()

    time.sleep(1)

    nc = NydusAPIClient(daemon.get_apisock())
    fsid = str(uuid.uuid4())

    blob_conf = (
        BlobEntryConf(nydus_anchor)
        .set_type("bootstrap")
        .set_metadata_path(nydus_scratch_image.bootstrap_path)
        .set_fsid(fsid)
        .set_backend()
        .set_prefetch()
    )

    nc.bind_fscache_blob(blob_conf)

    erofs = Erofs()
    erofs.mount(fsid=fsid, mountpoint=nydus_anchor.mountpoint)

    workload_gen = WorkloadGen(nydus_anchor.mountpoint, nydus_scratch_image.rootfs())

    workload_gen.setup_workload_generator()
    workload_gen.torture_read(4, 10)

    workload_gen.finish_torture_read()

    assert workload_gen.verify_entire_fs()

    assert not workload_gen.io_error
