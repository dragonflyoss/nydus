from nydus_anchor import NydusAnchor
from rafs import NydusDaemon, RafsImage, BlobEntryConf, Backend
import pytest
import uuid
from erofs import Erofs
from nydusd_client import NydusAPIClient
import time
from workload_gen import WorkloadGen
from utils import logging_setup


logging_setup()


def test_basic(nydus_anchor: NydusAnchor, nydus_image: RafsImage):

    nydus_image.set_backend(Backend.BACKEND_PROXY).create_image()

    daemon = NydusDaemon(nydus_anchor, None, None, mode="daemon")
    daemon.set_fscache().start()

    nc = NydusAPIClient(daemon.get_apisock())

    fsid = str(uuid.uuid4())

    time.sleep(2)

    blob_conf = (
        BlobEntryConf(nydus_anchor)
        .set_type("bootstrap")
        .set_metadata_path(nydus_image.bootstrap_path)
        .set_fsid(fsid)
        .set_backend()
    )

    nc.bind_fscache_blob(blob_conf)

    erofs = Erofs()
    erofs.mount(fsid=fsid, mountpoint=nydus_anchor.mountpoint)

    workload_gen = WorkloadGen(nydus_anchor.mountpoint, nydus_image.rootfs())
    time.sleep(0.5)

    workload_gen.setup_workload_generator()
    workload_gen.torture_read(4, 10)

    workload_gen.finish_torture_read()
    assert not workload_gen.io_error
