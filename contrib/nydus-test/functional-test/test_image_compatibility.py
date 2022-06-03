import os

import pytest
from rafs import RafsMount, RafsConf, RafsImage, Backend, Compressor
from nydus_anchor import NydusAnchor
from workload_gen import WorkloadGen
from distributor import Distributor
from utils import Size, Unit
import random
from nydusd_client import NydusAPIClient
import time


@pytest.mark.parametrize("thread_cnt", [4])
@pytest.mark.parametrize("compressor", [Compressor.LZ4_BLOCK, Compressor.NONE])
@pytest.mark.parametrize("is_cache_compressed", [False])
@pytest.mark.parametrize(
    "converter",
    [
        "framework/bin/nydus-image-1.3.0",
        "framework/bin/nydus-image-1.5.0",
        "framework/bin/nydus-image-1.6.3",
    ],
)
@pytest.mark.parametrize("items", [("enable_validation",), ()])
def test_prefetch_with_cache(
    nydus_anchor,
    nydus_scratch_image: RafsImage,
    rafs_conf: RafsConf,
    thread_cnt,
    compressor,
    is_cache_compressed,
    converter,
    items,
):
    """
    title: Prefetch from various backend
    description:
      - Enable rafs backend blob cache, as it is disabled by default
    pass_criteria:
      - Rafs can be mounted.
      - Rafs can be unmounted.
    """

    dist = Distributor(nydus_scratch_image.rootfs(), 4, 4)
    dist.generate_tree()
    dist.put_directories(20)
    dist.put_multiple_files(40, Size(3, Unit.MB))
    dist.put_multiple_files(10, Size(5, Unit.MB))
    dist.put_hardlinks(6)
    dist.put_multiple_chinese_files(random.randint(20, 28), Size(20, Unit.KB))

    nydus_scratch_image.set_backend(Backend.LOCALFS).create_image(
        image_bin=converter,
        compressor=compressor,
        readahead_policy="fs",
        readahead_files="/".encode(),
    )

    rafs_conf.enable_rafs_blobcache(
        is_compressed=is_cache_compressed
    ).enable_fs_prefetch()
    rafs_conf.set_rafs_backend(Backend.LOCALFS, image=nydus_scratch_image)

    if len(items) > 0:
        for i in items:
            item = RafsConf.__dict__[i]
            item(rafs_conf)

    rafs = RafsMount(nydus_anchor, nydus_scratch_image, rafs_conf)
    rafs.thread_num(6).mount()

    nc = NydusAPIClient(rafs.get_apisock())
    workload_gen = WorkloadGen(nydus_anchor.mount_point, nydus_scratch_image.rootfs())
    m = nc.get_blobcache_metrics()
    time.sleep(0.3)
    assert m["prefetch_data_amount"] != 0

    workload_gen.verify_entire_fs()

    workload_gen.setup_workload_generator()
    workload_gen.torture_read(thread_cnt, 6)

    assert NydusAnchor.check_nydusd_health()

    workload_gen.finish_torture_read()
    assert not workload_gen.io_error