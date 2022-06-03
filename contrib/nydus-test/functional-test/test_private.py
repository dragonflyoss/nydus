from conftest import ANCHOR
import posixpath
import pytest
from nydusify import Nydusify
from rafs import RafsMount, RafsConf, Backend
from nydus_anchor import NydusAnchor
from workload_gen import WorkloadGen

from utils import read_images_array

REGISTRY_ADDR = "https://docker.alibaba-inc.com/#/imageList"


IMAGE_ARRAY = ANCHOR.images_array


@pytest.mark.parametrize("source", IMAGE_ARRAY)
def test_nydusify(
    nydus_anchor: NydusAnchor, rafs_conf: RafsConf, source, nydusify_converter
):
    converter = Nydusify(nydus_anchor)

    converter.docker_v2().convert(source)
    layers, base = converter.extract_source_layers_names_and_download()
    nydus_anchor.mount_overlayfs(layers, base)

    rafs_conf.set_rafs_backend(
        Backend.REGTISTRY, repo=posixpath.basename(source).split(":")[0]
    )
    rafs_conf.enable_fs_prefetch()
    rafs_conf.enable_rafs_blobcache()
    rafs_conf.dump_rafs_conf()

    bootstrap = converter.locate_bootstrap()

    rafs = RafsMount(nydus_anchor, None, rafs_conf)

    workload_gen = WorkloadGen(nydus_anchor.mount_point, nydus_anchor.overlayfs)
    rafs.thread_num(6).bootstrap(bootstrap).prefetch_files("/").mount()

    assert workload_gen.verify_entire_fs()
    workload_gen.setup_workload_generator()
    workload_gen.torture_read(8, 12, verify=True)
    workload_gen.finish_torture_read()