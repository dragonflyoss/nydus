import pytest
import time
from nydus_anchor import NydusAnchor
from snapshotter import Snapshotter
from containerd import Containerd
from rafs import RafsConf, Backend
from cri import Cri
from nydusify import Nydusify
import uuid
import signal
import utils

ANCHOR = NydusAnchor()


SNAPSHOTTER_IMAGE_ARRAY = ANCHOR.images_array


@pytest.mark.parametrize("image_url", SNAPSHOTTER_IMAGE_ARRAY)
def test_snapshotter(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    image_url,
    nydus_snapshotter,
    local_registry,
):
    snapshotter = Snapshotter(nydus_anchor)
    containerd = Containerd(nydus_anchor, snapshotter).gen_config()
    snapshotter.set_root(containerd.root)

    nydus_anchor.put_dustbin(snapshotter)
    nydus_anchor.put_dustbin(containerd)

    converter = Nydusify(nydus_anchor)
    converter.docker_v2().convert(image_url)

    rafs_conf.set_rafs_backend(Backend.REGTISTRY, repo=converter.original_repo)
    rafs_conf.enable_xattr()
    rafs_conf.dump_rafs_conf()

    snapshotter.run(rafs_conf.path())
    time.sleep(1)
    containerd.run()

    cri = Cri(containerd.address, containerd.address)
    container_name = str(uuid.uuid4())
    cri.run_container(converter.converted_image, container_name)
    id, status = cri.check_container_status(container_name, timeout=30)
    assert id is not None
    assert status
    cri.stop_rm_container(id)
    cri.remove_image(converter.converted_image)
    containerd.remove_image_sync(converter.converted_image)


@pytest.mark.parametrize(
    "converted_images",
    [
        (
            "reg.docker.alibaba-inc.com/chge-nydus-test/python:3.8_converted",
            "reg.docker.alibaba-inc.com/chge-nydus-test/python:3.5_converted",
        )
    ],
)
def test_snapshotter_converted_images(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    converted_images,
    nydus_snapshotter,
):
    # snapshotter = Snapshotter(nydus_anchor).enable_nydus_overlayfs()
    snapshotter = Snapshotter(nydus_anchor)
    containerd = Containerd(nydus_anchor, snapshotter).gen_config()
    snapshotter.set_root(containerd.root)

    nydus_anchor.put_dustbin(snapshotter)
    nydus_anchor.put_dustbin(containerd)

    # We can safely pass the step provide repo configured into the rafs configuration file.
    rafs_conf.set_rafs_backend(Backend.REGTISTRY, scheme="https")
    rafs_conf.enable_xattr()
    rafs_conf.dump_rafs_conf()

    snapshotter.run(rafs_conf.path())
    time.sleep(1)
    containerd.run()
    cri = Cri(containerd.address, containerd.address)

    id_set = []
    for ref in converted_images:
        container_name = str(uuid.uuid4())
        cri.run_container(ref, container_name)
        id, status = cri.check_container_status(container_name, timeout=30)
        assert id is not None
        assert status
        id_set.append((id, ref))
        time.sleep(2)

    for id, ref in id_set:
        cri.stop_rm_container(id)
        cri.remove_image(ref)
        containerd.remove_image_sync(ref)

    # TODO: Rafs won't be unmounted and and nydusd still be alive even image is removed locally
    # So kill all nydusd here to make fowllowing test verification pass. Is this a bug?

    # Ensure nydusd must have been stopped here
    time.sleep(3)


@pytest.mark.skip(reason="Restart can't take over running nydusd")
@pytest.mark.parametrize(
    "converted_images",
    [
        (
            "reg.docker.alibaba-inc.com/chge-nydus-test/python:3.8_converted",
            "reg.docker.alibaba-inc.com/chge-nydus-test/python:3.5_converted",
        )
    ],
)
def test_snapshotter_restart(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    converted_images,
    nydus_snapshotter,
):
    snapshotter = Snapshotter(nydus_anchor)
    containerd = Containerd(nydus_anchor, snapshotter).gen_config()
    snapshotter.set_root(containerd.root)

    nydus_anchor.put_dustbin(containerd)

    # We can safely pass the step provide repo configured into the rafs configuration file.
    rafs_conf.set_rafs_backend(Backend.REGTISTRY, scheme="https")
    rafs_conf.enable_xattr().enable_fs_prefetch().enable_rafs_blobcache(
        work_dir=snapshotter.cache_dir()
    )
    rafs_conf.enable_xattr().dump_rafs_conf()
    rafs_conf.dump_rafs_conf()

    snapshotter.run(rafs_conf.path())
    time.sleep(1)
    containerd.run()
    cri = Cri(containerd.address, containerd.address)

    id_set = []
    for ref in converted_images:
        container_name = str(uuid.uuid4())
        cri.run_container(ref, container_name)
        id, status = cri.check_container_status(container_name, timeout=30)
        assert id is not None
        assert status
        id_set.append((id, ref))
        time.sleep(2)

    snapshotter.shutdown()
    snapshotter = Snapshotter(nydus_anchor)
    snapshotter.set_root(containerd.root)
    nydus_anchor.put_dustbin(snapshotter)
    snapshotter.run(rafs_conf.path())

    for id, ref in id_set:
        cri.stop_rm_container(id)
        cri.remove_image(ref)
        containerd.remove_image_sync(ref)


@pytest.mark.parametrize(
    "converted_images",
    [
        (
            "reg.docker.alibaba-inc.com/chge-nydus-test/python:3.8_converted",
            "reg.docker.alibaba-inc.com/chge-nydus-test/python:3.5_converted",
        )
    ],
)
def test_snapshotter_converted_images_with_cache(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    converted_images,
    nydus_snapshotter,
):
    snapshotter = Snapshotter(nydus_anchor)
    containerd = Containerd(nydus_anchor, snapshotter).gen_config()
    snapshotter.set_root(containerd.root)

    nydus_anchor.put_dustbin(snapshotter)
    nydus_anchor.put_dustbin(containerd)

    # We can safely pass the step provide repo configured into the rafs configuration file.
    rafs_conf.set_rafs_backend(
        Backend.REGTISTRY, scheme="https"
    ).enable_fs_prefetch().enable_rafs_blobcache(work_dir=snapshotter.cache_dir())
    rafs_conf.enable_xattr().dump_rafs_conf()

    snapshotter.run(rafs_conf.path())
    time.sleep(1)
    containerd.run()
    cri = Cri(containerd.address, containerd.address)

    id_set = []
    for ref in converted_images:
        container_name = str(uuid.uuid4())
        cri.run_container(ref, container_name)
        id, status = cri.check_container_status(container_name, timeout=30)
        assert id is not None
        assert status
        id_set.append((id, ref))
        time.sleep(2)

    for id, ref in id_set:
        cri.stop_rm_container(id)
        # image is tagged for multiple times, so try to remove the image by both ctr and critctl
        cri.remove_image(ref)
        containerd.remove_image_sync(ref)


@pytest.mark.parametrize(
    "converted_images",
    [("ghcr.io/changweige/python:3.8_converted",)],
)
def test_snapshotter_public_converted_images(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    converted_images,
    nydus_snapshotter,
):
    snapshotter = Snapshotter(nydus_anchor)
    containerd = Containerd(nydus_anchor, snapshotter).gen_config()
    snapshotter.set_root(containerd.root)

    nydus_anchor.put_dustbin(snapshotter)
    nydus_anchor.put_dustbin(containerd)

    # We can safely pass the step provide repo configured into the rafs configuration file.
    rafs_conf.set_rafs_backend(
        Backend.REGTISTRY, scheme="https"
    ).enable_fs_prefetch().enable_rafs_blobcache(work_dir=snapshotter.cache_dir())
    rafs_conf.enable_xattr().dump_rafs_conf()

    snapshotter.run(rafs_conf.path())
    time.sleep(1)
    containerd.run()
    cri = Cri(containerd.address, containerd.address)

    id_set = []
    for ref in converted_images:
        container_name = str(uuid.uuid4())
        cri.run_container(ref, container_name)
        id, status = cri.check_container_status(container_name, timeout=30)
        assert id is not None
        assert status
        id_set.append((id, ref))
        time.sleep(2)

    for id, ref in id_set:
        cri.stop_rm_container(id)
        cri.remove_image(ref)
        containerd.remove_image_sync(ref)

    snapshotter.shutdown()
    containerd.shutdown()