import sys
import os
import re
import shutil
import logging
import pytest
import docker

sys.path.append(os.path.realpath("framework"))
from nydus_anchor import NydusAnchor
from rafs import RafsImage, RafsConf
import utils

ANCHOR = NydusAnchor()
utils.logging_setup(ANCHOR.logging_file)

os.environ["RUST_BACKTRACE"] = "1"

from tools import artifact

# Fetch dependant artifacts.
# for stuff in ["containerd-nydus-grpc"]:
# artifact.ArtifactManager().fetch(stuff)
# os.chmod(stuff, 0o755)


@pytest.fixture()
def nydus_anchor(request):
    pass
    # TODO: check if nydusd executable exists and have a proper version
    # TODO: check if bootstrap exists
    # TODO: check if blob cache file exists and try to clear it if it does
    # TODO: check if blob file was put to oss

    nyta = NydusAnchor()
    nyta.check_prerequisites()

    logging.info("*** Testing case %s ***", os.environ.get("PYTEST_CURRENT_TEST"))

    yield nyta

    nyta.clear_blobcache()

    if hasattr(nyta, "scratch_dir"):
        logging.info("Clean up scratch dir")
        shutil.rmtree(nyta.scratch_dir)

    if hasattr(nyta, "nydusd"):
        # anchor will associate with a RafsMount if it is mounted.
        if os.path.ismount(nyta.mount_point):
            nyta.nydusd.umount()

    if hasattr(nyta, "overlayfs") and os.path.ismount(nyta.overlayfs):
        nyta.umount_overlayfs()

    # Check if nydusd is crashed.
    # TODO: Where the core file is places is controlled by kernel.
    # Check `/proc/sys/kernel/core_pattern`
    files = os.listdir()
    for one in files:
        assert re.match("^core\..*", one) is None

    try:
        shutil.rmtree(nyta.localfs_workdir)
    except FileNotFoundError:
        pass

    try:
        nyta.cleanup_dustbin()
    except FileNotFoundError:
        pass

    # All nydusd should stop.
    assert not NydusAnchor.capture_running_nydusd()


@pytest.fixture()
def nydus_image(nydus_anchor: NydusAnchor, request):
    """
    Create images using previous version nydus image tool.
    This fixture provides rafs image file, case is not responsible for performing
    creating image.
    """
    image = RafsImage(
        nydus_anchor, nydus_anchor.source_dir, "bootstrap", "blob", clear_from_oss=True
    )
    yield image
    try:
        image.clean_up()
    except FileNotFoundError as _:
        pass


@pytest.fixture()
def nydus_scratch_image(nydus_anchor: NydusAnchor):
    """No longger use source_dir but use scratch_dir,
    Scratch image's creation is delayed until runtime of each case.
    """
    nydus_anchor.prepare_scratch_dir()

    # Scratch image is not made here since specific case decides how to
    # scratch this dir
    image = RafsImage(
        nydus_anchor,
        nydus_anchor.scratch_dir,
        "boostrap_scratched",
        "blob_scratched",
        clear_from_oss=True,
    )

    yield image

    if not image.created:
        return

    try:
        image.clean_up()
    except FileNotFoundError as _:
        pass


@pytest.fixture()
def nydus_parent_image(nydus_anchor: NydusAnchor):
    parent_image = RafsImage(
        nydus_anchor, nydus_anchor.parent_rootfs, "boostrap_parent", "blob_parent"
    )
    yield parent_image
    try:
        parent_image.clean_up()
    except FileNotFoundError as _:
        pass


@pytest.fixture()
def nydus_scratch_parent_image(nydus_anchor: NydusAnchor):
    nydus_anchor.prepare_scratch_parent_dir()
    parent_image = RafsImage(
        nydus_anchor, nydus_anchor.scratch_parent_dir, "bs_parent", "blob_parent"
    )
    yield parent_image
    try:
        parent_image.clean_up()
    except FileNotFoundError as _:
        pass


@pytest.fixture(scope="session", autouse=False)
def collect_report(request):
    """
    To enable code coverage report, let @autouse be True.
    """
    build_dir = ANCHOR.build_dir
    from coverage_collect import collect_coverage

    def CC():
        collect_coverage(build_dir)

    request.addfinalizer(CC)


@pytest.fixture
def rafs_conf(nydus_anchor):
    """Generate conf file via libconf(https://pypi.org/project/libconf/)"""
    rc = RafsConf(nydus_anchor)
    rc.dump_rafs_conf()
    yield rc


@pytest.fixture(scope="session")
def nydusify_converter():
    # Can't access a `function` scope fixture.

    os.environ["GOTRACEBACK"] = "crash"

    nydusify_source_dir = os.path.join(ANCHOR.nydus_project, "contrib/nydusify")
    with utils.pushd(nydusify_source_dir):
        ret, _ = utils.execute(["make", "static-release"])
        assert ret


@pytest.fixture(scope="session")
def nydus_snapshotter():
    # Can't access a `function` scope fixture.
    snapshotter_source = os.path.join(ANCHOR.nydus_project, "contrib/nydus-snapshotter")
    with utils.pushd(snapshotter_source):
        ret, _ = utils.execute(["make"])
        assert ret


@pytest.fixture()
def local_registry():
    docker_client = docker.from_env()
    registry_container = docker_client.containers.run(
        "registry:latest", detach=True, network_mode="host", remove=True
    )

    yield registry_container

    try:
        registry_container.stop()
    except docker.errors.APIError:
        assert False, "fail in stopping container"
