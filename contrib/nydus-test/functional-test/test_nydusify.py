import pytest
import posixpath
import time
import platform

from nydus_anchor import NydusAnchor
from oss import OssHelper
from rafs import RafsConf, Backend, NydusDaemon
from nydusify import Nydusify
from workload_gen import WorkloadGen
import tempfile
import utils

ANCHOR = NydusAnchor()

FS_VERSION = ANCHOR.fs_version


@pytest.mark.parametrize(
    "source",
    [
        "openjdk:latest",
        "python:3.7",
        "docker.io/busybox:latest",
    ],
)
@pytest.mark.parametrize("fs_version", [FS_VERSION])
def test_basic_conversion(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    source,
    fs_version,
    local_registry,
    nydusify_converter,
):
    """
    No need to locate where bootstrap is as we can directly pull it from registry
    """
    converter = Nydusify(nydus_anchor)

    time.sleep(1)

    converter.docker_v2().enable_multiplatfrom(False).convert(
        source, fs_version=fs_version
    )
    assert converter.locate_bootstrap() is not None
    pulled_bootstrap = converter.pull_bootstrap(
        tempfile.TemporaryDirectory(
            dir=nydus_anchor.workspace, suffix="bootstrap"
        ).name,
        "pulled_bootstrap",
    )

    # Skopeo does not support media type: "application/vnd.oci.image.layer.nydus.blob.v1",
    # So can't download build cache like a oci image.

    layers, base = converter.extract_source_layers_names_and_download()
    nydus_anchor.mount_overlayfs(layers, base)

    converted_layers = converter.extract_converted_layers_names()
    converted_layers.sort()

    rafs_conf.set_rafs_backend(
        Backend.REGISTRY, repo=posixpath.basename(source).split(":")[0]
    )
    rafs_conf.enable_fs_prefetch()
    rafs_conf.enable_rafs_blobcache()
    rafs_conf.dump_rafs_conf()

    rafs = NydusDaemon(nydus_anchor, None, rafs_conf)

    # Use `nydus-image inspect` to compare blob table in bootstrap and manifest

    workload_gen = WorkloadGen(nydus_anchor.mountpoint, nydus_anchor.overlayfs)
    # No need to locate where bootstrap is as we can directly pull it from registry
    rafs.thread_num(6).bootstrap(pulled_bootstrap).prefetch_files("/").mount()

    assert workload_gen.verify_entire_fs()
    workload_gen.setup_workload_generator()
    workload_gen.torture_read(4, 6, verify=True)
    workload_gen.finish_torture_read()


@pytest.mark.parametrize(
    "source",
    [
        "python:3.7",
        "docker.io/busybox:latest",
    ],
)
@pytest.mark.parametrize("enable_multiplatform", [False])
def test_build_cache(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    source,
    enable_multiplatform,
    local_registry,
    nydusify_converter,
):
    """
    No need to locate where bootstrap is as we can directly pull it from registry
    """
    converter = Nydusify(nydus_anchor)

    time.sleep(1)

    converter.docker_v2().build_cache_ref(
        "localhost:5000/build_cache:000"
    ).enable_multiplatfrom(enable_multiplatform).convert(source)

    # No need to locate where bootstrap is as we can directly pull it from registry
    bootstrap = converter.locate_bootstrap()

    converter.docker_v2().build_cache_ref("localhost:5000/build_cache:000").convert(
        source
    )

    assert converter.locate_bootstrap() == None

    pulled_bootstrap = converter.pull_bootstrap(
        tempfile.TemporaryDirectory(
            dir=nydus_anchor.workspace, suffix="bootstrap"
        ).name,
        "pulled_bootstrap",
    )

    # Skopeo does not support media type: "application/vnd.oci.image.layer.nydus.blob.v1",
    # So can't download build cache like a oci image.

    layers, base = converter.extract_source_layers_names_and_download()
    nydus_anchor.mount_overlayfs(layers, base)

    converted_layers = converter.extract_converted_layers_names()
    converted_layers.sort()

    records = converter.get_build_cache_records("localhost:5000/build_cache:000")
    assert len(records) != 0
    cached_layers = [c["digest"] for c in records]
    cached_layers.sort()
    for l in converted_layers:
        assert l in cached_layers

    rafs_conf.set_rafs_backend(
        Backend.REGISTRY, repo=posixpath.basename(source).split(":")[0]
    )
    rafs_conf.enable_fs_prefetch()
    rafs_conf.enable_rafs_blobcache()
    rafs_conf.dump_rafs_conf()

    rafs = NydusDaemon(nydus_anchor, None, rafs_conf)

    # Use `nydus-image inspect` to compare blob table in bootstrap and manifest

    workload_gen = WorkloadGen(nydus_anchor.mountpoint, nydus_anchor.overlayfs)
    # No need to locate where bootstrap is as we can directly pull it from registry
    rafs.thread_num(6).bootstrap(pulled_bootstrap).prefetch_files("/").mount()

    assert workload_gen.verify_entire_fs()
    workload_gen.setup_workload_generator()
    workload_gen.torture_read(8, 12, verify=True)
    workload_gen.finish_torture_read()


@pytest.mark.skip(reason="Get rid of OSS dependency!")
@pytest.mark.parametrize(
    "source",
    [
        "docker.io/busybox:latest",
    ],
)
def test_upload_oss(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    source,
    local_registry,
    nydusify_converter,
):
    """
    docker python client manual: https://docker-py.readthedocs.io/en/stable/
    Use pulled bootstrap from registry instead of newly generated by nydus-image to check if the bootstrap is pushed successfully.
    """
    converter = Nydusify(nydus_anchor)

    time.sleep(1)

    oss_prefix = "nydus_v2/"

    converter.docker_v2().backend_type(
        "oss", oss_object_prefix=oss_prefix, filed=True
    ).build_cache_ref("localhost:5000/build_cache:000").force_push().convert(source)

    nydus_image_output = converter.nydus_image_output()
    blobs_to_remove = nydus_image_output["blobs"]

    # Just to observe if convertion is faster
    converter.docker_v2().backend_type(
        "oss", oss_object_prefix=oss_prefix
    ).build_cache_ref("localhost:5000/build_cache:000").force_push().convert(source)

    rafs_conf.set_rafs_backend(Backend.OSS, prefix=oss_prefix)
    rafs_conf.enable_fs_prefetch()
    rafs_conf.enable_rafs_blobcache()
    rafs_conf.dump_rafs_conf()

    bootstrap = converter.locate_bootstrap()

    # `check` deletes all files
    checker = Nydusify(nydus_anchor)
    checker.backend_type("oss", oss_object_prefix=oss_prefix).with_new_work_dir(
        nydus_anchor.nydusify_work_dir + "-check"
    ).check(source)

    converted_layers = converter.extract_converted_layers_names()

    # With oss backend, ant useage, `layers` only has one member
    records = converter.get_build_cache_records("localhost:5000/build_cache:000")
    assert len(records) != 0
    cached_layers = [c["digest"] for c in records]
    assert cached_layers.sort() == converted_layers.sort()

    pulled_bootstrap = converter.pull_bootstrap(
        tempfile.TemporaryDirectory(
            dir=nydus_anchor.workspace, suffix="bootstrap"
        ).name,
        "pulled_bootstrap",
    )

    layers, base = converter.extract_source_layers_names_and_download()
    nydus_anchor.mount_overlayfs(layers, base)

    rafs = NydusDaemon(nydus_anchor, None, rafs_conf)

    workload_gen = WorkloadGen(nydus_anchor.mountpoint, nydus_anchor.overlayfs)
    rafs.thread_num(6).bootstrap(pulled_bootstrap).prefetch_files("/").mount()

    assert workload_gen.verify_entire_fs()
    workload_gen.setup_workload_generator()
    workload_gen.torture_read(8, 12, verify=True)
    workload_gen.finish_torture_read()

    oss = OssHelper(
        nydus_anchor.ossutil_bin,
        endpoint=nydus_anchor.oss_endpoint,
        bucket=nydus_anchor.oss_bucket,
        ak_id=nydus_anchor.oss_ak_id,
        ak_secret=nydus_anchor.oss_ak_secret,
        prefix=None,
    )

    # Nydusify will skip upload blob as object if it exists.
    for b in blobs_to_remove:
        oss.rm(b)


@pytest.mark.parametrize(
    "source",
    [
        "busybox:latest",  # From DockerHub, manifest list image format, image config includes os/arch
    ],
)
@pytest.mark.parametrize("arch", ["arm64", "amd64"])
@pytest.mark.parametrize("enable_multiplatform", [True])
def test_cross_platform_multiplatform(
    nydus_anchor: NydusAnchor,
    rafs_conf: RafsConf,
    source,
    arch,
    enable_multiplatform,
    local_registry,
    nydusify_converter,
):
    """
    - copy the entire repo from source registry to target registry
    - One image coresponds to manifest list while the other one to single manifest
    - Use cloned source rather than the one from original registry
    - Push the converted images to the original source
    - Also test multiplatform here
    - ? Seems with flag --multiplatform to nydusify, it still just push single manifest
    - converted manifest index has one more image than origin.
    """

    # Copy the entire repo for multiplatform
    skopeo = utils.Skopeo()
    source_name_tagged = posixpath.basename(source)
    target_image = f"localhost:5000/{source_name_tagged}"
    cloned_source = f"localhost:5000/{source_name_tagged}"
    skopeo.copy_all_to_registry(source, target_image)

    origin_manifest_index = skopeo.manifest_list(cloned_source)
    utils.Skopeo.pretty_print(origin_manifest_index)

    converter = Nydusify(nydus_anchor)

    converter.docker_v2().build_cache_ref("localhost:5000/build_cache:000").platform(
        f"linux/{arch}"
    ).enable_multiplatfrom(enable_multiplatform).convert(
        cloned_source, target_ref=target_image
    )

    # TODO: configure registry backend from `local_registry` rather than anchor
    rafs_conf.set_rafs_backend(
        Backend.REGISTRY, repo=posixpath.basename(source).split(":")[0]
    )
    rafs_conf.enable_fs_prefetch()
    rafs_conf.enable_rafs_blobcache()

    pulled_bootstrap = converter.pull_bootstrap(
        tempfile.TemporaryDirectory(
            dir=nydus_anchor.workspace, suffix="bootstrap"
        ).name,
        "pulled_bootstrap",
        arch,
    )

    # Skopeo does not support media type: "application/vnd.oci.image.layer.nydus.blob.v1",
    # So can't download build cache like a oci image.
    layers, base = converter.extract_source_layers_names_and_download(arch=arch)
    nydus_anchor.mount_overlayfs(layers, base)

    converted_layers = converter.extract_converted_layers_names(arch=arch)
    converted_layers.sort()

    converted_manifest_index = skopeo.manifest_list(cloned_source)
    utils.Skopeo.pretty_print(converted_manifest_index)

    assert (
        len(converted_manifest_index["manifests"])
        - len(origin_manifest_index["manifests"])
        == 1
    )

    # `inspect` will succeed if image to arch can be found.
    skopeo.inspect(target_image, image_arch=arch)
    converter.find_nydus_image(target_image, arch)

    target_image_config = converter.pull_config(target_image, arch=arch)
    assert target_image_config["architecture"] == arch

    records = converter.get_build_cache_records("localhost:5000/build_cache:000")
    assert len(records) != 0
    cached_layers = [c["digest"] for c in records]
    cached_layers.sort()
    # >       assert cached_layers == converted_layers
    # E       AssertionError: assert None == ['sha256:3f18...af3234b4c257']
    # E         +None
    # E         -['sha256:3f18b27a912188108c8590684206bd9da7d81bbfd0e8325f3ef0af3234b4c257']
    for r in converted_layers:
        assert r in cached_layers

    # Use `nydus-image inspect` to compare blob table in bootstrap and manifest
    workload_gen = WorkloadGen(nydus_anchor.mountpoint, nydus_anchor.overlayfs)
    # No need to locate where bootstrap is as we can directly pull it from registry
    rafs = NydusDaemon(nydus_anchor, None, rafs_conf)
    rafs.thread_num(6).bootstrap(pulled_bootstrap).prefetch_files("/").mount()

    assert workload_gen.verify_entire_fs()
    workload_gen.setup_workload_generator()
    workload_gen.torture_read(8, 12, verify=True)
    workload_gen.finish_torture_read()
