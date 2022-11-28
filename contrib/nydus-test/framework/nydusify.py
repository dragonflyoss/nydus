import logging
import subprocess
import tempfile
import utils
from nydus_anchor import NydusAnchor
import os
import json
import posixpath
from linux_command import LinuxCommand
import shutil
import tarfile
import re


class NydusifyParam(LinuxCommand):
    def __init__(self, command_name):
        super().__init__(command_name)
        self.param_name_prefix = "--"

    def source(self, source):
        return self.set_param("source", source)

    def target(self, target):
        return self.set_param("target", target)

    def nydus_image(self, nydus_image):
        return self.set_param("nydus-image", nydus_image)

    def work_dir(self, work_dir):
        return self.set_param("work-dir", work_dir)

    def fs_version(self, fs_version):
        return self.set_param("fs-version", str(fs_version))

    def target_insecure(self):
        return self.set_flags("target-insecure")


class Nydusify(LinuxCommand):
    def __init__(self, anchor: NydusAnchor):
        self.image_builder = anchor.image_bin
        self.nydusify_bin = anchor.nydusify_bin
        self.registry_url = anchor.registry_url
        self.work_dir = anchor.nydusify_work_dir
        self.anchor = anchor
        # self.generate_auth_config(self.registry_url, anchor.registry_auth)
        # os.environ["DOCKER_CONFIG"] = self.__temp_auths_config_dir.name
        super().__init__(self.image_builder)
        self.cmd = NydusifyParam(self.nydusify_bin)
        self.cmd.nydus_image(self.image_builder).work_dir(self.work_dir)

    def convert(self, source, suffix="_converted", target_ref=None, fs_version=6):
        """
        A reference to image looks like registry/namespace/repo:tag
        Before conversion begins, split the reference into those parts.
        """
        # Notice: localhost:5000/busybox:latest
        self.__repo = posixpath.basename(source).split(":")[0]
        self.__converted_image = (
            posixpath.basename(source) + suffix if suffix is not None else ""
        )
        self.__source = source
        self.cmd.set_subcommand("convert")

        if target_ref is None:
            target_ref = posixpath.join(
                self.anchor.registry_url,
                self.anchor.registry_namespace,
                self.__converted_image,
            )

        self.cmd.source(source).target(target_ref).fs_version(
            fs_version
        ).target_insecure()

        self.target_ref = target_ref

        cmd = str(self.cmd)
        with utils.timer(
            f"### Rafs V{fs_version} Image conversion time including Pull and Push ###"
        ):
            _, p = utils.run(
                cmd,
                False,
                shell=True,
                stdout=self.anchor.logging_file,
                stderr=self.anchor.logging_file,
            )
            p.wait()
            assert p.returncode == 0

    def check(self, source, suffix="_converted", target_ref=None, fs_version=5):
        """
        A reference to image looks like registry/namespace/repo:tag
        Before conversion begins, split the reference into those parts.
        """
        # Notice: localhost:5000/busybox:latest
        self.__repo = posixpath.basename(source).split(":")[0]
        self.__converted_image = (
            posixpath.basename(source) + suffix if suffix is not None else ""
        )
        self.__source = source
        self.cmd.set_subcommand("check")
        self.cmd.set_param("nydusd", self.anchor.nydusd_bin)
        self.cmd.set_param("nydus-image", self.anchor.image_bin)

        if target_ref is None:
            target_ref = posixpath.join(
                self.anchor.registry_url,
                self.anchor.registry_namespace,
                self.__converted_image,
            )

        self.cmd.source(source).target(target_ref).fs_version(fs_version)
        self.target_ref = target_ref

        cmd = str(self.cmd)
        with utils.timer("### Image Check Duration ###"):
            _, p = utils.run(
                cmd,
                False,
                shell=True,
                stdout=self.anchor.logging_file,
                stderr=self.anchor.logging_file,
            )
            p.wait()
            assert p.returncode == 0

    def docker_v2(self):
        self.cmd.set_flags("docker-v2-format")
        return self

    def force_push(self):
        self.cmd.set_flags("backend-force-push")
        return self

    def platform(self, p):
        self.cmd.set_param("platform", p)
        return self

    def chunk_dict(self, chunk_dict_arg):
        self.cmd.set_param("chunk-dict", chunk_dict_arg)
        return self

    def with_new_work_dir(self, work_dir):
        self.work_dir = work_dir
        self.cmd.set_param("work-dir", work_dir)
        return self

    def enable_multiplatfrom(self, enable: bool):
        if enable:
            self.cmd.set_flags("multi-platform")
        return self

    def build_cache_ref(self, ref):
        self.cmd.set_param("build-cache", ref)
        return self

    def backend_type(self, type, oss_object_prefix=None, filed=False):
        config = {
            "endpoint": self.anchor.oss_endpoint,
            "access_key_id": self.anchor.oss_ak_id,
            "access_key_secret": self.anchor.oss_ak_secret,
            "bucket_name": self.anchor.oss_bucket,
        }

        if oss_object_prefix is not None:
            config["object_prefix"] = oss_object_prefix

        self.cmd.set_param("backend-type", type)

        if filed:
            with open("oss_conf.json", "w") as f:
                json.dump(config, f)
                self.cmd.set_param("backend-config-file", "oss_conf.json")
        else:
            self.cmd.set_param("backend-config", json.dumps(json.dumps(config)))

        return self

    def nydus_image_output(self):
        with utils.pushd(os.path.join(self.work_dir, "bootstraps")):
            outputs = [o for o in os.listdir() if re.match(r".*json$", o) is not None]
            outputs.sort(key=lambda x: int(x.split("-")[0]))
            with open(outputs[0], "r") as f:
                return json.load(f)

    @property
    def original_repo(self):
        return self.__repo

    @property
    def converted_repo(self):
        return posixpath.join(self.anchor.registry_namespace, self.__repo)

    @property
    def converted_image(self):
        return posixpath.join(
            self.registry_url, self.anchor.registry_namespace, self.__converted_image
        )

    def locate_bootstrap(self):
        bootstraps_dir = os.path.join(self.work_dir, "bootstraps")
        with utils.pushd(bootstraps_dir):
            each_layers = os.listdir()

            if len(each_layers) == 0:
                return None

            each_layers = [l.split("-") for l in each_layers]
            each_layers.sort(key=lambda x: int(x[0]))

        return os.path.join(bootstraps_dir, "-".join(each_layers[-1]))

    def generate_auth_config(self, registry_url, auth):
        auths = {"auths": {registry_url: {"auth": auth}}}
        self.__temp_auths_config_dir = tempfile.TemporaryDirectory()
        self.auths_config = os.path.join(
            self.__temp_auths_config_dir.name, "config.json"
        )
        with open(self.auths_config, "w+") as f:
            json.dump(auths, f)
            f.flush()

    def extract_source_layers_names_and_download(self, arch="amd64"):
        skopeo = utils.Skopeo()
        manifest, digest = skopeo.inspect(self.__source, image_arch=arch)
        layers = [l["digest"] for l in manifest["layers"]]

        # trimmed_layers = [os.path.join(self.work_dir, self.__source, l) for l in layers]
        # trimmed_layers.reverse()
        layers.reverse()
        skopeo.copy_to_local(
            self.__source,
            layers,
            os.path.join(self.work_dir, self.__source),
            resource_digest=digest,
        )
        return layers, os.path.join(self.work_dir, self.__source)

    def extract_converted_layers_names(self, arch="amd64"):
        skopeo = utils.Skopeo()
        manifest, _ = skopeo.inspect(
            self.target_ref,
            tls_verify=False,
            features="nydus.remoteimage.v1",
            image_arch=arch,
        )
        layers = [l["digest"] for l in manifest["layers"]]
        layers.reverse()
        return layers

    def pull_bootstrap(self, downloaded_dir, bootstrap_name, arch="amd64"):
        """
        Nydusify converts oci to nydus format and push the nydus image manifest to registry,
        which belongs to a manifest index.
        """
        skopeo = utils.Skopeo()
        nydus_manifest, _ = skopeo.inspect(
            self.target_ref,
            tls_verify=False,
            features="nydus.remoteimage.v1",
            image_arch=arch,
        )
        layers = nydus_manifest["layers"]

        for l in layers:
            if l["mediaType"] == "application/vnd.docker.image.rootfs.diff.tar.gzip":
                bootstrap_digest = l["digest"]

        import requests

        # Currently, we can not handle auth
        # OCI distribution spec: /v2/<name>/blobs/<digest>
        os.makedirs(downloaded_dir, exist_ok=True)

        reader = requests.get(
            f"http://{self.registry_url}/v2/{self.anchor.registry_namespace}/{self.original_repo}/blobs/{bootstrap_digest}",
            stream=True,
        )
        with utils.pushd(downloaded_dir):
            with open("image.gzip", "wb") as w:
                shutil.copyfileobj(reader.raw, w)
            with tarfile.open("image.gzip", "r:gz") as tar_gz:
                tar_gz.extractall()
                os.rename("image/image.boot", bootstrap_name)
            os.remove("image.gzip")

        return os.path.join(downloaded_dir, bootstrap_name)

    def pull_config(self, image, arch="amd64"):
        """
        Nydusify converts oci to nydus format and push the nydus image manifest to registry,
        which belongs to a manifest index.
        """
        skopeo = utils.Skopeo()
        nydus_manifest, digest = skopeo.inspect(
            image, tls_verify=False, image_arch=arch
        )

        import requests

        # Currently, we can handle auth
        # OCI distribution spec: /v2/<name>/manifests/<digest>
        reader = requests.get(
            f"http://{self.registry_url}/v2/{self.original_repo}/manifests/{digest}",
            stream=True,
        )

        manifest = json.load(reader.raw)

        config_digest = manifest["config"]["digest"]
        reader = requests.get(
            f"http://{self.registry_url}/v2/{self.original_repo}/blobs/{config_digest}",
            stream=True,
        )

        config = json.load(reader.raw)
        return config

    def find_nydus_image(self, image, arch):
        skopeo = utils.Skopeo()
        nydus_manifest, digest = skopeo.inspect(
            image, tls_verify=False, image_arch=arch, features="nydus.remoteimage.v1"
        )

        assert nydus_manifest is not None

    def get_build_cache_records(self, ref):
        skopeo = utils.Skopeo()
        build_cache_records, _ = skopeo.inspect(ref, tls_verify=False)

        c = json.dumps(build_cache_records, indent=4, sort_keys=False)

        logging.info("build cache: %s", c)

        records = build_cache_records["layers"]
        return records
