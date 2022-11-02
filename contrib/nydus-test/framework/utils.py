import posixpath
import subprocess
import logging
import sys
import os
import signal
from typing import Tuple
import io
import string
import random

try:
    import psutil
except ModuleNotFoundError:
    pass
import contextlib
import math
import enum
import datetime
import re
import random
import json
import tarfile
import pprint
import stat
import platform


def logging_setup(logging_stream=sys.stderr):
    """Inspired from Kadalu project"""
    root = logging.getLogger()

    if root.hasHandlers():
        return

    verbose = False
    try:
        if os.environ["NYDUS_TEST_VERBOSE"] == "YES":
            verbose = True
    except KeyError as _:
        pass

    # Errors should also be printed to screen.
    handler = logging.StreamHandler(logging_stream)

    if verbose:
        root.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
    else:
        root.setLevel(logging.INFO)
        handler.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s "
        "[%(module)s - %(lineno)s:%(funcName)s] "
        "- %(message)s"
    )
    handler.setFormatter(formatter)
    root.addHandler(handler)


def execute(cmd, **kwargs):
    exc = None

    shell = kwargs.pop("shell", False)
    print_output = kwargs.pop("print_output", False)
    print_cmd = kwargs.pop("print_cmd", True)
    print_err = kwargs.pop("print_err", True)

    if print_cmd:
        logging.info("Executing command: %s" % cmd)

    try:
        output = subprocess.check_output(
            cmd, shell=shell, stderr=subprocess.STDOUT, **kwargs
        )
        output = output.decode("utf-8")
        if print_output:
            logging.info("%s" % output)
    except subprocess.CalledProcessError as exc:
        o = exc.output.decode() if exc.output is not None else ""
        if print_err:
            logging.error(
                "Command: %s\nReturn code: %d\nError output:\n%s"
                % (cmd, exc.returncode, o)
            )

        return False, o

    return True, output


def run(cmd, wait: bool = True, verbose=True, **kwargs):
    if verbose:
        logging.info(cmd)
    else:
        logging.debug(cmd)

    popen_obj = subprocess.Popen(cmd, **kwargs)
    if wait:
        popen_obj.wait()
    return popen_obj.returncode, popen_obj


def kill_all_processes(program_name, sig=signal.SIGKILL):
    ret, out = execute(["pidof", program_name])
    if not ret:
        logging.warning("No %s running" % program_name)
        return

    processes = out.replace("\n", "").split(" ")

    for pid in processes:
        try:
            logging.info("Killing process %d" % int(pid))
            os.kill(int(pid), sig)
        except Exception as exc:
            logging.exception(exc)


def get_pid(proc_name: str) -> list:
    proc_list = []

    for proc in psutil.process_iter():
        try:
            if proc_name.lower() in proc.name().lower():
                proc_list.append((proc.pid, proc.name()))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return proc_list


def read_images_array(p) -> list:
    with open(p) as f:
        images = [i.rstrip("\n") for i in f.readlines() if not i.startswith("#")]
        return images


@contextlib.contextmanager
def pushd(new_path: str):
    previous_dir = os.getcwd()
    os.chdir(new_path)
    try:
        yield
    finally:
        os.chdir(previous_dir)


def round_up(n, decimals=0):
    return int(math.ceil(n / float(decimals))) * decimals


def get_current_time():
    return datetime.datetime.now()


def delta_time(t_end, t_start):
    delta = t_end - t_start
    return delta.total_seconds(), delta.microseconds


@contextlib.contextmanager
def timer(slogan):
    start = get_current_time()
    try:
        yield
    finally:
        end = get_current_time()
        sec, usec = delta_time(end, start)
        logging.info("%s, Takes time %u.%u seconds", slogan, sec, usec // 1000)


class Unit(enum.Enum):
    Byte = 1
    KB = 1024
    MB = 1024 * KB
    GB = 1024 * MB
    TB = 1024 * GB
    Blocks512 = 512
    Blocks4096 = 4096

    def get_value(self):
        return self.value


class Size:
    _KiB = 1024
    _MiB = _KiB * 1024
    _GiB = _MiB * 10244
    _TiB = _GiB * 1024
    _SECTOR_SIZE = 512

    def __init__(self, value: int, unit: Unit = Unit.Byte):
        self.bytes = value * unit.get_value()

    def __index__(self):
        return self.bytes

    @classmethod
    def from_B(cls, value):
        return cls(value)

    @classmethod
    def from_KiB(cls, value):
        return cls(value * cls._KiB)

    @classmethod
    def from_MiB(cls, value):
        return cls(value * cls._MiB)

    @classmethod
    def from_GiB(cls, value):
        return cls(value * cls._GiB)

    @classmethod
    def from_TiB(cls, value):
        return cls(value * cls._TiB)

    @classmethod
    def from_sector(cls, value):
        return cls(value * cls._SECTOR_SIZE)

    @property
    def B(self):
        return self.bytes

    @property
    def KiB(self):
        return self.bytes // self._KiB

    @property
    def MiB(self):
        return self.bytes // self._MiB

    @property
    def GiB(self):
        return self.bytes // self._GiB

    @property
    def TiB(self):
        return self.bytes / self._TiB

    @property
    def sectors(self):
        return self.bytes // self._SECTOR_SIZE

    def __str__(self):
        if self.bytes < self._KiB:
            return "{}B".format(self.B)
        elif self.bytes < self._MiB:
            return "{}K".format(self.KiB)
        elif self.bytes < self._GiB:
            return "{}M".format(self.MiB)
        elif self.bytes < self._TiB:
            return "{}G".format(self.GiB)
        else:
            return "{}T".format(self.TiB)


def dump_process_mem_cpu_load(pid):
    """
    https://psutil.readthedocs.io/en/latest/
    """
    p = psutil.Process(pid)
    mem_i = p.memory_info()
    logging.info(
        "[SYS LOAD]: RSS: %u(%u MB) VMS: %u(%u MB) DIRTY: %u | CPU num: %u, Usage: %f"
        % (
            mem_i.rss,
            mem_i.rss / 1024 // 1024,
            mem_i.vms,
            mem_i.vms / 1024 // 1024,
            mem_i.dirty,
            p.cpu_num(),
            p.cpu_percent(0.5),
        )
    )


def file_disk_usage(path):
    s = os.stat(path).st_blocks * 512
    return s


def list_object_to_dict(lst):
    return_list = []
    for l in lst:
        return_list.append(object_to_dict(l))
    return return_list


def object_to_dict(object):
    if hasattr(object, "__dict__"):
        dict = vars(object)
    else:
        return object
    for k, v in dict.items():
        if type(v).__name__ not in ["list", "dict", "str", "int", "float", "bool"]:
            dict[k] = object_to_dict(v)
        if type(v) is list:
            dict[k] = list_object_to_dict(v)
    return dict


def get_fs_type(path):
    partitions = psutil.disk_partitions()
    partitions.sort(reverse=True)

    for part in partitions:
        if path.startswith(part.mountpoint):
            return part.fstype


def mess_file(path):
    file_size = os.path.getsize(path)

    offset = random.randint(0, file_size)

    fd = os.open(path, os.O_WRONLY)
    os.pwrite(fd, os.urandom(1000), offset)
    os.close(fd)


# based on https://stackoverflow.com/a/42865957/2002471
units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}


def parse_size(size):
    size = size.upper()
    if not re.match(r" ", size):
        size = re.sub(r"([KMGT]?B)", r" \1", size)
    number, unit = [string.strip() for string in size.split()]
    return int(float(number) * units[unit])


def clean_pagecache():
    execute(["echo", "3", ">", "/proc/sys/vm/drop_caches"])


def pretty_print(*args, **kwargs):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(*args, **kwargs)


def is_regular(path):
    mode = os.stat(path)[stat.ST_MODE]
    return stat.S_ISREG(mode)


class ArtifactProcess:
    def __init__(self) -> None:
        super().__init__()

    def shutdown(self):
        pass


import gzip


def is_gzip(path):
    """
    gzip.BadGzipFile: means it is not a gzip
    """
    with gzip.open(path, "r") as fh:
        try:
            fh.read(1)
        except Exception:
            return False

        return True


class Skopeo:
    def __init__(self) -> None:
        super().__init__()
        self.bin = os.path.join(
            "framework",
            "bin",
            "skopeo" if platform.machine() == "x86_64" else "skopeo.aarch64",
        )

    @staticmethod
    def repo_from_image_ref(image):
        repo = posixpath.basename(image).split(":")[0]
        registry = posixpath.dirname(image)
        return posixpath.join(registry, repo)

    def inspect(
        self, image, tls_verify=False, image_arch="amd64", features=None, verifier=None
    ):
        """
        {
        "manifests": [
            {
            "digest": "sha256:0415f56ccc05526f2af5a7ae8654baec97d4a614f24736e8eef41a4591f08019",
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "platform": {
                "architecture": "amd64",
                "os": "linux"
            },
            "size": 527
            },
        <snipped>
        ---
        {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 1457,
            "digest": "sha256:b97242f89c8a29d13aea12843a08441a4bbfc33528f55b60366c1d8f6923d0d4"
        },
        "layers": [
            {
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "size": 764663,
            "digest": "sha256:e5d9363303ddee1686b203170d78283404e46a742d4c62ac251aae5acbda8df8"
            }
            ]
        }
        <snipped>
        ---
        Example to fetch manifest by its hash
            skopeo inspect  --raw docker://docker.io/busybox@sha256:0415f56ccc05526f2af5a7ae8654baec97d4a614f24736e8eef41a4591f08019

        """

        cmd = [self.bin, "inspect", "--raw", f"docker://{image}"]
        if not tls_verify:
            cmd.insert(2, "--tls-verify=false")

        ret, p = run(
            cmd,
            wait=False,
            shell=False,
            stdout=subprocess.PIPE,
        )
        out, _ = p.communicate()
        p.wait()
        m = json.loads(out)

        # manifest = None
        digest = None
        if m["mediaType"] == "application/vnd.docker.distribution.manifest.v2+json":
            manifest = m
        elif (
            m["mediaType"]
            == "application/vnd.docker.distribution.manifest.list.v2+json"
        ):
            for mf in m["manifests"]:
                # Choose coresponding platform
                if (
                    mf["platform"]["architecture"] == image_arch
                    and mf["platform"]["os"] == "linux"
                ):
                    if features is not None:
                        if "os.features" not in mf["platform"]:
                            continue
                        elif mf["platform"]["os.features"][0] != features:
                            logging.error("cccc %s", mf["platform"]["os.features"][0])
                            continue

                    digest = mf["digest"]
                    repo = Skopeo.repo_from_image_ref(image)
                    cmd = [
                        self.bin,
                        "inspect",
                        "--raw",
                        f"docker://{repo}@{digest}",
                    ]
                    if not tls_verify:
                        cmd.insert(2, "--tls-verify=false")

                    ret, p = run(
                        cmd,
                        wait=False,
                        shell=False,
                        stdout=subprocess.PIPE,
                    )
                    out, _ = p.communicate()
                    p.wait()
                    assert p.returncode == 0
                    manifest = json.loads(out)
                    break
        else:
            assert False
        assert isinstance(manifest, dict)

        return manifest, digest

    def copy_to_local(
        self, image, layers, extraced_dir, tls_verify=False, resource_digest=None
    ):
        """
        :layers: From which to decompress each layer
        """

        os.makedirs(extraced_dir, exist_ok=True)

        if resource_digest is not None:
            repo = Skopeo.repo_from_image_ref(image)
            cmd = [
                self.bin,
                "--insecure-policy",
                "copy",
                f"docker://{repo}@{resource_digest}",
                f"dir:{extraced_dir}",
            ]
        else:
            cmd = [
                self.bin,
                "copy",
                "--insecure-policy",
                f"docker://{image}",
                f"dir:{extraced_dir}",
            ]

        if not tls_verify:
            cmd.insert(1, "--tls-verify=false")

        ret, p = run(
            cmd,
            wait=True,
            shell=False,
            stdout=subprocess.PIPE,
        )
        assert ret == 0

        if layers is not None:
            with pushd(extraced_dir):
                for i in layers:
                    # Blob layer downloaded has no "sha256" prefix
                    try:
                        layer = i.replace("sha256:", "")
                        os.makedirs(i, exist_ok=True)
                        with tarfile.open(
                            layer, "r:gz" if is_gzip(layer) else "r:"
                        ) as tar_gz:
                            tar_gz.extractall(path=i)
                    except FileNotFoundError:
                        logging.warning("Should already downloaded")

    def copy_all_to_registry(self, source_image_tagged, dest_image_tagged):
        cmd = [
            self.bin,
            "--insecure-policy",
            "copy",
            "--all",
            "--tls-verify=false",
            f"docker://{source_image_tagged}",
            f"docker://{dest_image_tagged}",
        ]

        ret, p = run(
            cmd,
            wait=True,
            shell=False,
            stdout=subprocess.PIPE,
        )
        assert ret == 0

    def manifest_list(self, image, tls_verify=False):
        cmd = [self.bin, "inspect", "--raw", f"docker://{image}"]
        if not tls_verify:
            cmd.insert(2, "--tls-verify=false")

        ret, p = run(
            cmd,
            wait=False,
            shell=False,
            stdout=subprocess.PIPE,
        )
        out, _ = p.communicate()
        p.wait()
        m = json.loads(out)

        if m["mediaType"] == "application/vnd.docker.distribution.manifest.v2+json":
            return None
        elif (
            m["mediaType"]
            == "application/vnd.docker.distribution.manifest.list.v2+json"
        ):
            return m

    def pretty_print(artifact: dict):
        a = json.dumps(artifact, indent=4)
        print(a)


def write_tar_gz(source, tar_gz):
    def f(ti):
        ti.name = os.path.relpath(ti.name, start=source)
        return ti

    with tarfile.open(tar_gz, "w:gz") as t:
        t.add(source, arcname="")


def parse_stargz(stargz):
    """
    The footer MUST be the following 51 bytes (1 byte = 8 bits in gzip).
    Footer format:
    - 10 bytes  gzip header
    - 2  bytes  XLEN (length of Extra field) = 26 (4 bytes header + 16 hex digits + len("STARGZ"))
    - 2  bytes  Extra: SI1 = 'S', SI2 = 'G'
    - 2  bytes  Extra: LEN = 22 (16 hex digits + len("STARGZ"))
    - 22 bytes  Extra: subfield = fmt.Sprintf("%016xSTARGZ", offsetOfTOC)
    - 5  bytes  flate header: BFINAL = 1(last block), BTYPE = 0(non-compressed block), LEN = 0
    - 8  bytes  gzip footer
    (End of eStargz)
    """
    f = open(stargz, "rb")
    f.seek(-51, 2)
    footer = f.read(51)
    assert len(footer) == 51
    header_extra = footer[16:]
    toc_offset = header_extra[0:16]
    toc_offset = int(toc_offset.decode("utf-8"), base=16)

    f.seek(toc_offset)
    toc_gzip = f.read(toc_offset - 51)
    toc_tar = gzip.decompress(toc_gzip)
    t = io.BytesIO(toc_tar)

    with tarfile.open(fileobj=t, mode="r") as tf:
        tf.extractall()

    f.close()
    return "stargz.index.json"


def docker_image_repo(reference):
    return posixpath.basename(reference).split(":")[0]


def random_string(l=64):
    res = "".join(random.choices(string.ascii_uppercase + string.digits, k=l))
    return res
