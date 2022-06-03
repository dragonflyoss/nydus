import os
import shutil
from inspect import stack, getframeinfo
from containerd import Containerd
from snapshotter import Snapshotter
import utils
from stat import *
import time
import logging
import sys
import signal
import tempfile
import json
import platform

NYDUSD_BIN = "nydusd"
NYDUS_IMG_BIN = "nydus-image"

from conf import ANCHOR_PATH


class NydusAnchor:
    """
    Test environment setup, like,
        - location of test target executable
        - path to directory for data verification by comparing digest.
        - wrapper for test io engin.
    """

    def __init__(self, path=None):
        """
        :rootfs: An alias for bootstrap file.
        :verify_dir: Source directory from which to create this test image.
        """

        self.machine = platform.machine()

        if path is None:
            path = ANCHOR_PATH

        try:
            with open(path, "r") as f:
                kwargs = json.load(f)
        except FileNotFoundError:
            logging.error("Please define your own anchor file! [anchor_conf.json]")
            sys.exit(1)

        self.workspace = kwargs.pop("workspace", ".")
        # Path to be searched for nydus binaries
        self.nydus_project = kwargs.pop("nydus_project")

        # In case we want to build image on top an existed image.
        # Create an image from this parent rootfs firstly.
        # TODO: Better to specify a different file system thus to have same inode numbers.

        registry_conf = kwargs.pop("registry")
        self.registry_url = registry_conf["registry_url"]
        self.registry_auth = registry_conf["registry_auth"]
        self.registry_namespace = registry_conf["registry_namespace"]

        artifacts = kwargs.pop("artifacts")
        self.containerd_bin = artifacts["containerd"]
        self.ossutil_bin = (
            "framework/bin/ossutil64.x86"
            if self.machine != "aarch64"
            else "framework/bin/ossutil64.aarch64"
        )

        nydus_runtime_conf = kwargs.pop("nydus_runtime_conf")
        self.log_level = nydus_runtime_conf["log_level"]
        profile = nydus_runtime_conf["profile"]

        self.fs_version = kwargs.pop("fs_version", 5)

        oss_conf = kwargs.pop("oss")
        self.oss_ak_id = oss_conf["ak_id"]
        self.oss_ak_secret = oss_conf["ak_secret"]
        self.oss_bucket = oss_conf["bucket"]
        self.oss_endpoint = oss_conf["endpoint"]

        self.logging_file_path = kwargs.pop("logging_file")
        self.logging_file = self.decide_logging_file()

        self.dustbin = []
        self.tmp_dirs = []
        self.nydusd = None

        self.localfs_workdir = os.path.join(self.workspace, "localfs_workdir")
        self.nydusify_work_dir = os.path.join(self.workspace, "nydusify_work_dir")
        # Where to mount this rafs
        self.mount_point = os.path.join(self.workspace, "rafs_mnt")
        # From which directory to build rafs image
        self.blobcache_dir = os.path.join(self.workspace, "blobcache_dir")
        self.overlayfs = os.path.join(self.workspace, "overlayfs_mnt")
        self.source_dir = os.path.join(self.workspace, "gen_rootfs")
        self.parent_rootfs = os.path.join(self.workspace, "parent_rootfs")

        link_target = kwargs.pop("target")
        if link_target == "gnu":
            self.binary_release_dir = os.path.join(
                self.nydus_project, "target-fusedev/release"
            )
        elif link_target == "musl":
            arch = platform.machine()
            self.binary_release_dir = os.path.join(
                self.nydus_project,
                f"target-fusedev/{arch}-unknown-linux-musl",
                "release",
            )

        self.build_dir = os.path.join(self.nydus_project, "target-fusedev/debug")
        self.binary_debug_dir = os.path.join(self.nydus_project, "target-fusedev/debug")

        if profile == "release":
            self.binary_dir = self.binary_release_dir
        elif profile == "debug":
            self.binary_dir = self.binary_debug_dir
        else:
            sys.exit()

        self.nydusd_bin = os.path.join(self.binary_dir, NYDUSD_BIN)
        self.image_bin = os.path.join(self.binary_dir, NYDUS_IMG_BIN)
        self.nydusify_bin = os.path.join(
            self.nydus_project, "contrib", "nydusify", "cmd", "nydusify"
        )

        self.snapshotter_bin = kwargs.pop(
            "snapshotter",
            os.path.join(
                self.nydus_project,
                "contrib",
                "nydus-snapshotter",
                "bin",
                "containerd-nydus-grpc",
            ),
        )

        self.images_array = kwargs.pop("images")["images_array"]

        try:
            shutil.rmtree(self.blobcache_dir)
        except FileNotFoundError:
            pass

        os.makedirs(self.blobcache_dir)
        os.makedirs(self.mount_point, exist_ok=True)
        os.makedirs(self.overlayfs, exist_ok=True)

    def put_dustbin(self, path):
        self.dustbin.append(path)

    def cleanup_dustbin(self):
        for p in self.dustbin:
            if isinstance(p, utils.ArtifactProcess):
                p.shutdown()
            else:
                os.unlink(p)

    def check_prerequisites(self):
        assert os.path.exists(self.source_dir), "Verification direcotry not existed!"
        assert os.path.exists(self.blobcache_dir), "Blobcache diretory not existed!"
        assert len(os.listdir(self.blobcache_dir)) == 0, "Blobcache diretory not empty!"
        assert not os.path.ismount(self.mount_point), "Mount point was already mounted"

    def clear_blobcache(self):
        try:
            if os.listdir(self.blobcache_dir) == 0:
                return

            # Under some cases, blob cache dir is temporarily mounted.
            if os.path.ismount(self.blobcache_dir):
                utils.execute(["umount", self.blobcache_dir])

            shutil.rmtree(self.blobcache_dir)
            logging.info("Cleared cache %s", self.blobcache_dir)
            os.mkdir(self.blobcache_dir)
        except Exception as exc:
            print(exc)

    def prepare_scratch_dir(self):
        self.scratch_dir = os.path.join(
            self.workspace,
            os.path.basename(os.path.normpath(self.source_dir)) + "_scratch",
        )

        # We don't delete the scratch dir because it helps to analyze prolems.
        # But if another round of test trip begins, no need to keep it anymore.
        if os.path.exists(self.scratch_dir):
            shutil.rmtree(self.scratch_dir)

        shutil.copytree(self.source_dir, self.scratch_dir, symlinks=True)

    def prepare_scratch_parent_dir(self):
        self.scratch_parent_dir = os.path.join(
            self.workspace,
            os.path.basename(os.path.normpath(self.parent_rootfs)) + "_scratch",
        )

        # We don't delete the scratch dir because it helps to analyze prolems.
        # But if another round of test trip begins, no need to keep it anymore.
        if os.path.exists(self.scratch_parent_dir):
            shutil.rmtree(self.scratch_parent_dir)

        shutil.copytree(self.parent_rootfs, self.scratch_parent_dir, symlinks=True)

    @staticmethod
    def check_nydusd_health():
        pid_list = utils.get_pid(NYDUSD_BIN)

        if len(pid_list) == 1:
            return True
        else:
            logging.error("Captured nydusd process %s", pid_list)
            return False

    @staticmethod
    def capture_running_nydusd():
        pid_list = utils.get_pid(NYDUSD_BIN)

        if len(pid_list) != 0:
            logging.info("Captured nydusd process %s", pid_list)
            # Kill remaining nydusd thus not to affect following cases.
            # utils.kill_all_processes(NYDUSD_BIN, signal.SIGINT)
            time.sleep(2)
            return True
        else:
            return False

    def mount_overlayfs(self, layers, base=os.getcwd()):
        """
        We usually use overlayfs to act as a verifying dir. Some cases may scratch
        the oringal source dir.
        :source_dir: A directroy acts on a layer of overlayfs, from which to build the image
        :layers: tail item from layers is the bottom layer.
        Cited:

        ```
        Multiple lower layers
        ---------------------

        Multiple lower layers can now be given using the the colon (":") as a
        separator character between the directory names.  For example:

        mount -t overlay overlay -o lowerdir=/lower1:/lower2:/lower3 /merged

        As the example shows, "upperdir=" and "workdir=" may be omitted.  In
        that case the overlay will be read-only.

        The specified lower directories will be stacked beginning from the
        rightmost one and going left.  In the above example lower1 will be the
        top, lower2 the middle and lower3 the bottom layer.
        ```
        """

        handled_layers = [l.replace(":", "\\:") for l in layers]

        if len(handled_layers) == 1:
            self.sticky_lower_dir = tempfile.TemporaryDirectory(dir=self.workspace)
            handled_layers.append(self.sticky_lower_dir.name)

        layers_set = ":".join(handled_layers)
        with utils.pushd(base):
            cmd = [
                "mount",
                "-t",
                "overlay",
                "-o",
                f"lowerdir={layers_set}",
                "rafs_ci_overlay",
                self.overlayfs,
            ]

            ret, _ = utils.execute(cmd)
            assert ret

    def umount_overlayfs(self):
        cmd = ["umount", self.overlayfs]
        ret, _ = utils.execute(cmd)
        assert ret

    def decide_logging_file(self):
        try:
            p = os.environ["LOG_FILE"]
            return open(p, "w+")
        except KeyError:
            if self.logging_file_path == "stdin":
                return sys.stdin
            elif self.logging_file_path == "stderr":
                return sys.stderr
            else:
                return open(self.logging_file_path, "w+")


def check_fuse_conn(func):
    last_conn_id = 0
    print("last conn id %d" % last_conn_id)

    def wrapped():
        conn_id = func()
        if last_conn_id != 0:
            assert last_conn_id == conn_id
        else:
            last_conn_id == conn_id
        return conn_id

    return wrapped


# @check_fuse_conn
def inspect_sys_fuse():
    sys_fuse_path = "/sys/fs/fuse/connections"
    try:
        conns = os.listdir(sys_fuse_path)
        frameinfo = getframeinfo(stack()[1][0])
        logging.info(
            "%d | %d fuse connections: %s" % (frameinfo.lineno, len(conns), conns)
        )
        conn_id = int(conns[0])
        return conn_id
    except Exception as exc:
        logging.exception(exc)
