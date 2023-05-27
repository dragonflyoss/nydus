import os
import tempfile
import utils


class Snapshotter(utils.ArtifactProcess):
    def __init__(self, anchor: "NydusAnchor") -> None:
        self.anchor = anchor
        self.snapshotter_bin = anchor.snapshotter_bin
        self.__sock = tempfile.NamedTemporaryFile(suffix="snapshotter.sock")
        self.flags = []

    def sock(self):
        return self.__sock.name

    def set_root(self, dir):
        self.root = os.path.join(dir, "io.containerd.snapshotter.v1.nydus")

    def cache_dir(self):
        return os.path.join(self.root, "cache")

    def run(self, rafs_conf: os.PathLike):

        cmd = [
            self.snapshotter_bin,
            "--nydusd-path",
            self.anchor.nydusd_bin,
            "--config-path",
            rafs_conf,
            "--root",
            self.root,
            "--address",
            self.__sock.name,
            "--log-level",
            "info",
            "--log-to-stdout",
        ]

        cmd = cmd + self.flags

        ret, self.p = utils.run(
            cmd,
            wait=False,
            shell=False,
            stdout=self.anchor.logging_file,
            stderr=self.anchor.logging_file,
        )

    def shared_mount(self):
        self.flags.append("--shared-daemon")
        return self

    def enable_nydus_overlayfs(self):
        self.flags.append("--enable-nydus-overlayfs")
        return self

    def shutdown(self):
        self.p.terminate()
        self.p.wait()
