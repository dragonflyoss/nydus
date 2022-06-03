import tempfile
import subprocess
import toml
import os

from snapshotter import Snapshotter
import utils


class Containerd(utils.ArtifactProcess):
    state_dir = "/run/nydus-test_containerd"

    def __init__(self, anchor, snapshotter: Snapshotter) -> None:
        self.anchor = anchor
        self.containerd_bin = anchor.containerd_bin
        self.snapshotter = snapshotter

    def gen_config(self):
        _, p = utils.run(
            [self.containerd_bin, "config", "default"], stdout=subprocess.PIPE
        )
        out, _ = p.communicate()
        config = toml.loads(out.decode())
        config["state"] = self.state_dir
        self.__address = config["grpc"]["address"] = os.path.join(
            self.state_dir, "containerd.sock"
        )
        config["plugins"]["io.containerd.grpc.v1.cri"]["containerd"][
            "snapshotter"
        ] = "nydus"
        config["plugins"]["io.containerd.grpc.v1.cri"]["sandbox_image"] = "google/pause"
        config["plugins"]["io.containerd.grpc.v1.cri"]["containerd"][
            "disable_snapshot_annotations"
        ] = False
        config["plugins"]["io.containerd.runtime.v1.linux"]["no_shim"] = True

        self.__root = tempfile.TemporaryDirectory(
            dir=self.anchor.workspace, suffix="root"
        )
        config["root"] = self.__root.name

        config["proxy_plugins"] = {
            "nydus": {
                "type": "snapshot",
                "address": self.snapshotter.sock(),
            }
        }

        self.config = tempfile.NamedTemporaryFile(mode="w", suffix="config.toml")
        self.config.write(toml.dumps(config))
        self.config.flush()

        return self

    @property
    def root(self):
        return self.__root.name

    def run(self):
        _, self.p = utils.run(
            [self.containerd_bin, "--config", self.config.name],
            wait=False,
            stdout=self.anchor.logging_file,
            stderr=self.anchor.logging_file,
        )

    @property
    def address(self):
        return self.__address

    def remove_image_sync(self, repo):
        cmd = [
            "ctr",
            "-n",
            "k8s.io",
            "-a",
            self.__address,
            "images",
            "rm",
            repo,
            "--sync",
        ]
        ret, out = utils.execute(cmd)
        assert ret

    def shutdown(self):
        self.p.terminate()
        self.p.wait()
