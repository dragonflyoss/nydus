import yaml
import tempfile
from string import Template
import json
import time
import uuid

import utils


POD_CONF = """
metadata:
  attempt: 1
  name: nydus-sandbox
  namespace: default
  uid: ${uid}
log_directory: /tmp
linux:
  security_context:
    namespace_options:
      network: 2
"""

# annotations:
# "io.containerd.osfeature": "nydus.remoteimage.v1"


CONTAINER_CONF = """
metadata:
  name: ${container_name}
image:
  image: ${image}
log_path: container.1.log
command: ["sh"]
"""


class Cri:
    def __init__(self, runtime_endpoint, image_endpoint) -> None:
        config = dict()
        config["runtime-endpoint"] = f"unix://{runtime_endpoint}"
        config["image-endpoint"] = f"unix://{image_endpoint}"
        config["timeout"] = 10
        config["debug"] = False

        self._config = tempfile.NamedTemporaryFile(
            mode="w+", suffix="crictl.config", delete=False
        )
        yaml.dump(config, self._config)

    def run_container(
        self,
        image,
        container_name,
    ):
        container_config = tempfile.NamedTemporaryFile(
            mode="w+", suffix="container.config.yaml", delete=True
        )
        pod_config = tempfile.NamedTemporaryFile(
            mode="w+", suffix="pod.config.yaml", delete=True
        )
        print(pod_config.read())

        _s = Template(CONTAINER_CONF).substitute(
            image=image, container_name=container_name
        )

        container_config.write(_s)
        container_config.flush()
        pod_config.write(
            Template(POD_CONF).substitute(
                uid=uuid.uuid4(),
            )
        )
        pod_config.flush()

        ret, _ = utils.execute(
            [
                "crictl",
                "--config",
                self._config.name,
                "run",
                container_config.name,
                pod_config.name,
            ],
            print_err=True,
        )

        assert ret

    def stop_rm_container(self, id):
        cmd = [
            "crictl",
            "--config",
            self._config.name,
            "stop",
            id,
        ]
        ret, _ = utils.execute(cmd)

        assert ret

        cmd = [
            "crictl",
            "--config",
            self._config.name,
            "rm",
            id,
        ]
        ret, _ = utils.execute(cmd)

        assert ret

    def list_images(self):
        cmd = [
            "crictl",
            "--config",
            self._config.name,
            "images",
            "--output",
            "json",
        ]
        ret, out = utils.execute(cmd)
        assert ret
        images = json.loads(out)
        return images["images"]

    def remove_image(self, repo):
        images = self.list_images()
        for i in images:
            # Example:
            # {'id': 'sha256:cc6e5af55020252510374deecb0168fc7170b5621e03317cb7c4192949becb9a',
            # 'repoTags': ['reg.docker.alibaba-inc.com/chge-nydus-test/busybox:latest_converted'], 'repoDigests': ['reg.docker.alibaba-inc.com/chge-nydus-test/busybox@sha256:07592f0848a6752de1b58f06b8194dbeaff1cb3314ab3225b6ab698abac1185d'], 'size': '998569', 'uid': None, 'username': ''}
            if i["repoTags"][0] == repo:
                id = i["id"]
                cmd = [
                    "crictl",
                    "--config",
                    self._config.name,
                    "rmi",
                    id,
                ]
                ret, _ = utils.execute(cmd)
                assert ret
                return True
        assert False
        return False

    def check_container_status(self, name, timeout):
        """
        {
        "containers": [
            {
            "id": "4098985ed96655dbd43eef2d6502197598b72fe40cfec4cb77466aedf755807f",
            "podSandboxId": "2ae536d3481130d8a47a05fb6ffeb303cb3d57b29e8744d3ffcbbc27377ece3d",
            "metadata": {
                "name": "nydus-container",
                "attempt": 0
            },
            "image": {
                "image": "reg.docker.alibaba-inc.com/chge-nydus-test/mysql:latest_converted"
            },
            "imageRef": "sha256:68e06967547192d5eaf406a21ea39b3131f86e9dc8fb8b75e2437a1bde8d0aad",
            "state": "CONTAINER_EXITED",
            "createdAt": "1610018967168325132",
            "labels": {
            },
            "annotations": {
            }
            }
        ]
        }

        ---

        {
        "status": {
            "id": "4098985ed96655dbd43eef2d6502197598b72fe40cfec4cb77466aedf755807f",
            "metadata": {
            "attempt": 0,
            "name": "nydus-container"
            },
            "state": "CONTAINER_EXITED",
            "createdAt": "2021-01-07T19:29:27.168325132+08:00",
            "startedAt": "2021-01-07T19:29:28.172706527+08:00",
            "finishedAt": "2021-01-07T19:29:32.882263863+08:00",
            "exitCode": 0,
            "image": {
            "image": "reg.docker.alibaba-inc.com/chge-nydus-test/mysql:latest_converted"
            },
            "imageRef": "reg.docker.alibaba-inc.com/chge-nydus-test/mysql@sha256:ebadc23a8b2cbd468cb86ab5002dc85848e252de71cdc4002481f63a1d3c90be",
            "reason": "Completed",
            "message": "",
            "labels": {},
            "annotations": {},
            "mounts": [],
            "logPath": "/tmp/container.1.log"
        },
        """
        elapsed = 0
        while elapsed <= timeout:
            ps_cmd = [
                "crictl",
                "--config",
                self._config.name,
                "ps",
                "-a",
                "--output",
                "json",
            ]

            ret, out = utils.execute(
                ps_cmd,
                print_err=True,
            )

            assert ret
            containers = json.loads(out)
            for c in containers["containers"]:
                # The container is found, no need to wait anylonger
                if c["metadata"]["name"] == name:
                    id = c["id"]
                    inspect_cmd = [
                        "crictl",
                        "--config",
                        self._config.name,
                        "inspect",
                        id,
                    ]
                    ret, out = utils.execute(inspect_cmd)
                    assert ret
                    status = json.loads(out)
                    if status["status"]["exitCode"] == 0:
                        return id, True
                    else:
                        return None, False

            time.sleep(1)
            elapsed += 1

        return None, False
