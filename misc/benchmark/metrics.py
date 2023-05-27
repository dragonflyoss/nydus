#!/usr/bin/env python3
import csv
import json
import os
import posixpath
import random
import re
import shutil
import string
import subprocess
import sys
import time
import urllib.request
from typing import Tuple

import bench

"""
define some file path, and sock api url
"""
LOG_DIR = "log"
TEMP_DIR = "tmp"
URL_PREFIX = "http://localhost/api"
ACCESS_PATTERN_METRICS = "/v1/metrics/pattern"
BACKEND_METRICS = "/v1/metrics/backend"
BOOTSTRAP_DIR = "/var/lib/containerd-nydus/snapshots"
API_DIR = "/var/lib/containerd-nydus/socket"


class MetricsCollector:
    def __init__(self, cfg: dict):
        self.registry = cfg["registry"]
        self.insecure_registry = cfg["insecure_registry"]
        self.image = cfg["image"]

    def start_collet(self) -> str:
        runner = bench.BenchRunner(
            registry=self.registry,
            snapshotter="nydus",
            insecure_registry=self.insecure_registry,
        )
        image_ref = self.image_ref(self.image)
        container_name = self.image.replace(":", "-") + random_string()
        pull_cmd = self.pull_cmd(image_ref)
        print(pull_cmd)
        print("Pulling image %s ..." % image_ref)
        rc = os.system(pull_cmd)
        assert rc == 0
        repo = bench.image_repo(self.image)
        if repo in bench.BenchRunner.CMD_URL_WAIT:
            self.run_cmd_url_wait(runner=runner, runargs=bench.BenchRunner.CMD_URL_WAIT[repo], image_ref=image_ref, container_name=container_name)
        elif repo in bench.BenchRunner.CMD_ARG:
            self.run_cmd_arg(runner=runner, runargs=bench.BenchRunner.CMD_ARG[repo], image_ref=image_ref, container_name=container_name)
        elif repo in bench.BenchRunner.CMD_STDIN:
            self.run_cmd_stdin(runner=runner, runargs=bench.BenchRunner.CMD_STDIN[repo], image_ref=image_ref, container_name=container_name)
        else:
            print("Unknown bench: " + repo)
            os.exit(1)
        file = self.collect(self.image)
        self.clean_up(image_ref, container_name)
        return file

    def image_ref(self, repo):
        return posixpath.join(self.registry, repo)

    def pull_cmd(self, image_ref):
        insecure_flag = "--insecure-registry" if self.insecure_registry else ""
        return (
            f"sudo nerdctl --snapshotter nydus pull {insecure_flag} {image_ref}"
        )

    def stop_container_cmd(self, container_id):
        return f"sudo nerdctl --snapshotter nydus stop {container_id}"

    def run_cmd_url_wait(self, runner, runargs, image_ref, container_name):

        create_cmd = runner.create_cmd_url_wait_cmd(image_ref, container_name, runargs)
        print(create_cmd)

        print("Creating container for image %s ..." % image_ref)
        rc = os.system(create_cmd)
        assert rc == 0

        run_cmd = runner.task_start_cmd(container_name, iteration=False)
        print(run_cmd)

        print("Running container %s ..." % container_name)

        _ = subprocess.Popen(run_cmd, shell=True)
        while True:
            try:
                req = urllib.request.urlopen(runargs.waitURL)
                print(req.status)
                req.close()
                break
            except:
                time.sleep(0.01)

    def run_cmd_arg(self, runner, runargs, image_ref, container_name):
        assert len(runargs.mount) == 0

        create_cmd = runner.create_cmd_arg_cmd(image_ref, container_name, runargs)
        print(create_cmd)

        print("Creating container for image %s ..." % image_ref)
        rc = os.system(create_cmd)
        assert rc == 0

        run_cmd = runner.task_start_cmd(container_name, iteration=False)
        print(run_cmd)
        rc = os.system(run_cmd)
        assert rc == 0

    def run_cmd_stdin(self, runner, runargs, image_ref, container_name):

        create_cmd = runner.create_cmd_stdin_cmd(image_ref, container_name, runargs)
        print(create_cmd)

        print("Creating container for image %s ..." % image_ref)
        rc = os.system(create_cmd)
        assert rc == 0

        run_cmd = runner.task_start_cmd(container_name, iteration=True)
        print(run_cmd)

        print("Running container %s ..." % container_name)

        p = subprocess.Popen(
            run_cmd,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=sys.stdout,
            stderr=sys.stdout,
            bufsize=0,
        )

        print(runargs.stdin)
        stdin = runargs.stdin + "\nexit\n"
        p.communicate(stdin.encode())
        assert p.returncode == 0

    def clean_up(self, image_ref, container_id):
        print("Cleaning up environment for %s ..." % container_id)
        cmd = self.stop_container_cmd(container_id)
        print(cmd)
        rc = os.system(cmd)
        assert rc == 0
        cmd = f"sudo nerdctl --snapshotter nydus rm -f {container_id}"
        print(cmd)
        rc = os.system(cmd)
        assert rc == 0
        cmd = f"sudo nerdctl --snapshotter nydus rmi -f {image_ref}"
        print(cmd)
        rc = os.system(cmd)
        assert rc == 0

    def collect(self, repo) -> str:
        """
            collect the access files
        """
        socket = search_file(API_DIR, "api.sock")
        if socket == None:
            print("can't find the api.sock")
            exit(1)
        bootstrap = search_file(BOOTSTRAP_DIR, "image.boot")
        if bootstrap == None:
            print("can't find the bootstrap")
            exit(1)

        # bootstrap
        bootstap_data = check_bootstrap(bootstrap)

        # access_pattern
        access_pattern = get_access_pattern(socket, bootstap_data)

        header = ["file_path", "first_access_time", "file_size"]

        file_name = posixpath.join(repo + ".csv")
        if not os.path.exists(file_name):
            os.mknod(file_name)
        with open(file_name, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(header)
            for item in access_pattern:
                writer.writerow(
                    [item.file_path, item.first_access_time_secs * 10**9 + item.first_access_time_nanos, item.file_size])
        return file_name


def get_file_by_bootstrap(bootstrap, inode):
    """
    load the data of bootstrap
    """
    with open(bootstrap, 'r') as file:
        for line in file:
            if line.startswith("inode:"):
                result = re.search(r'"([^"]+)".*ino (\d+).*i_size (\d+)', line)
                value_file_path = result.group(1)
                value_ino = result.group(2)
                value_file_size = result.group(3)
                if int(value_ino) == inode:
                    return value_file_path, value_file_size
    return None, None


def check_bootstrap(bootstrap):
    """
    use nydus-image to get the data of bootstap
    """
    file_path = random_string()
    cmd = ["sudo", "nydus-image", "check"]
    cmd.extend(["-B", bootstrap, "-v"])
    with open(TEMP_DIR + "/" + file_path, 'w') as f:
        _ = run_cmd(
            cmd,
            shell=True,
            stdout=f,
            stderr=f,
        )
    return TEMP_DIR + "/" + file_path


class AccessPattern:
    def __init__(self, file_path, first_access_time_secs, first_access_time_nanos, file_size):
        self.file_path = file_path
        self.first_access_time_secs = first_access_time_secs
        self.first_access_time_nanos = first_access_time_nanos
        self.file_size = file_size


def get_access_pattern(sock, bootstap_data):
    """
    get the file access pattern from the sock
    """
    contents = ""
    # The api occasionally returns incomplete information
    while contents.endswith("]") == False:
        with open(send_request(sock, ACCESS_PATTERN_METRICS), 'r') as file:
            contents = file.read()
    resp = json.loads(contents)
    access_pattern_list = []
    for item in resp:
        item['first_access_time_secs'] = item['first_access_time_secs']
        item["first_access_time_nanos"] = item["first_access_time_nanos"]
        file_path, file_size = get_file_by_bootstrap(bootstap_data, item['ino'])
        access_pattern_list.append(AccessPattern(
            file_path, item['first_access_time_secs'], item['first_access_time_nanos'], file_size))
    return access_pattern_list


def get_backend_metrics(sock) -> dict:
    """
    get the backend metrics from the sock
    """
    with open(send_request(sock, BACKEND_METRICS), 'r') as file:
        content = file.read()

    return eval(content)


def random_string():
    """
    generate a random string of fixed length
    """
    return "".join(random.choice(string.ascii_lowercase) for _ in range(10))


def search_file(root_dir, file_name):
    """
    search the bootsatrap and api.scok of the image, but only return the first match file,
    so we need to clear the images and containers befor we start metrics.py
    """
    for subdir, _, files in os.walk(root_dir):
        if file_name in files:
            return os.path.join(subdir, file_name)
    return None


def send_request(sock_path, url):
    """
    send request to the local socket with the url.
    save the response in the file.
    """
    file_path = random_string()
    cmd = ["sudo", "curl", "--unix-socket", sock_path]
    cmd.extend(["-X", "GET", URL_PREFIX + url])
    with open(TEMP_DIR + "/" + file_path, 'w') as f:
        _ = run_cmd(
            cmd,
            shell=True,
            stdout=f,
            stderr=subprocess.PIPE
        )
    return TEMP_DIR + "/" + file_path


def run_cmd(cmd, wait: bool = True, **kwargs):
    """
    run a cmd with the subprocess
    """
    shell = kwargs.pop("shell", False)
    if shell:
        cmd = " ".join(cmd)
    popen_obj = subprocess.Popen(cmd, shell=shell, **kwargs)
    if wait:
        popen_obj.wait()
    return popen_obj.returncode, popen_obj


def init():
    if os.path.exists(TEMP_DIR):
        if os.path.isdir(TEMP_DIR):
            shutil.rmtree(TEMP_DIR)
        else:
            os.remove(TEMP_DIR)
    os.mkdir(TEMP_DIR)


def collect_access(local_registry, insecure_local_registry, image) -> str:
    """
    collect access pattern for benchmark.py
    """
    init()
    cfg = {"registry": local_registry, "insecure_registry": insecure_local_registry, "image": image}
    file = MetricsCollector(cfg).start_collet()
    shutil.rmtree(TEMP_DIR)
    return file


def collect_backend() -> Tuple[str, str]:
    """
    collect backend metrics for benchmark.py

    return (Read Amount, Read Count)
    """
    init()
    socket = search_file(API_DIR, "api.sock")
    if socket == None:
        print("can't find the api.sock")
        exit(1)
    backend = get_backend_metrics(socket)
    shutil.rmtree(TEMP_DIR)
    return round(backend["read_amount_total"] / 1024 / 1024, 2), backend["read_count"]


def collect_size(repo: str, tag: str):
    """
    collect image size for benchmark

    return the image size
    """
    init()
    file_path = random_string()
    cmd = ["sudo", "curl", "-H", "'Accept: application/vnd.docker.distribution.manifest.v2+json'"]
    cmd.extend([f"localhost:5000/v2/{repo}/manifests/{tag}"])
    with open(TEMP_DIR + "/" + file_path, 'w') as f:
        _ = run_cmd(
            cmd,
            shell=True,
            stdout=f,
            stderr=subprocess.PIPE
        )
    with open(TEMP_DIR + "/" + file_path, 'r') as file:
        content = file.read()
        if "errors" in content:
            file_path_zran = random_string()
            cmd = ["sudo", "curl", "-H", "'Accept: application/vnd.oci.image.manifest.v1+json'"]
            cmd.extend([f"localhost:5000/v2/{repo}/manifests/{tag}"])
            with open(TEMP_DIR + "/" + file_path_zran, 'w') as f:
                _ = run_cmd(
                    cmd,
                    shell=True,
                    stdout=f,
                    stderr=subprocess.PIPE
                )
            with open(TEMP_DIR + "/" + file_path_zran, 'r') as file_zran:
                content = file_zran.read()
    manifest = json.loads(content)
    size = 0
    for item in manifest["layers"]:
        size += item["size"]
    shutil.rmtree(TEMP_DIR)
    return round(size / 1024 / 1024, 2)
