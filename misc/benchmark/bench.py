#!/usr/bin/env python3
"""
    bench.py references the repo[https://github.com/nydusaccelerator/hello-bench].
"""
import copy
import json
import logging
import os
import posixpath
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager
from datetime import datetime
from io import TextIOWrapper

import metrics


def logging_setup(logging_stream=sys.stderr):
    root = logging.getLogger()

    if root.hasHandlers():
        return

    verbose = True

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


logging_setup()


def run(cmd, wait: bool = True, verbose=True, **kwargs):

    shell = kwargs.pop("shell", False)
    if shell:
        cmd = " ".join(cmd)

    if verbose:
        logging.info(cmd)
    else:
        logging.debug(cmd)

    popen_obj = subprocess.Popen(cmd, shell=shell, **kwargs)
    if wait:
        popen_obj.wait()
    return popen_obj.returncode, popen_obj


def get_current_time():
    return datetime.now()


def delta_time(t_end, t_start):
    delta = t_end - t_start
    return delta.total_seconds(), delta.microseconds


@contextmanager
def timer(cmd):
    start = get_current_time()
    try:
        rc = os.system(cmd)
        assert rc == 0
        end = get_current_time()
        sec, usec = delta_time(end, start)
        yield sec + usec / 1e6
        logging.info("%s, Takes time %u.%u seconds", cmd, sec, usec)
    finally:
        pass


class RunArgs:
    def __init__(
        self, waitURL=""
    ):
        self.waitURL = waitURL


class Bench:
    def __init__(self, name, category="other"):
        self.name = name
        self.category = category

    def __str__(self):
        return json.dumps(self.__dict__)

    def set_tag(self, tag):
        self.name = f"{self.name}:{tag}"


class BenchRunner:
    CMD_URL_WAIT = {
        "wordpress": RunArgs(waitURL="http://localhost:80"),
    }

    # complete listing
    ALL = dict(
        [
            ("wordpress", Bench("wordpress", "web-framework")),
        ]
    )

    def __init__(
        self,
        registry="localhost:5000",
        snapshotter="overlayfs",
        cleanup=True,
        insecure_registry=False,
    ):
        self.registry = registry
        if self.registry != "":
            self.registry += "/"

        self.snapshotter = snapshotter
        self.insecure_registry = insecure_registry

        self.cleanup = cleanup

    def image_ref(self, repo):
        return posixpath.join(self.registry, repo)

    def run(self, bench):
        repo = image_repo(bench.name)
        if repo in BenchRunner.CMD_URL_WAIT:
            return self.run_cmd_url_wait(
                repo=bench.name, runargs=BenchRunner.CMD_URL_WAIT[repo]
            )
        else:
            print("Unknown bench: " + repo)
            sys.exit(1)

    def run_cmd_url_wait(self, repo, runargs):
        image_ref = self.image_ref(repo)
        container_id = repo.replace(":", "-")

        pull_cmd = self.pull_cmd(image_ref)
        print(pull_cmd)
        print("Pulling image %s ..." % image_ref)
        with timer(pull_cmd) as t:
            pull_elapsed = t

        create_cmd = self.create_cmd_url_wait_cmd(image_ref, container_id, runargs)
        print(create_cmd)

        print("Creating container for image %s ..." % image_ref)
        with timer(create_cmd) as t:
            create_elapsed = t

        run_cmd = self.task_start_cmd(container_id, iteration=False)
        print(run_cmd)

        print("Running container %s ..." % container_id)
        start_run = datetime.now()

        _ = subprocess.Popen(run_cmd, shell=True)
        while True:
            try:
                req = urllib.request.urlopen(runargs.waitURL)
                print(req.status)
                req.close()
                break
            except:
                time.sleep(0.01)

        end_run = datetime.now()
        run_elapsed = datetime.timestamp(end_run) - datetime.timestamp(start_run)

        print("Run time: %f s" % run_elapsed)

        read_amount, read_count = "-", "-"
        if self.snapshotter == "nydus":
            read_amount, read_count = metrics.collect_backend()
        image_size = metrics.collect_size(image_repo(repo), image_tag(repo))

        if self.cleanup:
            self.clean_up(image_ref, container_id)

        return pull_elapsed, create_elapsed, run_elapsed, image_size, read_amount, read_count

    def pull_cmd(self, image_ref):
        insecure_flag = "--insecure-registry" if self.insecure_registry else ""
        return (
            f"sudo nerdctl --snapshotter {self.snapshotter} pull {insecure_flag} {image_ref}"
        )

    def create_cmd_url_wait_cmd(self, image_ref, container_id, runargs):
        cmd = f"sudo nerdctl --snapshotter {self.snapshotter} create --net=host "
        cmd += f"--name={container_id} {image_ref}"
        return cmd

    def task_start_cmd(self, container_id, iteration: bool):
        if iteration:
            return f"sudo nerdctl --snapshotter {self.snapshotter} start -a {container_id}"
        else:
            return f"sudo nerdctl --snapshotter {self.snapshotter} start {container_id}"

    def task_kill_cmd(self, container_id):
        return f"sudo nerdctl --snapshotter {self.snapshotter} stop {container_id}"

    def clean_up(self, image_ref, container_id):
        print("Cleaning up environment for %s ..." % container_id)
        cmd = self.task_kill_cmd(container_id)
        print(cmd)
        rc = os.system(cmd)  # sometimes containers already exit. we ignore the failure.
        cmd = f"sudo nerdctl --snapshotter {self.snapshotter} rm -f {container_id}"
        print(cmd)
        rc = os.system(cmd)
        assert rc == 0
        cmd = f"sudo nerdctl --snapshotter {self.snapshotter} rmi -f {image_ref}"
        print(cmd)
        rc = os.system(cmd)
        assert rc == 0


def image_repo(ref: str):
    return ref.split(":")[0]


def image_tag(ref: str) -> str:
    try:
        return ref.split(":")[1]
    except IndexError:
        return None


def bench_image(local_registry, insecure_local_registry, image, f: TextIOWrapper, snapshotter="overlayfs"):
    try:
        bench = copy.deepcopy(BenchRunner.ALL[image_repo(image)])
        tag = image_tag(image)
        if tag is not None:
            bench.set_tag(tag)
    except KeyError:
        logging.warning("image %s not supported, skip", image)
        sys.exit(1)
    runner = BenchRunner(
        registry=local_registry,
        snapshotter=snapshotter,
        cleanup=True,
        insecure_registry=insecure_local_registry,
    )
    pull_elapsed, create_elapsed, run_elapsed, image_size, read_amount, read_count = runner.run(bench)
    total_elapsed = f"{pull_elapsed + create_elapsed + run_elapsed: .2f}"
    pull_elapsed = f"{pull_elapsed: .2f}"
    create_elapsed = f"{create_elapsed: .2f}"
    run_elapsed = f"{run_elapsed: .2f}"
    line = f"{pull_elapsed},{create_elapsed},{run_elapsed},{total_elapsed},{image_size},{read_amount},{read_count}"
    f.writelines(line + "\n")
    f.flush()
