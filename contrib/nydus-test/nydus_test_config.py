import os
import sys
import json
import shutil
import random
import logging
import random
import yaml
from argparse import ArgumentParser

sys.path.append(os.path.realpath("framework"))
from nydus_anchor import NydusAnchor
from distributor import Distributor
import utils
from utils import Size, logging_setup

logging_setup()

ANCHOR = NydusAnchor()


def define_fs_structure(structure_dist):
    with open(structure_dist) as fd:
        fs_dist = yaml.safe_load(fd)

    return fs_dist


def put_files(dist: Distributor, f_type, count, size):
    """Example:
    depth: 4
    width: 4
    layers:
    - layer1:
        - size: 10KB
            type: regular
            count: 2000
        - size: 12MB
            type: regular
            count: 10
        - size: 90MB
            type: regular
            count: 1
        - type: symlink
            count: 100

    """

    logging.info("puting %s, count %d", f_type, count)
    if f_type == "regular":
        size_in_bytes = utils.parse_size(size)
        dist.put_multiple_files(count, Size(size_in_bytes))
    elif f_type == "dir":
        dist.put_directories(count)
    elif f_type == "symlink":
        dist.put_symlinks(count)
    elif f_type == "hardlink":
        dist.put_hardlinks(count)


if __name__ == "__main__":
    workspace = ANCHOR.workspace
    generated_rootfs = ANCHOR.source_dir
    generated_parent_rootfs = ANCHOR.parent_rootfs

    parser = ArgumentParser()
    parser.add_argument(
        "-D",
        "--dist",
        help="A Yaml to define file system structure",
        type=str,
        default="",
    )

    args = parser.parse_args()
    dist_define = args.dist

    try:
        shutil.rmtree(generated_rootfs)
    except FileNotFoundError:
        pass

    try:
        shutil.rmtree(generated_parent_rootfs)
    except FileNotFoundError:
        pass

    os.mkdir(generated_rootfs)
    os.mkdir(generated_parent_rootfs)

    fs_dist = define_fs_structure(dist_define)

    depth = fs_dist["depth"]
    width = fs_dist["width"]
    layers_desc = fs_dist["layers"]

    dist = Distributor(generated_rootfs, depth, width)
    dist.generate_tree()

    for ld in layers_desc:
        with utils.timer("Generating test layer"):
            for d in ld.values():
                for f in d:
                    try:
                        size = f["size"]
                    except KeyError:
                        size = None
                    put_files(dist, f["type"], f["count"], size)

    parent_dist = Distributor(generated_parent_rootfs, depth, width)
    parent_dist.generate_tree()

    for ld in layers_desc:
        with utils.timer("Generating test parent layer"):
            for d in ld.values():
                for f in d:
                    try:
                        size = f["size"]
                    except KeyError:
                        size = None
                    put_files(parent_dist, f["type"], f["count"], size)
