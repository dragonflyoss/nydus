import sys
import os
from argparse import ArgumentParser
import logging

sys.path.append(os.path.realpath("framework"))
from nydus_anchor import NydusAnchor

from oss import OssHelper

ANCHOR = NydusAnchor()


class ArtifactManager:
    def __init__(self) -> None:
        super().__init__()
        envs = os.environ
        endpoint = ANCHOR.oss_endpoint
        ak_id = ANCHOR.oss_ak_id
        ak_secret = ANCHOR.oss_ak_secret
        bucket = ANCHOR.oss_bucket
        self.oss_helper = OssHelper(
            ANCHOR.ossutil_bin,
            endpoint,
            bucket,
            ak_id,
            ak_secret,
            prefix="nydus_test_artifacts/",
        )

    def fetch(self, artifact):
        self.oss_helper.download(artifact, os.getcwd())

    def push(self, artifact):
        self.oss_helper.upload(artifact, os.path.basename(artifact), force=True)

    def list(self):
        self.oss_helper.list()


def push_set_args(subparsers):
    push_parser = subparsers.add_parser("push")
    push_parser.add_argument(
        "--artifacts", dest="artifacts", required=True, type=str, nargs="+"
    )


def fetch_set_args(subparsers):
    fetch_parser = subparsers.add_parser("fetch")
    fetch_parser.add_argument(
        "--artifacts", dest="artifacts", required=True, type=str, nargs="+"
    )


def list_set_args(subparsers):
    fetch_parser = subparsers.add_parser("list")


if __name__ == "__main__":
    parser = ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode")
    push_set_args(subparsers)
    fetch_set_args(subparsers)
    list_set_args(subparsers)

    args = parser.parse_args()

    artifacts_manager = ArtifactManager()
    if args.mode == "push":
        artifacts = args.artifacts
        for a in artifacts:
            artifacts_manager.push(a)
    elif args.mode == "fetch":
        artifacts = args.artifacts
        for a in artifacts:
            artifacts_manager.fetch(a)
    elif args.mode == "list":
        artifacts_manager.list()
