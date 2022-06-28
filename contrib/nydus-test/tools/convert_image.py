from logging import log
import os
import sys
from argparse import ArgumentParser

sys.path.append(os.path.realpath("framework"))

from nydus_anchor import NydusAnchor
from nydusify import Nydusify
from utils import logging_setup

logging_setup()


# alpine:3.10.2 fedora:30 rethinkdb:2.3.6 postgres:13.1 redis:5.0.5 mariadb:10.5 python:3.9 golang:1.12.9 gcc:10.2.0 jruby:9.2.8.0
# perl:5.30 php:7.3.8 pypy:3.5 r-base:3.6.1 drupal:8.7.6 jenkins:2.60.3 node:13.13.0 tomcat:10.0.0-jdk15-openjdk-buster wordpress:5.7

if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument(
        "--sources",
        nargs="+",
        type=str,
        default="",
    )

    parser.add_argument(
        "--backend",
        type=str,
        default="",
    )

    parser.add_argument(
        "--anchor",
        type=str,
        default="",
    )

    parser.add_argument(
        "--oss-object-prefix",
        dest="oss_object_prefix",
        type=str,
        default=None,
    )

    args = parser.parse_args()
    backend = args.backend
    anchor = NydusAnchor(args.anchor)
    sources = args.sources
    oss_object_prefix = args.oss_object_prefix
    print(sources)

    for s in sources:
        converter = Nydusify(anchor)
        converter.docker_v2().backend_type(backend, oss_object_prefix).convert(s)