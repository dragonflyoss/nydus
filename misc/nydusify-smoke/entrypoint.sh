#!/bin/sh

set -e

TEST_NAME=$1

dockerd-entrypoint.sh & sleep 50
mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
../nydusify-smoke -test.run $TEST_NAME
