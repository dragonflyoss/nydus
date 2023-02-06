#!/bin/bash

set -e

which bats && exit

BATS_REPO="https://github.com/bats-core/bats-core.git"
LOCAL_DIR="/tmp/bats"
echo "Install BATS from sources"
rm -rf $LOCAL_DIR
mkdir -p $LOCAL_DIR
pushd "${LOCAL_DIR}"
git clone "${BATS_REPO}" || true
cd bats-core
sh -c "./install.sh /usr"
popd
rm -rf $LOCAL_DIR
