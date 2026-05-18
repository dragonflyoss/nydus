#!/bin/bash
# setup_erofsfuse.sh — 安装 erofs-utils（含 erofsfuse / mkfs.erofs）
set -euo pipefail

EROFS_DIR="/tmp/erofs-utils"
EROFS_TAG="v1.7.1"

echo "====> Installing erofs-utils dependencies..."
apt-get update -qq
apt-get install -y -qq autoconf automake libtool pkg-config \
    libfuse3-dev libfuse-dev liblz4-dev libzstd-dev zlib1g-dev \
    libselinux1-dev uuid-dev build-essential git 2>/dev/null

if [ ! -d "${EROFS_DIR}" ]; then
    git clone -b "${EROFS_TAG}" \
        https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git \
        "${EROFS_DIR}"
fi

cd "${EROFS_DIR}"
./autogen.sh
./configure --enable-fuse --enable-lz4 --enable-zstd
make -j"$(nproc)"
make install
ldconfig

echo "====> erofsfuse: $(which erofsfuse)"
echo "====> mkfs.erofs: $(which mkfs.erofs)"
