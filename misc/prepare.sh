#!/bin/bash

set -euo pipefail

: "${INSTALL_TARGET_TYPE:=release}"
source "$(dirname "${BASH_SOURCE[0]}")/github-release.sh"

SNAPSHOTTER_CONFIG="misc/performance/snapshotter_config.toml"
if [ "${1:-}" == "takeover_test" ]; then
    sed -i 's/recover_policy = "restart"/recover_policy = "failover"/' "$SNAPSHOTTER_CONFIG"
fi

SNAPSHOTTER_VERSION=$(github_latest_stable_tag https://github.com/containerd/nydus-snapshotter/releases)
NERDCTL_VERSION=$(github_latest_stable_tag https://github.com/containerd/nerdctl/releases)
NERDCTL_VERSION=${NERDCTL_VERSION#v}
CNI_PLUGINS_VERSION=$(github_latest_stable_tag https://github.com/containernetworking/plugins/releases)

# setup nerdctl and nydusd env
sudo install -D -m 755 contrib/nydusify/cmd/nydusify /usr/local/bin
sudo install -D -m 755 target/$INSTALL_TARGET_TYPE/nydusd target/$INSTALL_TARGET_TYPE/nydus-image /usr/local/bin
wget https://github.com/containerd/nydus-snapshotter/releases/download/$SNAPSHOTTER_VERSION/nydus-snapshotter-$SNAPSHOTTER_VERSION-linux-amd64.tar.gz
tar zxvf nydus-snapshotter-$SNAPSHOTTER_VERSION-linux-amd64.tar.gz
sudo install -D -m 755 bin/containerd-nydus-grpc /usr/local/bin
sudo wget https://github.com/containerd/nerdctl/releases/download/v$NERDCTL_VERSION/nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz
sudo tar -xzvf nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz -C /usr/local/bin
sudo mkdir -p /opt/cni/bin
sudo wget https://github.com/containernetworking/plugins/releases/download/$CNI_PLUGINS_VERSION/cni-plugins-linux-amd64-$CNI_PLUGINS_VERSION.tgz 
sudo tar -xzvf cni-plugins-linux-amd64-$CNI_PLUGINS_VERSION.tgz -C /opt/cni/bin
sudo install -D misc/performance/containerd_config.toml /etc/containerd/config.toml
sudo systemctl restart containerd
sudo install -D misc/performance/nydusd_config.json /etc/nydus/nydusd-config.fusedev.json
sudo install -D $SNAPSHOTTER_CONFIG /etc/nydus/config.toml
sudo install -D misc/performance/nydus-snapshotter.service /etc/systemd/system/nydus-snapshotter.service
sudo systemctl start nydus-snapshotter

# setup protoc
bash misc/install-protoc.sh
