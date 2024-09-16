#!/bin/bash

SNAPSHOTTER_CONFIG="misc/performance/snapshotter_config.toml"
if [ "$1" == "takeover_test" ]; then
    SNAPSHOTTER_CONFIG="misc/takeover/snapshotter_config.toml"
fi

readonly SNAPSHOTTER_VERSION=0.14.0
readonly NERDCTL_VERSION=1.7.6
readonly CNI_PLUGINS_VERSION=1.5.0

# setup nerdctl and nydusd env
sudo install -D -m 755 contrib/nydusify/cmd/nydusify /usr/local/bin
sudo install -D -m 755 target/release/nydusd target/release/nydus-image /usr/local/bin
wget https://github.com/containerd/nydus-snapshotter/releases/download/v$SNAPSHOTTER_VERSION/nydus-snapshotter-v$SNAPSHOTTER_VERSION-linux-amd64.tar.gz
tar zxvf nydus-snapshotter-v$SNAPSHOTTER_VERSION-linux-amd64.tar.gz
sudo install -D -m 755 bin/containerd-nydus-grpc /usr/local/bin
sudo wget https://github.com/containerd/nerdctl/releases/download/v$NERDCTL_VERSION/nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz
sudo tar -xzvf nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz -C /usr/local/bin
sudo mkdir -p /opt/cni/bin
sudo wget https://github.com/containernetworking/plugins/releases/download/v$CNI_PLUGINS_VERSION/cni-plugins-linux-amd64-v$CNI_PLUGINS_VERSION.tgz 
sudo tar -xzvf cni-plugins-linux-amd64-v$CNI_PLUGINS_VERSION.tgz -C /opt/cni/bin
sudo install -D misc/performance/containerd_config.toml /etc/containerd/config.toml
sudo systemctl restart containerd
sudo install -D misc/performance/nydusd_config.json /etc/nydus/nydusd-config.fusedev.json
sudo install -D $SNAPSHOTTER_CONFIG /etc/nydus/config.toml
sudo install -D misc/performance/nydus-snapshotter.service /etc/systemd/system/nydus-snapshotter.service
sudo systemctl start nydus-snapshotter
