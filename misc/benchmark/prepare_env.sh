#!/bin/bash

readonly SNAPSHOOTER_VERSION=0.7.3
readonly NERDCTL_VERSION=1.3.0
readonly CNI_PLUGINS_VERSION=1.2.0

# setup nerdctl and nydusd env
case "$1" in
  "oci")
    sudo install -D -m 755 contrib/nydusify/cmd/nydusify /usr/local/bin
    sudo install -D -m 755 target/release/nydusd target/release/nydus-image /usr/local/bin
    sudo wget https://github.com/containerd/nerdctl/releases/download/v$NERDCTL_VERSION/nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz
    sudo tar -xzvf nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz -C /usr/local/bin
    sudo mkdir -p /opt/cni/bin
    sudo wget https://github.com/containernetworking/plugins/releases/download/v$CNI_PLUGINS_VERSION/cni-plugins-linux-amd64-v$CNI_PLUGINS_VERSION.tgz 
    sudo tar -xzvf cni-plugins-linux-amd64-v$CNI_PLUGINS_VERSION.tgz -C /opt/cni/bin
    sudo install -D misc/benchmark/cni_bridge.conf /etc/cni/net.d/bridge.conf
    ;;
  "nydus")
    sudo install -D -m 755 contrib/nydusify/cmd/nydusify /usr/local/bin
    sudo install -D -m 755 target/release/nydusd target/release/nydus-image /usr/local/bin
    wget https://github.com/containerd/nydus-snapshotter/releases/download/v$SNAPSHOOTER_VERSION/nydus-snapshotter-v$SNAPSHOOTER_VERSION-x86_64.tgz
    tar zxvf nydus-snapshotter-v$SNAPSHOOTER_VERSION-x86_64.tgz
    sudo install -D -m 755 nydus-snapshotter/containerd-nydus-grpc /usr/local/bin/
    sudo wget https://github.com/containerd/nerdctl/releases/download/v$NERDCTL_VERSION/nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz
    sudo tar -xzvf nerdctl-$NERDCTL_VERSION-linux-amd64.tar.gz -C /usr/local/bin
    sudo mkdir -p /opt/cni/bin
    sudo wget https://github.com/containernetworking/plugins/releases/download/v$CNI_PLUGINS_VERSION/cni-plugins-linux-amd64-v$CNI_PLUGINS_VERSION.tgz 
    sudo tar -xzvf cni-plugins-linux-amd64-v$CNI_PLUGINS_VERSION.tgz -C /opt/cni/bin
    sudo install -D misc/benchmark/cni_bridge.conf /etc/cni/net.d/bridge.conf
    sudo install -D misc/benchmark/nydusd_config.json /etc/nydus/config.json
    sudo install -D misc/benchmark/containerd_config.toml /etc/containerd/config.toml
    sudo systemctl restart containerd
    sudo install -D misc/benchmark/nydus-snapshotter.service /etc/systemd/system/nydus-snapshotter.service
    sudo systemctl start nydus-snapshotter
    ;;
  *)
    echo "Unknown command: $1"
    ;;
esac
# setup registry env
sudo docker run -d --restart=always -p 5000:5000 --name registry registry
git clone https://github.com/magnific0/wondershaper.git
sudo install -D -m 755 wondershaper/wondershaper /usr/local/bin
