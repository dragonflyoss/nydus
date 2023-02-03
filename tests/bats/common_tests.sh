repo_base_dir="${BATS_TEST_DIRNAME}/../.."
rust_toolchain=$(cat ${repo_base_dir}/rust-toolchain)
compile_image="localhost/compile-image:${rust_toolchain}"
nydus_snapshotter_repo="https://github.com/containerd/nydus-snapshotter.git"

run_nydus_snapshotter() {
  rm -rf /var/lib/containerd/io.containerd.snapshotter.v1.nydus
  rm -rf /var/lib/nydus/cache
  cat >/tmp/nydus-erofs-config.json <<EOF
{
  "type": "bootstrap",
  "config": {
    "backend_type": "registry",
    "backend_config": {
      "scheme": "https"
    },
    "cache_type": "fscache"
  }
}
EOF
  containerd-nydus-grpc --config-path /tmp/nydus-erofs-config.json --daemon-mode shared \
    --fs-driver fscache --root /var/lib/containerd/io.containerd.snapshotter.v1.nydus \
    --address /run/containerd/containerd-nydus-grpc.sock --nydusd /usr/local/bin/nydusd \
    --log-to-stdout >${BATS_TEST_DIRNAME}/nydus-snapshotter-${BATS_TEST_NAME}.log 2>&1 &
}

config_containerd_for_nydus() {
  [ -d "/etc/containerd" ] || mkdir -p /etc/containerd
  cat >/etc/containerd/config.toml <<EOF
version = 2

[plugins]
  [plugins."io.containerd.grpc.v1.cri"]
    [plugins."io.containerd.grpc.v1.cri".cni]
      bin_dir = "/usr/lib/cni"
      conf_dir = "/etc/cni/net.d"
  [plugins."io.containerd.internal.v1.opt"]
    path = "/var/lib/containerd/opt"

[proxy_plugins]
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/containerd/containerd-nydus-grpc.sock"

[plugins."io.containerd.grpc.v1.cri".containerd]
   snapshotter = "nydus"
   disable_snapshot_annotations = false
EOF
  systemctl restart containerd
}
