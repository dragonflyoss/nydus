parse_toml() {
    local input=$1
    local key=$2

    # Using sed to extract the value of a specified key from Toml content
    local value
    value=$(echo "$input" | sed -n 's/.*'"$key"' = "\(.*\)"/\1/p')
    # Remove quote
    # shellcheck disable=SC2001
    value=$(echo "$value" | sed 's/"//g')

    echo "$value"
}

get_rust_toolcahin() {
    local base_dir=$1
    local toml_file="${base_dir}/rust-toolchain.toml"
    local legacy_toml_file="${base_dir}/rust-toolchain"
    local version

    if [ -f "$toml_file" ]; then
        local toml_content
        toml_content=$(cat "$toml_file")
        version=$(parse_toml "$toml_content" 'channel')
    else
        version=$(cat "$legacy_toml_file")
    fi

    echo "$version"
}

repo_base_dir="${BATS_TEST_DIRNAME}/../.."
rust_toolchain=$(get_rust_toolcahin "$repo_base_dir")
compile_image="localhost/compile-image:${rust_toolchain}"
nydus_snapshotter_repo="https://github.com/containerd/nydus-snapshotter.git"

generate_rust_golang_dockerfile() {
  local dockerfile=${1:-"/tmp/rust_golang_dockerfile"}
  local rust_version=${2:-"${rust_toolchain}"}
  cat > $dockerfile <<EOF
FROM rust:${rust_version}-bullseye

RUN apt-get update -y \
    && apt-get install -y cmake g++ pkg-config jq libcurl4-openssl-dev libelf-dev libdw-dev binutils-dev libiberty-dev musl-tools \
    && rustup component add rustfmt clippy \
    && rm -rf /var/lib/apt/lists/*

# install golang env
Run wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz \
    && rm -rf go1.21.5.linux-amd64.tar.gz

ENV PATH \$PATH:/usr/local/go/bin
RUN go env -w GO111MODULE=on
RUN go env -w GOPROXY=https://goproxy.io,direct
EOF
}

run_nydus_snapshotter() {
  local nydus_snapshotter_logfile=${1:-"${BATS_TEST_DIRNAME}/nydus-snapshotter-${BATS_TEST_NAME}.log"}
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
    --log-to-stdout > $nydus_snapshotter_logfile 2>&1 &
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
  sleep 3
}
