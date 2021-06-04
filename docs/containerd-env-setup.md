# Nydus Setup for Containerd Environment

This document will walk through how to setup a nydus image service to work with containerd. It assumes that you already have containerd installed. If not, please refer to [containerd documents](https://github.com/containerd/containerd/blob/master/docs/ops.md) on how to install and set it up.

### Install all nydus binaries

Get `nydus-image`, `nydusd`, `nydusify`, and `containerd-nydus-grpc` binaries from [release](https://github.com/dragonflyoss/image-service/releases/latest) page.

```bash
sudo cp nydusd nydus-image /usr/local/bin
sudo cp nydusify containerd-nydus-grpc /usr/local/bin
```

## Start containerd snapshotter for nydus

Nydus provides a containerd remote snapshotter `containerd-nydus-grpc` to prepare container rootfs with nydus formatted images. To start it, first save a nydusd config to `/etc/nydusd-config.json`:
```bash
$ cat > /etc/nydusd-config.json << EOL
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "scheme": "http",
        "timeout": 5,
        "connect_timeout": 5,
        "retry_limit": 0
      }
    },
    "cache": {
      "type": "blobcache",
      "config": {
        "work_dir": "cache"
      }
    }
  },
  "mode": "direct",
  "digest_validate": false,
  "iostats_files": true,
  "enable_xattr": false,
  "fs_prefetch": {
    "enable": true,
    "threads_count": 10
  }
}
EOL
```

Then start `containerd-nydus-grpc` remote snapshotter:
```bash
/usr/local/bin/containerd-nydus-grpc --nydusd-path /usr/local/bin/nydusd \
    --config-path /etc/nydusd-config.json \
    --log-level debug \
    --root /var/lib/containerd/io.containerd.snapshotter.v1.nydus \
    --cache-dir /var/lib/nydus/cache \
    --address /run/containerd/containerd-nydus-grpc.sock
```
`cache-dir` argument represent the blob cache root dir, if unset, it will be set `root` + "/cache". It overrides the `work_dir` option in nydusd-config.json.
## Configure and Start containerd

Nydus uses two features of containerd:
* remote snapshotter
* snapshotter annotations

To set them up, add something like the following to your containerd config (default to `/etc/containerd/config.toml`):
```toml
[proxy_plugins]
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/containerd/containerd-nydus-grpc.sock"
[plugins.cri]
  [plugins.cri.containerd]
    snapshotter = "nydus"
    disable_snapshot_annotations = false
```

Then restart containerd, e.g.:
```base
systemctl restart containerd
```

## Start A Local Registry Container

```bash
docker run -d --restart=always -p 5000:5000 registry
```

## Convert An Image To Nydus Format

```bash
nydusify convert --nydus-image /usr/local/bin/nydus-image --source ubuntu --target localhost:5000/ubuntu-nydus
```

## Create New Pods With Nydus Format Image

For example, use the following `cat pod-config.yaml` and `container-config.yaml`

```
$ cat pod-config.yaml
metadata:
  attempt: 1
  name: nydus-sandbox
  namespace: default
log_directory: /tmp
linux:
  security_context:
    namespace_options:
      network: 2
annotations:
  "io.containerd.osfeature": "nydus.remoteimage.v1"
```

```
$cat container-config.yaml
metadata:
  name: nydus-container
image:
  image: localhost:5000/ubuntu-nydus:latest
command:
- /bin/sleep
args:
- 600
log_path: container.1.log
```

To create a new pod with the just converted nydus image:

```
$ crictl run container-config.yaml pod-config.yaml
77f5a5c87d37dde96afbd6a950fbff49402a95073b11f952aa3a572c7113d151
$ crictl ps
CONTAINER           IMAGE                                 CREATED             STATE               NAME                ATTEMPT             POD ID
77f5a5c87d37d       localhost:5000/ubuntu-nydus:latest   8 seconds ago       Running             nydus-container     0                   0f3aefac561b3
```
