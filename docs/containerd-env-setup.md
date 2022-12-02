# Nydus Setup for Containerd Environment

This document will walk through how to setup a nydus image service to work with containerd. It assumes that you already have `containerd` installed. If not, please refer to [containerd documents](https://github.com/containerd/containerd/blob/master/docs/ops.md) on how to install and set it up.

## Install All Nydus Binaries

Get `nydus-image`, `nydusd`, `nydusify`, `ctr-remote` and `nydus-overlayfs` binaries from [release](https://github.com/dragonflyoss/image-service/releases/latest) page.

```bash
sudo cp nydusd nydus-image /usr/local/bin
sudo cp nydusify containerd-nydus-grpc /usr/local/bin
sudo cp ctr-remote nydus-overlayfs /usr/local/bin
```

Get `containerd-nydus-grpc` binary from nydus-snapshotter [release](https://github.com/containerd/nydus-snapshotter/releases) page.

```bash
sudo cp nydusify containerd-nydus-grpc /usr/local/bin
```

## Start Containerd Snapshotter for Nydus

Nydus provides a containerd remote snapshotter `containerd-nydus-grpc` to prepare container rootfs with nydus formatted images. To start it, first save a `nydusd` configuration to `/etc/nydusd-config.json`:

```bash
$ sudo tee /etc/nydusd-config.json > /dev/null << EOF
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "scheme": "",
        "skip_verify": false,
        "timeout": 5,
        "connect_timeout": 5,
        "retry_limit": 2,
        "auth": "YOUR_LOGIN_AUTH="
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
  "iostats_files": false,
  "enable_xattr": true,
  "fs_prefetch": {
    "enable": true,
    "threads_count": 4
  }
}
EOF
```

Note:

- The `scheme` is registry url scheme, leave empty to automatically detect, otherwise specify to `https` or `http` according to your registry server configuration.
- The `auth` is base64 encoded `username:password`. It is required by `nydusd` to lazily pull image data from registry which is authentication enabled.
- `containerd-nydus-grpc` will automatically read docker login auth from the configuration `$HOME/.docker/config.json`, otherwise please copy it to replace `YOUR_LOGIN_AUTH=`.

Then start `containerd-nydus-grpc` remote snapshotter:

```bash
sudo /usr/local/bin/containerd-nydus-grpc \
    --config-path /etc/nydusd-config.json \
    --shared-daemon \
    --log-level info \
    --root /var/lib/containerd/io.containerd.snapshotter.v1.nydus \
    --cache-dir /var/lib/nydus/cache \
    --address /run/containerd/containerd-nydus-grpc.sock \
    --nydusd-path /usr/local/bin/nydusd \
    --nydusimg-path /usr/local/bin/nydus-image \
    --log-to-stdout
```

`cache-dir` argument represents the local blob cache root dir, if unset, it will be set to `root` + "/cache". It overrides the `device.cache.config.work_dir` option in `nydusd-config.json`.

## Configure and Start Containerd

Nydus uses two features of containerd:

- remote snapshotter
- snapshotter annotations

To set them up, first add something like the following to your `containerd` configuration (default to `/etc/containerd/config.toml`):

```toml
[proxy_plugins]
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/containerd/containerd-nydus-grpc.sock"
```

Next you should change default snapshotter to `nydus` and enable snapshot annotations like below:

For version 1 containerd config format:

```toml
[plugins.cri]
  [plugins.cri.containerd]
    snapshotter = "nydus"
    disable_snapshot_annotations = false
```

For version 2 containerd config format:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd]
   snapshotter = "nydus"
   disable_snapshot_annotations = false
```

Then restart containerd, e.g.:

```bash
sudo systemctl restart containerd
```

## Start a Local Registry Container

To make it easier to convert and run nydus images next, we can run a local registry service with docker:

```bash
sudo docker run -d --restart=always -p 5000:5000 registry
```

## Convert an Image to Nydus Format

Currently, nydus image must be created by converting from an existed OCI or docker v2 image.

Note: For private registry repo, please make sure you are authorized to pull and push the target registry. The basic method is to use `docker pull` and `docker push` to validate your access to the target registry.

```bash
sudo nydusify convert --nydus-image /usr/local/bin/nydus-image --source ubuntu --target localhost:5000/ubuntu-nydus
```

For more details about how to build nydus image, please refer to [nydusify](https://github.com/dragonflyoss/image-service/blob/master/docs/nydusify.md) conversion tool and [acceld](https://github.com/goharbor/acceleration-service).

## Try Nydus with `nerdctl`

Nydus snapshotter has been supported by [nerdctl](https://github.com/containerd/nerdctl)(requires >= v0.22), we can lazily start container with it.

```bash
$ sudo nerdctl --snapshotter nydus run --rm -it localhost:5000/ubuntu-nydus:latest bash
```

## Try Nydus with `ctr-remote`

Also nydus provides an enhanced `ctr` tool named as `ctr-remote` (Get binary from [release](https://github.com/dragonflyoss/image-service/releases) page) which is capable of pulling nydus image and start container based on nydus image, e.g.:

Use extra `ctr-remote image rpull` command to lazily pull nydus image:

```bash
$ sudo ctr-remote image rpull --plain-http localhost:5000/ubuntu-nydus:latest
fetching sha256:9523a2de... application/vnd.oci.image.manifest.v1+json
fetching sha256:a2cdb40d... application/vnd.oci.image.config.v1+json
fetching sha256:18059446... application/vnd.oci.image.layer.v1.tar+gzip
```

Next run container with nydus snapshotter:

```bash
$ sudo ctr-remote run --rm -t --snapshotter=nydus localhost:5000/ubuntu-nydus:latest test /bin/bash
$ ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 13:45 pts/0    00:00:00 /bin/bash
root          10       1  0 13:46 pts/0    00:00:00 ps -ef
```

## Create Pod with Nydus Image in Kubernetes

For example, use the following `nydus-sandbox.yaml` and `nydus-container.yaml`

The `nydus-sandbox.yaml` looks like below:

```yaml
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

The `nydus-container.yaml` looks like below:

```yaml
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

To create a pod with the just converted nydus image:

```bash
$ sudo crictl pull localhost:5000/ubuntu-nydus:latest
$ pod=`sudo crictl runp nydus-sandbox.yaml`
$ container=`sudo crictl create $pod nydus-container.yaml nydus-sandbox.yaml`
$ sudo crictl start $container
$ sudo crictl ps
CONTAINER ID        IMAGE                                CREATED             STATE               NAME                      ATTEMPT             POD ID
f4a6c6dc47e34       localhost:5000/ubuntu-nydus:latest   9 seconds ago       Running             nydus-container           0                   21b91779d551e
```
