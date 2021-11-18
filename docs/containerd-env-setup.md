# Nydus Setup for Containerd Environment

This document will walk through how to setup a nydus image service to work with containerd. It assumes that you already have `containerd` installed. If not, please refer to [containerd documents](https://github.com/containerd/containerd/blob/master/docs/ops.md) on how to install and set it up.

## Install All Nydus Binaries

Get `nydus-image`, `nydusd`, `nydusify`, `ctr-remote`, `nydus-overlayfs` and `containerd-nydus-grpc` binaries from [release](https://github.com/dragonflyoss/image-service/releases/latest) page.

```bash
sudo cp nydusd nydus-image /usr/local/bin
sudo cp nydusify containerd-nydus-grpc /usr/local/bin
sudo cp ctr-remote nydus-overlayfs /usr/local/bin
```

## Start Containerd Snapshotter for Nydus

Nydus provides a containerd remote snapshotter `containerd-nydus-grpc` to prepare container rootfs with nydus formatted images. To start it, first save a `nydusd` configuration to `/etc/nydusd-config.json`:

```bash
$ sudo cat > /etc/nydusd-config.json << EOL
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "scheme": "http",
        "timeout": 5,
        "connect_timeout": 5,
        "retry_limit": 2,
        "auth": YOUR+LOGIN+AUTH=
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
EOL
```

Note:

- The `auth` is Base64 encoded `username:password`. It is required by `nydusd` to enforce HTTP basic authentication method.
- You might have to change the scheme from `http` to `https` according to you registry configuration.
- Please copy your docker login auth from `$HOME/.docker/config.json` to replace `YOUR+LOGIN+AUTH=`.

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

`cache-dir` argument represents the blob cache root dir, if unset, it will be set to `root` + "/cache". It overrides the `work_dir` option in `nydusd-config.json`.

## Configure and Start Containerd

Nydus uses two features of containerd:

- remote snapshotter
- snapshotter annotations

To set them up, add something like the following to your `containerd` configuration (default to `/etc/containerd/config.toml`):

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

```bash
sudo systemctl restart containerd
```

## Start a Local Registry Container

```bash
sudo docker run -d --restart=always -p 5000:5000 registry
```

## Convert an Image to Nydus Format

Currently, nydus image must be created by converting from an existed OCI or docker v2 image.
Please make sure you are authorized to pull and push the target registry. The basic method is to use `docker pull` and `docker push` to validate your access to the target registry.

```bash
sudo nydusify convert --nydus-image /usr/local/bin/nydus-image --source ubuntu --target localhost:5000/ubuntu-nydus
```

## Create New Pods with Nydus Image in Kubernetes

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

To create a new pod with the just converted nydus image:

```bash
$ sudo crictl pull localhost:5000/ubuntu-nydus:latest
$ pod=`sudo crictl runp nydus-sandbox.yaml`
$ container=`sudo crictl create $pod nydus-container.yaml nydus-sandbox.yaml`
$ sudo crictl start $container
$ sudo crictl ps
CONTAINER ID        IMAGE                                CREATED             STATE               NAME                      ATTEMPT             POD ID
f4a6c6dc47e34       localhost:5000/ubuntu-nydus:latest   9 seconds ago       Running             nydus-container           0                   21b91779d551e
```

## Try Nydus with `ctr-remote`

Nydus provides an enhanced `ctr` tool named as `ctr-remote` which is capable of pulling nydus image and start container based on nydus image leveraging `nydus-snapshotter` if it is properly configured and appends more critical labels to the nydus image which should consumed when `nydus-snapshotter` is setting up snapshot.

You can also use `ctr-remote` to run containers with converted nydus image and pull it:

```bash
$ sudo ctr-remote image rpull --plain-http localhost:5000/ubuntu-nydus:latest
fetching sha256:9523a2de... application/vnd.oci.image.manifest.v1+json
fetching sha256:a2cdb40d... application/vnd.oci.image.config.v1+json
fetching sha256:18059446... application/vnd.oci.image.layer.v1.tar+gzip
```

Next run container:

```bash
$ sudo ctr-remote run --rm -t --snapshotter=nydus localhost:5000/ubuntu-nydus:latest test /bin/bash
$ ps -ef
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 13:45 pts/0    00:00:00 /bin/bash
root          10       1  0 13:46 pts/0    00:00:00 ps -ef
```

## Try Nydus with `nerdctl`

To lazily start container with `nerdctl`, you CAN'T directly pull image using `nerdctl pull` or run container using `nerdctl run` since `nydus-snapshotter` relies on extra information to identify the image reference.
`nydus-snapshotter` searches labels when preparing snapshot. Normal `pull` and `run` operations can't append such information to image when downloading and unpacking.
Here, we MUST previously use `ctr-remote` to complete the image pulling.

Then to lazily start container:

```bash
sudo ctr-remote image rpull --plain-http localhost:5000/ubuntu-nydus:latest
sudo nerdctl --snapshotter nydus run --rm -it localhost:5000/ubuntu-nydus bash
```
