# Nydus Setup for Containerd Environment

This document will walk through how to setup a nydus image service to work with containerd. It assumes that you already have `containerd` installed. If not, please refer to [containerd documents](https://github.com/containerd/containerd/blob/master/docs/ops.md) on how to install and set it up.

## Install All Nydus Binaries

1. Get `nydus-image`, `nydusd`, `nydusify`, `nydusctl` and `nydus-overlayfs` binaries from [release](https://github.com/dragonflyoss/image-service/releases/latest) page.

```bash
sudo install -D -m 755 nydusd nydus-image nydusify nydusctl nydus-overlayfs /usr/bin
```

2. Get `containerd-nydus-grpc` (nydus snapshotter) binary from nydus-snapshotter [release](https://github.com/containerd/nydus-snapshotter/releases/latest) page.

```bash
sudo install -D -m 755 containerd-nydus-grpc /usr/bin
```

## Start Nydus Snapshotter

Nydus provides a containerd remote snapshotter `containerd-nydus-grpc` (nydus snapshotter) to prepare container rootfs with nydus formatted images.

1. Prepare a `nydusd` configuration to `/etc/nydus/nydusd-config.fusedev.json`:

```bash
$ sudo tee /etc/nydus/nydusd-config.fusedev.json > /dev/null << EOF
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "scheme": "",
        "skip_verify": true,
        "timeout": 5,
        "connect_timeout": 5,
        "retry_limit": 4,
        "auth": ""
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

Please refer to the nydusd [doc](./nydusd.md) to learn more options.

⚠️ Note:

- The `device.backend.config.scheme` is the URL scheme for the registry. Leave it empty for automatic detection, or specify `https` or `http` depending on your registry server configuration.
- The `device.backend.config.auth` is the base64 encoded `username:password` authentication string required by nydusd to lazily pull image data from an authenticated registry. The nydus snapshotter will automatically read it from the `$HOME/.docker/config.json` configuration file, or you can also fill it with your own.
- The `device.backend.config.skip_verify` allows you to skip the insecure https certificate checks for the registry, only set it to `true` when necessary. Note that enabling this option is a security risk for the connection to registry, so you should only use this when you are sure it is safe.
- The `fs_prefetch.enable` option enables nydusd to prefetch image data in background, which can make container startup faster when it needs to read a large amount of image data. Set this to `false` if you don't need this functionality when it brings disk and network pressure.

2. [Optional] Cleanup snapshotter environment:

Make sure the default nydus snapshotter root directory is clear.

```
sudo rm -rf /var/lib/containerd-nydus
```

3. Start `containerd-nydus-grpc` (nydus snapshotter):
Optionally, a TOML based nydus-snapshotter configuration file can be provided by appending `--config <CONFIG>` when starting nydus-snapshotter if you want fine-grained control items. An example configuration file can be found [here](https://github.com/containerd/nydus-snapshotter/blob/main/misc/snapshotter/config.toml)

```bash
sudo /usr/bin/containerd-nydus-grpc \
    --nydusd-config /etc/nydus/nydusd-config.fusedev.json \
    --log-to-stdout
```

## Configure and Start Containerd

Nydus depends on two features of Containerd:

- Support remote snapshotter plugin
- Support passing annotations to remote snapshotter

To enable them, add below configuration items to your `containerd` configuration file (default path is `/etc/containerd/config.toml`):

```toml
[proxy_plugins]
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/containerd-nydus/containerd-nydus-grpc.sock"
```

When working with Kubernetes CRI, please change the default snapshotter to `nydus` and enable snapshot annotations like below:

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

### Using Runtime-level Snapshotter in Container for Nydus
Containerd (>= v1.7.0) supports configuring the ```runtime-level``` snapshotter. By following the steps below, we can declare runtimes that use different snapshotters:
#### Step 1: Configure Containerd
```toml
[plugins."io.containerd.grpc.v1.cri".containerd]
  snapshotter = "overlayfs"
  disable_snapshot_annotations = false
  discard_unpacked_layers = false
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nydus-runc]
    snapshotter = "nydus"
```
#### Step 2: Add an Extra Annotation in Sandbox Spec
The annotation ```"io.containerd.cri.runtime-handler": "nydus-runc"``` must be set in sandbox spec. The ```nydus-sandbox.yaml``` looks like below:
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
  "io.containerd.cri.runtime-handler": "nydus-runc"
```
As shown above, the sandbox is declared with ```"io.containerd.cri.runtime-handler": "nydus-runc"``` annotation will use the ```nydus``` snapshotter, while others will use the default ```overlayfs``` snapshotter.

## Start a Local Registry Container

To make it easier to convert and run nydus images next, we can run a local registry service with docker:

```bash
sudo docker run -d --restart=always -p 5000:5000 registry
```

## Convert/Build an Image to Nydus Format

Nydus image can be created by converting from an existing OCI or docker v2 image stored in container registry or directly built from Dockerfile(with [Buildkit](https://github.com/moby/buildkit/blob/master/docs/nydus.md))

Note: For private registry repo, please make sure you are authorized to pull and push the target registry. The basic method is to use `docker pull` and `docker push` to verify your access to the source or target registry.

```bash
sudo nydusify convert --source ubuntu --target localhost:5000/ubuntu-nydus
```

For more details about how to build nydus image, please refer to [Nydusify](https://github.com/dragonflyoss/image-service/blob/master/docs/nydusify.md) conversion tool, [Acceld](https://github.com/goharbor/acceleration-service) conversion service or [Nerdctl](https://github.com/containerd/nerdctl/blob/master/docs/nydus.md#build-nydus-image-using-nerdctl-image-convert).

## Try Nydus with `nerdctl`

Nydus snapshotter has been supported by [nerdctl](https://github.com/containerd/nerdctl)(requires >= v0.22), we can lazily start container with it.

```bash
$ sudo nerdctl --snapshotter nydus run --rm -it localhost:5000/ubuntu-nydus:latest bash
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

## Integrate P2P with Dragonfly

Nydus is deeply integrated with [Dragonfly](https://d7y.io/) P2P system, which can greatly reduce the network latency and the single point of network pressure for registry server, testing in the production environment shows that using Dragonfly can reduce network latency by more than 80%, to understand the performance test data and how to configure Nydus to use Dragonfly, please refer to the [doc](https://d7y.io/docs/setup/integration/nydus).
