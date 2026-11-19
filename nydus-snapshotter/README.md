# nydus-snapshotter

A containerd proxy snapshotter for Nydus v3 images. It skips downloading nydus
data layers, starts one `nydus fuse` daemon per image as a transient systemd
unit, and gives each container an overlay rootfs on top of the FUSE mount.
Plain OCI images run beside them like on containerd's overlay snapshotter.

It runs as a host systemd unit ordered before `containerd.service`. A
DaemonSet only installs and upgrades it. Design, flows, configuration and
paths: [docs/snapshotter.md](../docs/snapshotter.md).

## Build

```shell
make build      # bin/nydus-snapshotter
make test       # go test -race ./...
make fmt        # golangci-lint fmt
make vet        # go vet ./...
make lint       # golangci-lint v2
make generate   # mocks
make image      # installer image with the nydus binary, built from the repository root
```

A multi-arch image: `make image IMAGE=<registry>/nydus-snapshotter
IMAGE_FLAGS="--platform linux/amd64,linux/arm64 --push"`.

## Deploy

1. Install the [Helm chart](https://github.com/dragonflyoss/helm-charts/tree/main/charts/nydus-snapshotter),
   the only Kubernetes deployment, which runs the image as a DaemonSet. On every node
   `nydus-snapshotter install` copies the binaries, units and config to the
   host, enables `nydus-snapshotter.socket` and `nydus-snapshotter.service`,
   restarts the service when its binary, units or `config.yaml` changed, and
   keeps `/run/nydus-snapshotter/kubernetes/{token,ca.crt,kubeconfig}` in
   sync for `auth.kube_secret`. `deploy/nydus-snapshotter/` holds the default
   `config.yaml`.
2. Merge `deploy/containerd/config-v1.6.toml` into a
   `/etc/containerd/config.toml` of `version = 2`, or `config-v2.toml` into one
   of `version = 3`, and restart containerd. The file's version decides, not
   containerd's: a containerd 2.x reading a version 2 config takes the first.
   The installer never edits containerd's config. Point a node at the
   snapshotter only once it is installed there: the installer Pod itself needs
   a working snapshotter to start, so new nodes either join with overlayfs
   first or carry the units in their image.

The installer copies ConfigMap changes to the host every sync interval
without restarting the snapshotter, which reloads `cgroup` and
`nydusd.config` itself; other keys apply when the installer Pods restart. An
invalid `config.yaml` or `hosts.toml` is never copied to the host. Removing the DaemonSet leaves the snapshotter running; uninstalling is manual:
`systemctl disable --now nydus-snapshotter.socket nydus-snapshotter.service`,
then `systemctl stop system-nydusd.slice` once no container runs on a nydus
image, which also stops the daemons left, and removing the paths listed in the
design doc.

Without Kubernetes, copy the binaries, `deploy/systemd/` and
`deploy/nydus-snapshotter/` to the paths in the design doc and enable both
units.
