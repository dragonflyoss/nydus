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
   restarts the service when its binary, units or `config.toml` changed, and
   keeps `/run/containerd-nydus-v3/kubernetes/{token,ca.crt,kubeconfig}` in
   sync for `[auth.kubesecret]`. `deploy/nydus-snapshotter/` holds the default
   `config.toml` and `nydusd.template.yaml`.
2. Merge `deploy/containerd/config-v1.6.toml` or `config-v2.toml` into
   `/etc/containerd/config.toml` and restart containerd. The installer never
   edits containerd's config. Point a node at the snapshotter only once it is
   installed there: the installer Pod itself needs a working snapshotter to
   start, so new nodes either join with overlayfs first or carry the units in
   their image.

The installer copies ConfigMap changes to the host every sync interval
without restarting the snapshotter, which reloads `[cgroup]` and
`[nydusd.dragonfly]` itself; other keys apply when the installer Pods restart.
An invalid `config.toml`, nydusd template or `hosts.toml` is never copied to
the host. Removing the DaemonSet leaves the snapshotter running; uninstalling is a manual
`systemctl disable --now nydus-snapshotter.socket nydus-snapshotter.service`
and removing the paths listed in the design doc.

Without Kubernetes, copy the binaries, `deploy/systemd/` and
`deploy/nydus-snapshotter/` to the paths in the design doc and enable both
units.
