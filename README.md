[**[⬇️ Download]**](https://github.com/dragonflyoss/image-service/releases)
[**[📖 Website]**](https://nydus.dev/)
[**[☸ Quick Start (Kubernetes)**]](https://github.com/containerd/nydus-snapshotter/blob/main/docs/run_nydus_in_kubernetes.md)
[**[🤓 Quick Start (nerdctl)**]](https://github.com/containerd/nerdctl/blob/master/docs/nydus.md)
[**[❓ FAQs & Troubleshooting]**](https://github.com/dragonflyoss/image-service/wiki/FAQ)

# Nydus: Dragonfly Container Image Service

<p><img src="misc/logo.svg" width="170"></p>

[![Release Version](https://img.shields.io/github/v/release/dragonflyoss/image-service?style=flat)](https://github.com/dragonflyoss/image-service/releases)
[![License](https://img.shields.io/crates/l/nydus-rs)](https://crates.io/crates/nydus-rs)
[![Twitter](https://img.shields.io/twitter/url?style=social&url=https%3A%2F%2Ftwitter.com%2Fdragonfly_oss)](https://twitter.com/dragonfly_oss)
[![Nydus Stars](https://img.shields.io/github/stars/dragonflyoss/image-service?label=Nydus%20Stars&style=social)](https://github.com/dragonflyoss/image-service)

[![Smoke Test](https://github.com/dragonflyoss/image-service/actions/workflows/smoke.yml/badge.svg?event=schedule)](https://github.com/dragonflyoss/image-service/actions/workflows/smoke.yml)
[![Image Conversion](https://github.com/dragonflyoss/image-service/actions/workflows/convert.yml/badge.svg?event=schedule)](https://github.com/dragonflyoss/image-service/actions/workflows/convert.yml)
[![Release Test Daily](https://github.com/dragonflyoss/image-service/actions/workflows/release.yml/badge.svg?event=schedule)](https://github.com/dragonflyoss/image-service/actions/workflows/release.yml)
[![Coverage](https://codecov.io/gh/dragonflyoss/image-service/branch/master/graph/badge.svg)](https://codecov.io/gh/dragonflyoss/image-service)

## Introduction
Nydus implements a content-addressable file system on the RAFS format, which enhances the current OCI image specification by improving container launch speed, image space and network bandwidth efficiency, and data integrity.

The following Benchmarking results demonstrate that Nydus images significantly outperform OCI images in terms of container cold startup elapsed time on Containerd, particularly as the OCI image size increases.

![Container Cold Startup](./misc/perf.jpg)

## Principles

***Provide Fast, Secure And Easy Access to Data Distribution***

- **Performance**: Second-level container startup speed, millisecond-level function computation code package loading speed.
- **Low Cost**: Written in memory-safed language `Rust`, numerous optimizations help improve memory, CPU, and network consumption.
- **Flexible**: Supports container runtimes such as [runC](https://github.com/opencontainers/runc) and [Kata](https://github.com/kata-containers), and provides [Confidential Containers](https://github.com/confidential-containers) and vulnerability scanning capabilities
- **Security**: End to end data integrity check, Supply Chain Attack can be detected and avoided at runtime.

## Key features

- **On-demand Load**: Container images/packages are downloaded on-demand in chunk unit to boost startup.
- **Chunk Deduplication**: Chunk level data de-duplication cross-layer or cross-image to reduce storage, transport, and memory cost.
- **Compatible with Ecosystem**: Storage backend support with Registry, OSS, NAS, Shared Disk, and [P2P service](https://d7y.io/). Compatible with the [OCI images](https://github.com/dragonflyoss/image-service/blob/master/docs/nydus-zran.md), and provide native [eStargz images](https://github.com/containerd/stargz-snapshotter) support.
- **Data Analyzability**: Record accesses, data layout optimization, prefetch, IO amplification, abnormal behavior detection.
- **POSIX Compatibility**: In-Kernel EROFS or FUSE filesystems together with overlayfs provide full POSIX compatibility
- **I/O optimization**: Use merged filesystem tree, data prefetching and User I/O amplification to reduce read latency and improve user I/O performance.

## Ecosystem
### Nydus tools

| Tool                                                                                                 | Description                                                                                                                                                |
| ---------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [nydusd](https://github.com/dragonflyoss/image-service/blob/master/docs/nydusd.md)                   | Nydus user-space daemon, it processes all fscache/FUSE messages from the kernel and parses Nydus images to fullfil those requests                          |
| [nydus-image](https://github.com/dragonflyoss/image-service/blob/master/docs/nydus-image.md)         | Convert a single layer of OCI format container image into a nydus format container image generating meta part file and data part file respectively         |
| [nydusify](https://github.com/dragonflyoss/image-service/blob/master/docs/nydusify.md)               | It pulls OCI image down and unpack it, invokes `nydus-image create` to convert image and then pushes the converted image back to registry and data storage |
| [nydusctl](https://github.com/dragonflyoss/image-service/blob/master/docs/nydus-image.md)            | Nydusd CLI client (`nydus-image inspect`), query daemon's working status/metrics and configure it                                                          |
| [ctr-remote](https://github.com/dragonflyoss/image-service/tree/master/contrib/ctr-remote)           | An enhanced `containerd` CLI tool enable nydus support with `containerd` ctr                                                                               |
| [nydus-docker-graphdriver](https://github.com/nydusaccelerator/docker-nydus-graphdriver)             | [Experimental] Works as a `docker` remote graph driver to control how images and containers are stored and managed                                         |
| [nydus-overlayfs](https://github.com/dragonflyoss/image-service/tree/master/contrib/nydus-overlayfs) | `Containerd` mount helper to invoke overlayfs mount with tweaking mount options a bit. So nydus prerequisites can be passed to vm-based runtime            |
| [nydus-backend-proxy](./contrib/nydus-backend-proxy/README.md)                                       | A simple HTTP server to serve local directory as a blob backend for nydusd                                                                                 |

### Supported platforms

| Type          | Platform                                                                                                        | Description                                                                                                                                                  | Status |
| ------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| Storage       | Registry/OSS/S3/NAS                                                                                             | Support for OCI-compatible distribution implementations such as Docker Hub, Harbor, Github GHCR, Aliyun ACR, NAS, and Aliyun OSS-like object storage service | ✅      |
| Storage/Build | [Harbor](https://github.com/goharbor/acceleration-service)                                                      | Provides a general service for Harbor to support acceleration image conversion based on kinds of accelerator like Nydus and eStargz etc                      | ✅      |
| Distribution  | [Dragonfly](https://github.com/dragonflyoss/Dragonfly2)                                                         | Improve the runtime performance of Nydus image even further with the Dragonfly P2P data distribution system                                                  | ✅      |
| Build         | [Buildkit](https://github.com/moby/buildkit/blob/master/docs/nydus.md)                                          | Provides the ability to build and export Nydus images directly from Dockerfile                                                                               | ✅      |
| Build/Runtime | [Nerdctl](https://github.com/containerd/nerdctl/blob/master/docs/nydus.md)                                      | The containerd client to build or run (requires nydus snapshotter) Nydus image                                                                               | ✅      |
| Runtime       | [Docker / Moby](https://github.com/dragonflyoss/image-service/blob/master/docs/docker-env-setup.md)             | Run Nydus image in Docker container with containerd and nydus-snapshotter                                                                                    | ✅      |
| Runtime       | [Kubernetes](https://github.com/containerd/nydus-snapshotter/blob/main/docs/run_nydus_in_kubernetes.md)         | Run Nydus image using CRI interface                                                                                                                          | ✅      |
| Runtime       | [Containerd](https://github.com/containerd/nydus-snapshotter)                                                   | Nydus Snapshotter, a containerd remote plugin to run Nydus image                                                                                             | ✅      |
| Runtime       | [CRI-O / Podman](https://github.com/containers/nydus-storage-plugin)                                            | Run Nydus image with CRI-O or Podman                                                                                                                         | 🚧      |
| Runtime       | [KataContainers](https://github.com/kata-containers/kata-containers/blob/main/docs/design/kata-nydus-design.md) | Run Nydus image in KataContainers as a native solution                                                                                                       | ✅      |
| Runtime       | [EROFS](https://www.kernel.org/doc/html/latest/filesystems/erofs.html)                                          | Run Nydus image directly in-kernel EROFS for even greater performance improvement                                                                            | ✅      |

## Build

### Build Binary
```shell
# build debug binary
make
# build release binary
make release
# build static binary with docker
make docker-static
```

### Build Nydus Image

Convert OCIv1 image to Nydus image: [Nydusify](./docs/nydusify.md), [Acceld](https://github.com/goharbor/acceleration-service) or [Nerdctl](https://github.com/containerd/nerdctl/blob/master/docs/nydus.md#build-nydus-image-using-nerdctl-image-convert).

Build Nydus image from Dockerfile directly: [Buildkit](https://github.com/moby/buildkit/blob/master/docs/nydus.md).

Build Nydus layer from various sources: [Nydus Image Builder](./docs/nydus-image.md).

#### Image prefetch optimization
To further reduce container startup time, a nydus image with a prefetch list can be built using the NRI plugin (containerd >=1.7): [Container Image Optimizer](https://github.com/containerd/nydus-snapshotter/blob/main/docs/optimize_nydus_image.md)

## Run
### Quick Start

For more details on how to lazily start a container with `nydus-snapshotter` and nydus image on Kubernetes nodes or locally use `nerdctl` rather than CRI, please refer to [Nydus Setup](./docs/containerd-env-setup.md)

### Run Nydus Snapshotter

Nydus-snapshotter is a non-core sub-project of containerd.

Check out its code and tutorial from [Nydus-snapshotter repository](https://github.com/containerd/nydus-snapshotter).
It works as a `containerd` remote snapshotter to help setup container rootfs with nydus images, which handles nydus image format when necessary. When running without nydus images, it is identical to the containerd's builtin overlayfs snapshotter.

### Run Nydusd Daemon

Normally, users do not need to start `nydusd` by hand. It is started by `nydus-snapshotter` when a container rootfs is prepared.

Run Nydusd Daemon to serve Nydus image: [Nydusd](./docs/nydusd.md).

### Run Nydus with in-kernel EROFS filesystem

In-kernel EROFS has been fully compatible with RAFS v6 image format since Linux 5.16. In other words, uncompressed RAFS v6 images can be mounted over block devices since then.

Since [Linux 5.19](https://lwn.net/Articles/896140), EROFS has added a new file-based caching (fscache) backend. In this way, compressed RAFS v6 images can be mounted directly with fscache subsystem, even such images are partially available. `estargz` can be converted on the fly and mounted in this way too.

Guide to running Nydus with fscache: [Nydus-fscache](./docs/nydus-fscache.md)

### Run Nydus with Dragonfly P2P system

Nydus is deeply integrated with [Dragonfly](https://d7y.io/) P2P system, which can greatly reduce the network latency and the single point pressure of the registry server. Benchmarking results in the production environment demonstrate that using Dragonfly can reduce network latency by more than 80%, to understand the performance results and integration steps, please refer to the [nydus integration](https://d7y.io/docs/setup/integration/nydus).

If you want to deploy Dragonfly and Nydus at the same time through Helm, please refer to the **[Quick Start](https://github.com/dragonflyoss/helm-charts/blob/main/INSTALL.md)**.

### Run OCI image directly with Nydus

Nydus is able to generate a tiny artifact called a `nydus zran` from an existing OCI image in the short time. This artifact can be used to accelerate the container boot time without the need for a full image conversion. For more information, please see the [documentation](./docs/nydus-zran.md).

### Run with Docker(Moby)

Nydus provides a variety of methods to support running on docker(Moby), please refer to [Nydus Setup for Docker(Moby) Environment](./docs/docker-env-setup.md)

### Run with macOS

Nydus can also run with macfuse(a.k.a osxfuse). For more details please read [nydus with macOS](./docs/nydus_with_macos.md).

### Run eStargz image (with lazy pulling)

The containerd remote snapshotter plugin [nydus-snapshotter](https://github.com/containerd/nydus-snapshotter) can be used to run nydus images, or to run [eStargz](https://github.com/containerd/stargz-snapshotter) images directly by appending `--enable-stargz` command line option.

In the future, `zstd::chunked` can work in this way as well.

### Run Nydus Service

Using the key features of nydus as native in your project without preparing and invoking `nydusd` deliberately, [nydus-service](./service/README.md) helps to reuse the core services of nyuds.

## Documentation

Please visit [**Wiki**](https://github.com/dragonflyoss/image-service/wiki), or [**docs**](./docs)

## Community

Nydus aims to form a **vendor-neutral opensource** image distribution solution to all communities.
Questions, bug reports, technical discussion, feature requests and contribution are always welcomed!

We're very pleased to hear your use cases any time.
Feel free to reach us via Slack or Dingtalk.

- **Slack:** [Nydus Workspace](https://join.slack.com/t/nydusimageservice/shared_invite/zt-pz4qvl4y-WIh4itPNILGhPS8JqdFm_w)

- **Twitter:** [@dragonfly_oss](https://twitter.com/dragonfly_oss)

- **Dingtalk:** [34971767](https://qr.dingtalk.com/action/joingroup?code=v1,k1,ioWGzuDZEIO10Bf+/ohz4RcQqAkW0MtOwoG1nbbMxQg=&_dt_no_comment=1&origin=11)

<img src="./misc/dingtalk.jpg" width="250" height="300"/>

- **Technical Meeting:** Every Wednesday at 06:00 UTC (Beijing, Shanghai 14:00), please see our [HackMD](https://hackmd.io/@Nydus/Bk8u2X0p9) page for more information.
