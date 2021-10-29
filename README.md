# Nydus: Dragonfly Container Image Service

<p><img src="misc/logo.svg" width="170"></p>

The nydus project implements a user space filesystem on top of a container image format that improves over the current OCI image specification, in terms of container launching speed, image space, and network bandwidth efficiency, as well as data integrity.

The following benchmarking result shows the performance improvement compared with the OCI image for the container cold startup elapsed time on containerd. As the OCI image size increases, the container startup time of using Nydus image remains very short.

![Container Cold Startup](./misc/perf.jpg)

Nydus' key features include:

- Container images may be downloaded on demand in chunks to boost container startup
- Chunk level data de-duplication among layers in a single repository to reduce storage, transport and memory cost
- Flatten image metadata and data to remove all intermediate layers
- Deleted(whiteout) files in certain layer aren't packed into nydus image, therefore, image size may be reduced
- E2E image data integrity check. So security issues like "Supply Chain Attach" can be avoided and detected at runtime
- Compatible with the OCI artifacts spec and distribution spec, so nydus image can be stored in a regular container registry
- Integrated with CNCF incubating project Dragonfly to distribute container images in P2P fashion and mitigate the pressure on container registries
- Different container image storage backends are supported. For example, Registry, NAS, Aliyun/OSS.
- Capable to prefetch data block before user IO hits the block thus to reduce read latency
- Readonly FUSE file system with Linux overlayfs to provide full POSIX compatibility
- Record files access pattern during runtime gathering access trace/log, by which user abnormal behaviors are easily caught
- Access trace based prefetch table
- User IO amplification to reduce the amount of small requests to storage backend.

Currently the repository includes following tools:

| Tool                     | Description                                                                                                                                         |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| nydusd                   | Linux FUSE user-space daemon, it processes all fuse messages from host/guest kernel and parses nydus container image to fullfil those requests      |
| nydus-image              | Convert a single layer of OCI format container image into a nydus format container image generating meta part file and data part file respectively  |
| nydusify                 | It pulls OCI image down and unpack it, invokes `nydus-image` to convert image and then pushes the converted image back to registry and data storage |
| containerd-nydus-grpc    | Works as a `containerd` remote snapshotter to help setup container rootfs with nydus images                                                         |
| nydusctl                 | Nydusd CLI client, query daemon's working status/metrics and configure it                                                                           |
| ctr-remote               | An enhanced `containerd` CLI tool enable nydus support with `containerd ` ctr                                                                       |
| nydus-docker-graphdriver | Works as a `docker` remote graph driver to control how images and containers are stored and managed                                                 |

To try nydus image service:

1. Convert an original OCI image to nydus image and store it somewhere like Docker/Registry, NAS or Aliyun/OSS. This can be directly done by `nydusify`. Normal users don't have to get involved with `nydus-image`.
2. Get `nydus-snapshotter`(`containerd-nydus-grpc`) installed locally and configured properly. Or install `nydus-docker-graphdriver` plugin.
3. Operate container in legacy approaches. For example, `docker`, `nerdctl`, `CRI` and `ctr`

## Build Binary

```shell
# build debug binary
make
# build release binary
make release
# build static binary with docker
make docker-static
```

## Build Nydus Image

Build Nydus image from directory source: [Nydus Image Builder](./docs/nydus-image.md).

Convert OCI image to Nydus image: [Nydusify](./docs/nydusify.md).

## Nydus Snapshotter

Nydus supports `containerd`. To run containers with nydus images and `containerd`, please build and install the nydus snapshotter. It is a `containerd` remote snapshotter and handles nydus image format when necessary. When running without nydus images, it is identical to the containerd's builtin overlayfs snapshotter.

To build and setup nydus-snapshotter for containerd, please refer to [Nydus Snapshotter](./contrib/nydus-snapshotter/README.md)

## Run Nydusd Daemon

Normally, users do not need to start `nydusd` by hand. It is started by `nydus-snapshotter` or `nydus-docker-graphdriver` when a container rootfs is prepared.

Run Nydusd Daemon to serve Nydus image: [Nydusd](./docs/nydusd.md).

## Docker graph driver support

Docker graph driver is also accompanied, it helps to start container from nydus image. For more particular instructions, please refer to

- [Nydus Graph Driver](./contrib/docker-nydus-graphdriver/README.md)
- [使用 docker 启动容器](./docs/chinese_docker_graph_driver_guide.md)

## Learn Concepts and Commands

Browse the documentation to learn more. Here are some topics you may be interested in:

- [A Nydus Tutorial for Beginners](./docs/tutorial.md)
- Our talk on Open Infra Summit 2020: [Toward Next Generation Container Image](https://drive.google.com/file/d/1LRfLUkNxShxxWU7SKjc_50U0N9ZnGIdV/view)
- [Nydus Design Doc](./docs/nydus-design.md)

## Community

Welcome to share your use cases and contribute to Nydus project.
You can reach the community via Dingtalk and Slack

Any bug report, feature requirement, and technique discussion and cooperation are welcomed and expected!

- Slack

  Join our Slack [workspace](https://join.slack.com/t/nydusimageservice/shared_invite/zt-pz4qvl4y-WIh4itPNILGhPS8JqdFm_w)

- Dingtalk

  Join nydus-devel group by clicking [URL](https://qr.dingtalk.com/action/joingroup?code=v1,k1,YfGzhaTOnpm10Bf+/ohz4WcuDEIe9nTIjo+MPuIgRGQ=&_dt_no_comment=1&origin=11) from your phone.

  You can also search our talking group by number _34971767_ and QR code

<img src="./misc/dingtalk.jpg" width="250" height="300"/>
