# A Nydus Tutorial for Beginners

## INTRODUCTION

### What is Nydus?

Nydus is an image-service that improves over the current OCI image specification in terms of container launching speed, image space and network bandwidth efficiency, as well as data integrity. The image-service project is designed and implemented by developers at Ant Group and Alibaba Cloud. It is a good addition to the Dragonfly landscape to better support container image distribution and help users to launch containers in a faster, more efficient, and more secure way.

Currently, Nydus includes the following tools:

- A `nydusify` tool to convert an OCI format container image into a nydus format container image.
- A `nydus-image` tool to convert an unpacked container image into a nydus format image.
- A `nydusd` daemon to parse a nydus format image and expose a FUSE mountpoint for containers to access. `nydusd` can also work as a virtiofs backend, therefore, guest is capable of accessing files in the host.
- A `containerd-nydus-grpc` daemon provides a containerd remote snapshotter plugin, allows to run nydus image in containerd.

### What will this tutorial teach me?

This tutorial aims to be the one-stop shop for getting your hands dirty with Nydus. Apart from demystifying the Nydus landscape, it'll give you hands-on experience with building and deploying your own images on host.

## GETTING STARTED

### Setting up your computer

The getting started guide on Docker has detailed instructions for setting up Docker on [Linux](https://docs.docker.com/engine/install/centos/).

### Get binaries from release page

Get `nydus-image`, `nydusd`, `nydusify`, and `containerd-nydus-grpc` binaries from [release](https://github.com/dragonflyoss/image-service/releases/latest) page.

## Build Nydus Image through nydusify

Nydus offers a powerful tool that converts an OCI image into a nydus image easily. Here we demonstrate how to use it with a local registry.

### Deploy a local registry server

Use a command like the following to start the registry container:

```bash
$ docker run -d -p 5000:5000 --restart=always --name registry registry:2
```

The registry is now ready to use. Please refer to [docker document](https://docs.docker.com/registry/deploying) for more details.

### Convert OCI Image to Nydus Image

You can pull an image from Docker Hub and push it to your local registry. The following example pulls the `ubuntu:16.04` image from Docker Hub, convert to Nydus image, then pushes it to the local registry and re-tags it as `ubuntu:16.04-nydus`.

```bash
# workdir: nydus-rs/contrib/nydusify
  $ sudo nydusify convert \
  --nydus-image /path/to/nydus-image \
  --source ubuntu:16.04 \
  --target localhost:5000/ubuntu:16.04-nydus

INFO[2021-04-11T03:06:19Z] Parsing image ubuntu:16.04
INFO[2021-04-11T03:06:39Z] Converting to localhost:5000/ubuntu:16.04-nydus
INFO[2021-04-11T03:06:39Z] [SOUR] Mount layer          Digest="sha256:92473f7ef45574f608989888a6cfc8187d3a1425e3a63f974434acab03fed068" Size="46 MB"
INFO[2021-04-11T03:06:39Z] [SOUR] Mount layer          Digest="sha256:fb52bde70123ac7f3a1b88fee95e74f4bdcdbd81917a91a35b56a52ec7671947" Size="851 B"
INFO[2021-04-11T03:06:39Z] [SOUR] Mount layer          Digest="sha256:33f6d5f2e001ababe3ddac4731d9c33121e1148ef32a87a83a5b470cb401abef" Size="169 B"
INFO[2021-04-11T03:06:39Z] [SOUR] Mount layer          Digest="sha256:64788f86be3fd71809b5de602deff9445f3de18d2f44a49d0a053dfc9a2008ae" Size="527 B"
INFO[2021-04-11T03:06:42Z] [SOUR] Mount layer          Digest="sha256:fb52bde70123ac7f3a1b88fee95e74f4bdcdbd81917a91a35b56a52ec7671947" Size="851 B" Time=3.214077176s
INFO[2021-04-11T03:06:42Z] [SOUR] Mount layer          Digest="sha256:64788f86be3fd71809b5de602deff9445f3de18d2f44a49d0a053dfc9a2008ae" Size="527 B" Time=3.213687722s
INFO[2021-04-11T03:06:42Z] [SOUR] Mount layer          Digest="sha256:33f6d5f2e001ababe3ddac4731d9c33121e1148ef32a87a83a5b470cb401abef" Size="169 B" Time=3.229410571s
INFO[2021-04-11T03:07:21Z] [SOUR] Mount layer          Digest="sha256:92473f7ef45574f608989888a6cfc8187d3a1425e3a63f974434acab03fed068" Size="46 MB" Time=42.020599192s
INFO[2021-04-11T03:07:21Z] [DUMP] Build layer          Digest="sha256:92473f7ef45574f608989888a6cfc8187d3a1425e3a63f974434acab03fed068" Size="46 MB"
INFO[2021-04-11T03:07:22Z] [DUMP] Build layer          Digest="sha256:92473f7ef45574f608989888a6cfc8187d3a1425e3a63f974434acab03fed068" Size="46 MB" Time=944.69207ms
INFO[2021-04-11T03:07:22Z] [DUMP] Build layer          Digest="sha256:fb52bde70123ac7f3a1b88fee95e74f4bdcdbd81917a91a35b56a52ec7671947" Size="851 B"
INFO[2021-04-11T03:07:22Z] [BOOT] Push bootstrap       Digest="sha256:92473f7ef45574f608989888a6cfc8187d3a1425e3a63f974434acab03fed068" Size="1.2 MB"
INFO[2021-04-11T03:07:22Z] [DUMP] Build layer          Digest="sha256:fb52bde70123ac7f3a1b88fee95e74f4bdcdbd81917a91a35b56a52ec7671947" Size="851 B" Time=102.295903ms
INFO[2021-04-11T03:07:22Z] [DUMP] Build layer          Digest="sha256:64788f86be3fd71809b5de602deff9445f3de18d2f44a49d0a053dfc9a2008ae" Size="527 B"
INFO[2021-04-11T03:07:22Z] [BOOT] Push bootstrap       Digest="sha256:fb52bde70123ac7f3a1b88fee95e74f4bdcdbd81917a91a35b56a52ec7671947" Size="1.2 MB"
INFO[2021-04-11T03:07:22Z] [DUMP] Build layer          Digest="sha256:64788f86be3fd71809b5de602deff9445f3de18d2f44a49d0a053dfc9a2008ae" Size="527 B" Time=111.598031ms
INFO[2021-04-11T03:07:22Z] [DUMP] Build layer          Digest="sha256:33f6d5f2e001ababe3ddac4731d9c33121e1148ef32a87a83a5b470cb401abef" Size="169 B"
INFO[2021-04-11T03:07:22Z] [BOOT] Push bootstrap       Digest="sha256:64788f86be3fd71809b5de602deff9445f3de18d2f44a49d0a053dfc9a2008ae" Size="1.2 MB"
INFO[2021-04-11T03:07:22Z] [BOOT] Push bootstrap       Digest="sha256:92473f7ef45574f608989888a6cfc8187d3a1425e3a63f974434acab03fed068" Size="1.2 MB" Time=236.172323ms
INFO[2021-04-11T03:07:22Z] [BLOB] Push blob            Digest="sha256:4a1e761661afac28c47e032d167edd965f11adac17b9318186c6d4dbb2d72cde" Size="66 MB"
INFO[2021-04-11T03:07:22Z] [DUMP] Build layer          Digest="sha256:33f6d5f2e001ababe3ddac4731d9c33121e1148ef32a87a83a5b470cb401abef" Size="169 B" Time=107.079253ms
INFO[2021-04-11T03:07:22Z] [BOOT] Push bootstrap       Digest="sha256:33f6d5f2e001ababe3ddac4731d9c33121e1148ef32a87a83a5b470cb401abef" Size="1.2 MB"
INFO[2021-04-11T03:07:22Z] [BOOT] Push bootstrap       Digest="sha256:fb52bde70123ac7f3a1b88fee95e74f4bdcdbd81917a91a35b56a52ec7671947" Size="1.2 MB" Time=303.798017ms
INFO[2021-04-11T03:07:22Z] [BLOB] Push blob            Digest="sha256:3584e42078bf684ee823a0f31d9d0b57c75f565c1130656352cf4bea102b5d06" Size="420 B"
INFO[2021-04-11T03:07:22Z] [BLOB] Push blob            Digest="sha256:3584e42078bf684ee823a0f31d9d0b57c75f565c1130656352cf4bea102b5d06" Size="420 B" Time=22.279049ms
INFO[2021-04-11T03:07:22Z] [BOOT] Push bootstrap       Digest="sha256:64788f86be3fd71809b5de602deff9445f3de18d2f44a49d0a053dfc9a2008ae" Size="1.2 MB" Time=305.908405ms
INFO[2021-04-11T03:07:22Z] [BOOT] Push bootstrap       Digest="sha256:33f6d5f2e001ababe3ddac4731d9c33121e1148ef32a87a83a5b470cb401abef" Size="1.2 MB" Time=268.819724ms
INFO[2021-04-11T03:07:22Z] [BLOB] Push blob            Digest="sha256:00d151e7d392e68e2c756a6fc42640006ddc0a98d37dba3f90a7b73f63188bbd" Size="7 B"
INFO[2021-04-11T03:07:22Z] [BLOB] Push blob            Digest="sha256:00d151e7d392e68e2c756a6fc42640006ddc0a98d37dba3f90a7b73f63188bbd" Size="7 B" Time=5.520117ms
INFO[2021-04-11T03:07:22Z] [BLOB] Push blob            Digest="sha256:4a1e761661afac28c47e032d167edd965f11adac17b9318186c6d4dbb2d72cde" Size="66 MB" Time=373.357074ms
INFO[2021-04-11T03:07:22Z] [MANI] Push manifest
INFO[2021-04-11T03:07:23Z] [MANI] Push manifest        Time=28.019532ms
INFO[2021-04-11T03:07:23Z] Converted to localhost:5000/ubuntu:16.04-nydus
```

The Nydus image is converted layer by layer automatically under the `tmp` directory of current working directory.

```bash
# workdir: nydus-rs/contrib/nydusify
$sudo tree tmp -L 4
tmp
├── blobs
│   ├── 00d151e7d392e68e2c756a6fc42640006ddc0a98d37dba3f90a7b73f63188bbd
│   ├── 3584e42078bf684ee823a0f31d9d0b57c75f565c1130656352cf4bea102b5d06
│   └── 4a1e761661afac28c47e032d167edd965f11adac17b9318186c6d4dbb2d72cde
├── bootstraps
│   ├── 1-sha256:92473f7ef45574f608989888a6cfc8187d3a1425e3a63f974434acab03fed068
│   ├── 1-sha256:92473f7ef45574f608989888a6cfc8187d3a1425e3a63f974434acab03fed068-output.json
│   ├── 2-sha256:fb52bde70123ac7f3a1b88fee95e74f4bdcdbd81917a91a35b56a52ec7671947
│   ├── 2-sha256:fb52bde70123ac7f3a1b88fee95e74f4bdcdbd81917a91a35b56a52ec7671947-output.json
│   ├── 3-sha256:64788f86be3fd71809b5de602deff9445f3de18d2f44a49d0a053dfc9a2008ae
│   ├── 3-sha256:64788f86be3fd71809b5de602deff9445f3de18d2f44a49d0a053dfc9a2008ae-output.json
│   ├── 4-sha256:33f6d5f2e001ababe3ddac4731d9c33121e1148ef32a87a83a5b470cb401abef
│   └── 4-sha256:33f6d5f2e001ababe3ddac4731d9c33121e1148ef32a87a83a5b470cb401abef-output.json
└── source
```

Tips: The local registry is an http server, therefore, we set the `target-insecure=true`. Otherwise, we will meet a FATA with `http: server gave HTTP response to HTTPS client`.

After you have converted the image format, we could use `nydusd` to parse it and expose a FUSE mount point for containers to access.

The `Nydusd` runs with a container image registry as a storage backend. Therefore, the registry backend is configured with the following json file.

```json
$ cat registry.json
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "scheme": "http",
        "host": "localhost:5000",
        "repo": "ubuntu"
      }
    },
    "digest_validate": false
  },
  "mode": "direct"
}
```

```bash
# workdir: nydus-rs
$ sudo nydusd \
  --config  ./registry.json \
  --mountpoint ./mnt \
  --bootstrap ./contrib/nydusify/tmp/bootstraps/4-sha256:33f6d5f2e001ababe3ddac4731d9c33121e1148ef32a87a83a5b470cb401abef \
  --log-level info
2020-10-22T10:22:23+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T10:22:23+08:00 - INFO - backend config: CommonConfig { proxy: ProxyConfig { url: "", ping_url: "", fallback: true, check_interval: 5 }, timeout: 5, connect_timeout: 5, force_upload: false, retry_limit: 0 }
2020-10-22T10:22:23+08:00 - INFO - rafs imported
2020-10-22T10:22:23+08:00 - INFO - rafs mounted: mode=direct digest_validate=false iostats_files=false
2020-10-22T10:22:23+08:00 - INFO - vfs mounted
2020-10-22T10:22:23+08:00 - INFO - mount source nydusfs dest /media/nvme/user/nydus/nydus-rs/mnt with fstype fuse opts default_permissions,allow_other,fd=11,rootmode=40000,user_id=0,group_id=0 fd 11
2020-10-22T10:22:23+08:00 - INFO - starting fuse daemon
```

And the image files are mounted on the `mnt` directory.

```bash
# workdir: nydus-rs
$ sudo ls  ./mnt/
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

To verify your `Nydusd` setup, try accessing a file in the mounted directory.

```bash
# workdir: nydus-rs
$ sudo cat  ./mnt/etc/bash.bashrc
# System-wide .bashrc file for interactive bash(1) shells.

# To enable the settings / commands in this file for login shells as well,
# this file has to be sourced in /etc/profile.

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize
...

```

## Build Nydus Image From Directory Source

Nydus also offers a `nydus-image` tool to convert an unpacked container image into a Nydus format image. For multiple layers of an image, you need to manually and recursively convert them from the lowest layer, one layer at a time.
The layers of an image could be rendered by the following command.

```bash
$ docker inspect ubuntu:16.04
...
"GraphDriver": {
            "Data": {
                "LowerDir": "/var/lib/docker/overlay2/747f5ea4b306b2cbe5c389053355653290fa749428877ec6ff0be10c28593f5b/diff:/var/lib/docker/overlay2/13d9b589b51a8a6f58eeaca6afd6ecd1bec77ce32e978ee5b037950b06
0b7909/diff:/var/lib/docker/overlay2/2d0abffedd569eb9485e95008c5c4a2344b33e2c69a26f949eff636a3132db08/diff",
                "MergedDir": "/var/lib/docker/overlay2/111a7c00f9da7862d99bb5017491427acad649061e30dbfc31cab8c5e68fd5b1/merged",
                "UpperDir": "/var/lib/docker/overlay2/111a7c00f9da7862d99bb5017491427acad649061e30dbfc31cab8c5e68fd5b1/diff",
                "WorkDir": "/var/lib/docker/overlay2/111a7c00f9da7862d99bb5017491427acad649061e30dbfc31cab8c5e68fd5b1/work"
            },
            "Name": "overlay2"
        }
<output truncated>
```

As we can see, Docker is using the `overlay2` storage driver and has automatically created the overlay mount with the required `lowerdir`, `upperdir`, `merged`, and `workdir` constructs. The lowest layer only contains `committed`, `diff` and `link`. Each higher layer also contains `lower` and `work`. The `lower` is a file, which denotes its parent, and the `diff` is a directory which contains its contents. Please refer to the [overlay document](https://docs.docker.com/storage/storagedriver/overlayfs-driver/) for more details.

![overlay](https://docs.docker.com/storage/storagedriver/images/overlay_constructs.jpg)

For Nydus, a directory tree (usually an image layer) is constructed into two parts:

- `bootstrap` is a file presenting filesystem metadata information of the directory;
- `blob` stores all files data in the directory;

Firstly, we prepare a directory `nydus-image` under current working directory. The `blobs` directory is for each `blob` file of each layer, and the `layer#` directories are for each `bootstrap` file of each layer.

```bash
# workdir: nydus-rs
$ tree -L 2 ./nydus-image
./nydus-image
├── blobs
├── layer1
├── layer2
├── layer3
└── layer4
```

Then, we convert the lowest layer to the `layer1` directory.

```bash
$ sudo nydus-image create \
  --bootstrap ./nydus-image/layer1/bootstrap \
  --blob-dir ./nydus-image/blobs \
  --log-level debug \
  --compressor none /var/lib/docker/overlay2/2d0abffedd569eb9485e95008c5c4a2344b33e2c69a26f949eff636a3132db08/diff
```

And the directory `nydus-image` will look like below.

```bash
# workdir: nydus-rs
$ tree -L 2 ./nydus-image
./nydus-image
├── blobs
│   └── 55cbe4acb5df3657174b2411f7a114c209b2ff968b238c9ffa0268f11b89ed5c
├── layer1
│   └── bootstrap
├── layer2
├── layer3
└── layer4
```

Next, we convert the Second-lowest layer(layer2) and we need to specify the `./nydus-image/layer1/bootstrap` converted in the last step as parent bootstrap.

```bash
$ sudo nydus-image create \
  --parent-bootstrap ./nydus-image/layer1/bootstrap \
  --bootstrap ./nydus-image/layer2/bootstrap \
  --blob-dir ./nydus-image/blobs \
  --log-level debug \
  --compressor none /var/lib/docker/overlay2/13d9b589b51a8a6f58eeaca6afd6ecd1bec77ce32e978ee5b037950b060b7909/diff
```

The third-lowest layer(layer3) and fourth-lowest layer(layer4) are converted by the following command. And we need to specify their parent bootstrap separately.

```bash
# third-lowest layer(layer3)
$ sudo nydus-image create \
  --parent-bootstrap ./nydus-image/layer2/bootstrap \
  --bootstrap ./nydus-image/layer3/bootstrap \
  --blob-dir ./nydus-image/blobs \
  --log-level debug \
  --compressor none /var/lib/docker/overlay2/747f5ea4b306b2cbe5c389053355653290fa749428877ec6ff0be10c28593f5b/diff

# fourth-lowest layer(layer4)
$ sudo nydus-image create \
  --parent-bootstrap ./nydus-image/layer3/bootstrap \
  --bootstrap ./nydus-image/layer4/bootstrap \
  --blob-dir ./nydus-image/blobs \
  --log-level debug \
  --compressor none /var/lib/docker/overlay2/111a7c00f9da7862d99bb5017491427acad649061e30dbfc31cab8c5e68fd5b1/diff
```

And the directory `nydus-image` will look like below.

```bash
# workdir: nydus-rs
$ tree -L 2 ./nydus-image
./nydus-image
├── blobs
│   ├── 00d151e7d392e68e2c756a6fc42640006ddc0a98d37dba3f90a7b73f63188bbd
│   ├── 55cbe4acb5df3657174b2411f7a114c209b2ff968b238c9ffa0268f11b89ed5c
│   └── a05871d77686231455df3fc4c48b39db5e0d7a14021d5de406f7502a1943887c
├── layer1
│   └── bootstrap
├── layer2
│   └── bootstrap
├── layer3
│   └── bootstrap
└── layer4
    └── bootstrap

```

Finaly, we use `nydusd` to mount the converted nydus image with last converted bootstrap (`./nydus-image/layer4/bootstrap`).

```bash
$ sudo nydusd \
  --config  ./localfs.json \
  --mountpoint ./mnt \
  --bootstrap ./nydus-image/layer4/bootstrap \
  --log-level info
```

The nydus image is stored in local storage, therefore, we specified the configuration with the following json file.

```bash
$ cat localfs.json
{
  "device": {
    "backend": {
      "type": "localfs",
      "config": {
        "dir": "/media/nvme/user/nydus/image/blobs"
      }
    }
  },
  "mode": "direct"
}
```

As in the previous section, we could verify the setup by accessing a file in the mounted directory.

## Run Containers With Nydus

### Simple Example

There is a [simple example](../misc/example/README.md) to run containers with nydus images in a docker container environment.

### More Detailed Example

Please refer to the [nydus environment setup document](containerd-env-setup.md).
