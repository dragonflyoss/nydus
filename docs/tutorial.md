# A Nydus Tutorial for Beginners

## INTRODUCTION

### What is Nydus?

Nydus is an image-service that improves over the current OCI image specification in terms of container launching speed, image space and network bandwidth efficiency, as well as data integrity. The image-service project is designed and implemented by developers at Ant Group and Alibaba Cloud. It is a good addition to the Dragonfly landscape to better support container image distribution and help users to launch containers in a faster, more efficient, and more secure way.

Currently, Nydus includes the following tools:
- A `nydusify` tool to convert an OCI format container image into a nydus format container image.
- A `nydus-image` tool to convert an unpacked container image into a nydus format image.
- A `nydusd` daemon to parse a nydus format image and expose a FUSE mountpoint for containers to access. `nydusd` can also work as a virtiofs backend, therefore, guest is capable of accessing files in the host.

### What will this tutorial teach me?

This tutorial aims to be the one-stop shop for getting your hands dirty with Nydus. Apart from demystifying the Nydus landscape, it'll give you hands-on experience with building and deploying your own images on host. 

## GETTING STARTED

### Setting up your computer

The getting started guide on Docker has detailed instructions for setting up Docker on [Linux](https://docs.docker.com/engine/install/centos/).

### Build tools in this repository

Please refer to [README](../README.md) to build the `nydusd` and `nydus-image`. And refer to [nydusify document](./nydusify.md) to build the `nydusify`. And refert to [nydus snapshotter document](../contrib/nydus-snapshotter/README.md) to build `containerd-nydus-grpc`.

## Build Nydus Image through nydusify

Nydus offers a powerful tool that converts an OCI format container image into a nydus format container image easily. Here we demonstrate how to use it with a local registry.

### Deploy a local registry server

Use a command like the following to start the registry container:

``` bash
$ docker run -d -p 5000:5000 --restart=always --name registry registry:2
```

The registry is now ready to use. Please refer to [docker document](https://docs.docker.com/registry/deploying) for more details.

### Convert OCI Image to Nydus Image

You can pull an image from Docker Hub and push it to your local registry. The following example pulls the `ubuntu:16.04` image from Docker Hub, convert to Nydus image, then pushes it to the local registry and re-tags it as `ubuntu:16.04-nydus`. 

``` bash
# workdir: nydus-rs/contrib/nydusify
  $ sudo cmd/nydusify convert \
  --nydus-image ../../target-fusedev/debug/nydus-image \
  --source docker.io/library/ubuntu:16.04 \
  --target localhost:5000/ubuntu:16.04-nydus

INFO[2020-10-22T19:16:57+08:00] Pulling image docker.io/library/ubuntu:16.04 with platform linux/amd64
INFO[2020-10-22T19:17:04+08:00] Unpacking layer sha256:4f53fa4d2cf0e29c6a522433e0ac71a7ce0fdab158481052b2198b5518b83248
INFO[2020-10-22T19:17:07+08:00] Building layer sha256:4f53fa4d2cf0e29c6a522433e0ac71a7ce0fdab158481052b2198b5518b83248
2020-10-22T19:17:16+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T19:17:16+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T19:17:16+08:00 - INFO - build finished, blob id: ["61db3e721c7bcc5ddea0ca808568ff848a05c62adad6d9a544f5b03efb3c2a2e"], blob file: "MP8GAz"
INFO[2020-10-22T19:17:16+08:00] Unpacking layer sha256:6af7c939e38e8e3160fbbdcc26a32669529b962c79f7337df0a26bf0e9a76d59
INFO[2020-10-22T19:17:16+08:00] Pushing blob layer sha256:61db3e721c7bcc5ddea0ca808568ff848a05c62adad6d9a544f5b03efb3c2a2e
INFO[2020-10-22T19:17:16+08:00] Building layer sha256:6af7c939e38e8e3160fbbdcc26a32669529b962c79f7337df0a26bf0e9a76d59
2020-10-22T19:17:16+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T19:17:17+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T19:17:17+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T19:17:17+08:00 - INFO - build finished, blob id: ["61db3e721c7bcc5ddea0ca808568ff848a05c62adad6d9a544f5b03efb3c2a2e", "dbdb78d70d50e6c44a71eff2100d3fcb7a440698c57ec5bf3bafe9736dbfb7f8"], blob file: "UT0Gcj"
INFO[2020-10-22T19:17:17+08:00] Unpacking layer sha256:903d0ffd64f6ca1355d2b2df702fc674f5663981dfd100fe4588fb390dd3382c
INFO[2020-10-22T19:17:17+08:00] Pushing blob layer sha256:dbdb78d70d50e6c44a71eff2100d3fcb7a440698c57ec5bf3bafe9736dbfb7f8
INFO[2020-10-22T19:17:17+08:00] Building layer sha256:903d0ffd64f6ca1355d2b2df702fc674f5663981dfd100fe4588fb390dd3382c
2020-10-22T19:17:17+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T19:17:18+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T19:17:18+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T19:17:18+08:00 - INFO - build finished, blob id: ["61db3e721c7bcc5ddea0ca808568ff848a05c62adad6d9a544f5b03efb3c2a2e", "dbdb78d70d50e6c44a71eff2100d3fcb7a440698c57ec5bf3bafe9736dbfb7f8"]
INFO[2020-10-22T19:17:18+08:00] Unpacking layer sha256:04feeed388b71fdca5cc3bce619d65a34f8a1a3e5b0ef03f8392d499970818eb
INFO[2020-10-22T19:17:18+08:00] Pushing blob layer sha256:dbdb78d70d50e6c44a71eff2100d3fcb7a440698c57ec5bf3bafe9736dbfb7f8
INFO[2020-10-22T19:17:18+08:00] Building layer sha256:04feeed388b71fdca5cc3bce619d65a34f8a1a3e5b0ef03f8392d499970818eb
2020-10-22T19:17:18+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T19:17:19+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T19:17:19+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T19:17:19+08:00 - INFO - build finished, blob id: ["61db3e721c7bcc5ddea0ca808568ff848a05c62adad6d9a544f5b03efb3c2a2e", "dbdb78d70d50e6c44a71eff2100d3fcb7a440698c57ec5bf3bafe9736dbfb7f8", "00d151e7d392e68e2c756a6fc42640006ddc0a98d37dba3f90a7b73f63188bbd"], blob file: "feYSYp"
INFO[2020-10-22T19:17:19+08:00] Pushing blob layer sha256:00d151e7d392e68e2c756a6fc42640006ddc0a98d37dba3f90a7b73f63188bbd
INFO[2020-10-22T19:17:19+08:00] Pushing bootstrap layer sha256:4f7841616a4c102560462516cf125eaa0a677d5007598a26195a259712c2e5e7
INFO[2020-10-22T19:17:19+08:00] Pushing nydus manifest
INFO[2020-10-22T19:17:19+08:00] Pushing manifest index
INFO[2020-10-22T19:17:19+08:00] Success convert image docker.io/library/ubuntu:16.04 to localhost:5000/ubuntu:16.04-nydus
```

The Nydus image is converted layer by layer automatically under the `tmp` directory of current working directory.

``` bash
# workdir: nydus-rs/contrib/nydusify
$sudo tree tmp -L 4
tmp
├── docker.io
│   └── library
│       └── ubuntu:16.04
│           ├── sha256:04feeed388b71fdca5cc3bce619d65a34f8a1a3e5b0ef03f8392d499970818eb
│           ├── sha256:4f53fa4d2cf0e29c6a522433e0ac71a7ce0fdab158481052b2198b5518b83248
│           ├── sha256:6af7c939e38e8e3160fbbdcc26a32669529b962c79f7337df0a26bf0e9a76d59
│           └── sha256:903d0ffd64f6ca1355d2b2df702fc674f5663981dfd100fe4588fb390dd3382c
└── localhost:5000
    └── ubuntu:16.04-nydus
        ├── blobs
        │   ├── 00d151e7d392e68e2c756a6fc42640006ddc0a98d37dba3f90a7b73f63188bbd
        │   ├── 61db3e721c7bcc5ddea0ca808568ff848a05c62adad6d9a544f5b03efb3c2a2e
        │   └── dbdb78d70d50e6c44a71eff2100d3fcb7a440698c57ec5bf3bafe9736dbfb7f8
        ├── bootstrap
        └── bootstrap-parent

```

Tips: The local registry is an http server, therefore, we set the `target-insecure=true`. Otherwise, we will meet a FATA with `http: server gave HTTP response to HTTPS client`.

After you have converted the image format, we could use `nydusd` to parse it and expose a FUSE mount point for containers to access. 

``` bash
# workdir: nydus-rs
$ sudo target-fusedev/debug/nydusd \
  --config  ./registry.json \
  --mountpoint ./mnt \
  --bootstrap ./contrib/nydusify/tmp/localhost:5000/ubuntu:16.04-nydus/bootstrap \
  --log-level info
2020-10-22T10:22:23+08:00 - INFO - rafs superblock features: COMPRESS_LZ4_BLOCK DIGESTER_BLAKE3 EXPLICIT_UID_GID
2020-10-22T10:22:23+08:00 - INFO - backend config: CommonConfig { proxy: ProxyConfig { url: "", ping_url: "", fallback: true, check_interval: 5 }, timeout: 5, connect_timeout: 5, force_upload: false, retry_limit: 0 }
2020-10-22T10:22:23+08:00 - INFO - rafs imported
2020-10-22T10:22:23+08:00 - INFO - rafs mounted: mode=direct digest_validate=false iostats_files=false
2020-10-22T10:22:23+08:00 - INFO - vfs mounted
2020-10-22T10:22:23+08:00 - INFO - mount source nydusfs dest /media/nvme/user/nydus/nydus-rs/mnt with fstype fuse opts default_permissions,allow_other,fd=11,rootmode=40000,user_id=0,group_id=0 fd 11
2020-10-22T10:22:23+08:00 - INFO - starting fuse daemon
```

The `Nydusd` runs with a container image registry as a storage backend. Therefor, the registry backend is configured with the following json file.

``` json
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

And the image files are mounted on the `mnt` directory.

``` bash
# workdir: nydus-rs
$ sudo ls  ./mnt/
bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

To verify your `Nydusd` setup, try accessing a file in the mounted directory.

``` bash
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

Nydus also offers a  `nydus-image` tool to convert an unpacked container image into a Nydus format image. For multiple layers of an image, you need to manually and recursively convert them from the lowest layer, one layer at a time.
The layers of an image could be rendered by the following command.

``` bash
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

As we can see, Docker is using the `overlay2` storage driver and has automatically created the overlay mount with the required `lowerdir`, `upperdir`, `merged`, and `workdir` constructs. The lowest layer only contains `committed`, `diff` and `link`. Each higher layer also contains `lower` and  `work`. The `lower` is a file, which denotes its parent, and the `diff` is a directory which contains its contents. Please refer to the [overlay document](https://docs.docker.com/storage/storagedriver/overlayfs-driver/) for more details.

![overlay](https://docs.docker.com/storage/storagedriver/images/overlay_constructs.jpg)

For Nydus, a directory tree (usually an image layer) is constructed into two parts: 
- `bootstrap` is a file presenting filesystem metadata information of the directory;
- `blob` stores all files data in the directory;

Firstly, we prepare a directory `nydus-image` under current working directory. The `blobs` directory is for each `blob` file of each layer, and the `layer#` directories are for each `bootstrap` file of each layer.

``` bash
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

``` bash
$ sudo ./target-fusedev/debug/nydus-image create \
            --bootstrap ./nydus-image/layer1/bootstrap \
            --backend-type=localfs \
            --backend-config '{"dir":"./nydus-image/blobs"}' \
            --log-level debug \
            --compressor none /var/lib/docker/overlay2/2d0abffedd569eb9485e95008c5c4a2344b33e2c69a26f949eff636a3132db08/diff
```

And the directory `nydus-image` will look like below.

``` bash
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

``` bash
$ sudo ./target-fusedev/debug/nydus-image create \
            --parent-bootstrap ./nydus-image/layer1/bootstrap \
            --bootstrap ./nydus-image/layer2/bootstrap \
            --backend-type=localfs \
            --backend-config '{"dir":"./nydus-image/blobs"}' \
            --log-level debug \
            --compressor none /var/lib/docker/overlay2/13d9b589b51a8a6f58eeaca6afd6ecd1bec77ce32e978ee5b037950b060b7909/diff
```

The third-lowest layer(layer3) and fourth-lowest layer(layer4) are converted by the following command. And we need to specify their parent bootstrap separately.

``` bash
# third-lowest layer(layer3)
$ sudo ./target-fusedev/debug/nydus-image create \
            --parent-bootstrap ./nydus-image/layer2/bootstrap \
            --bootstrap ./nydus-image/layer3/bootstrap \
            --backend-type=localfs \
            --backend-config '{"dir":"./nydus-image/blobs"}' \
            --log-level debug \
            --compressor none /var/lib/docker/overlay2/747f5ea4b306b2cbe5c389053355653290fa749428877ec6ff0be10c28593f5b/diff

# fourth-lowest layer(layer4)
$ sudo ./target-fusedev/debug/nydus-image create \
            --parent-bootstrap ./nydus-image/layer3/bootstrap \
            --bootstrap ./nydus-image/layer4/bootstrap \
            --backend-type=localfs \
            --backend-config '{"dir":"./nydus-image/blobs"}' \
            --log-level debug \
            --compressor none /var/lib/docker/overlay2/111a7c00f9da7862d99bb5017491427acad649061e30dbfc31cab8c5e68fd5b1/diff
```

And the directory `nydus-image` will look like below.

``` bash
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

``` bash
$ sudo target-fusedev/debug/nydusd \
  --config  ./localfs.json \
  --mountpoint ./mnt \
  --bootstrap ./nydus-image/layer4/bootstrap \
  --log-level info
```

The nydus image is stored in local storage, therefore, we specified the configuration with the following json file.

``` bash
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
Please refer to the [nydus environment setup document](env-setup.md).
