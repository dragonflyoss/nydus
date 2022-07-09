# Nydus EROFS fscache user guide

This guide shows you how to use fscache-based EROFS nydus image service to launch containers with the fscache-enabled in-kernel EROFS on-demand download feature.

## Prepare the kernel

Be aware of using the fscache-enabled EROFS kernel (Linux 5.19+), it can be built with the following steps:

1.  ``git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git`` \
     or (mirror in china): ``git://kernel.source.codeaurora.cn/pub/scm/linux/kernel/git/torvalds/linux.git``

2. ``make olddefconfig``

3. `make menuconfig` to update _.config_ to enable the follow kernel configurations:
```
CONFIG_FSCACHE=m
CONFIG_CACHEFILES=m
CONFIG_CACHEFILES_ONDEMAND=y
CONFIG_EROFS_FS=m
CONFIG_EROFS_FS_ONDEMAND=y
```

5. ``make -jX``

6. ``make modules_install && make install``

7. Reboot to the kernel just built

8. ``modprobe cachefiles`` if cachefiles is built as module

9.  ``[ -c /dev/cachefiles ] && echo ok``

## Get ctr-remote and the fscache-supported nydusd

1. Make sure you have installed _rust 1.52.1_ version and golang.

2. Check out the latest nydus source code with \
``git clone https://github.com/dragonflyoss/image-service.git``

3. Build nydusd and nydus-image with 

``` bash
cd image-service
make release
```

4. Copy the "nydus-image" binary file compiled in Step 3 into _$PATH_ e.g. /usr/local/bin with \
``cp target-fusedev/release/nydus-image /usr/local/bin``

5. Build ctr-remote with

``` bash
cd contrib/ctr-remote
make
```

## Run container with nydus snapshotter

1. Make sure your containerd version is 1.4 or above.

2. Get nydus snapshotter with EROFS supported:
  ```shell
  # clone code
  git clone https://github.com/containerd/nydus-snapshotter.git
  # compile binary to ./bin/containerd-nydus-grpc
  cd nydus-snapshotter
  make
  ```

3. Prepare a configuration json like below, named as `/path/nydus-erofs-config.json`:

```json
{
  "type": "bootstrap",
  "config": {
    "backend_type": "registry",
    "backend_config": {
      "scheme": "https"
    },
    "cache_type": "fscache"
  }
}
```

4. Start nydus snapshotter with the command below:

```
# make sure the directory exists.
mkdir -p /var/lib/containerd/io.containerd.snapshotter.v1.nydus

./bin/containerd-nydus-grpc \
 --config-path /path/nydus-erofs-config.json \
 --daemon-mode shared \
 --daemon-backend fscache \
 --log-level info \
 --root /var/lib/containerd/io.containerd.snapshotter.v1.nydus \
 --cache-dir /var/lib/nydus/cache \
 --address /run/containerd/containerd-nydus-grpc.sock \
 --nydusd-path /path/to/nydusd \
 --log-to-stdout
```

5. Configure containerd to use `nydus-snapshotter` by editing
   `/etc/containerd/config.toml` like below:

``` toml
version = 2

[plugins]
  [plugins."io.containerd.grpc.v1.cri"]
    [plugins."io.containerd.grpc.v1.cri".cni]
      bin_dir = "/usr/lib/cni"
      conf_dir = "/etc/cni/net.d"
  [plugins."io.containerd.internal.v1.opt"]
    path = "/var/lib/containerd/opt"

[proxy_plugins]
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/containerd/containerd-nydus-grpc.sock"

[plugins."io.containerd.grpc.v1.cri".containerd]
   snapshotter = "nydus"
   disable_snapshot_annotations = false
```

For more information on how to configure containerd to use nydus snapshotter please refer to [here](./containerd-env-setup.md).

6. Restart containerd with
   `service containerd restart`

7. Run container with [ctr-remote](../contrib/ctr-remote)

``` shell
# pull nydus image
contrib/ctr-remote/bin/ctr-remote images rpull docker.io/hsiangkao/ubuntu:20.04-rafs-v6

# run nydus image
ctr run --rm -t --snapshotter=nydus docker.io/hsiangkao/ubuntu:20.04-rafs-v6 ubuntu /bin/bash

# remove nydus image
ctr images rm docker.io/hsiangkao/ubuntu:20.04-rafs-v6
```

Some RAFS v6 referenced images (in Zstd algorithms):
```
docker.io/hsiangkao/ubuntu:20.04-rafs-v6
docker.io/hsiangkao/ubuntu:22.04-rafs-v6
docker.io/hsiangkao/wordpress:5.7-rafs-v6
docker.io/hsiangkao/wordpress:6.0-rafs-v6
```

## Try to convert a new image to RAFS v6

1. Get nydus image conversion tool `accelctl`

``` shell
# clone acceld code
git clone https://github.com/goharbor/acceleration-service.git

# compile binary to ./accelctl
cd acceleration-service
make
```

2. Convert to nydus image

Duplicate `./misc/config/config.yaml.nydus.tmpl` configuration file as `path/to/config.yaml`, make sure that the `rafs_version` option in `converter.driver.config` is changed to `6` and the registry auth have been configured in `provider.source`.

``` shell
# convert to nydus image
./accelctl convert --config path/to/config.yaml <your-registry-address>/ubuntu:latest
```

## Recordings

1. Pull Nydus / OCI wordpress images

[![asciicast](https://asciinema.org/a/1a6aQA6rOFsoAgivDh9mBV0lE.svg)](https://asciinema.org/a/1a6aQA6rOFsoAgivDh9mBV0lE?speed=2)
