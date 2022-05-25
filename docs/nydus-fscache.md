# Nydus EROFS fscache user guide

This guide shows you how to use fscache-based EROFS nydus image service to launch docker containers with the fscache-enabled in-kernel erofs on-demand download feature.

**Please be careful**, currently, the user-space daemon only implements _the basic functionality_ and it's aimed to test the fscache on-demand kernel code as a real end-to-end workload for container use cases, so it may take more extra steps compared with existing well-done solutions. This guide can be _frequently updated_ due to the overall implementation changes, so please make sure that you're now referring to the latest document version.

## Prepare the kernel

Be aware of using the fscache-enabled erofs linux kernel, it can be built with the following steps:

1.  ``git clone git://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs.git`` \
     or (mirror in china): ``git://kernel.source.codeaurora.cn/pub/scm/linux/kernel/git/xiang/erofs.git``

2. ``make olddefconfig``

3. Update _.config_ to enable the follow kernel configurations:
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
``git clone https://github.com/dragonflyoss/image-service.git -b fscache``

3. Build nydusd with \
``cargo build --target x86_64-unknown-linux-gnu --features=fusedev --release --target-dir target-fusedev --bin nydusd``

4. Build ctr-remote with

``` bash
cd contrib/ctr-remote
make
```

## Run container with nydus snapshotter

1. Make sure your containerd version is 1.4 or above.

2. Get nydus snapshotter with erofs supported:
  ```shell
  # clone code
  git clone https://github.com/imeoer/nydus-snapshotter.git -b erofs-with-fscache-support
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
./bin/containerd-nydus-grpc \
 --config-path /path/nydus-erofs-config.json \
 --daemon-mode shared \
 --daemon-backend erofs \
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
contrib/ctr-remote/bin/ctr-remote images rpull docker.io/hsiangkao/ubuntu:20.04-rafs-v6-docker

# run nydus image
ctr run --rm -t --snapshotter=nydus docker.io/hsiangkao/ubuntu:20.04-rafs-v6-docker ubuntu /bin/bash

# remove nydus image
ctr images rm docker.io/hsiangkao/ubuntu:20.04-rafs-v6-docker
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
