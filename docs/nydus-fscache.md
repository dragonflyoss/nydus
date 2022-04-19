# Nydus EROFS fscache user guide

This guide shows you how to use fscache-based EROFS nydus image service to launch docker containers with the fscache-enabled in-kernel erofs on-demand download feature.

**Please be careful**, currently, the user-space daemon only implements _the basic functionality_ and it's aimed to test the fscache on-demand kernel code as a real end-to-end workload for container use cases, so it may take more extra steps compared with existing well-done solutions. This guide can be _frequently updated_ due to the overall implementation changes, so please make sure that you're now referring to the latest document version.

Currently docker runtime (with graphdriver plugin) and containerd runtime (with nydus-snapshotter) is supported.

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

## Get the fscache-supported nydusd

1. Make sure you have installed _rust 1.52.1_ version

2. Check out the latest nydus source code with \
``git clone https://github.com/dragonflyoss/image-service.git -b fscache``

3. Build nydusd with \
``cargo build --target x86_64-unknown-linux-gnu --features=fusedev --release --target-dir target-fusedev --bin nydusd``

## Run container with docker graph driver

### Prepare fscache and work directory

1. Mkdir a cache directory for fscache with \
``mkdir ~/fscachedir``

2. (For now) Mkdir a nydus working directory with \
``mkdir [nydusdir]/workdir``

3. Launch nydusd with \
``target-fusedev/x86_64-unknown-linux-gnu/release/nydusd daemon --apisock /var/run/nydusd.sock --fscache ~/fscachedir``
   and you should keep it running while the entire testing.

### Install the nydus graphdriver

1. ``docker plugin install hsiangkao/nydus-erofs-graphdriver:0.3.0``

2. ``docker plugin enable hsiangkao/nydus-erofs-graphdriver:0.3.0``

3. Edit ``/etc/docker/daemon.json`` like below:
```json
{
    "experimental": true,
    "storage-driver": "hsiangkao/nydus-erofs-graphdriver:0.3.0"
}
```

4. ``systemctl restart docker.service`` or ``service docker restart``

### Try with existing nydus container images

1. Get the nydus bootstrap files with \
   ``docker pull hsiangkao/wordpress:5.7-rafs-v6-docker`` or ``hsiangkao/ubuntu:20.04-rafs-v6-docker`` \
   It should only download filesystem metadata due to the current Nydus implementation.

2. Find the image.boot (metadata) file with \
   ``find /var/lib/docker -name image.boot``

3. (for now) Prepare a configuration json like below (take _wordpress_ as an example):
```json
{
  "type": "bootstrap",
  "id": "demo",
  "domain_id": "demo",
  "config": {
    "id": "factory1",
    "backend_type": "registry",
    "backend_config": {
      "scheme": "https",
      "host": "index.docker.io",
      "repo": "hsiangkao/ubuntu"
    },
    "cache_type": "fscache",
    "cache_config": {
      "work_dir": "workdir"
    },
    "metadata_path": "[image.boot dir]/image.boot"
  }
}
```
   Please ensure that _"metadata_path"_ and _backend_ are the ones for the image.

   Also, due to the graphdriver current implementation, _"id"_ and _"domain_id"_ should be _"demo"_ (because it's hardcoded in the graphdriver for now).

4.  (For now) Send an nydusd API request manually to register: \
``curl --http1.1 --unix-socket /var/run/nydusd.sock -XPUT -d "@[jsonfile].json" http://localhost/api/v2/blobs``

5. ``docker run``, and you can see EROFS has already been mounted if ``mount | grep erofs`` is typed. Good luck!

## Run container with nydus snapshotter

For more information on how to configure containerd to use nydus snapshotter please refer to [here](./containerd-env-setup.md).

1. Get nydus snapshotter with erofs supported.
  ```shell
  # clone code
  git clone https://github.com/imeoer/nydus-snapshotter.git -b erofs-with-fscache-support
  # compile binary to ./bin/containerd-nydus-grpc
  make
  ```

2. Prepare a configuration json like below, named to `/path/nydus-erofs-config.json`.

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

3. Start nydus snapshotter with command below:

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
 --nydusimg-path /path/to/nydus-image \
 --log-to-stdout
```

4. Run container with [ctr-remote](../contrib/ctr-remote)

```shell
# pull nydus image
ctr-remote images rpull hsiangkao/ubuntu:20.04-rafs-v6-docker
# run nydus image
ctr-remote run --rm -t --snapshotter=nydus hsiangkao/ubuntu:20.04-rafs-v6-docker ubuntu /bin/bash
# remove nydus image
ctr-remote images rm hsiangkao/ubuntu:20.04-rafs-v6-docker
```

## Try to convert a new nydus image

TBD
