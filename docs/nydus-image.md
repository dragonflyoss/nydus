# Toolset for Working with RAFS Filesystems and Nydus Container Images

The `nydus-image` toolset provides tools to build, check, inspect and export RAFS filesystems and Nydus container images.

Logically, a RAFS filesystem consists of two parts:
- a bootstrap/meta blob, containing filesystem metadata, such directory name, file attributes etc.
- one or more data blobs, containing file contents.

Physically, RAFS bootstrap/meta blobs can be stored as separate files, or inlined into data blob files.
Therefore, a RAFS file system may consist of the following parts:
- a blob file containing both RAFS metadata and data
- a blob file containing RAFS metadata, and one or more blob files for RAFS data
- a blob file containing RAFS metadata, and one or more blob files for RAFS data, and associated targz files for RAFS ZRAN mode.

## Installation

Get latest `nydus-image` binary from [release](https://github.com/dragonflyoss/nydus/releases/latest) page.

## Nydus Image Builder

The `nydus-image create` subcommand creates a RAFS filesystem or a layer of Nydus image from a tar file or from a directory.

RAFS filesystem/Nydus image has three modes: Native, Zran and Tarfs. Each mode has different features and may be used for different scenarios.

|  Mode  |    Blobs in Registry    |       Local Cache File        | Runtime Integrity | Lazy-loading | Chunk Dedup | Encryption | OCIv1 Compatible |
|:------:|:-----------------------:|:-----------------------------:|:-----------------:|:------------:|:-----------:|:----------:|:----------------:|
| Tarfs  |    tar.gz / tar.zst     |       nydus.meta & tar        |     Optional      |      No      |         No          |     No     |       Yes        |
| Zran   |   tar.gz & nydus.meta   | nydus.meta & nydus.data.cache |        Yes        |     Yes      |      Yes       |     No     |       Yes        |
| Native | nydus.data & nydus.meta | nydus.meta & nydus.data.cache |       Yes         |      Yes     |     Yes      |    Yes     |        No        | 

### Specify Data Blob Output Path

There are two ways to specify where to save the resulting data blob:

- Specify the file path via `--blob <BLOB_FILE>`. It could be a regular file into which the data blob contents are dumped. It can also be a fifo (named pipe) from which "nydusify" or other tools can receive the generated blob content.

- Specify a directory with `-D/--blob-dir BLOB_DIR`. `nydus-image` will use the sha256 digest of the resulting data blob as the filename, concatenated to the directory path. This is useful when you don't want to set a custom name or you are building a layered nydus image. Please create `BLOB_DIR` before executing the command.

### Build RAFS Filesystem in Native Mode from a Directory
```shell
nydus-image create -t dir-rafs \
  -D /path/to/output/directory \
  /path/to/source/dir
  
[root@image-service]# nydus-image create -t dir-rafs -D images/ src 
[2023-03-29 16:34:28.092347 +08:00] INFO successfully built RAFS filesystem: 
meta blob path: images/f62a7e668c7f306655233367f8b6e4073d7fa94a6f57826069db3e745e2fd327
data blob size: 0xe32b
data blobs: ["e9d3d45f6ad9f647cc1a2e2f699a46f553ce87b1136026d53d474c6142f80763"]
[root@image-service]# ls -l images/
-rw-r--r-- 1 root root 58155 3月  29 16:34 e9d3d45f6ad9f647cc1a2e2f699a46f553ce87b1136026d53d474c6142f80763
-rw-r--r-- 1 root root 20480 3月  29 16:34 f62a7e668c7f306655233367f8b6e4073d7fa94a6f57826069db3e745e2fd327
```

### Build RAFS Filesystem in Native Mode with Inlined Metadata from a Directory
```shell
nydus-image create -t dir-rafs \
  --blob-inline-meta \
  -D /path/to/output/directory \
  /path/to/source/dir
  
[root@image-service]# nydus-image create -t dir-rafs --blob-inline-meta -D images/ src 
[2023-03-29 16:36:14.629372 +08:00] INFO successfully built RAFS filesystem: 
meta blob path: <none>
data blob size: 0x1392b
data blobs: ["903c62564da0cb18997a4d4c40f25d73c0ab9baef2177f9030d5e0c06ac26fa4"]
[root@image-service]# ls -l images/
-rw-r--r-- 1 root root 80171 3月  29 16:36 903c62564da0cb18997a4d4c40f25d73c0ab9baef2177f9030d5e0c06ac26fa4
```

### Build RAFS Filesystem in Native Mode from a tar.gz File
```shell
nydus-image create -t targz-rafs \
  -D /path/to/output/directory \
  /path/to/source/targz.file
  
[root@image-service]# nydus-image create -t targz-rafs -D images/ src.tar.gz
[2023-03-29 16:40:20.484997 +08:00] INFO successfully built RAFS filesystem:
meta blob path: images/94bf66fc81425bfb72939c942ee1ead90e2e2ac9f09f08f369db15afde163b3b
data blob size: 0xe328
data blobs: ["d3bb8a2cdb6778cbdc31d97be88ef00217d29e4c119f41ef0a4d9f202088d813"]
[root@image-service]# ls -l images/
-rw-r--r-- 1 root root 20480 3月  29 16:40 94bf66fc81425bfb72939c942ee1ead90e2e2ac9f09f08f369db15afde163b3b
-rw-r--r-- 1 root root 58152 3月  29 16:40 d3bb8a2cdb6778cbdc31d97be88ef00217d29e4c119f41ef0a4d9f202088d813
```

### Build RAFS Filesystem in Zran Mode from a tar.gz File
```shell
nydus-image create -t targz-ref \
  -D /path/to/output/directory \
  /path/to/source/targz.file
  
[root@image-service]# sha256sum src.tar.gz 
13111d487b1958281514769eedea840d14e5f27f0d7c2c97b8a286d62645766b  src.tar.gz
[root@image-service]# cp src.tar.gz images/13111d487b1958281514769eedea840d14e5f27f0d7c2c97b8a286d62645766b
[root@image-service]# file images/13111d487b1958281514769eedea840d14e5f27f0d7c2c97b8a286d62645766b 
images/13111d487b1958281514769eedea840d14e5f27f0d7c2c97b8a286d62645766b: gzip compressed data, last modified: Wed Mar 29 08:39:20 2023, from Unix, original size 245760
[root@image-service]# nydus-image create -t targz-ref -D images/ images/13111d487b1958281514769eedea840d14e5f27f0d7c2c97b8a286d62645766b 
[2023-03-29 16:48:51.656612 +08:00] INFO successfully built RAFS filesystem: 
meta blob path: images/606e8f8fbce6496b676f09f6b5231d15c301424af5b54a0433b2e9071bbe857d
data blob size: 0xb008
data blobs: ["13111d487b1958281514769eedea840d14e5f27f0d7c2c97b8a286d62645766b"]
[root@image-service]# ls -l images/
-rw-r--r-- 1 root root 45064 3月  29 16:48 13111d487b1958281514769eedea840d14e5f27f0d7c2c97b8a286d62645766b
-rw-r--r-- 1 root root  4343 3月  29 16:48 2ae4b87374bbb7be0f10300c20617bc7f40d96a8a12a43445f88d95dd326c7dd
-rw-r--r-- 1 root root 20480 3月  29 16:48 606e8f8fbce6496b676f09f6b5231d15c301424af5b54a0433b2e9071bbe857d
```

### Build RAFS Filesystem in Tarfs Mode from a tar File
```shell
nydus-image create -t tar-tarfs \
  -D /path/to/output/directory \
  /path/to/source/tar.file
  
[root@image-service]# sha256sum src.tar
0e2dbe8b6e0f55f42c75034ed9dfc582ad0a94098cfc248c968522e7ef02e00a  src.tar
[root@image-service]# cp src.tar images/0e2dbe8b6e0f55f42c75034ed9dfc582ad0a94098cfc248c968522e7ef02e00a
[root@image-service]# nydus-image create -t tar-tarfs -D images/ images/0e2dbe8b6e0f55f42c75034ed9dfc582ad0a94098cfc248c968522e7ef02e00a 
[2023-03-29 16:52:44.251252 +08:00] INFO successfully built RAFS filesystem: 
meta blob path: images/90f0e6e7e0ff822d4acddf30c36ac77fe06f549fe58f89a818fa824b19f70d47
data blob size: 0x3c000
data blobs: ["0e2dbe8b6e0f55f42c75034ed9dfc582ad0a94098cfc248c968522e7ef02e00a"]
[root@image-service]# ls -l images/
-rw-r--r-- 1 root root 245760 3月  29 16:52 0e2dbe8b6e0f55f42c75034ed9dfc582ad0a94098cfc248c968522e7ef02e00a
-rw-r--r-- 1 root root  20480 3月  29 16:52 90f0e6e7e0ff822d4acddf30c36ac77fe06f549fe58f89a818fa824b19f70d47
```

### Layered Build Nydus Image

`nydus-image` tool supports to build Nydus image from multiple layers of image:

 ```shell
 # Build from lower layer
 nydus-image create \
  -D /path/to/output/dir \
  /path/to/lower/dir
 # Build from upper layer based on lower layer
 nydus-image create \
  --parent-bootstrap /path/to/parent-bootstrap \
  -D /path/to/output/dir \
  /path/to/upper/dir
```

### Build Nydus Image With Chunk-Dict
`nydus-image` tool supports to build Nydus image with chunk-dict for chunk deduplication:
1. reference chunks which are same as chunks in chunk-dict to blobs in chunk-dict
2. new dumped blob would be smaller than without using chunk-dict
3. save space of remote storage because of chunk-deduplication between images (e.g. oss, registry)
```shell
# Build with bootstrap type chunk-dict
nydus-image create \
  --chunk-dict bootstrap=/path/to/dict.boot \
  -D /path/to/output/dir \
  /path/to/lower/dir
```

## Merge Multiple RAFS Filesystems into One

`nydus-image` tool supports to build Nydus image from multiple layers of image:
The `nydus-image merge` subcommand supports merging multiple RAFS filesystems into one.
It applies the overlay rules defined the OCI Image Spec or the overlayfs, to avoid using `overlayfs` at runtime.

```shell
nydus-image merge \
  -D /path/to/output/dir \
  /path/to/bootstrap1 /path/to/bootstrap2
  
[root@image-service]# nydus-image create --blob-inline-meta -D images/ src
[2023-03-29 17:02:06.231478 +08:00] INFO successfully built RAFS filesystem: 
meta blob path: <none>
data blob size: 0x1392b
data blobs: ["903c62564da0cb18997a4d4c40f25d73c0ab9baef2177f9030d5e0c06ac26fa4"]
[root@image-service]# nydus-image create --blob-inline-meta -D images/ blobfs/
[2023-03-29 17:02:08.980743 +08:00] INFO successfully built RAFS filesystem: 
meta blob path: <none>
data blob size: 0x86ba
data blobs: ["9e50ae5ac02b2ef6ffb86075720e49d95d8240eed4717dd8ac9c68cadba00762"]
[root@image-service]# nydus-image merge -D images/ images/903c62564da0cb18997a4d4c40f25d73c0ab9baef2177f9030d5e0c06ac26fa4 images/9e50ae5ac02b2ef6ffb86075720e49d95d8240eed4717dd8ac9c68cadba00762 
[root@image-service]# ls -l images/
-rw-r--r-- 1 root root 80171 3月  29 17:02 903c62564da0cb18997a4d4c40f25d73c0ab9baef2177f9030d5e0c06ac26fa4
-rw-r--r-- 1 root root 34490 3月  29 17:02 9e50ae5ac02b2ef6ffb86075720e49d95d8240eed4717dd8ac9c68cadba00762
-rw-r--r-- 1 root root 20480 3月  29 17:02 df01f389850b79cd5a6ca6db98495bb457aa0821b0558351c55537551322fb96
```

## Compact Nydus Image
`nydus-image` tool supports to compact Nydus image for
1. reduce number of blobs
2. optimize size of blobs (remove unused chunks in blob, merge small blobs)
```shell
# backend config for getting chunk data from remote storage
# e.g. OSS backend config
cat /path/to/backend-config.json
{
  "endpoint": "region.aliyuncs.com",
  "access_key_id": "",
  "access_key_secret": "",
  "bucket_name": ""
}

# min_used_ratio:
#   rebuild blobs whose used_ratio < min_used_ratio
#   used_ratio = (compress_size of all chunks which are referenced by bootstrap) / blob_compress_size
#   available value: 0-99, 0 means disable
# compact_blob_size:
#   we only compact blob whose compress_size < compact_blob_size
# max_compact_size:
#   final merged blob compress_size <= max_compact_size
# layers_to_compact:
#   if number of blobs >= layers_to_compact, try compact nydus image
#   0 means always try compact
cat /path/to/compact.json
{
  "min_used_ratio": 10,
  "compact_blob_size": 10485760,
  "max_compact_size": 104857600,
  "layers_to_compact": 32,
  "blobs_dir": "/path/to/blobs"
}

# Compact Nydus image with chunk-dict
nydus-image create \
  --bootstrap /path/to/bootstrap \
  --chunk-dict bootstrap=/path/to/dict \
  --config /path/to/compact.json \
  --backend-config-file /path/to/backend-config.json \
  --backend-type oss \
  /path/to/lower/dir
```

## Export RAFS Filesystem into Other Formats

### Export RAFS Filesystem as Raw Block Device Image

A RAFS filesystem can be exported as a raw block device image, so it can be exposed as block device through loop device, NBD and virtio-blk etc.
If the `--verity` option is given, it will also generate verification data to enable `dm-verity`.

```shell
 nydus-image export --block --verity \
  -D /path/to/output/dir \
  -B /path/to/bootstrap  
 
[root@image-service]# nydus-image create -t tar-tarfs -D images/ src.tar
[2023-03-29 17:20:02.500167 +08:00] INFO successfully built RAFS filesystem: 
meta blob path: images/90f0e6e7e0ff822d4acddf30c36ac77fe06f549fe58f89a818fa824b19f70d47
data blob size: 0x3c000
data blobs: ["0e2dbe8b6e0f55f42c75034ed9dfc582ad0a94098cfc248c968522e7ef02e00a"]
[root@image-service]# cp src.tar images/0e2dbe8b6e0f55f42c75034ed9dfc582ad0a94098cfc248c968522e7ef02e00a
[root@image-service]# nydus-image export --block --verity -D images/ -B images/90f0e6e7e0ff822d4acddf30c36ac77fe06f549fe58f89a818fa824b19f70d47 
[2023-03-29 17:20:47.676914 +08:00] INFO RAFS features: COMPRESSION_NONE | HASH_SHA256 | EXPLICIT_UID_GID | TARTFS_MODE
dm-verity options: --no-superblock --format=1 -s "" --hash=sha256 --data-block-size=512 --hash-block-size=4096 --data-blocks 4576 --hash-offset 2342912 6b5743e7da406a33ab3a8bb03b65e67d1c1951b2d7ebc5026e0de3fb44a7cc20
[root@image-service]# ls -l images/
-rw-r--r-- 1 root root  245760 3月  29 17:20 0e2dbe8b6e0f55f42c75034ed9dfc582ad0a94098cfc248c968522e7ef02e00a
-rw-r--r-- 1 root root   20480 3月  29 17:20 90f0e6e7e0ff822d4acddf30c36ac77fe06f549fe58f89a818fa824b19f70d47
-rw-r--r-- 1 root root 2494464 3月  29 17:20 90f0e6e7e0ff822d4acddf30c36ac77fe06f549fe58f89a818fa824b19f70d47.disk
[root@image-service]# losetup /dev/loop1 images/90f0e6e7e0ff822d4acddf30c36ac77fe06f549fe58f89a818fa824b19f70d47.disk 
[root@image-service]# veritysetup open --no-superblock --format=1 -s "" --hash=sha256 --data-block-size=512 --hash-block-size=4096 --data-blocks 4576 --hash-offset 2342912 /dev/loop1 verity /dev/loop1 6b5743e7da406a33ab3a8bb03b65e67d1c1951b2d7ebc5026e0de3fb44a7cc20
[root@image-service]# lsblk
NAME     MAJ:MIN RM  SIZE RO TYPE  MOUNTPOINT
loop1      7:1    0  2.4M  0 loop  
└─verity 252:0    0  2.2M  1 crypt /root/nydus/mnt
[root@image-service]# mount -t erofs -r /dev/dm-0 mnt/
```

**Note**: the argument value of image layer id specified in nydus-image CLI should omit `sha256:` prefix.
