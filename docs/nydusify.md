# Nydusify

The Nydusify CLI tool supports:
1. Convert an OCI container image from source registry into a Nydus image using `nydus-image` CLI layer by layer, then push Nydus image to target registry.
2. Convert local file system dictionary into Nydus image using `nydus-image`, then push Nydus-image to target remote storage(e.g. oss) optionally.

### Get binaries from release page

Get `nydus-image`, `nydusd` and `nydusify` binaries from [release](https://github.com/dragonflyoss/nydus/releases/latest) page and install them to system PATH like `/usr/bin` or `/usr/local/bin`.

## Basic Usage

Convert oci image:
```
nydusify convert \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus
```
Pack local file system dictionary:
```
nydusify pack \
  --bootstrap target.bootstrap \
  --target-dir /path/to/target \
  --output-dir /path/to/output
```

## Upload blob to storage backend

Nydusify uploads Nydus blob to registry by default, change this behavior by specifying `--backend-type` option.

### OSS Backend

``` shell
cat /path/to/backend-config.json
{
  "endpoint": "region.aliyuncs.com",
  "scheme": "https",
  "access_key_id": "",
  "access_key_secret": "",
  "bucket_name": "",
  "object_prefix": "nydus/"
}
```

``` shell
nydusify convert \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus \
  --backend-type oss \
  --backend-config-file /path/to/backend-config.json
```

### S3 Backend

`nydusify convert` can upload blob to the aws s3 service or other s3 compatible services (for example minio, ceph s3 gateway, etc.) by specifying `--backend-type s3` option.

The `endpoint` field of the `backend-config.json` is optional when using aws s3 service.

``` shell
cat /path/to/backend-config.json
{
  "endpoint": "localhost:9000",
  "scheme": "http",
  "access_key_id": "",
  "access_key_secret": "",
  "bucket_name": "",
  "object_prefix": "nydus/"
}
```

Note: the `endpoint` in the s3 `backend-config.json` **should not** contain the scheme prefix.

``` shell
nydusify convert \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus \
  --backend-type s3 \
  --backend-config-file /path/to/backend-config.json
```

### localfs

``` shell
cat /path/to/backend-config.json
{
  "dir": "/path/to/blobs"
}

nydusify convert \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus \
  --backend-config-file /path/to/backend-config.json \
```

Note: Image manifest is still published to target registry (`myregistry`). Blob files are published to localfs.

## Push Nydus Image to storage backend with subcommand pack

### OSS

``` shell
# meta_prefix:
#  push bootstrap into oss://$bucket_name/$meta_prefix$bootstrap_name
# object_prefix:
#  push blobs into oss://$bucket_name/$object_prefix$blob_id
cat /path/to/backend-config.json
{
  "bucket_name": "",
  "endpoint": "region.aliyuncs.com",
  "access_key_id": "",
  "access_key_secret": "",
  "meta_prefix": "meta/",
  "object_prefix": "nydus/"
}

nydusify pack --bootstrap target.bootstrap \
  --backend-push \
  --backend-type oss \
  --backend-config-file /path/to/backend-config.json \
  --target-dir /path/to/target \
  --output-dir /path/to/output
```

### S3

``` shell
# meta_prefix:
#  push bootstrap into s3://$bucket_name/$meta_prefix$bootstrap_name
# object_prefix:
#  push blobs into s3://$bucket_name/$object_prefix$blob_id
cat /path/to/backend-config.json
{
  "bucket_name": "",
  "endpoint": "my-s3-service.net",
  "access_key_id": "",
  "access_key_secret": "",
  "meta_prefix": "meta/",
  "object_prefix": "nydus/"
}

nydusify pack --bootstrap target.bootstrap \
  --backend-push \
  --backend-type s3 \
  --backend-config-file /path/to/backend-config.json \
  --target-dir /path/to/target \
  --output-dir /path/to/output
```

## Check Nydus image

Nydusify provides a checker to validate Nydus image, the checklist includes image manifest, Nydus bootstrap, file metadata, and data consistency in rootfs with the original OCI image. Meanwhile, the checker dumps OCI & Nydus image information to `output` (default) directory.

Only check the manifest and bootstrap of Nydus image:

``` shell
nydusify check \
  --target myregistry/repo:tag-nydus
```

You can find parsed image manifest, image config, and Nydus bootstrap file in `output` (default) directory:

``` shell
$ tree ./output

./output
├── nydus_bootstrap
├── nydus_bootstrap_debug.json
├── nydus_config.json
├── nydus_manifest.json
├── oci_config.json
└── oci_manifest.json
```

Specify `--source` and options to walk the rootfs of OCI image and Nydus image to compare file metadata:

``` shell
nydusify check \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus
```

Specify `--backend-type` and `--backend-config` options to compare file metadata and file data consistency:

``` shell
nydusify check \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus \
  --backend-type oss \
  --backend-config-file /path/to/backend-config.json
```


## Mount the nydus image as a filesystem

The nydusify mount command can mount a nydus image stored in the backend as a filesystem. Now  the  supported backend types include Registry (default backend), s3, oss, and localfs.

When using Registry as the backend, you don't need to specify the `--backend-type` .

``` shell
nydusify mount \
  --target myregistry/repo:tag-nydus
```

Specify `--backend-type` and `--backend-config` options to mount for other backends::

``` shell
nydusify mount \
  --target mybackend/repo:tag-nydus \
  --backend-type oss \
  --backend-config-file /path/to/backend-config.json
```

## Copy image between registry repositories

``` shell
nydusify copy \
  --source myregistry/repo:tag-nydus \
  --target myregistry/repo:tag-nydus-copy
```

It supports copying OCI v1 or Nydus images, use the options `--all-platforms` / `--platform` to copy the images of specific platforms.

## Export to / Import from local tarball

All you need is to change the `source` or `target` parameter in `nydusify copy` command to a local file path, which must start with `file://`.

``` shell
# registry repository --> local tarball
nydusify copy \
  --source myregistry/repo:tag-nydus \
  --target file:///home/user/repo-tag-nydus.tar
```

Absolute path is also supported.

``` shell
# local tarball --> registry repository
nydusify copy \
  --source file://./repo-tag-nydus.tar \
  --target myregistry/repo:tag-nydus
```

## Commit nydus image from container's changes

The nydusify commit command can commit a nydus image from a nydus container, like `nerdctl commit` command.

``` shell
nydusify convert \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus

nerdctl --snapshotter nydus run \
  -dt myregistry/repo:tag-nydus sh

nydusify commit \
  --container containerID
  --target myregistry/repo:tag-nydus-committed

nerdctl --snapshotter nydus run \
  -dt myregistry/repo:tag-nydus-committed sh
```

The original container ID need to be a full container ID rather than an abbreviation.

## Optimize nydus image from prefetch files

The nydusify optimize command can optimize a nydus image from prefetch files, prefetch files are file access patterns during container startup. This will generate a new bootstrap and a new blob wich contains all data indicated by prefetch files.

The content of prefetch files likes this:
```
/path/to/file1 start_offset1-end_offset1, start_offset2-end_offset2, ...
/path/to/file2 start_offset1-end_offset1, start_offset2-end_offset2, ...
```

``` shell
nydusify optimize \
  --nydus-image  /path/to/nydus-image \
  --source myregistry/repo:tag-nydus \
  --target myregistry/repo:tag-nydus-optimized \
  --prefetch-files /path/to/prefetch-files \
```

## More Nydusify Options

See `nydusify convert/check/mount --help`

## Use Nydusify as a package

```
See `contrib/nydusify/examples/converter/main.go`
```

## Hook Plugin (Experimental)

Nydusify supports the hook function execution as [go-plugin](https://github.com/hashicorp/go-plugin) at key stages of image conversion.

Write a hook plugin go file like [plugin/main.go](../contrib/nydusify/plugin/main.go), then build with the below command line:

```
go build -o nydus-hook-plugin ./plugin
```

And run `nydusify` with environment variable `NYDUS_HOOK_PLUGIN_PATH` (optional):

```
NYDUS_HOOK_PLUGIN_PATH=./nydus-hook-plugin nydusify convert --source ... --target ...
```
