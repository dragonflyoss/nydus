# Nydusify

The Nydusify CLI tool supports:
1. Convert an OCI container image from source registry into a Nydus image using `nydus-image` CLI layer by layer, then push Nydus image to target registry.
2. Convert local file system dictionary into Nydus image using `nydus-image`, then push Nydus-image to target remote storage(e.g. oss) optionally.

### Get binaries from release page

Get `nydus-image`, `nydusd` and `nydusify` binaries from [release](https://github.com/dragonflyoss/image-service/releases/latest) page and install them to system PATH like `/usr/bin` or `/usr/local/bin`.

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
  "access_key_id": "",
  "access_key_secret": "",
  "bucket_name": ""
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
  "bucket_name": ""
}
```

``` shell
nydusify convert \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus \
  --backend-type s3 \
  --backend-config-file /path/to/backend-config.json
```

## Push Nydus Image to OSS with subcommand pack
``` shell
# meta_prefix:
#  push bootstrap into oss://$bucket_name/$meta_prefix/$bootstrap_name
# blob_prefix:
#  push blobs into oss://$bucket_name/$blob_prefix/$blob_id
cat /path/to/backend-config.json
{
  "bucket_name": "",
  "endpoint": "region.aliyuncs.com",
  "access_key_id": "",
  "access_key_secret": "",
  "meta_prefix": "meta",
  "blob_prefix": "blob"
}

nydusify pack --bootstrap target.bootstrap \
  --backend-push \
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

## More Nydusify Options

See `nydusify convert/check --help`

## Use Nydusify as a package

``` golang
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
