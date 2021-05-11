# Nydusify

The Nydusify CLI tool converts an OCI container image from source registry into a Nydus image using `nydus-image` CLI layer by layer, then pushes Nydus image to target registry.

### Get binaries from release page

Get `nydus-image` and `nydusify` binaries from [release](https://github.com/dragonflyoss/image-service/releases/latest) page.

## Basic Usage

```
nydusify convert \
  --nydus-image /path/to/nydus-image \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus
```

## Upload blob to storage backend

Nydusify uploads Nydus blob to registry by default, change this behavior by specifying `--backend-type` option.

OSS Backend:

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
  --nydus-image /path/to/nydus-image \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus \
  --backend-type oss \
  --backend-config-file /path/to/backend-config.json
```

## Check Nydus image

Nydusify provides a checker to validate Nydus image, the checklist includes image manifest, Nydus bootstrap, file metadata, and data consistency in rootfs with the original OCI image. Meanwhile, the checker dumps OCI & Nydus image information to `output` (default) directory.

Only check the manifest and bootstrap of Nydus image:

``` shell
nydusify check \
  --nydus-image /path/to/nydus-image \
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

Specify `--source` and `--nydusd` options to walk the rootfs of OCI image and Nydus image to compare file metadata:

``` shell
nydusify check \
  --nydus-image /path/to/nydus-image \
  --nydusd /path/to/nydusd \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus
```

Specify `--backend-type` and `--backend-config` options to compare file metadata and file data consistency:

``` shell
nydusify check \
  --nydus-image /path/to/nydus-image \
  --nydusd /path/to/nydusd \
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
