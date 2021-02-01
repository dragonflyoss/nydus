# Nydusify

The Nydusify CLI tool converts an OCI container image from source registry into a Nydus image using `nydus-image` CLI layer by layer, then pushes Nydus image to target registry.

## Dependencies

- Golang 1.14 or above

## Build

```
cd contrib/nydusify
make
```

## Release Build

```
cd contrib/nydusify
make static-release
```

## Basic Usage

```
cmd/nydusify convert \
  --nydus-image ../../target-fusedev/debug/nydus-image \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus
```

## Upload blob to storage backend

Nydusify uploads Nydus blob to registry by default, change this behavior by specifying `--backend-type` option.

OSS Backend:

``` shell
cmd/nydusify convert \
  --nydus-image ../../target-fusedev/debug/nydus-image \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus \
  --backend-type oss \
  --backend-config '{"endpoint":"region.aliyuncs.com","access_key_id":"","access_key_secret":"","bucket_name":""}'
```

## More Nydusify Options

See `cmd/nydusify convert --help`
