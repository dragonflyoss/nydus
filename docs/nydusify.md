# Nydusify

The Nydusify CLI tool converts an OCI container image from source registry into a Nydus image using `nydus-image` CLI layer by layer, then pushes Nydus image to target registry.

## Dependencies

- Golang 1.14 or above
- Containerd: Nydusify uses containerd service to pull & push image.

## Build

```
cd contrib/nydusify
make
```

## Release Build

```
cd contrib/nydusify
make build-release
```

## Basic Usage

```
cmd/nydusify convert \
  --nydus-image ../../target-fusedev/debug/nydus-image \
  --source-auth <base64-encoded-auth> \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus
```

## Nydusify Conversion Options

See `cmd/nydusify convert --help`
