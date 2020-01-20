# Nydusify

The nydusify tool converts a remote container image into a nydus image.

## Dependencies

Containerd service: Nydusify uses containerd to pull source image and push target image.

## Build

```
make
```

## Release Build

```
make build-release
```

## Usage

```
cmd/nydusify convert \
  --nydus-image ../../target-fusedev/debug/nydus-image \
  --source-auth <base64-encoded-auth> \
  --source myregistry/repo:tag \
  --target myregistry/repo:tag-nydus
```
