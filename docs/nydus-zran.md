# Nydus zran artifact user guide

This guide explains how to create a tiny **nydus zran artifact** from an existing OCI image, which can be used to accelerate the image directly with lazy pulling. It provides several advantages because of reusing the OCI image blobs:

- It eliminates the need to store two separate full images, which can save massive space in your image registry.
- Generating such artifact is faster than converting the full accelerated image.

A simple test result is shown below:

- Image: node:19.0
- Workload: node -v
- Registry Network: 3MB/s

| image type             | image size | nydusify conversion | nydusify push | nerdctl run | read data |
| ---------------------- | ---------- | ------------------- | ------------- | ----------- | --------- |
| OCI v1                 | 353.05MB   | -                   | -             | 126s        | 353.05MB  |
| Nydus (Native RAFS v6) | 337.94MB   | 29s                 | 1m58s         | 11s         | 21.18MB   |
| Nydus (Zran)           | 14MB       | 11s                 | 12s           | 15s         | 28.78MB   |

## Generate nydus zran artifact

1. Get nydus components `nydusd`, `nydus-image`, `nydusify` from [release](https://github.com/dragonflyoss/nydus/releases) page (requires >= v2.2).

```
sudo install -D -m 755 nydusd nydus-image nydusify /usr/bin
```

2. Get nydus zran artifact:

There are some pre-generated nydus zran artifacts under the same OCI image repo available for testing:

- `docker.io/hsiangkao/wordpress:6.0` -> `docker.io/hsiangkao/wordpress:6.0-nydus-oci-ref`
- `docker.io/hsiangkao/node:18` -> `docker.io/hsiangkao/node:18-nydus-oci-ref`
- `docker.io/hsiangkao/gcc:12.2.0` -> `docker.io/hsiangkao/gcc:12.2.0-nydus-oci-ref`

Or you can generate one by `nydusify` tool:

``` bash
# Convert the existing OCI image `your-registry.com/node:19.0` to `your-registry.com/node:19.0-nydus-oci-ref`:
sudo nydusify convert --oci-ref --source your-registry.com/node:19.0 --target your-registry.com/node:19.0-nydus-oci-ref
```
**Tips**: 
- Nydus ZRAN artifacts must be in the same namespace with the OCI image.
## Run nydus zran artifact:

Follow the [documentation](https://github.com/dragonflyoss/nydus/blob/master/docs/containerd-env-setup.md) to configure `containerd` and `nydus-snapshotter` (containerd-nydus-grpc):

``` bash
# Run nydus zran artifact
sudo nerdctl --snapshotter nydus run --rm -it docker.io/hsiangkao/node:18-nydus-oci-ref node -v
```

## Recording

Pull ZRAN-indexed OCI / OCI wordpress images

[![asciicast](https://asciinema.org/a/7IOWhUk8Rna0Ju1avcamu7T5f.svg)](https://asciinema.org/a/7IOWhUk8Rna0Ju1avcamu7T5f?speed=2)
