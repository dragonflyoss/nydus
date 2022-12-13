# Nydus zran artifact user guide

This guide explains how to create a tiny **nydus zran artifact** from an existing OCI image, which can be used to accelerate the image directly with lazy pulling. It provides several advantages because of reusing the OCI image blobs:

- It eliminates the need to store two separate full images, which can save massive space in your image registry.
- Generating such artifact is faster than converting the full accelerated image.

A simple test result is shown below:

- Image: node:19.0
- Workload: node -v
- Registry Network: 3MB/s

| image type             | image size | acceld conversion | acceld push | nerdctl run | read data |
| ---------------------- | ---------- | ----------------- | ----------- | ----------- | --------- |
| OCI v1                 | 353.05MB   | -                 | -           | 126s        | 353.05MB  |
| Nydus (Native RAFS v6) | 337.94MB   | 29s               | 1m58s       | 11s         | 21.18MB   |
| Nydus (Zran)           | 14MB       | 11s               | 12s         | 15s         | 28.78MB   |

## Generate nydus zran artifact

1. Build `nydus-image` and `nydusd`:

``` bash
git clone https://github.com/dragonflyoss/image-service.git

# Install nydusd
cargo build --target x86_64-unknown-linux-musl --release --bin nydusd
sudo install -D -m 755 ./target/x86_64-unknown-linux-musl/release/nydusd /usr/local/bin

# Install nydus-image
cargo build --target x86_64-unknown-linux-musl --release --bin nydus-image
sudo install -D -m 755 ./target/x86_64-unknown-linux-musl/release/nydus-image /usr/local/bin
```

2. Get nydus zran artifact:

There are some pre-generated nydus zran artifacts under the same OCI image repo available for testing:

- `docker.io/hsiangkao/wordpress:6.0` -> `docker.io/hsiangkao/wordpress:6.0-nydus-oci-ref`
- `docker.io/hsiangkao/node:18` -> `docker.io/hsiangkao/node:18-nydus-oci-ref`
- `docker.io/hsiangkao/gcc:12.2.0` -> `docker.io/hsiangkao/gcc:12.2.0-nydus-oci-ref`

Or you can generate one by `accelctl` tool:

``` bash
# Clone accelctl repo
git clone https://github.com/imeoer/acceleration-service.git -b nydus-zran-ref
cd acceleration-service

# Get compiled ./accelctl
make

# Make sure the base64 encoded registry auth is configured correctly in `./misc/config/config.nydus.ref.yaml` configuration file.
#
# Convert the existing OCI image `your-registry.com/node:19.0` to `your-registry.com/node:19.0-nydus-oci-ref`:
sudo ./accelctl convert --config ./misc/config/config.nydus.ref.yaml your-registry.com/node:19.0
```

## Run nydus zran artifact:

Follow the [documentation](https://github.com/dragonflyoss/image-service/blob/master/docs/containerd-env-setup.md) to configure `containerd` and `nydus-snapshotter` (containerd-nydus-grpc):

``` bash
# Run nydus zran artifact
sudo nerdctl --snapshotter nydus run --rm -it docker.io/hsiangkao/node:18-nydus-oci-ref node -v
```
