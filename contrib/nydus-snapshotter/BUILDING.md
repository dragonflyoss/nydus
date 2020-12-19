# Build nydus-snapshotter from source

This doc includes:

* [Build requirements] (#build-requirements)
* [Build nydus snapshotter] (#build-nydus-snapshotter)
* [Build nydus snapshotter image] (#build-nydus-snapshotter-image)

## Build requirements

To build the `nydus snapshotter` daemon, the following build system dependencies are required:

* Go 1.13.x or above except 1.14.x

## Build nydus snapshotter

nydus snaphotter will be built under bin directory

```bash
make build
```

## Build nydus snapshotter image 

build nydusd binary first and put nydusd binary under ./build/bin/

```bash
make build-image
```
