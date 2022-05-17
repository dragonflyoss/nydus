# Nydus Image Builder

`nydus-image` tool converts a directory tree (usually an image layer) into two parts: `bootstrap` and `blob`:

- `bootstrap` is a file presenting filesystem metadata information of the directory;
- `blob` stores all files data in the directory;

### Get binary from release page

Get `nydus-image` binary from [release](https://github.com/dragonflyoss/image-service/releases/latest) page.

## Build Nydus Image From Directory Source

```shell
nydus-image create \
  --bootstrap /path/to/bootstrap \
  --blob /path/to/blob \
  /path/to/source/dir
```

## Output Blob

Nydus-image tool writes data portion into a file which is generally called `blob`. It has two options to control where `blob` is saved.

- With `--blob <BLOB_FILE>` option, nydus-image tool will write blob contents into the custom file path `BLOB_FILE`

- With `--blob-dir BLOB_DIR` provided to command, nydus-image tool creates the blob file named as its sha-256 digest. This is useful when you don't want to set a custom name or you are building a layered nydus image. Please create the `BLOB_DIR` before performing the command.

Generally, this is regular file which blob content will be dumped into. It can also be a fifo(named pipe) from which nydusify or other tool can receive blob content.

## Layered Build Nydus Image

`nydus-image` tool supports to build Nydus image from multiple layers of image:

```shell
# Build from lower layer
nydus-image create \
  --bootstrap /path/to/bootstrap \
  --blob /path/to/blob \
  /path/to/lower/dir
# Build from upper layer based on lower layer
nydus-image create \
  --parent-bootstrap /path/to/parent-bootstrap \
  --bootstrap /path/to/bootstrap \
  --blob /path/to/blob \
  /path/to/upper/dir
```

## Build Nydus Image With Chunk-Dict
`nydus-image` tool supports to build Nydus image with chunk-dict for chunk deduplication:
1. reference chunks which are same as chunks in chunk-dict to blobs in chunk-dict
2. new dumped blob would be smaller than without using chunk-dict
3. save space of remote storage because of chunk-deduplication between images (e.g. oss, registry)
```shell
# Build with bootstrap type chunk-dict
nydus-image create \
  --bootstrap /path/to/bootstrap \
  --chunk-dict bootstrap=/path/to/dict.boot \
  --blob /path/to/blob \
  /path/to/lower/dir
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

## Build Nydus Image From Stargz Index

### Convert image layer to stargz format

```shell
tar --xattrs --selinux -czvf ./layer.tar.gz <layer-directory>
stargzify file:layer.tar.gz file:layer.stargz
tar -xzvf layer.stargz stargz.index.json
```

### Stargz build

```shell
nydus-image create \
  --source-type stargz_index \
  --bootstrap /path/to/parent-bootstrap \
  --blob-id <image-lower-layer-id> \
  /path/to/stargz.index.lower.json
```

### Stargz layered build:

```shell
nydus-image create \
  --source-type stargz_index \
  --parent-bootstrap /path/to/parent-bootstrap \
  --bootstrap /path/to/bootstrap \
  --blob-id <image-upper-layer-id> \
  /path/to/stargz.index.upper.json
```

**Note**: the argument value of image layer id specified in nydus-image CLI should omit `sha256:` prefix.
