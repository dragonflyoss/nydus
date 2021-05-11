# Nydus Image Builder

`nydus-image` tool converts a directory tree (usually an image layer) into two parts: `bootstrap` and `blob`:

- `bootstrap` is a file presenting filesystem metadata information of the directory;
- `blob` stores all files data in the directory;

### Get binary from release page

Get `nydus-image` binary from [release](https://github.com/dragonflyoss/image-service/releases/latest) page.

## Build Nydus Image From Directory Source

```shell
nydus-image create \
  --bootstrap /path/to/bootstrap
  --blob /path/to/blob
  /path/to/source/dir
```

## Output Blob

Nydus-image tool writes data portion into a file which is generally called `blob`. It has two options to control where `blob` is saved.

- With `--blob <BLOB_FILE>` option, nydus-image tool will write blob contents into the custom file path `BLOB_FILE`

- With `--blob-dir BLOB_DIR` provided to command, nydus-image tool creates the blob file named as its sha-256 digest. This is useful when you don't want to set a custom name or you are building a layered nydus image. Please create the `BLOB_DIR` before perform the command.

Generally, this is regular file which blob content will be dumped into. It can also be a fifo(named pipe) from which nydusify or other tool can receive blob content.

## Layered Build Nydus Image

`nydus-image` tool supports to build Nydus image from multiple layers of image:

```shell
# Build from lower layer
nydus-image create \
  --bootstrap /path/to/parent-bootstrap
  --blob /path/to/blob
  /path/to/lower/dir
# Build from upper layer based on lower layer
nydus-image create \
  --parent-bootstrap /path/to/parent-bootstrap
  --bootstrap /path/to/bootstrap
  --blob /path/to/blob
  /path/to/upper/dir
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

Note: the argument value of image layer id specified in nydus-image CLI should omit `sha256:` prefix.
