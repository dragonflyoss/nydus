# Nydus Image Builder

`nydus-image` tool converts a directory tree (usually an image layer) into two parts: `bootstrap` and `blob`:

- `bootstrap` is a file presenting filesystem metadata information of the directory;
- `blob` stores all files data in the directory;

## Build Nydus Image From Directory Source

```shell
nydus-image create \
  --bootstrap /path/to/bootstrap
  --backend-type localfs
  --backend-config '{"dir":"/path/to/blobs/dir"}'
  /path/to/source/dir
```

## Output Blob

We can upload the blob to a storage backend or specify an output path, here are some examples with backend config in JSON string:

Localfs Backend:

``` shell
# Build blob file to specified file path
--backend-type localfs --backend-config '{"blob_file":"/path/to/blob"}'
# Build blob file to specified directory path
--backend-type localfs --backend-config '{"dir":"/path/to/blobs/dir"}'
```

OSS Backend:

``` shell
--backend-type oss --backend-config '{"endpoint":"region.aliyuncs.com","access_key_id":"","access_key_secret":"","bucket_name":""}'
```

Container Image Registry Backend:

``` shell
--backend-type registry --backend-config '{"scheme":"https","host":"my-registry:5000","repo":"test/repo","auth":"<base64_encoded_auth>"}'
```

Or using a backend JSON config file:

``` shell
--backend-type registry --backend-config-file /path/to/config.json
```

Or using `--blob` option to specify an output path:

``` shell
--blob /path/to/blob
```

## Layered Build Nydus Image

`nydus-image` tool supports to build Nydus image from multiple layers of image:

```shell
# Build from lower layer
nydus-image create \
  --bootstrap /path/to/parent-bootstrap
  --backend-type localfs
  --backend-config '{"dir":"/path/to/blobs"}'
  /path/to/lower/dir
# Build from upper layer based on lower layer
nydus-image create \
  --parent-bootstrap /path/to/parent-bootstrap
  --bootstrap /path/to/bootstrap
  --backend-type localfs
  --backend-config '{"dir":"/path/to/blobs"}'
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
