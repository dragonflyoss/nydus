# Nydus Image Builder

`nydus-image` tool converts a directory tree (usually an image layer) into two parts: `bootstrap` and `blob`:

- `bootstrap` is a file presenting filesystem metadata information of the directory;
- `blob` stores all files data in the directory;

## Build Nydus Image From Directory Source

```shell
nydus-image create \
  --bootstrap /path/to/bootstrap
  --backend-type localfs
  --backend-config '{"dir":"/path/to/blobs"}'
  /path/to/source/dir
```

## Use Different Storage Backend

Some examples with backend config:

Localfs Backend:

``` shell
# Build blob file to specified file path
--backend_type localfs --backend_config '{"blob_file":"/path/to/blob"}'
# Build blob file to specified directory path
--backend_type localfs --backend_config '{"dir":"/path/to/blobs"}'
```

OSS Backend:

``` shell
--backend_type localfs --backend_config '{"endpoint":"region.aliyuncs.com","access_key_id":"","access_key_secret":"","bucket_name":""}'
```

Container Image Registry Backend:

``` shell
--backend_config '{"scheme":"https","host":"my-registry:5000","repo":"test/repo","auth":"<base64_encoded_auth>"}'
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
