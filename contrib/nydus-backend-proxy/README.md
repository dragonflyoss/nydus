# nydus-backend-proxy
A simple HTTP server to serve a local directory as blob backend for nydusd.

In some scenarios such as [sealer](https://github.com/alibaba/sealer), it uses nydus to boost up cluster image distribution. There is no registry (OCI distribution) or OSS service available for blob storage, so we need a simple HTTP server to serve a local directory as blob backend for nydusd. This server exposes OCI distribution like API to handle HTTP HEAD and range GET requests from nydusd for checking and fetching blob.

## Definition for response
support the following APIs:
```bash
HEAD /$namespace/$repo/blobs/sha256:xxx ### Check Blob
GET /$namespace/$repo/blobs/sha256:xxx ### Fetch Blob
```
### Check Blob
```
HEAD /v2/<name>/blobs/<digest>
```
On Success: OK
```
200 OK
Content-Length: <length of blob>
Docker-Content-Digest: <digest>

```
### Fetch Blob
```
GET /v2/<name>/blobs/<digest>
Host: <registry host>
```
On Success: OK
```
200 OK
Content-Length: <length>
Docker-Content-Digest: <digest>
Content-Type: application/octet-stream

<blob binary data>
```
On Failure: Not Found
```
404 Not Found
```
### Fetch Blob in Chunks
```
GET /v2/<name>/blobs/<digest>
Host: <registry host>
Range: bytes=<start>-<end>
```
On Success: OK
```
200 OK
Content-Length: <length>
Docker-Content-Digest: <digest>
Content-Range: bytes <start>-<end>/<size>
Content-Type: application/octet-stream

<blob binary data>
```
On Failure: Not Found
```
404 Not Found
```

On Failure: Range Not Satisfiable
```
416 Range Not Satisfiable
```

## How to use

### Run nydus-backend-proxy
```bash
./nydus-backend-proxy --blobsdir /path/to/nydus/blobs/dir
```
### Nydusd config
reuse nydusd registry backend
```bash
#cat httpserver.json
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "scheme": "http",
	"host": "xxx.xxx.xxx.xxx:8000",
	"repo": "xxxx"
      }
    },
    "cache": {
      "type": "blobcache",
      "config": {
        "work_dir": "./cache"
      }
    }
  },
  "mode": "direct",
  "digest_validate": false,
  "enable_xattr": true,
  "fs_prefetch": {
    "enable": true,
    "threads_count": 2,
    "merging_size": 131072,
    "bandwidth_rate":10485760
  }
}
```
