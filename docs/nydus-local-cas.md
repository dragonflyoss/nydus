# Nydus local-cas artifact user guide

This guide mainly introduces the background, design principles and usage of local-cas.  Local CAS(content addressable storage)maintains node-level data information through a local database (sqlite) and skips locally cached data when downloading images, thereby reducing locally cached data on the node. 

Local cas is divided into two modules: static deduplication and dynamic deduplication. Static deduplication realizes the redirection of nydus data access by modifying the chunk index information in the bootstrap file, thereby reusing the chunk data of other nydus images. But there is a serious problem: it may reuse chunks that cannot be obtained by the backend of the current image, resulting in the container being unable to load the corresponding chunk data on demand during runtime. To address this issue, dynamic deduplication was introduced. When nydusd initializes the blob cache, it reads the corresponding backend configuration information of the blob from the CAS database, enabling the blob cache to read chunk data from other backend.

## local-cas artifact

1. Add deduplication related information to the nydusd configuration file(such ac /etc/nydus/nydusd-config.fusedev.json).

```
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "timeout": 5,
        "connect_timeout": 5,
        "retry_limit": 2
      }
    },
    "cache": {
      "type": "blobcache"
    },
    "deduplication": {
      "enable": true,
      "work_dir": "/var/lib/containerd-nydus/"
    }
  },
  "mode": "direct",
  "digest_validate": false,
  "iostats_files": false,
  "enable_xattr": true,
  "fs_prefetch": {
    "enable": true,
    "threads_count": 8,
    "merging_size": 1048576,
    "prefetch_all": true
  }
}

```

2. Turn on the chunk-deduplication option of nydus-snapshotter.
```
./containerd-nydus-grpc \
--config /etc/nydus/config.toml \
--nydusd-config /etc/nydus/nydusd-config.fusedev.json \
--log-to-stdout --chunk-deduplication
```

3. Other steps are exactly the same as the normal nydus startup process.