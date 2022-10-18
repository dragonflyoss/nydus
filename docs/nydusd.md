# Nydusd

`nydusd` running as daemon to expose a [FUSE](https://www.kernel.org/doc/html/latest/filesystems/fuse.html) mountpoint or a [Virtio-FS](https://virtio-fs.gitlab.io/) mountpoint inside guest for containers to access.

### Get binary from release page

Get `nydusd` binary from [release](https://github.com/dragonflyoss/image-service/releases/latest) page.

## Run Nydusd Daemon

``` shell
# Prepare nydusd configuration
cat /path/to/config-localfs.json
{
  "device": {
    "backend": {
      "type": "localfs",
      "config": {
        "dir": "/path/to/blobs",
      }
    }
  }
}
```

### Run With FUSE
If no `/path/to/bootstrap` is available, please refer to [nydus-image.md](https://github.com/dragonflyoss/image-service/blob/master/docs/nydus-image.md) for more details.

``` shell
sudo nydusd \
  --config /path/to/config-localfs.json \
  --mountpoint /path/to/mnt \
  --bootstrap /path/to/bootstrap \
  --log-level info
```

### Run With Virtio-FS
If no `/path/to/bootstrap` is available, please refer to [nydus-image.md](https://github.com/dragonflyoss/image-service/blob/master/docs/nydus-image.md) for more details.

Virtio-fs is supported by both [QEMU](https://www.qemu.org/) and [Cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor). To run `nydusd` with virtio-fs support, first start it with `--sock` option to expose a virtio-fs socket endpoint.

``` shell
sudo nydusd \
  --config /path/to/config-localfs.json \
  --sock /path/to/vhost-user-fs.sock \
  --bootstrap /path/to/bootstrap \
  --log-level info
```

Then start a qemu process with a `vhost-user-fs-pci` device, run something like:

``` shell
./qemu-system-x86_64 -M pc -cpu host --enable-kvm -smp 2 \
        -m 2G,maxmem=16G -object memory-backend-file,id=mem,size=2G,mem-path=/dev/shm,share=on -numa node,memdev=mem \
        -chardev socket,id=char0,path=/path/to/vhost-user-fs.sock \
        -device vhost-user-fs-pci,chardev=char0,tag=nydus,queue-size=1024,indirect_desc=false,event_idx=false \
        -serial mon:stdio -vga none -nographic -curses -kernel ./kernel \
        -append 'console=ttyS0 root=/dev/vda1 virtio_fs.dyndbg="+pfl" fuse.dyndbg="+pfl"' \
        -device virtio-net-pci,netdev=net0,mac=AE:AD:BE:EF:6C:FB -netdev type=user,id=net0 \
        -qmp unix:/path/to/qmp.sock,server,nowait \
        -drive if=virtio,file=./bionic-server-cloudimg-amd64.img
```

Then we can mount nydus virtio-fs inside the guest with:

``` shell
mount -t virtio_fs none /mnt -o tag=nydus,default_permissions,allow_other,rootmode=040000,user_id=0,group_id=0,nodev
```

Or simply below if you are running newer guest kernel:

``` shell
mount -t virtiofs nydus /mnt
```

We are working on enabling cloud-hypervisor support for nydus.

### Nydus Configuration

#### Common Fields In Config

```
{
  "device": {
    "backend": {
      // localfs | oss | registry
      "type": "localfs",
      "config": {
        // Drop the read request once http request timeout, in seconds
        "timeout": 5,
        // Drop the read request once http connection timeout, in seconds
        "connect_timeout": 5,
        // Retry count when read request failed
        "retry_limit": 0,
      }
    },
    "cache": {
      // Blobcache: enable local fs cache
      // Dummycache: disable cache, access remote storage backend directly
      "type": "blobcache",
      // Enable cache compression
      "compressed": true,
      "config": {
        // Directory of cache files, only for blobcache
        "work_dir": "/cache"
      }
    }
  },
  // direct | cached
  "mode": "direct",
  // Validate inode tree digest and chunk digest on demand
  "digest_validate": false,
  // Enable file IO metric
  "iostats_files": true,
  // Enable support of fs extended attributes
  "enable_xattr": false,
  "fs_prefetch": {
    // Enable blob prefetch
    "enable": false,
    // Prefetch thread count
    "threads_count": 10,
    // Maximal read size per prefetch request, e.g. 128kb
    "merging_size": 131072,
    // Limit prefetch bandwidth to 1MB/S, it aims at reducing congestion with normal user io
    "bandwidth_rate": 1048576
  }
}
```

#### Use Different Storage Backends

##### Localfs Backend

```
{
  "device": {
    "backend": {
      "type": "localfs",
      "config": {
        // The directory included all blob files declared in bootstrap
        "dir": "/path/to/blobs/",
        // Record read access log, prefetch data on next time
        "readahead": true,
        // Duration of recording access log
        "readahead_sec": 10
      }
    },
    ...
  },
  ...
}
```

##### OSS backend with blobcache

```
{
  "device": {
    "backend": {
      "type": "oss",
      "config": {
        ...
        "endpoint": "region.aliyuncs.com",
        "access_key_id": "",
        "access_key_secret": "",
        "bucket_name": ""
      }
    },
    ...
  },
  ...
}
```

##### Registry backend

```
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        ...
        // Registry url scheme, https or http
        "scheme": "http",
        // Registry hostname with format `$host:$port`
        "host": "my-registry:5000",
        // Skip SSL certificate validation for HTTPS scheme
        "skip_verify": false,
        // Use format `$namespace/$repo` (no image tag)
        "repo": "test/repo",
        // Username and password for auth
        // base64(username:password), optional
        "auth": "<base64_encoded_auth>",
        // Bearer token for auth, optional
        "registry_token": "<bearer_token>"
        // Redirected blob download host, optional
        "blob_redirected_host": "<blob_redirected_host>"
      }
    },
    ...
  },
  ...
}
```

##### Enable P2P Proxy for Storage Backend

Add `device.backend.config.proxy` field to enable HTTP proxy for storage backend. For example, use P2P distribution service to reduce network workload and latency in large scale container cluster using [Dragonfly](https://d7y.io/) (enable centralized dfdaemon mode).

```
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "proxy": {
          // Access remote storage backend via P2P proxy, e.g. Dragonfly dfdaemon server URL
          "url": "http://p2p-proxy:65001",
          // Fallback to remote storage backend if P2P proxy ping failed
          "fallback": true,
          // Endpoint of P2P proxy health checking
          "ping_url": "http://p2p-proxy:40901/server/ping",
          // Interval of P2P proxy health checking, in seconds
          "check_interval": 5
        },
        ...
      }
    },
    ...
  },
  ...
}
```

Once the configuration is loaded successfully on nydusd starting, we will see the log as shown below:

```
INFO [storage/src/backend/connection.rs:136] backend config: CommonConfig { proxy: ProxyConfig { url: "http://p2p-proxy:65001", ping_url: "http://p2p-proxy:40901/server/ping", fallback: true, check_interval: 5 }, timeout: 5, connect_timeout: 5, retry_limit: 0 }
```

##### Enable Mirrors for Storage Backend

Add `device.backend.config.mirrors` field to enable mirrors for storage backend. The mirror can be a P2P distribution server (such as [Dragonfly](https://d7y.io/)) or registry. If the request to mirror server failed, it will fall back to the original registry.
Currently, the mirror mode is only tested in the registry backend, and in theory, the OSS backend also supports it.

<font color='red'>!!</font> The `mirrors` field is conflicts with `proxy` field.

```
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "mirrors": [
          {
            // Mirror server URL (include scheme), e.g. Dragonfly dfdaemon server URL
            "host": "http://dragonfly1.io:65001",
            // true: Send the authorization request to the mirror e.g. another docker registry.
            // false: Authorization request won't be relayed by the mirror e.g. Dragonfly.
            "auth_through": false,
            // Headers for mirror server
            "headers": {
              // For Dragonfly dfdaemon server URL, we need to specify "X-Dragonfly-Registry" (include scheme). 
              // When Dragonfly does not cache data, it will pull them from "X-Dragonfly-Registry". 
              // If not set "X-Dragonfly-Registry", Dragonfly will pull data from proxy.registryMirror.url.
              "X-Dragonfly-Registry": "https://index.docker.io"
            }
          },
          {
            "host": "http://dragonfly2.io:65001",
            "headers": {
              "X-Dragonfly-Registry": "https://index.docker.io"
            }
          }
        ],
        ...
      }
    },
    ...
  },
  ...
}
```

### Mount Bootstrap Via API

To mount a bootstrap via api, first launch nydusd without a bootstrap:

``` shell
sudo nydusd \
  --apisock /path/to/api.sock \
  --config /path/to/config.json \
  --mountpoint /path/to/mountpoint
```

Then use curl to mount a bootstrap to `/path/to/mountpoint/sub`:

``` shell
curl --unix-socket api.sock \
     -X POST "http://localhost/api/v1/mount?mountpoint=/sub" \
     -H "Content-Type: application/json" \
     -d '{
        "source":"/path/to/bootstrap",
        "fs_type":"rafs",
        "config":"{\"device\":{\"backend\":{\"type\":\"localfs\",\"config\":{\"dir\":\"blobs\"}},\"cache\":{\"type\":\"blobcache\",\"config\":{\"work_dir\":\"cache\"}}},\"mode\":\"direct\",\"digest_validate\":true}"
	}'
```

The `config` field is a JSON format string that can be obtained by `cat rafs.config | jq tostring`.

### Multiple Pseudo Mounts

One single nydusd can have multiple pseudo mounts within a mountpoint.

To achieve that, you can trigger backend fs (e.g., rafs) mount through the HTTP interfaces using curl command.

When starting nydusd without the --bootstrap option, there will be no backend file system in a nydus mountpoint. You can use curl command to mount multiple backend fs at different sub-directories.

#### Example

Given that your mountpoint is `/mnt` which can be a directory in local host or inside guest.

When you have two pseudo mounts which are named "pseudo_1" and "pseudo_2" identified in http request body.

pseudo_1 and pseudo_2 correspond to bootstrap respectively.

``` shell
tree -L 1 mnt
mnt
├── pseudo_1
└── pseudo_2
```
