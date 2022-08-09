# CRI-O/Podman Nydus Store Plugin

The project is an implementation of additional layer store plugin of CRI-O/Podman, it provides CRI-O/Podman with the ability to lazy mount [nydus](https://nydus.dev/) images.

⚠️ This project is still in progress, see more details in this [proposal](https://github.com/containers/podman/issues/15249).

[![asciicast](https://asciinema.org/a/EqYr5HCcP5LndnFbKnBucPeqd.svg)](https://asciinema.org/a/EqYr5HCcP5LndnFbKnBucPeqd)


## Quick Start

1. Build store plugin

```shell
$ git clone https://github.com/containers/nydus-storage-plugin.git
$ cd nydus-storage-plugin
$ go build cmd/store/main.go
```

2. Install nydusd

Download nydus binaries from [nydus release](https://github.com/dragonflyoss/image-service/releases/) page, and then install with the command below:

```shell
$ tar xzvf nydus-static-$version-linux-amd64.tgz
$ sudo mv nydus-static/nydusd-fusedev /usr/bin/nydusd
$ sudo mv nydus-static/nydusify /usr/bin/nydusify
$ sudo mv nydus-static/nydus-image /usr/bin/nydus-image
```

3. Configure podman

Get an `/etc/containers/storage.conf` example from [here](https://github.com/containers/podman/blob/main/vendor/github.com/containers/storage/storage.conf), and add with `[storage.options]` section like:

```shell
[storage.options]
additionallayerstores = [
  "/var/lib/nydus-store/store:ref"
]
```

Make sure you have created the directory with `mkdir -p /var/lib/nydus-store/store`.

4. Run store plugin

Prepare a nydus configuration JSON file like below, named as `/etc/nydusd-config.json`:

```json
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "scheme": "http",
        "timeout": 5,
        "connect_timeout": 5,
        "retry_limit": 2
      }
    },
    "cache": {
      "type": "blobcache",
      "config": {
        "work_dir": "/var/lib/nydus/cache"
      }
    }
  },
  "mode": "direct",
  "digest_validate": false,
  "iostats_files": false,
  "enable_xattr": true,
  "fs_prefetch": {
    "enable": true,
    "threads_count": 2
  }
}
```

```shell
$ sudo ./store --log-to-stdout --log-level debug --config-path /etc/nydusd-config.json --root /var/lib/nydus-store
```

5. Convert a nydus image

```shell
# Prepare a local registry
$ podman run -d -it -p 5000:5000 --name registry docker.io/library/registry:2

# Convert OCI v1 image to nydus image:
$ sudo nydusify convert --source ubuntu --target localhost:5000/ubuntu:latest-nydus
```

6. Run container with nydus image

```shell
$ sudo podman run -it --tls-verify=false --rm localhost:5000/ubuntu:latest-nydus /bin/bash
```
