# Nydus Snapshotter

## Start Containerd

For using nydus snapshotter with containerd, you need to install containerd beyond version 1.4.0, please refer to this [guide](https://github.com/containerd/containerd/blob/master/BUILDING.md) for more details. To add the nydus snapshotter plugin, add the plugin to containerd's config file (by default at /etc/containerd/config.toml).

```toml
# Plug nydus snapshotter into containerd
# Containerd recognizes nydus snapshotter through specified socket address.
# The specified address below is the default which nydus snapshotter listen to.
[proxy_plugins]
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/containerd-nydus/containerd-nydus-grpc.sock"

# Use nydus as default snapshot through CRI
[plugins."io.containerd.grpc.v1.cri".containerd]
   snapshotter = "nydus"
```

Then you can start containerd in one terminal with following command.

```bash
$ /path/to/containerd --config /etc/containerd/config.toml
```

## Setting up the Nydus snapshotter

### Generate Nydus config

You can configure nydus snapshotter with custom configurations. The config file must be formatted with json and can be passed to nydus snapshotter with `--config-path` option. Your configuration file should look like below, where value of `auth` is a based64-encoded `username:password` string. You can generate it using `echo -n 'username:password' | base64`.

```json
{
  "device": {
    "backend": {
      "type": "registry",
      "config": {
        "scheme": "https",
        "auth": "<registry auth token>",
        "timeout": 5,
        "connect_timeout": 5,
        "retry_limit": 0
      }
    },
    "cache": {
      "type": "blobcache",
      "config": {
        "work_dir": "/tmp/cache"
      }
    }
  },
  "mode": "direct",
  "digest_validate": true,
  "iostats_files": true,
  "enable_xattr": true,
  "fs_prefetch": {
    "enable": true,
    "threads_count": 10,
    "merging_size": 131072
  }
}
```

### Start Nydus snapshotter

Nydus snapshotter is implemented as a [proxy plugin](https://github.com/containerd/containerd/blob/04985039cede6aafbb7dfb3206c9c4d04e2f924d/PLUGINS.md#proxy-plugins) daemon (`containerd-nydus-grpc`) for containerd. You can start the daemon as following

```bash
# nydusd-path is the path of nydusd binary, you need to compile the binary first
# address is the socket address that you configured in containerd config file
# root is the path of nydus snapshotter
# config-path is the path of your nydus configuration file you just generated

$ ./containerd-nydus-grpc \
  --nydusd-path /bin/nydusd \
  --config-path /etc/nydus/config.json \
  --root /var/lib/containerd/io.containerd.snapshotter.v1.nydus \
  --address /var/run/containerd-nydus/containerd-nydus-grpc.sock 
```

### Check nydus snapshotter

There is a default cli named `ctr` based on the GRPC api for containerd. This cli will allow you to create and manage containers run with containerd. And you can check if nydus snapshotter has started successfully by running the following commands:

```bash
$ ctr -a /run/containerd/containerd.sock plugin ls | grep nydus
```

## Using nydus snapshotter

### Download crictl tools

crictl is a tool to help developers debug their runtime without needing to set up Kubernetes components. `crictl` can be downloaded from cri-tools [release page](https://github.com/kubernetes-sigs/cri-tools/releases):

```bash
VERSION="v1.17.0"
wget https://github.com/kubernetes-sigs/cri-tools/releases/download/$VERSION/crictl-$VERSION-linux-amd64.tar.gz
sudo tar zxvf crictl-$VERSION-linux-amd64.tar.gz -C /usr/local/bin
rm -f crictl-$VERSION-linux-amd64.tar.gz
```

### Create crictl config

The runtime endpoint can be set in the config file. Please refer to [crictl](https://github.com/kubernetes-sigs/cri-tools/blob/master/docs/crictl.md) document for more details.

``` bash
$ cat crictl.yaml
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 10
debug: true
```

### Have fun with nydus

You can create a container in the pod sandbox with config file.

```bash
$ cat pod-config.yaml
metadata:
  attempt: 1
  name: nydus-sandbox
  namespace: default
  uid: hdishd83djaidwnduwk28bcsb
log_directory: /tmp
linux:
  security_context:
    namespace_options:
      network: 2
annotations:
  "io.containerd.osfeature": "nydus.remoteimage.v1"

$ cat container-config.yaml
metadata:
  name: nydus-container
image:
  image: <nydus-image>
command:
- /bin/sleep
args:
- 600
log_path: container.1.log

#auth is base64 of registry username:password
$ crictl --config ./crictl.yaml run \
 --auth <base64 of registry auth> \
 ./container-config.yaml ./podsandbox-config.yaml
```

List and check running nydus container.

```bash
$ crictl --config ./crictl.yaml ps
```

Attach into nydus container.

```bash
$ crictl --config ./crictl.yaml exec -it <containerID> bash
```
