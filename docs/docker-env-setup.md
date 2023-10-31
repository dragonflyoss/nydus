# Nydus Setup for Docker(Moby) Environment
## Install Nydus Snapshotter for Docker(Moby) with Systemd
1. Docker(Moby) newer than [5c1d6c957b97321c8577e10ddbffe6e01981617a](https://github.com/moby/moby/commit/5c1d6c957b97321c8577e10ddbffe6e01981617a) is needed on your host. The commit is expected to be included in Docker v24. 
```
git clone https://github.com/moby/moby
cd moby
make binary
cd bundles/binary
sudo systemctl stop docker
sudo systemctl stop containerd
sudo cp ./* /usr/bin/
```

2. Download nydus-snapshotter release tarball from [the release page](https://github.com/containerd/nydus-snapshotter/releases). 
```
# Get the latest version. If this version does not work for you, you can try v0.6.0
TAG=`curl -s https://api.github.com/repos/containerd/nydus-snapshotter/releases/latest | grep tag_name | cut -f4 -d "\""`
wget https://github.com/containerd/nydus-snapshotter/releases/download/"$TAG"/nydus-snapshotter-"$TAG"-x86_64.tgz
tar -xzvf nydus-snapshotter-"$TAG"-x86_64.tgz
sudo install -D -m 755 nydus-snapshotter/containerd-nydus-grpc /usr/local/bin

wget -O /etc/nydus/nydusd-config.json https://raw.githubusercontent.com/containerd/nydus-snapshotter/"$TAG"/misc/snapshotter/nydusd-config.fusedev.json
wget -O /etc/nydus/config.toml https://raw.githubusercontent.com/containerd/nydus-snapshotter/"$TAG"/misc/snapshotter/config.toml
```

3. Download nydus image service release tarball from [the release page](https://github.com/dragonflyoss/nydus/releases). 
```
# Get the latest version. If this version does not work for you, you can try v2.1.4
TAG=`curl -s https://api.github.com/repos/dragonflyoss/nydus/releases/latest | grep tag_name | cut -f4 -d "\""`
wget https://github.com/dragonflyoss/nydus/releases/download/"$TAG"/nydus-static-"$TAG"-linux-amd64.tgz
tar -xzvf nydus-static-"$TAG"-linux-amd64.tgz
sudo install -D -m 755 nydus-static/* /usr/local/bin
```

4. Enable `containerd-snapshotter` feature and `nydus`snapshotter in Docker. Add the following to docker's configuration file (typically: /etc/docker/daemon.json). 
```json
{
  "features": {
    "containerd-snapshotter": true
  },
  "storage-driver": "nydus"
}
```

5. Enable nydus snapshotter in containerd. Add the following configuration to containerd's configuration file (typically: /etc/containerd/config.toml). 
```toml
version = 2

# Plug nydus snapshotter into containerd
[proxy_plugins]
  [proxy_plugins.nydus]
    type = "snapshot"
    address = "/run/containerd-nydus/containerd-nydus-grpc.sock"
```

6. Install fuse  
- centos
```bash
# centos 7
sudo yum install fuse
# centos 8
sudo dnf install fuse

sudo modprobe fuse
```

- ubuntu
```bash
sudo apt-get install fuse
sudo modprobe fuse
```

7. Start nydus-snapshotter and restart containerd and docker 
```
# install nydus snapshotter service
wget -O /etc/systemd/system/nydus-snapshotter.service https://raw.githubusercontent.com/containerd/nydus-snapshotter/main/misc/snapshotter/nydus-snapshotter.fusedev.service
sudo systemctl enable --now nydus-snapshotter
sudo systemctl restart containerd

sudo sed -i "s/fd:/unix:/g" /lib/systemd/system/docker.service
sudo systemctl daemon-reload
sudo systemctl restart docker
```
 8. Run nydus image in docker
```
# Start local registry
sudo docker run -d --restart=always -p 5000:5000 registry
# Convert Nydus image
sudo nydusify convert --source ubuntu --target localhost:5000/ubuntu-nydus
# Run Nydus image
sudo docker run --rm -it localhost:5000/ubuntu-nydus:latest bash
```

## Install Docker Nydus Graph Driver for Docker [Experimental]
This feature is currently **experimental**, please do not use it in a production environment.

1. For older versions of Docker(Moby) lower than v24, please use [Docker Nydus Graph Driver](https://github.com/nydusaccelerator/docker-nydus-graphdriver).