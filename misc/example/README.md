# nydus example in docker image

This would show how to run a nydus enabled environment in a docker container.

## Prerequisites
1. Make sure docker is using `devicemapper` storage driver. We need this because we want to nest overlay snapshotter in nydus example container.
To do it, add something like below in `/etc/docker/daemon.json`:
```json
{
	"storage-driver": "devicemapper"
}
```
Refer to docker official guide on how to set `devicemapper` storage driver:  https://docs.docker.com/storage/storagedriver/device-mapper-driver/

## Build nydus binaries
```bash
$ make docker-example
```

## Run the example
```bash
$ docker run -it -d --privileged --name nydus-example nydus-rs-example
```

Now you have a nydus example in docker container. Try to exec into it and there
is a helper script to run a very simple example:
```
$ docker exec -it nydus-example sh
/ # cat run.sh
#!/bin/sh

set -eu

# start registry
docker run -d --restart=always -p 5000:5000 registry

# prepare nydus image
NYDUS_IMAGE=/opt/bin/nydus-image
SOURCE_IMAGE=busybox
TARGET_IMAGE=localhost:5000/busybox-nydus
/opt/bin/nydusify convert --nydus-image $NYDUS_IMAGE --source $SOURCE_IMAGE --target $TARGET_IMAGE

# run a container with nydus image
crictl run container-config.yaml pod-config.yaml
```

The simple example would do the following things:
* start a local registry listening on port 5000
* convert a busybox image fetched from dockerhub and convert it into a nydus image and upload to the local registry

```
/ # ./run.sh
Unable to find image 'registry:latest' locally
latest: Pulling from library/registry
cbdbe7a5bc2a: Pull complete
47112e65547d: Pull complete
46bcb632e506: Pull complete
c1cc712bcecd: Pull complete
3db6272dcbfa: Pull complete
Digest: sha256:8be26f81ffea54106bae012c6f349df70f4d5e7e2ec01b143c46e2c03b9e551d
Status: Downloaded newer image for registry:latest
83ceabfcfaca61ba743129fed5d71d1819df2547ab550204046c04f6a55e81b7
[BLOB sha256:ea97eb0eb3ec0bbe00d90be500431050af63c31dc0706c2e8fb53e16cff7761f] Building   --- [========================================================[BLOB sha256:ea97eb0eb3ec0bbe00d90be500431050af63c31dc0706c2e8fb53e16cff7761f] Pushed   --- [====================================================================] 100% 988 kB/988 kB
[BOOT sha256:082df24fe9344e010046766dddea8663badab0a085ae84287e43c965d6342129] Pushed   --- [====================================================================] 100% 6.3 kB/6.3 kB
[MANI sha256:bc354e849494b68bc9de9888ff767cf47987ebf3cead550da0a7ef66cf126a66] Pushed   --- [====================================================================] 100% 100 B/100 B
INFO[2020-12-16T13:34:19Z] Success convert image busybox to localhost:5000/busybox-nydus
820fdc8cb8bd45e29c5b0769b44747cbb7f5117e31eb6c7717f5b8049e032e81
```
