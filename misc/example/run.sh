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
