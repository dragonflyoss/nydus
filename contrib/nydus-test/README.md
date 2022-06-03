
# Nydus Functional Test

## Introduction

Nydus functional test suit is built on top of [pytest](https://docs.pytest.org/en/stable/).

It basically includes two parts:

* Specific test cases
* Test framework

Test framework includes several key components which are likely to be used by each test case.

* RafsMount
* RafsImage
* TestAnchor
* Distributor
* NydusClient
* WorkloadGenerator
* Supervisor

Cases are categorized into several files.

* test_nydus.py
* test_api.py:
* test_layered_image.py
* test_stress.py
* test_private.py

## Getting Started


### Generate target rootfs

```bash
python3 nydus_test_config.py -D fs_structure.yaml
```

### Configure frame work

```json
{
    "workspace": "/path/where/temporary/files/placed",
    "mount_point": "/mnt",
    "blobcache_dir": "/path/where/saves/blobcache/file",
    "binary_dir": "/path/to/nydusd/image-builder/binary",
    "build_dir": "/nydus/source/",
    "ossutil_bin": "/binary/ossutil",
    "overlayfs": "/path/where/mount/overlayfs",
    "log_level": "info",
    "rootfs": "/target/rootfs",
    "parent_rootfs": "/target/parent/rootfs",
    "target_registry": "localhost:5000",
    "nydusify_work_dir": "/nydusify/workdir",
    "images_array": "/images/will/be/tested/by/nydusify"
}
```

### Build container

```bash
cd /path/to/this-test-suit
docker build --tag ${IMAGE_NAME} - < Dockerfile
```

### Compile Nydus

### Set up test environment

Ensure you have an OSS backend which is accessible from local node running this test suit.
The test framework will obtain OSS configuration from environment variable

#### Configure OSS backend

1. OSS endpoint from `NYDUS_ENDPOINT`

2. OSS access ID from `NYDUS_AK_ID`

3. OSS access secret from `NYDUS_AK_SECRET`

4. OSS bucket from `NYDUS_OSS_BUCKET`

Before running test, please ensure you have fulfilled those environment variables.

#### Generate your own original rootfs

The framework provides a tool to generate rootfs which will be the test target.

```bash
 python3 nydus_test_config.py
```

### Run test

#### From from docker

e.g.

```bash
# Copy binary for this test
mkdir -p $PWD/target-fusedev/release
sudo cp $HOME/.cargo/target-fusedev/release/nydusd $PWD/target-fusedev/release/.
sudo cp $HOME/.cargo/target-fusedev/release/nydus-image $PWD/target-fusedev/release/.

# On host
NYDUS_TEST_ROOT=$PWD/nydus-test
NYDUS_RS_ROOT=$PWD/target-fusedev
NYDUS_TEST_ANCHOR_CONF=/nydus/anchor_conf.json
SNAPSHOTTER_IMAGES_ARRAY=/nydus/snapshotter_images_array.txt
NYDUS_SOURCE=$PWD/nydus-rs

# Inside container
NYDUS_TEST_WORKDIR=/nydus-test

mkdir workspace

sudo docker run \
  --rm \
  -v $NYDUS_TEST_ROOT:/nydus-test \
  -v $NYDUS_RS_ROOT:/nydus-rs/target-fusedev \
  -v $NYDUS_TEST_ANCHOR_CONF:$NYDUS_TEST_WORKDIR/anchor_conf.json \
  -v $SNAPSHOTTER_IMAGES_ARRAY:$NYDUS_TEST_WORKDIR/snapshotter_images_array.txt \
  -v /sys/fs/fuse:/sys/fs/fuse \
  -v $PWD/workspace:/workspace \
  -v $NYDUS_SOURCE:/nydus-source \
  --env-file /nydus/oss_env \
  --env PREFERRED_MODE=direct \
  --env ANCHOR_PATH=$NYDUS_TEST_WORKDIR \
  --env LOG_FILE=/workspace/pyteset.direct.log \
  --env GOPROXY=https://goproxy.io \
  --workdir $NYDUS_TEST_WORKDIR \
  --net=host \
  --privileged \
  nydus-test:0118
```

Rafs has two kinds of metadata mode - `cached` and `direct`. Framework will try to read the preferred metadata mode from environment variable `PREFERRED_MODE`. If `PREFERRED_MODE` is never assigned framework will select `direct` as the metadata mode.

#### Run all test cases

The whole nydus functional test suit works on top of pytest.

#### Run a specific test case

e.g.

```bash
pytest -sv functional-test/test_nydus.py::test_basic
```

#### Run a set of test cases

e.g.

```bash
pytest -sv functional-test/test_nydus.py
```

#### Stop once a case fails

e.g.

```bash
pytest -sv functional-test/test_nydus.py::test_basic --pdb
```

#### Run case step by step

e.g.

```bash
pytest -sv functional-test/test_nydus.py::test_basic --trace
```

### Tune test framework

The entire test is controlled by a configuration file named `anchor_conf.json`.
When test container starts, it already includes an anchor file located at `/etc/anchor_conf.json`.
You can also override it by mounting a local `anchor_conf.json` into test container.

#### 1. Log level

Log level can be changed for both nydus image builder `nydus-image` and `nydusd` by `log_level` name/value pair in `anchor_conf.json`

#### 2. Specify nydusd execution location

The framework can find executions from a specified path from `binary_dir` in `anchor_conf.json` file. This is useful when you want to change to different compiled targets, like from release version to debug version of the binary.

#### 3. Specify original rootfs directory

## Future work

* Specify a pattern how to generate tree structure.
