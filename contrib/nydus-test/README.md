
# Nydus Functional Test

## Introduction

Nydus functional test a.k.a nydus-test is built on top of [pytest](https://docs.pytest.org/en/stable/).

It basically includes two parts:

* Specific test cases located at sub-directory functional-test
* Test framework located at sub-directory framework

## Prerequisites

Debian/Ubuntu

```bash
sudo apt update && sudo apt install --no-install-recommends -y attr libattr1-dev fio pkg-config libssl-dev python3-pip libpython3.7-dev libffi-dev
python3 -m pip install --upgrade pip
# Ensure you install below modules as root user
sudo pip3 install pytest xattr requests psutil requests_unixsocket libconf py-splice fallocate pytest-repeat PyYAML six docker toml
```

## Getting Started

### Configure framework

Nydus-test is controlled and configured by `anchor_conf.json`. Nydus-test will try to find it from its root directory before executing all tests.

```json
{
    "workspace": "/path/to/where/nydus-test/stores/intermediates",
    "nydus_project": "/path/to/image-service/repo",
    "nydus_runtime_conf": {
        "profile": "release",
        "log_level": "info"
    },
    "registry": {
        "registry_url": "127.0.0.1:5000",
        "registry_namespace": "nydus",
        "registry_auth": "YourRegistryAuth",
        "backend_proxy_url": "127.0.0.1:8000",
        "backend_proxy_blobs_dir": "/path/to/where/backend/simulator/stores/blobs"
    },
    "images": {
        "images_array": [
            "busybox:latest"
        ]
    },
    "artifacts": {
        "containerd": "/usr/bin/containerd"
    },
    "logging_file": "stderr",
    "target": "gnu"
}
```

### Compile Nydus components

Before running nydus-test, please compile nydus components.

`nydusd` and `nydus-image`

```bash
cd /path/to/image-service/repo
make release
```

`nydus-backend-proxy`

```bash
cd /path/to/image-service/repo
make -C contrib/nydus-backend-proxy
```

### Define target fs structure

```yaml
depth: 4
width: 6
layers:
  - layer1:
      - size: 10KB
        type: regular
        count: 5
      - size: 4MB
        type: regular
        count: 30
      - size: 128KB
        type: regular
        count: 100
      - size: 90MB
        type: regular
        count: 1
      - type: symlink
        count: 100
```

### Generate your own original rootfs

The framework provides a tool to generate rootfs which will be the test target.

```text
 $ sudo python3 nydus_test_config.py --dist fs_structure.yaml

INFO [nydus_test_config - 49:put_files] - putting regular, count 5
INFO [nydus_test_config - 49:put_files] - putting regular, count 30
INFO [nydus_test_config - 49:put_files] - putting regular, count 100
INFO [nydus_test_config - 49:put_files] - putting regular, count 1
INFO [nydus_test_config - 49:put_files] - putting symlink, count 100
INFO [utils - 171:timer] - Generating test layer, Takes time 0.857 seconds
INFO [nydus_test_config - 49:put_files] - putting regular, count 5
INFO [nydus_test_config - 49:put_files] - putting regular, count 30
INFO [nydus_test_config - 49:put_files] - putting regular, count 100
INFO [nydus_test_config - 49:put_files] - putting regular, count 1
INFO [nydus_test_config - 49:put_files] - putting symlink, count 100
INFO [utils - 171:timer] - Generating test parent layer, Takes time 0.760 seconds
```

## Run test

Please run tests as root user.

### Run All Test Cases

The whole nydus functional test suit works on top of pytest.

### Run a Specific Test Case

```bash
pytest -sv functional-test/test_nydus.py::test_basic
```

### Run a Set of Test Cases

```bash
pytest -sv functional-test/test_nydus.py
```

### Stop Once a Case Fails

```bash
pytest -sv functional-test/test_nydus.py::test_basic --pdb
```

### Run case Step by Step

```bash
pytest -sv functional-test/test_nydus.py::test_basic --trace
```
