#!/usr/bin/bats

load "${BATS_TEST_DIRNAME}/common_tests.sh"

setup() {
	rm -rf /tmp/nydus-snapshotter
        mkdir /tmp/nydus-snapshotter
        git clone "${nydus_snapshotter_repo}" /tmp/nydus-snapshotter
}

@test "compile nydus snapshotter" {
        docker run --rm -v /tmp/nydus-snapshotter:/nydus-snapshotter $compile_image bash -c 'cd /nydus-snapshotter && make clear && make'
        if [ -f "/tmp/nydus-snapshotter/bin/containerd-nydus-grpc" ]; then
                /usr/bin/cp -f /tmp/nydus-snapshotter/bin/containerd-nydus-grpc /usr/local/bin/
                echo "nydus-snapshotter version"
                containerd-nydus-grpc --version
        else
                echo "cannot find containerd-nydus-grpc binary"
                exit 1
        fi
}

teardown() {
	rm -rf /tmp/nydus-snapshotter
}
