#!/usr/bin/bats

load "${BATS_TEST_DIRNAME}/common_tests.sh"

setup() {
	dockerfile="/tmp/rust_golang_dockerfile"
	generate_rust_golang_dockerfile $dockerfile
}

@test "build rust golang image" {
	yum install -y docker
        docker build -f $dockerfile -t $compile_image .
}

teardown() {
	rm -f $dockerfile
}

