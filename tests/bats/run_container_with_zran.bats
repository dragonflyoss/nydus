#!/usr/bin/bats

load "${BATS_TEST_DIRNAME}/common_tests.sh"

setup() {
	nydus_zran_image="docker.io/hsiangkao/node:18-nydus-oci-ref"
	run_nydus_snapshotter
	config_containerd_for_nydus
	ctr images ls | grep -q "${nydus_zran_image}" && ctr images rm $nydus_zran_image
	ctr-remote images rpull $nydus_zran_image
}

@test "run container with zran" {
	ctr run --rm --snapshotter=nydus $nydus_zran_image test_container tar cvf /tmp/foo.tar --exclude=/sys --exclude=/proc --exclude=/dev /
}

teardown() {
	dmesg -T | tail -300 > ${BATS_TEST_DIRNAME}/dmesg-${BATS_TEST_NAME}.log
	ctr images ls | grep -q "${nydus_zran_image}" && ctr images rm $nydus_zran_image
	if ps -ef | grep containerd-nydus-grpc | grep -v grep; then
		ps -ef | grep containerd-nydus-grpc | grep -v grep | awk '{print $2}' | xargs kill -9
	fi
	if ps -ef | grep nydusd | grep fscache; then
		ps -ef | grep nydusd | grep fscache | awk '{print $2}' | xargs kill -9
	fi
	if mount | grep 'erofs on'; then
		mount | grep 'erofs on' | awk '{print $3}' | xargs umount
	fi
}
