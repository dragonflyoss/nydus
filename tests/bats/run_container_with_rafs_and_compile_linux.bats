load "${BATS_TEST_DIRNAME}/common_tests.sh"

setup() {
	nydus_rafs_image="ghcr.io/dragonflyoss/image-service/bldlinux:v0.1-rafs-v6-lz4"
	run_nydus_snapshotter
	config_containerd_for_nydus
	ctr images ls | grep -q "${nydus_rafs_image}" && ctr images rm $nydus_rafs_image
	ctr-remote images rpull $nydus_rafs_image
}

@test "run container with rafs and compile linux" {
	nerdctl run --rm --net=host --snapshotter=nydus $nydus_rafs_image /bin/bash -c 'cd /linux-5.10.87; make defconfig; make -j8'
	echo "drop cache and compile linux in container again"
	echo 3 > /proc/sys/vm/drop_caches
	nerdctl run --rm --net=host --snapshotter=nydus $nydus_rafs_image /bin/bash -c 'cd /linux-5.10.87; make defconfig; make -j8'
}

teardown() {
	dmesg -T | tail -300 > ${BATS_TEST_DIRNAME}/dmesg-${BATS_TEST_NAME}.log
	ctr images ls | grep -q "${nydus_rafs_image}" && ctr images rm $nydus_rafs_image
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
