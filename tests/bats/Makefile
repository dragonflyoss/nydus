ifneq (,$(wildcard /usr/lib/os-release))
include /usr/lib/os-release
else
include /etc/os-release
endif

ci:
	bash -f ./install_bats.sh
	bats --formatter tap build_docker_image.bats
	bats --formatter tap compile_nydusd.bats
	bats --formatter tap compile_ctr_remote.bats
	bats --formatter tap compile_nydus_snapshotter.bats
	bats --formatter tap run_container_with_rafs.bats
	bats --formatter tap run_container_with_zran.bats
	bats --formatter tap run_container_with_rafs_and_compile_linux.bats
