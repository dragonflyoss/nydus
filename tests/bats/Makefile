ifneq (,$(wildcard /usr/lib/os-release))
include /usr/lib/os-release
else
include /etc/os-release
endif

ci:
	bash -f ./install_bats.sh
	bats --show-output-of-passing-tests --formatter tap build_docker_image.bats
	bats --show-output-of-passing-tests --formatter tap compile_nydusd.bats
	bats --show-output-of-passing-tests --formatter tap compile_ctr_remote.bats
	bats --show-output-of-passing-tests --formatter tap compile_nydus_snapshotter.bats
	bats --show-output-of-passing-tests --formatter tap run_container_with_rafs.bats
