#!/usr/bin/bats

load "${BATS_TEST_DIRNAME}/common_tests.sh"

@test "compile nydusd" {
        docker run --rm -v $repo_base_dir:/image-service $compile_image bash -c 'cd /image-service && make clean && make release'
        if [ -f "${repo_base_dir}/target/release/nydusd" ] && [ -f "${repo_base_dir}/target/release/nydus-image" ]; then
                /usr/bin/cp -f ${repo_base_dir}/target/release/nydusd /usr/local/bin/
                /usr/bin/cp -f ${repo_base_dir}/target/release/nydus-image /usr/local/bin/
        else
                echo "cannot find nydusd binary or nydus-image binary"
                exit 1
        fi
}
