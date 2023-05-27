#!/usr/bin/bats

load "${BATS_TEST_DIRNAME}/common_tests.sh"

@test "compile ctr remote" {
        docker run --rm -v $repo_base_dir:/image-service $compile_image bash -c 'cd /image-service/contrib/ctr-remote && make clean && make'
        if [ -f "${repo_base_dir}/contrib/ctr-remote/bin/ctr-remote" ]; then
                /usr/bin/cp -f ${repo_base_dir}/contrib/ctr-remote/bin/ctr-remote /usr/local/bin/
        else
                echo "cannot find ctr-remote binary"
                exit 1
        fi
}

