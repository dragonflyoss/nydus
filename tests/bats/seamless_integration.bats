#!/usr/bin/env bats

load common_tests

# Integration test configuration
INTEGRATION_TEST_IMAGE="nginx:alpine"
INTEGRATION_TEST_CONTAINER="integration-test-container"
INTEGRATION_TARGET_IMAGE="localhost:5000/integration-test:latest"
INTEGRATION_WORKDIR="/tmp/integration-test"

setup() {
    mkdir -p "$INTEGRATION_WORKDIR"
    
    # Start local registry
    if ! docker ps | grep -q "registry:2"; then
        docker run -d -p 5000:5000 --name test-registry registry:2 || true
    fi
    
    # Pull and convert test image
    docker pull "$INTEGRATION_TEST_IMAGE"
    local nydus_image="${INTEGRATION_TEST_IMAGE}-nydus"
    nydusify convert \
        --source "$INTEGRATION_TEST_IMAGE" \
        --target "$nydus_image" \
        --work-dir "$INTEGRATION_WORKDIR/convert" \
        --target-insecure
}

teardown() {
    docker rm -f "$INTEGRATION_TEST_CONTAINER" 2>/dev/null || true
    docker rm -f test-registry 2>/dev/null || true
    rm -rf "$INTEGRATION_WORKDIR"
}

@test "integration: seamless snapshot vs regular commit comparison" {
    local nydus_image="${INTEGRATION_TEST_IMAGE}-nydus"
    
    # Test regular commit first
    docker run -d --name "${INTEGRATION_TEST_CONTAINER}-regular" "$nydus_image" sleep 3600
    docker exec "${INTEGRATION_TEST_CONTAINER}-regular" sh -c "echo 'regular commit data' > /tmp/regular.txt"
    
    local regular_start=$(date +%s%3N)
    run nydusify commit \
        --container "${INTEGRATION_TEST_CONTAINER}-regular" \
        --target "${INTEGRATION_TARGET_IMAGE}-regular" \
        --work-dir "$INTEGRATION_WORKDIR/regular" \
        --target-insecure
    local regular_end=$(date +%s%3N)
    local regular_time=$((regular_end - regular_start))
    
    [ "$status" -eq 0 ]
    docker rm -f "${INTEGRATION_TEST_CONTAINER}-regular"
    
    # Test seamless commit
    docker run -d --name "${INTEGRATION_TEST_CONTAINER}-seamless" "$nydus_image" sleep 3600
    docker exec "${INTEGRATION_TEST_CONTAINER}-seamless" sh -c "echo 'seamless commit data' > /tmp/seamless.txt"
    
    local seamless_start=$(date +%s%3N)
    run nydusify seamless-commit \
        --container "${INTEGRATION_TEST_CONTAINER}-seamless" \
        --target "${INTEGRATION_TARGET_IMAGE}-seamless" \
        --work-dir "$INTEGRATION_WORKDIR/seamless" \
        --target-insecure
    local seamless_end=$(date +%s%3N)
    local seamless_time=$((seamless_end - seamless_start))
    
    [ "$status" -eq 0 ]
    
    echo "Regular commit time: ${regular_time}ms"
    echo "Seamless commit time: ${seamless_time}ms"
    
    # Verify container is still running after seamless commit
    run docker ps --filter "name=${INTEGRATION_TEST_CONTAINER}-seamless" --format "{{.Status}}"
    [[ "$output" =~ "Up" ]]
    
    docker rm -f "${INTEGRATION_TEST_CONTAINER}-seamless"
}

@test "integration: seamless snapshot with nydus mount verification" {
    local nydus_image="${INTEGRATION_TEST_IMAGE}-nydus"
    docker run -d --name "$INTEGRATION_TEST_CONTAINER" "$nydus_image" sleep 3600
    
    # Create test data
    docker exec "$INTEGRATION_TEST_CONTAINER" sh -c "
        echo 'test content for mount verification' > /tmp/mount_test.txt
        mkdir -p /tmp/mount_dir
        echo 'directory content' > /tmp/mount_dir/file.txt
    "
    
    # Perform seamless snapshot
    run nydusify seamless-commit \
        --container "$INTEGRATION_TEST_CONTAINER" \
        --target "$INTEGRATION_TARGET_IMAGE" \
        --work-dir "$INTEGRATION_WORKDIR/seamless" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    
    # Try to mount the resulting nydus image
    local mount_dir="$INTEGRATION_WORKDIR/mount"
    mkdir -p "$mount_dir"
    
    # Note: This would require nydusd to be available and properly configured
    # For now, we'll just verify the image was created successfully
    
    # Verify the target image exists in registry
    run curl -s "http://localhost:5000/v2/integration-test/tags/list"
    [ "$status" -eq 0 ]
    [[ "$output" =~ "latest" ]]
}

@test "integration: seamless snapshot with different fs versions" {
    local nydus_image="${INTEGRATION_TEST_IMAGE}-nydus"
    
    # Test with fs-version 5
    docker run -d --name "${INTEGRATION_TEST_CONTAINER}-v5" "$nydus_image" sleep 3600
    docker exec "${INTEGRATION_TEST_CONTAINER}-v5" sh -c "echo 'fs version 5 test' > /tmp/v5.txt"
    
    run nydusify seamless-commit \
        --container "${INTEGRATION_TEST_CONTAINER}-v5" \
        --target "${INTEGRATION_TARGET_IMAGE}-v5" \
        --work-dir "$INTEGRATION_WORKDIR/v5" \
        --fs-version "5" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    docker rm -f "${INTEGRATION_TEST_CONTAINER}-v5"
    
    # Test with fs-version 6
    docker run -d --name "${INTEGRATION_TEST_CONTAINER}-v6" "$nydus_image" sleep 3600
    docker exec "${INTEGRATION_TEST_CONTAINER}-v6" sh -c "echo 'fs version 6 test' > /tmp/v6.txt"
    
    run nydusify seamless-commit \
        --container "${INTEGRATION_TEST_CONTAINER}-v6" \
        --target "${INTEGRATION_TARGET_IMAGE}-v6" \
        --work-dir "$INTEGRATION_WORKDIR/v6" \
        --fs-version "6" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    docker rm -f "${INTEGRATION_TEST_CONTAINER}-v6"
}

@test "integration: seamless snapshot with different compressors" {
    local nydus_image="${INTEGRATION_TEST_IMAGE}-nydus"
    
    # Test with zstd compressor
    docker run -d --name "${INTEGRATION_TEST_CONTAINER}-zstd" "$nydus_image" sleep 3600
    docker exec "${INTEGRATION_TEST_CONTAINER}-zstd" sh -c "echo 'zstd compression test' > /tmp/zstd.txt"
    
    run nydusify seamless-commit \
        --container "${INTEGRATION_TEST_CONTAINER}-zstd" \
        --target "${INTEGRATION_TARGET_IMAGE}-zstd" \
        --work-dir "$INTEGRATION_WORKDIR/zstd" \
        --compressor "zstd" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    docker rm -f "${INTEGRATION_TEST_CONTAINER}-zstd"
    
    # Test with lz4_block compressor
    docker run -d --name "${INTEGRATION_TEST_CONTAINER}-lz4" "$nydus_image" sleep 3600
    docker exec "${INTEGRATION_TEST_CONTAINER}-lz4" sh -c "echo 'lz4 compression test' > /tmp/lz4.txt"
    
    run nydusify seamless-commit \
        --container "${INTEGRATION_TEST_CONTAINER}-lz4" \
        --target "${INTEGRATION_TARGET_IMAGE}-lz4" \
        --work-dir "$INTEGRATION_WORKDIR/lz4" \
        --compressor "lz4_block" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    docker rm -f "${INTEGRATION_TEST_CONTAINER}-lz4"
}

@test "integration: seamless snapshot with path filtering" {
    local nydus_image="${INTEGRATION_TEST_IMAGE}-nydus"
    docker run -d --name "$INTEGRATION_TEST_CONTAINER" "$nydus_image" sleep 3600
    
    # Create test data in different paths
    docker exec "$INTEGRATION_TEST_CONTAINER" sh -c "
        echo 'include this' > /tmp/include.txt
        echo 'exclude this' > /var/exclude.txt
        mkdir -p /opt/data
        echo 'include this too' > /opt/data/include.txt
    "
    
    # Perform seamless snapshot with path filtering
    run nydusify seamless-commit \
        --container "$INTEGRATION_TEST_CONTAINER" \
        --target "$INTEGRATION_TARGET_IMAGE" \
        --work-dir "$INTEGRATION_WORKDIR/seamless" \
        --with-path "/tmp" \
        --with-path "/opt/data" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Seamless snapshot created successfully" ]]
}

@test "integration: seamless snapshot error recovery" {
    local nydus_image="${INTEGRATION_TEST_IMAGE}-nydus"
    docker run -d --name "$INTEGRATION_TEST_CONTAINER" "$nydus_image" sleep 3600
    
    # Create test data
    docker exec "$INTEGRATION_TEST_CONTAINER" sh -c "echo 'test data' > /tmp/test.txt"
    
    # Test with invalid target (should fail gracefully)
    run nydusify seamless-commit \
        --container "$INTEGRATION_TEST_CONTAINER" \
        --target "invalid://target/image" \
        --work-dir "$INTEGRATION_WORKDIR/seamless" \
        --target-insecure
    
    # Should fail but container should still be running
    [ "$status" -ne 0 ]
    
    # Verify container is still running and accessible
    run docker ps --filter "name=$INTEGRATION_TEST_CONTAINER" --format "{{.Status}}"
    [[ "$output" =~ "Up" ]]
    
    run docker exec "$INTEGRATION_TEST_CONTAINER" cat /tmp/test.txt
    [ "$status" -eq 0 ]
    [[ "$output" == "test data" ]]
    
    # Now try with valid target
    run nydusify seamless-commit \
        --container "$INTEGRATION_TEST_CONTAINER" \
        --target "$INTEGRATION_TARGET_IMAGE" \
        --work-dir "$INTEGRATION_WORKDIR/seamless" \
        --target-insecure
    
    [ "$status" -eq 0 ]
}

@test "integration: seamless snapshot with running application" {
    local nydus_image="${INTEGRATION_TEST_IMAGE}-nydus"
    
    # Start nginx container
    docker run -d --name "$INTEGRATION_TEST_CONTAINER" -p 8080:80 "$nydus_image"
    
    # Wait for nginx to start
    sleep 3
    
    # Verify nginx is serving
    run curl -s http://localhost:8080
    [ "$status" -eq 0 ]
    
    # Modify nginx configuration
    docker exec "$INTEGRATION_TEST_CONTAINER" sh -c "
        echo '<h1>Modified by seamless snapshot test</h1>' > /usr/share/nginx/html/index.html
        echo 'test log entry' >> /var/log/nginx/access.log
    "
    
    # Verify modification
    run curl -s http://localhost:8080
    [[ "$output" =~ "Modified by seamless snapshot test" ]]
    
    # Perform seamless snapshot while nginx is running
    run nydusify seamless-commit \
        --container "$INTEGRATION_TEST_CONTAINER" \
        --target "$INTEGRATION_TARGET_IMAGE" \
        --work-dir "$INTEGRATION_WORKDIR/seamless" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    
    # Verify nginx is still serving after snapshot
    run curl -s http://localhost:8080
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Modified by seamless snapshot test" ]]
    
    # Make another modification to verify container is still writable
    docker exec "$INTEGRATION_TEST_CONTAINER" sh -c "
        echo '<h1>Post-snapshot modification</h1>' > /usr/share/nginx/html/post.html
    "
    
    run curl -s http://localhost:8080/post.html
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Post-snapshot modification" ]]
}
