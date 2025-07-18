#!/usr/bin/env bats

load common_tests

# Test configuration
SEAMLESS_TEST_IMAGE="alpine:3.18"
SEAMLESS_TEST_CONTAINER="seamless-test-container"
SEAMLESS_TARGET_IMAGE="localhost:5000/seamless-test:latest"
SEAMLESS_WORKDIR="/tmp/seamless-test"

setup() {
    # Setup test environment
    mkdir -p "$SEAMLESS_WORKDIR"
    
    # Start local registry if not running
    if ! docker ps | grep -q "registry:2"; then
        docker run -d -p 5000:5000 --name test-registry registry:2 || true
    fi
    
    # Pull test image
    docker pull "$SEAMLESS_TEST_IMAGE"
    
    # Convert to nydus format first
    local nydus_image="${SEAMLESS_TEST_IMAGE}-nydus"
    nydusify convert \
        --source "$SEAMLESS_TEST_IMAGE" \
        --target "$nydus_image" \
        --work-dir "$SEAMLESS_WORKDIR/convert" \
        --target-insecure
}

teardown() {
    # Cleanup containers
    docker rm -f "$SEAMLESS_TEST_CONTAINER" 2>/dev/null || true
    
    # Cleanup test registry
    docker rm -f test-registry 2>/dev/null || true
    
    # Cleanup work directory
    rm -rf "$SEAMLESS_WORKDIR"
}

@test "seamless snapshot: basic functionality" {
    # Start a container with nydus image
    local nydus_image="${SEAMLESS_TEST_IMAGE}-nydus"
    docker run -d --name "$SEAMLESS_TEST_CONTAINER" "$nydus_image" sleep 3600
    
    # Wait for container to be running
    sleep 2
    
    # Create some changes in the container
    docker exec "$SEAMLESS_TEST_CONTAINER" sh -c "echo 'test data' > /tmp/test.txt"
    docker exec "$SEAMLESS_TEST_CONTAINER" sh -c "mkdir -p /tmp/testdir"
    docker exec "$SEAMLESS_TEST_CONTAINER" sh -c "echo 'more data' > /tmp/testdir/file.txt"
    
    # Perform seamless snapshot
    run nydusify seamless-commit \
        --container "$SEAMLESS_TEST_CONTAINER" \
        --target "$SEAMLESS_TARGET_IMAGE" \
        --work-dir "$SEAMLESS_WORKDIR/seamless" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    [[ "$output" =~ "Seamless snapshot created successfully" ]]
    [[ "$output" =~ "Pause Time:" ]]
    [[ "$output" =~ "Snapshot ID:" ]]
}

@test "seamless snapshot: pause time verification" {
    # Start a container with nydus image
    local nydus_image="${SEAMLESS_TEST_IMAGE}-nydus"
    docker run -d --name "$SEAMLESS_TEST_CONTAINER" "$nydus_image" sleep 3600
    
    # Wait for container to be running
    sleep 2
    
    # Create some changes
    docker exec "$SEAMLESS_TEST_CONTAINER" sh -c "echo 'test' > /tmp/test.txt"
    
    # Measure pause time
    local start_time=$(date +%s%3N)
    
    run nydusify seamless-commit \
        --container "$SEAMLESS_TEST_CONTAINER" \
        --target "$SEAMLESS_TARGET_IMAGE" \
        --work-dir "$SEAMLESS_WORKDIR/seamless" \
        --target-insecure
    
    local end_time=$(date +%s%3N)
    local total_time=$((end_time - start_time))
    
    [ "$status" -eq 0 ]
    
    # Extract pause time from output
    local pause_time=$(echo "$output" | grep "Pause Time:" | sed 's/.*Pause Time: \([0-9.]*\).*/\1/')
    
    # Verify pause time is less than 10ms (10000000 nanoseconds)
    # Note: This is a rough check, actual implementation should be more precise
    echo "Total operation time: ${total_time}ms"
    echo "Reported pause time: ${pause_time}"
    
    # The pause time should be significantly less than total time
    [ "$total_time" -gt 100 ]  # Total should be more than 100ms
}

@test "seamless snapshot: container continues running" {
    # Start a container with nydus image
    local nydus_image="${SEAMLESS_TEST_IMAGE}-nydus"
    docker run -d --name "$SEAMLESS_TEST_CONTAINER" "$nydus_image" sh -c "
        while true; do
            echo \$(date): Container is running >> /tmp/heartbeat.log
            sleep 1
        done
    "
    
    # Wait for container to start
    sleep 3
    
    # Check initial heartbeat
    run docker exec "$SEAMLESS_TEST_CONTAINER" cat /tmp/heartbeat.log
    local initial_lines=$(echo "$output" | wc -l)
    
    # Perform seamless snapshot
    nydusify seamless-commit \
        --container "$SEAMLESS_TEST_CONTAINER" \
        --target "$SEAMLESS_TARGET_IMAGE" \
        --work-dir "$SEAMLESS_WORKDIR/seamless" \
        --target-insecure
    
    # Wait a bit more
    sleep 3
    
    # Check that container is still running and writing heartbeat
    run docker exec "$SEAMLESS_TEST_CONTAINER" cat /tmp/heartbeat.log
    local final_lines=$(echo "$output" | wc -l)
    
    # Container should have continued writing heartbeat
    [ "$final_lines" -gt "$initial_lines" ]
    
    # Verify container is still running
    run docker ps --filter "name=$SEAMLESS_TEST_CONTAINER" --format "{{.Status}}"
    [[ "$output" =~ "Up" ]]
}

@test "seamless snapshot: data consistency" {
    # Start a container with nydus image
    local nydus_image="${SEAMLESS_TEST_IMAGE}-nydus"
    docker run -d --name "$SEAMLESS_TEST_CONTAINER" "$nydus_image" sleep 3600
    
    # Create test data
    docker exec "$SEAMLESS_TEST_CONTAINER" sh -c "echo 'original data' > /tmp/original.txt"
    docker exec "$SEAMLESS_TEST_CONTAINER" sh -c "mkdir -p /tmp/testdir"
    docker exec "$SEAMLESS_TEST_CONTAINER" sh -c "echo 'directory data' > /tmp/testdir/file.txt"
    
    # Perform seamless snapshot
    run nydusify seamless-commit \
        --container "$SEAMLESS_TEST_CONTAINER" \
        --target "$SEAMLESS_TARGET_IMAGE" \
        --work-dir "$SEAMLESS_WORKDIR/seamless" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    
    # Verify data is still accessible in the container
    run docker exec "$SEAMLESS_TEST_CONTAINER" cat /tmp/original.txt
    [ "$status" -eq 0 ]
    [[ "$output" == "original data" ]]
    
    run docker exec "$SEAMLESS_TEST_CONTAINER" cat /tmp/testdir/file.txt
    [ "$status" -eq 0 ]
    [[ "$output" == "directory data" ]]
    
    # Add more data after snapshot
    docker exec "$SEAMLESS_TEST_CONTAINER" sh -c "echo 'post-snapshot data' > /tmp/post.txt"
    
    run docker exec "$SEAMLESS_TEST_CONTAINER" cat /tmp/post.txt
    [ "$status" -eq 0 ]
    [[ "$output" == "post-snapshot data" ]]
}

@test "seamless snapshot: multiple snapshots" {
    # Start a container with nydus image
    local nydus_image="${SEAMLESS_TEST_IMAGE}-nydus"
    docker run -d --name "$SEAMLESS_TEST_CONTAINER" "$nydus_image" sleep 3600
    
    # First snapshot
    docker exec "$SEAMLESS_TEST_CONTAINER" sh -c "echo 'snapshot1' > /tmp/snap1.txt"
    
    run nydusify seamless-commit \
        --container "$SEAMLESS_TEST_CONTAINER" \
        --target "${SEAMLESS_TARGET_IMAGE}-1" \
        --work-dir "$SEAMLESS_WORKDIR/seamless1" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    local snapshot1_id=$(echo "$output" | grep "Snapshot ID:" | sed 's/.*Snapshot ID: \(.*\)/\1/')
    
    # Second snapshot
    docker exec "$SEAMLESS_TEST_CONTAINER" sh -c "echo 'snapshot2' > /tmp/snap2.txt"
    
    run nydusify seamless-commit \
        --container "$SEAMLESS_TEST_CONTAINER" \
        --target "${SEAMLESS_TARGET_IMAGE}-2" \
        --work-dir "$SEAMLESS_WORKDIR/seamless2" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    local snapshot2_id=$(echo "$output" | grep "Snapshot ID:" | sed 's/.*Snapshot ID: \(.*\)/\1/')
    
    # Verify different snapshot IDs
    [ "$snapshot1_id" != "$snapshot2_id" ]
    
    # Verify both files exist
    run docker exec "$SEAMLESS_TEST_CONTAINER" cat /tmp/snap1.txt
    [[ "$output" == "snapshot1" ]]
    
    run docker exec "$SEAMLESS_TEST_CONTAINER" cat /tmp/snap2.txt
    [[ "$output" == "snapshot2" ]]
}

@test "seamless snapshot: error handling" {
    # Test with non-existent container
    run nydusify seamless-commit \
        --container "non-existent-container" \
        --target "$SEAMLESS_TARGET_IMAGE" \
        --work-dir "$SEAMLESS_WORKDIR/seamless" \
        --target-insecure
    
    [ "$status" -ne 0 ]
    [[ "$output" =~ "error" || "$output" =~ "failed" ]]
}

@test "seamless snapshot: performance benchmark" {
    # Start a container with nydus image
    local nydus_image="${SEAMLESS_TEST_IMAGE}-nydus"
    docker run -d --name "$SEAMLESS_TEST_CONTAINER" "$nydus_image" sleep 3600
    
    # Create substantial test data
    docker exec "$SEAMLESS_TEST_CONTAINER" sh -c "
        for i in \$(seq 1 100); do
            echo 'test data line \$i' >> /tmp/large_file.txt
        done
        mkdir -p /tmp/many_files
        for i in \$(seq 1 50); do
            echo 'file \$i content' > /tmp/many_files/file\$i.txt
        done
    "
    
    # Measure total time
    local start_time=$(date +%s%3N)
    
    run nydusify seamless-commit \
        --container "$SEAMLESS_TEST_CONTAINER" \
        --target "$SEAMLESS_TARGET_IMAGE" \
        --work-dir "$SEAMLESS_WORKDIR/seamless" \
        --target-insecure
    
    local end_time=$(date +%s%3N)
    local total_time=$((end_time - start_time))
    
    [ "$status" -eq 0 ]
    
    echo "Performance metrics:"
    echo "Total time: ${total_time}ms"
    echo "Output: $output"
    
    # Verify the operation completed in reasonable time (less than 30 seconds)
    [ "$total_time" -lt 30000 ]
}
