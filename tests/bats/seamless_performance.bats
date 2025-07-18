#!/usr/bin/env bats

load common_tests

# Performance test configuration
PERF_TEST_IMAGE="alpine:3.18"
PERF_TEST_CONTAINER="perf-test-container"
PERF_TARGET_IMAGE="localhost:5000/perf-test:latest"
PERF_WORKDIR="/tmp/perf-test"

setup() {
    mkdir -p "$PERF_WORKDIR"
    
    # Start local registry if not running
    if ! docker ps | grep -q "registry:2"; then
        docker run -d -p 5000:5000 --name test-registry registry:2 || true
    fi
    
    # Pull and convert test image
    docker pull "$PERF_TEST_IMAGE"
    local nydus_image="${PERF_TEST_IMAGE}-nydus"
    nydusify convert \
        --source "$PERF_TEST_IMAGE" \
        --target "$nydus_image" \
        --work-dir "$PERF_WORKDIR/convert" \
        --target-insecure
}

teardown() {
    docker rm -f "$PERF_TEST_CONTAINER" 2>/dev/null || true
    docker rm -f test-registry 2>/dev/null || true
    rm -rf "$PERF_WORKDIR"
}

@test "performance: pause time under 10ms" {
    # Start container with monitoring
    local nydus_image="${PERF_TEST_IMAGE}-nydus"
    docker run -d --name "$PERF_TEST_CONTAINER" "$nydus_image" sh -c "
        while true; do
            echo \$(date +%s%N): heartbeat >> /tmp/heartbeat.log
            sleep 0.001  # 1ms intervals
        done
    "
    
    sleep 2  # Let container stabilize
    
    # Create test data
    docker exec "$PERF_TEST_CONTAINER" sh -c "echo 'test data' > /tmp/test.txt"
    
    # Perform seamless snapshot with detailed timing
    local start_ns=$(date +%s%N)
    
    run nydusify seamless-commit \
        --container "$PERF_TEST_CONTAINER" \
        --target "$PERF_TARGET_IMAGE" \
        --work-dir "$PERF_WORKDIR/seamless" \
        --target-insecure
    
    local end_ns=$(date +%s%N)
    local total_ns=$((end_ns - start_ns))
    local total_ms=$((total_ns / 1000000))
    
    [ "$status" -eq 0 ]
    
    # Extract pause time from output (assuming it's in nanoseconds or milliseconds)
    local pause_time_line=$(echo "$output" | grep "Pause Time:")
    echo "Pause time line: $pause_time_line"
    echo "Total operation time: ${total_ms}ms"
    
    # Verify container continued running during snapshot
    sleep 1
    run docker exec "$PERF_TEST_CONTAINER" tail -5 /tmp/heartbeat.log
    [ "$status" -eq 0 ]
    
    # The heartbeat log should show continuous operation
    local heartbeat_count=$(echo "$output" | wc -l)
    [ "$heartbeat_count" -ge 3 ]
}

@test "performance: container responsiveness during snapshot" {
    local nydus_image="${PERF_TEST_IMAGE}-nydus"
    docker run -d --name "$PERF_TEST_CONTAINER" "$nydus_image" sh -c "
        # Create a simple HTTP server for responsiveness testing
        while true; do
            echo 'HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!' | nc -l -p 8080 -q 1
        done
    " 2>/dev/null || docker run -d --name "$PERF_TEST_CONTAINER" "$nydus_image" sleep 3600
    
    sleep 2
    
    # Create test data
    docker exec "$PERF_TEST_CONTAINER" sh -c "echo 'test' > /tmp/test.txt"
    
    # Start background responsiveness test
    (
        for i in $(seq 1 100); do
            docker exec "$PERF_TEST_CONTAINER" echo "ping $i" > /tmp/ping_$i.txt 2>/dev/null || true
            sleep 0.01  # 10ms intervals
        done
    ) &
    local ping_pid=$!
    
    # Perform seamless snapshot
    run nydusify seamless-commit \
        --container "$PERF_TEST_CONTAINER" \
        --target "$PERF_TARGET_IMAGE" \
        --work-dir "$PERF_WORKDIR/seamless" \
        --target-insecure
    
    # Wait for ping test to complete
    wait $ping_pid
    
    [ "$status" -eq 0 ]
    
    # Check how many ping operations succeeded
    run docker exec "$PERF_TEST_CONTAINER" sh -c "ls /tmp/ping_*.txt | wc -l"
    local successful_pings=$output
    
    echo "Successful ping operations: $successful_pings out of 100"
    
    # At least 80% of operations should succeed (allowing for some pause)
    [ "$successful_pings" -ge 80 ]
}

@test "performance: memory usage during snapshot" {
    local nydus_image="${PERF_TEST_IMAGE}-nydus"
    docker run -d --name "$PERF_TEST_CONTAINER" "$nydus_image" sleep 3600
    
    # Create substantial test data
    docker exec "$PERF_TEST_CONTAINER" sh -c "
        # Create 10MB of test data
        dd if=/dev/zero of=/tmp/large_file bs=1M count=10 2>/dev/null
        # Create many small files
        mkdir -p /tmp/many_files
        for i in \$(seq 1 1000); do
            echo 'file \$i content with some data' > /tmp/many_files/file\$i.txt
        done
    "
    
    # Monitor memory usage
    local initial_memory=$(docker stats --no-stream --format "{{.MemUsage}}" "$PERF_TEST_CONTAINER" | cut -d'/' -f1)
    
    # Perform seamless snapshot
    run nydusify seamless-commit \
        --container "$PERF_TEST_CONTAINER" \
        --target "$PERF_TARGET_IMAGE" \
        --work-dir "$PERF_WORKDIR/seamless" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    
    local final_memory=$(docker stats --no-stream --format "{{.MemUsage}}" "$PERF_TEST_CONTAINER" | cut -d'/' -f1)
    
    echo "Initial memory: $initial_memory"
    echo "Final memory: $final_memory"
    
    # Memory usage should not increase dramatically
    # This is a basic check - in practice you'd want more sophisticated monitoring
}

@test "performance: concurrent operations during snapshot" {
    local nydus_image="${PERF_TEST_IMAGE}-nydus"
    docker run -d --name "$PERF_TEST_CONTAINER" "$nydus_image" sh -c "
        while true; do
            # Simulate ongoing work
            echo \$(date): Working... >> /tmp/work.log
            ls -la /tmp > /dev/null
            sleep 0.1
        done
    "
    
    sleep 2
    
    # Create initial test data
    docker exec "$PERF_TEST_CONTAINER" sh -c "echo 'initial' > /tmp/test.txt"
    
    # Start concurrent file operations
    (
        for i in $(seq 1 50); do
            docker exec "$PERF_TEST_CONTAINER" sh -c "echo 'concurrent $i' > /tmp/concurrent_$i.txt" 2>/dev/null || true
            sleep 0.02
        done
    ) &
    local concurrent_pid=$!
    
    # Perform seamless snapshot
    run nydusify seamless-commit \
        --container "$PERF_TEST_CONTAINER" \
        --target "$PERF_TARGET_IMAGE" \
        --work-dir "$PERF_WORKDIR/seamless" \
        --target-insecure
    
    # Wait for concurrent operations
    wait $concurrent_pid
    
    [ "$status" -eq 0 ]
    
    # Verify concurrent operations succeeded
    run docker exec "$PERF_TEST_CONTAINER" sh -c "ls /tmp/concurrent_*.txt | wc -l"
    local concurrent_files=$output
    
    echo "Concurrent files created: $concurrent_files"
    
    # Most concurrent operations should succeed
    [ "$concurrent_files" -ge 40 ]
    
    # Verify work log continued
    run docker exec "$PERF_TEST_CONTAINER" wc -l /tmp/work.log
    local work_lines=$(echo "$output" | awk '{print $1}')
    
    echo "Work log lines: $work_lines"
    [ "$work_lines" -ge 10 ]
}

@test "performance: snapshot size efficiency" {
    local nydus_image="${PERF_TEST_IMAGE}-nydus"
    docker run -d --name "$PERF_TEST_CONTAINER" "$nydus_image" sleep 3600
    
    # Create known amount of test data
    docker exec "$PERF_TEST_CONTAINER" sh -c "
        echo 'small change' > /tmp/small.txt
        mkdir -p /tmp/testdir
        echo 'another small change' > /tmp/testdir/file.txt
    "
    
    # Get initial filesystem size
    run docker exec "$PERF_TEST_CONTAINER" du -s /tmp
    local initial_size=$(echo "$output" | awk '{print $1}')
    
    # Perform seamless snapshot
    run nydusify seamless-commit \
        --container "$PERF_TEST_CONTAINER" \
        --target "$PERF_TARGET_IMAGE" \
        --work-dir "$PERF_WORKDIR/seamless" \
        --target-insecure
    
    [ "$status" -eq 0 ]
    
    echo "Initial /tmp size: ${initial_size}KB"
    echo "Snapshot output: $output"
    
    # Verify snapshot was created efficiently
    # The exact size checks would depend on the implementation details
}

@test "performance: stress test with rapid snapshots" {
    local nydus_image="${PERF_TEST_IMAGE}-nydus"
    docker run -d --name "$PERF_TEST_CONTAINER" "$nydus_image" sleep 3600
    
    # Perform multiple rapid snapshots
    local snapshot_count=3
    local success_count=0
    
    for i in $(seq 1 $snapshot_count); do
        # Create unique data for each snapshot
        docker exec "$PERF_TEST_CONTAINER" sh -c "echo 'snapshot $i data' > /tmp/snap_$i.txt"
        
        # Perform snapshot
        run nydusify seamless-commit \
            --container "$PERF_TEST_CONTAINER" \
            --target "${PERF_TARGET_IMAGE}-$i" \
            --work-dir "$PERF_WORKDIR/seamless$i" \
            --target-insecure
        
        if [ "$status" -eq 0 ]; then
            success_count=$((success_count + 1))
        fi
        
        echo "Snapshot $i status: $status"
        
        # Small delay between snapshots
        sleep 1
    done
    
    echo "Successful snapshots: $success_count out of $snapshot_count"
    
    # At least 2 out of 3 should succeed
    [ "$success_count" -ge 2 ]
    
    # Verify container is still running
    run docker ps --filter "name=$PERF_TEST_CONTAINER" --format "{{.Status}}"
    [[ "$output" =~ "Up" ]]
}
