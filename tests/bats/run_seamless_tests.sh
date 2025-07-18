#!/bin/bash

# Seamless Snapshot Test Runner
# This script runs all seamless snapshot tests and provides detailed reporting

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$SCRIPT_DIR"
REPORT_DIR="/tmp/seamless-test-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test files
BASIC_TESTS="$TEST_DIR/seamless_snapshot.bats"
PERFORMANCE_TESTS="$TEST_DIR/seamless_performance.bats"
INTEGRATION_TESTS="$TEST_DIR/seamless_integration.bats"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if bats is installed
    if ! command -v bats &> /dev/null; then
        log_error "bats is not installed. Please install bats-core."
        exit 1
    fi
    
    # Check if docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker is not running or not accessible."
        exit 1
    fi
    
    # Check if nydusify is available
    if ! command -v nydusify &> /dev/null; then
        log_error "nydusify is not available in PATH."
        exit 1
    fi
    
    # Check if curl is available (for registry tests)
    if ! command -v curl &> /dev/null; then
        log_warning "curl is not available. Some tests may fail."
    fi
    
    log_success "Prerequisites check passed"
}

setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Create report directory
    mkdir -p "$REPORT_DIR"
    
    # Clean up any existing test containers
    docker rm -f seamless-test-container perf-test-container integration-test-container 2>/dev/null || true
    docker rm -f seamless-test-container-regular seamless-test-container-seamless 2>/dev/null || true
    docker rm -f integration-test-container-v5 integration-test-container-v6 2>/dev/null || true
    docker rm -f integration-test-container-zstd integration-test-container-lz4 2>/dev/null || true
    
    # Clean up test registry
    docker rm -f test-registry 2>/dev/null || true
    
    # Clean up test directories
    rm -rf /tmp/seamless-test /tmp/perf-test /tmp/integration-test 2>/dev/null || true
    
    log_success "Test environment setup completed"
}

run_test_suite() {
    local test_file="$1"
    local test_name="$2"
    local report_file="$REPORT_DIR/${test_name}_${TIMESTAMP}.txt"
    
    log_info "Running $test_name tests..."
    
    if [ ! -f "$test_file" ]; then
        log_error "Test file not found: $test_file"
        return 1
    fi
    
    # Run tests and capture output
    if bats "$test_file" > "$report_file" 2>&1; then
        log_success "$test_name tests passed"
        return 0
    else
        log_error "$test_name tests failed"
        echo "Error details:"
        tail -20 "$report_file"
        return 1
    fi
}

run_performance_analysis() {
    log_info "Running performance analysis..."
    
    local perf_report="$REPORT_DIR/performance_analysis_${TIMESTAMP}.txt"
    
    {
        echo "=== Seamless Snapshot Performance Analysis ==="
        echo "Timestamp: $(date)"
        echo ""
        
        echo "=== System Information ==="
        echo "OS: $(uname -a)"
        echo "Docker Version: $(docker --version)"
        echo "Available Memory: $(free -h | grep Mem)"
        echo "CPU Info: $(grep 'model name' /proc/cpuinfo | head -1)"
        echo ""
        
        echo "=== Test Results Summary ==="
        
        # Analyze basic test results
        if [ -f "$REPORT_DIR/basic_${TIMESTAMP}.txt" ]; then
            echo "Basic Tests:"
            grep -E "(✓|✗)" "$REPORT_DIR/basic_${TIMESTAMP}.txt" | head -10
            echo ""
        fi
        
        # Analyze performance test results
        if [ -f "$REPORT_DIR/performance_${TIMESTAMP}.txt" ]; then
            echo "Performance Tests:"
            grep -E "(✓|✗)" "$REPORT_DIR/performance_${TIMESTAMP}.txt" | head -10
            echo ""
            
            # Extract timing information
            echo "Timing Analysis:"
            grep -i "time\|pause\|ms\|ns" "$REPORT_DIR/performance_${TIMESTAMP}.txt" | head -20
            echo ""
        fi
        
        # Analyze integration test results
        if [ -f "$REPORT_DIR/integration_${TIMESTAMP}.txt" ]; then
            echo "Integration Tests:"
            grep -E "(✓|✗)" "$REPORT_DIR/integration_${TIMESTAMP}.txt" | head -10
            echo ""
        fi
        
    } > "$perf_report"
    
    log_success "Performance analysis saved to $perf_report"
}

cleanup_test_environment() {
    log_info "Cleaning up test environment..."
    
    # Stop and remove test containers
    docker rm -f seamless-test-container perf-test-container integration-test-container 2>/dev/null || true
    docker rm -f seamless-test-container-regular seamless-test-container-seamless 2>/dev/null || true
    docker rm -f integration-test-container-v5 integration-test-container-v6 2>/dev/null || true
    docker rm -f integration-test-container-zstd integration-test-container-lz4 2>/dev/null || true
    
    # Stop test registry
    docker rm -f test-registry 2>/dev/null || true
    
    # Clean up test directories
    rm -rf /tmp/seamless-test /tmp/perf-test /tmp/integration-test 2>/dev/null || true
    
    log_success "Cleanup completed"
}

generate_summary_report() {
    local summary_file="$REPORT_DIR/summary_${TIMESTAMP}.txt"
    
    log_info "Generating summary report..."
    
    {
        echo "=== Seamless Snapshot Test Summary ==="
        echo "Timestamp: $(date)"
        echo "Report Directory: $REPORT_DIR"
        echo ""
        
        echo "=== Test Results ==="
        
        local total_tests=0
        local passed_tests=0
        local failed_tests=0
        
        for report in "$REPORT_DIR"/*_${TIMESTAMP}.txt; do
            if [ -f "$report" ] && [[ "$report" != *"summary"* ]] && [[ "$report" != *"analysis"* ]]; then
                local test_name=$(basename "$report" | sed "s/_${TIMESTAMP}.txt//")
                echo "Test Suite: $test_name"
                
                local suite_total=$(grep -c "^[[:space:]]*✓\|^[[:space:]]*✗" "$report" 2>/dev/null || echo "0")
                local suite_passed=$(grep -c "^[[:space:]]*✓" "$report" 2>/dev/null || echo "0")
                local suite_failed=$(grep -c "^[[:space:]]*✗" "$report" 2>/dev/null || echo "0")
                
                echo "  Total: $suite_total, Passed: $suite_passed, Failed: $suite_failed"
                
                total_tests=$((total_tests + suite_total))
                passed_tests=$((passed_tests + suite_passed))
                failed_tests=$((failed_tests + suite_failed))
                
                if [ "$suite_failed" -gt 0 ]; then
                    echo "  Failed tests:"
                    grep "^[[:space:]]*✗" "$report" | head -5
                fi
                echo ""
            fi
        done
        
        echo "=== Overall Summary ==="
        echo "Total Tests: $total_tests"
        echo "Passed: $passed_tests"
        echo "Failed: $failed_tests"
        
        if [ "$failed_tests" -eq 0 ]; then
            echo "Status: ALL TESTS PASSED ✓"
        else
            echo "Status: SOME TESTS FAILED ✗"
        fi
        
    } > "$summary_file"
    
    log_success "Summary report saved to $summary_file"
    
    # Display summary
    echo ""
    echo "=== TEST SUMMARY ==="
    tail -10 "$summary_file"
}

# Main execution
main() {
    echo "=== Seamless Snapshot Test Runner ==="
    echo "Starting test execution at $(date)"
    echo ""
    
    # Check prerequisites
    check_prerequisites
    
    # Setup environment
    setup_test_environment
    
    local overall_result=0
    
    # Run test suites
    if [ -f "$BASIC_TESTS" ]; then
        if ! run_test_suite "$BASIC_TESTS" "basic"; then
            overall_result=1
        fi
    else
        log_warning "Basic tests not found: $BASIC_TESTS"
    fi
    
    if [ -f "$PERFORMANCE_TESTS" ]; then
        if ! run_test_suite "$PERFORMANCE_TESTS" "performance"; then
            overall_result=1
        fi
    else
        log_warning "Performance tests not found: $PERFORMANCE_TESTS"
    fi
    
    if [ -f "$INTEGRATION_TESTS" ]; then
        if ! run_test_suite "$INTEGRATION_TESTS" "integration"; then
            overall_result=1
        fi
    else
        log_warning "Integration tests not found: $INTEGRATION_TESTS"
    fi
    
    # Generate reports
    run_performance_analysis
    generate_summary_report
    
    # Cleanup
    cleanup_test_environment
    
    echo ""
    if [ "$overall_result" -eq 0 ]; then
        log_success "All test suites completed successfully!"
    else
        log_error "Some test suites failed. Check reports in $REPORT_DIR"
    fi
    
    echo "Test execution completed at $(date)"
    echo "Reports available in: $REPORT_DIR"
    
    exit $overall_result
}

# Handle script arguments
case "${1:-}" in
    "basic")
        check_prerequisites
        setup_test_environment
        run_test_suite "$BASIC_TESTS" "basic"
        cleanup_test_environment
        ;;
    "performance")
        check_prerequisites
        setup_test_environment
        run_test_suite "$PERFORMANCE_TESTS" "performance"
        cleanup_test_environment
        ;;
    "integration")
        check_prerequisites
        setup_test_environment
        run_test_suite "$INTEGRATION_TESTS" "integration"
        cleanup_test_environment
        ;;
    "all"|"")
        main
        ;;
    *)
        echo "Usage: $0 [basic|performance|integration|all]"
        echo "  basic       - Run basic functionality tests"
        echo "  performance - Run performance tests"
        echo "  integration - Run integration tests"
        echo "  all         - Run all tests (default)"
        exit 1
        ;;
esac
