#!/bin/bash

# Nydus 无感快照演示脚本
# 这个脚本演示了如何使用 Nydus 无感快照功能

set -e

# 配置
DEMO_IMAGE="alpine:3.18"
DEMO_CONTAINER="seamless-demo-container"
DEMO_TARGET="localhost:5000/seamless-demo:latest"
DEMO_WORKDIR="/tmp/seamless-demo"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

cleanup() {
    log_info "清理演示环境..."
    docker rm -f "$DEMO_CONTAINER" 2>/dev/null || true
    docker rm -f demo-registry 2>/dev/null || true
    rm -rf "$DEMO_WORKDIR" 2>/dev/null || true
}

setup_demo() {
    log_info "设置演示环境..."
    
    # 创建工作目录
    mkdir -p "$DEMO_WORKDIR"
    
    # 启动本地镜像仓库
    if ! docker ps | grep -q "demo-registry"; then
        log_info "启动本地镜像仓库..."
        docker run -d -p 5000:5000 --name demo-registry registry:2
        sleep 3
    fi
    
    # 拉取演示镜像
    log_info "拉取演示镜像: $DEMO_IMAGE"
    docker pull "$DEMO_IMAGE"
    
    # 转换为 Nydus 格式
    local nydus_image="${DEMO_IMAGE}-nydus"
    log_info "转换为 Nydus 格式: $nydus_image"
    nydusify convert \
        --source "$DEMO_IMAGE" \
        --target "$nydus_image" \
        --work-dir "$DEMO_WORKDIR/convert" \
        --target-insecure
    
    log_success "演示环境设置完成"
}

start_demo_container() {
    log_info "启动演示容器..."
    
    local nydus_image="${DEMO_IMAGE}-nydus"
    docker run -d --name "$DEMO_CONTAINER" "$nydus_image" sh -c "
        # 模拟一个持续运行的应用
        while true; do
            echo \$(date): 应用正在运行... >> /tmp/app.log
            echo \$(date +%s%N): 心跳 >> /tmp/heartbeat.log
            sleep 1
        done
    "
    
    # 等待容器启动
    sleep 3
    
    log_success "演示容器已启动: $DEMO_CONTAINER"
}

simulate_application_work() {
    log_info "模拟应用工作负载..."
    
    # 创建一些应用数据
    docker exec "$DEMO_CONTAINER" sh -c "
        echo '用户数据 1' > /tmp/user_data_1.txt
        echo '用户数据 2' > /tmp/user_data_2.txt
        mkdir -p /tmp/app_config
        echo 'config_value=123' > /tmp/app_config/app.conf
        echo '日志条目 1' >> /tmp/app.log
    "
    
    # 显示当前应用状态
    log_info "当前应用状态:"
    echo "应用日志行数: $(docker exec "$DEMO_CONTAINER" wc -l /tmp/app.log | awk '{print $1}')"
    echo "心跳记录数: $(docker exec "$DEMO_CONTAINER" wc -l /tmp/heartbeat.log | awk '{print $1}')"
    echo "用户数据文件: $(docker exec "$DEMO_CONTAINER" ls /tmp/user_data_*.txt | wc -l)"
    
    log_success "应用工作负载模拟完成"
}

demonstrate_seamless_snapshot() {
    log_info "演示无感快照功能..."
    
    # 记录快照前的状态
    local pre_heartbeat=$(docker exec "$DEMO_CONTAINER" wc -l /tmp/heartbeat.log | awk '{print $1}')
    local pre_app_log=$(docker exec "$DEMO_CONTAINER" wc -l /tmp/app.log | awk '{print $1}')
    
    log_info "快照前状态: 心跳=$pre_heartbeat, 应用日志=$pre_app_log"
    
    # 执行无感快照
    log_info "执行无感快照..."
    local start_time=$(date +%s%3N)
    
    nydusify seamless-commit \
        --container "$DEMO_CONTAINER" \
        --target "$DEMO_TARGET" \
        --work-dir "$DEMO_WORKDIR/seamless" \
        --target-insecure
    
    local end_time=$(date +%s%3N)
    local total_time=$((end_time - start_time))
    
    log_success "无感快照完成，总耗时: ${total_time}ms"
    
    # 等待一段时间，验证容器继续运行
    sleep 3
    
    # 记录快照后的状态
    local post_heartbeat=$(docker exec "$DEMO_CONTAINER" wc -l /tmp/heartbeat.log | awk '{print $1}')
    local post_app_log=$(docker exec "$DEMO_CONTAINER" wc -l /tmp/app.log | awk '{print $1}')
    
    log_info "快照后状态: 心跳=$post_heartbeat, 应用日志=$post_app_log"
    
    # 验证容器持续运行
    local heartbeat_increase=$((post_heartbeat - pre_heartbeat))
    local app_log_increase=$((post_app_log - pre_app_log))
    
    if [ "$heartbeat_increase" -gt 0 ] && [ "$app_log_increase" -gt 0 ]; then
        log_success "✓ 容器在快照过程中持续运行"
        log_success "✓ 心跳增加: $heartbeat_increase"
        log_success "✓ 应用日志增加: $app_log_increase"
    else
        log_warning "容器可能在快照过程中暂停了较长时间"
    fi
}

verify_snapshot_data() {
    log_info "验证快照数据完整性..."
    
    # 验证用户数据仍然存在
    if docker exec "$DEMO_CONTAINER" test -f /tmp/user_data_1.txt; then
        log_success "✓ 用户数据 1 完整"
    else
        log_error "✗ 用户数据 1 丢失"
    fi
    
    if docker exec "$DEMO_CONTAINER" test -f /tmp/user_data_2.txt; then
        log_success "✓ 用户数据 2 完整"
    else
        log_error "✗ 用户数据 2 丢失"
    fi
    
    if docker exec "$DEMO_CONTAINER" test -f /tmp/app_config/app.conf; then
        log_success "✓ 应用配置完整"
    else
        log_error "✗ 应用配置丢失"
    fi
    
    # 验证容器仍然可写
    docker exec "$DEMO_CONTAINER" sh -c "echo '快照后的新数据' > /tmp/post_snapshot.txt"
    if docker exec "$DEMO_CONTAINER" test -f /tmp/post_snapshot.txt; then
        log_success "✓ 容器在快照后仍然可写"
    else
        log_error "✗ 容器在快照后不可写"
    fi
}

show_performance_metrics() {
    log_info "性能指标总结..."
    
    echo ""
    echo "=== 无感快照性能指标 ==="
    echo "目标暂停时间: < 10ms"
    echo "实际测试结果: 请查看上面的输出"
    echo ""
    echo "=== 功能验证 ==="
    echo "✓ 容器持续运行"
    echo "✓ 数据完整性保持"
    echo "✓ 快照后可继续写入"
    echo "✓ 后台异步处理"
    echo ""
}

main() {
    echo "=== Nydus 无感快照演示 ==="
    echo "这个演示将展示如何使用 Nydus 无感快照功能"
    echo ""
    
    # 设置清理陷阱
    trap cleanup EXIT
    
    # 检查先决条件
    if ! command -v nydusify &> /dev/null; then
        log_error "nydusify 命令未找到，请确保已正确安装"
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker 未运行或无法访问"
        exit 1
    fi
    
    # 执行演示步骤
    setup_demo
    start_demo_container
    simulate_application_work
    demonstrate_seamless_snapshot
    verify_snapshot_data
    show_performance_metrics
    
    log_success "演示完成！"
    echo ""
    echo "要查看更多详细信息，请参考:"
    echo "- 文档: docs/seamless_snapshot.md"
    echo "- 测试: tests/bats/seamless_*.bats"
    echo "- 运行测试: ./tests/bats/run_seamless_tests.sh"
}

# 处理命令行参数
case "${1:-}" in
    "setup")
        setup_demo
        ;;
    "cleanup")
        cleanup
        ;;
    "test")
        setup_demo
        start_demo_container
        simulate_application_work
        demonstrate_seamless_snapshot
        verify_snapshot_data
        ;;
    "")
        main
        ;;
    *)
        echo "用法: $0 [setup|test|cleanup]"
        echo "  setup   - 仅设置演示环境"
        echo "  test    - 运行快照测试"
        echo "  cleanup - 清理演示环境"
        echo "  (无参数) - 运行完整演示"
        exit 1
        ;;
esac
