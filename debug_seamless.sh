#!/bin/bash

# 调试无感快照后台处理的脚本

set -e

echo "=== 调试无感快照后台处理 ==="

# 检查是否有运行的容器
CONTAINER_ID=$(docker ps -q | head -1)
if [ -z "$CONTAINER_ID" ]; then
    echo "没有找到运行的容器，创建一个测试容器..."
    docker run -d --name seamless-debug-test alpine:latest sleep 3600
    CONTAINER_ID=$(docker ps -q --filter "name=seamless-debug-test")
    echo "创建了测试容器: $CONTAINER_ID"
else
    echo "使用现有容器: $CONTAINER_ID"
fi

# 在容器中创建测试数据
echo "在容器中创建测试数据..."
docker exec "$CONTAINER_ID" sh -c "echo 'debug test data' > /tmp/debug.txt"
docker exec "$CONTAINER_ID" sh -c "mkdir -p /tmp/debug && echo 'more debug data' > /tmp/debug/file.txt"

# 启动本地 registry（如果还没有运行）
if ! docker ps | grep -q "registry:2"; then
    echo "启动本地 registry..."
    docker run -d -p 5000:5000 --name debug-registry registry:2
    sleep 3
fi

TARGET_IMAGE="localhost:5000/debug:seamless-$(date +%s)"

echo "执行无感快照命令..."
echo "容器ID: $CONTAINER_ID"
echo "目标镜像: $TARGET_IMAGE"

# 设置详细日志级别
export LOG_LEVEL=debug

# 执行无感快照命令并捕获所有输出
echo "开始执行无感快照..."
./cmd/nydusify seamless-commit \
    --container "$CONTAINER_ID" \
    --target "$TARGET_IMAGE" \
    --target-insecure \
    --work-dir /tmp/seamless-debug 2>&1 | tee /tmp/seamless-debug.log

echo ""
echo "=== 命令执行完成 ==="

# 等待一段时间让后台处理完成
echo "等待后台处理完成..."
sleep 10

# 检查日志中是否有后台处理的信息
echo ""
echo "=== 检查后台处理日志 ==="
if grep -q "starting background goroutine" /tmp/seamless-debug.log; then
    echo "✅ 找到后台 goroutine 启动日志"
else
    echo "❌ 没有找到后台 goroutine 启动日志"
fi

if grep -q "background processing completed successfully" /tmp/seamless-debug.log; then
    echo "✅ 找到后台处理成功日志"
else
    echo "❌ 没有找到后台处理成功日志"
fi

if grep -q "background processing failed" /tmp/seamless-debug.log; then
    echo "❌ 发现后台处理失败日志"
    grep "background processing failed" /tmp/seamless-debug.log
else
    echo "✅ 没有发现后台处理失败日志"
fi

# 检查是否有错误信息
echo ""
echo "=== 检查错误信息 ==="
if grep -i "error\|failed\|panic" /tmp/seamless-debug.log; then
    echo "发现错误信息："
    grep -i "error\|failed\|panic" /tmp/seamless-debug.log
else
    echo "✅ 没有发现明显的错误信息"
fi

# 检查目标镜像是否存在
echo ""
echo "=== 检查目标镜像 ==="
if curl -s "http://localhost:5000/v2/debug/tags/list" | grep -q "seamless"; then
    echo "✅ 目标镜像已推送到 registry"
    curl -s "http://localhost:5000/v2/debug/tags/list"
else
    echo "❌ 目标镜像未找到在 registry 中"
fi

# 显示完整日志
echo ""
echo "=== 完整日志 ==="
cat /tmp/seamless-debug.log

# 清理
echo ""
echo "清理测试环境..."
docker rm -f seamless-debug-test 2>/dev/null || true
docker rm -f debug-registry 2>/dev/null || true
rm -rf /tmp/seamless-debug 2>/dev/null || true
rm -f /tmp/seamless-debug.log 2>/dev/null || true

echo "调试完成"
