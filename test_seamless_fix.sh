#!/bin/bash

# 测试无感快照修复的脚本

set -e

echo "=== 测试无感快照修复 ==="

# 检查 nydusify 是否编译成功
if [ ! -f "contrib/nydusify/cmd/nydusify" ]; then
    echo "错误: nydusify 二进制文件不存在，请先编译"
    exit 1
fi

# 检查是否有运行的容器
CONTAINER_ID=$(docker ps -q | head -1)
if [ -z "$CONTAINER_ID" ]; then
    echo "没有找到运行的容器，创建一个测试容器..."
    
    # 启动一个简单的测试容器
    docker run -d --name seamless-test alpine:latest sleep 3600
    CONTAINER_ID=$(docker ps -q --filter "name=seamless-test")
    
    if [ -z "$CONTAINER_ID" ]; then
        echo "错误: 无法创建测试容器"
        exit 1
    fi
    
    echo "创建了测试容器: $CONTAINER_ID"
else
    echo "使用现有容器: $CONTAINER_ID"
fi

# 在容器中创建一些测试数据
echo "在容器中创建测试数据..."
docker exec "$CONTAINER_ID" sh -c "echo 'test data' > /tmp/test.txt"
docker exec "$CONTAINER_ID" sh -c "mkdir -p /tmp/testdir && echo 'more data' > /tmp/testdir/file.txt"

# 测试无感快照命令
echo "测试无感快照命令..."
TARGET_IMAGE="localhost:5000/test:seamless-$(date +%s)"

# 启动本地 registry（如果还没有运行）
if ! docker ps | grep -q "registry:2"; then
    echo "启动本地 registry..."
    docker run -d -p 5000:5000 --name test-registry registry:2
    sleep 3
fi

echo "执行无感快照..."
echo "容器ID: $CONTAINER_ID"
echo "目标镜像: $TARGET_IMAGE"

# 执行无感快照命令
./contrib/nydusify/cmd/nydusify seamless-commit \
    --container "$CONTAINER_ID" \
    --target "$TARGET_IMAGE" \
    --target-insecure \
    --work-dir /tmp/seamless-test

RESULT=$?

if [ $RESULT -eq 0 ]; then
    echo "✅ 无感快照命令执行成功！"
    
    # 验证容器仍在运行
    if docker ps | grep -q "$CONTAINER_ID"; then
        echo "✅ 容器仍在运行"
    else
        echo "❌ 容器已停止"
    fi
    
    # 验证数据完整性
    if docker exec "$CONTAINER_ID" cat /tmp/test.txt | grep -q "test data"; then
        echo "✅ 数据完整性验证通过"
    else
        echo "❌ 数据完整性验证失败"
    fi
    
else
    echo "❌ 无感快照命令执行失败，退出码: $RESULT"
fi

# 清理
echo "清理测试环境..."
docker rm -f seamless-test 2>/dev/null || true
docker rm -f test-registry 2>/dev/null || true
rm -rf /tmp/seamless-test 2>/dev/null || true

echo "测试完成"
exit $RESULT
