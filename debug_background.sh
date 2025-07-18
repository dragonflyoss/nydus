#!/bin/bash

# 调试后台处理的脚本

echo "=== 调试无感快照后台处理 ==="

# 设置详细日志
export LOG_LEVEL=debug

# 使用 --wait 参数来等待后台处理完成
echo "执行带 --wait 参数的无感快照..."

./cmd/nydusify seamless-commit \
    --container cbd53a12c362 \
    --target 992382636473.dkr.ecr.us-east-1.amazonaws.com/clacky/docker:front-cbd53a12c362-test-debug \
    --wait \
    --target-insecure

echo "命令执行完成，退出码: $?"
