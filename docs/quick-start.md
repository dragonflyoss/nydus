# 无感快照快速入门指南

## 🎯 5分钟快速体验

本指南将帮助您在5分钟内体验无感快照技术的强大功能。

## 📋 前置条件

### 系统要求
- **操作系统**: Linux (支持overlay文件系统)
- **容器运行时**: containerd + nerdctl
- **快照器**: nydus-snapshotter
- **权限**: root权限或适当的capabilities

### 环境检查

```bash
# 检查containerd是否运行
systemctl status containerd

# 检查nerdctl是否可用
nerdctl version

# 检查nydus-snapshotter是否运行
systemctl status nydus-snapshotter

# 检查overlay文件系统支持
mount | grep overlay
```

## 🚀 步骤1: 编译无感快照工具

```bash
# 克隆项目（如果还没有）
git clone <repository>
cd contrib/nydusify

# 编译nydusify工具
go build -o cmd/nydusify cmd/nydusify.go

# 验证编译成功
./cmd/nydusify --help
```

## 📦 步骤2: 准备测试容器

```bash
# 拉取基础镜像
nerdctl --snapshotter nydus pull ubuntu:20.04

# 启动测试容器
nerdctl --snapshotter nydus run -d --name test-container ubuntu:20.04 sleep 3600

# 验证容器运行
nerdctl ps
```

## ✏️ 步骤3: 在容器中创建测试数据

```bash
# 进入容器
nerdctl exec -it test-container bash

# 创建测试文件
echo "Hello, Seamless Snapshot!" > /test-file.txt
echo "User data: $(date)" > /user-data.log
mkdir -p /app/data
echo "Application state" > /app/data/state.json

# 验证文件创建
ls -la /test-file.txt /user-data.log /app/data/state.json
cat /test-file.txt

# 退出容器
exit
```

## 📸 步骤4: 执行无感快照

```bash
# 执行无感快照（替换为您的registry地址）
./cmd/nydusify seamless-commit \
    --container test-container \
    --target your-registry.com/test:seamless-snapshot \
    --wait

# 观察输出，应该看到类似以下内容：
# Seamless snapshot created successfully:
#   Snapshot ID: snapshot-xxx
#   Pause Time: ~20µs
#   ...
# Background processing completed successfully.
```

## ✅ 步骤5: 验证快照结果

```bash
# 停止原容器
nerdctl stop test-container

# 从快照镜像启动新容器
nerdctl --snapshotter nydus run -it --name test-from-snapshot \
    your-registry.com/test:seamless-snapshot bash

# 验证用户数据是否保留
cat /test-file.txt
cat /user-data.log
cat /app/data/state.json

# 应该看到之前创建的所有文件和内容
```

## 🎉 成功！

如果您看到了之前创建的所有文件和内容，恭喜！您已经成功体验了无感快照技术。

## 📊 性能验证

### 查看暂停时间

在快照输出中，您应该看到类似以下的性能指标：

```
Pause Time: 8.72416ms  # 实际通常在20µs左右
```

这个极短的暂停时间就是无感快照的核心优势！

### 对比传统方案

```bash
# 传统docker commit（需要停止容器）
time docker commit test-container traditional-snapshot

# 无感快照（容器继续运行）
time ./cmd/nydusify seamless-commit \
    --container test-container \
    --target your-registry.com/test:seamless-snapshot-2
```

您会发现无感快照的用户响应时间更短，且容器无需停止。

## 🔧 高级用法

### 1. 自定义配置

```bash
# 使用自定义工作目录和压缩算法
./cmd/nydusify seamless-commit \
    --container test-container \
    --target your-registry.com/test:custom-config \
    --work-dir /data/nydus-work \
    --compressor zstd \
    --fs-version 6
```

### 2. 批量快照

```bash
# 对多个容器执行快照
for container in container1 container2 container3; do
    ./cmd/nydusify seamless-commit \
        --container $container \
        --target your-registry.com/test:$container-snapshot &
done
wait
```

### 3. 监控和调试

```bash
# 启用详细日志
export LOG_LEVEL=debug

# 执行快照并查看详细信息
./cmd/nydusify seamless-commit \
    --container test-container \
    --target your-registry.com/test:debug-snapshot \
    --wait
```

## 🛠️ 故障排除

### 问题1: 容器ID解析失败

```bash
# 错误: container not found
# 解决: 使用完整的容器ID或确保容器正在运行
nerdctl ps -a | grep test-container
```

### 问题2: Registry推送失败

```bash
# 错误: authentication required
# 解决: 配置registry认证
nerdctl login your-registry.com

# 或使用不安全连接（仅测试环境）
./cmd/nydusify seamless-commit \
    --container test-container \
    --target localhost:5000/test:snapshot \
    --target-insecure
```

### 问题3: 权限不足

```bash
# 错误: permission denied
# 解决: 使用root权限或配置适当的capabilities
sudo ./cmd/nydusify seamless-commit ...
```

### 问题4: 文件系统不支持

```bash
# 错误: overlay not supported
# 解决: 检查内核模块
modprobe overlay
lsmod | grep overlay
```

## 📈 性能调优

### 1. 优化工作目录

```bash
# 使用SSD存储作为工作目录
./cmd/nydusify seamless-commit \
    --work-dir /fast-ssd/nydus-work \
    ...
```

### 2. 调整压缩算法

```bash
# 使用不同压缩算法进行性能测试
for compressor in lz4_block zstd gzip; do
    time ./cmd/nydusify seamless-commit \
        --container test-container \
        --target your-registry.com/test:$compressor \
        --compressor $compressor
done
```

### 3. 并发处理

```bash
# 系统支持的情况下，可以同时处理多个快照
# 无感快照的设计支持高并发操作
```

## 🎓 下一步

现在您已经掌握了无感快照的基本使用，可以：

1. **阅读详细文档**: 查看 [技术概述](./seamless-snapshot.md) 了解更多特性
2. **学习API**: 查看 [API参考](./api-reference.md) 了解编程接口
3. **深入技术**: 查看 [技术设计](./technical-design.md) 了解实现原理
4. **生产部署**: 根据您的需求配置生产环境

## 💡 最佳实践

### 1. 快照命名规范

```bash
# 使用有意义的标签
./cmd/nydusify seamless-commit \
    --container web-server \
    --target registry.com/myapp:web-server-$(date +%Y%m%d-%H%M%S)
```

### 2. 定期清理

```bash
# 定期清理旧的快照目录
find /data/containerd/io.containerd.snapshotter.v1.nydus/snapshots/ \
    -name "fs-old-*" -mtime +7 -exec rm -rf {} \;
```

### 3. 监控集成

```bash
# 集成到监控系统
./cmd/nydusify seamless-commit ... && \
    echo "snapshot_success 1" | curl -X POST http://prometheus-pushgateway:9091/metrics/job/nydus-snapshot
```

---

🎉 **恭喜！您已经成功掌握了无感快照技术！**

这项技术将为您的容器化应用带来前所未有的快照体验。如有任何问题，请查看详细文档或提交Issue。
