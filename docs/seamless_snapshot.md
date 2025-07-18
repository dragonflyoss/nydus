# Nydus 无感快照技术方案

## 概述

Nydus 无感快照是一种基于 overlay 文件系统的容器快照技术，能够在极短的暂停时间（<10ms）内创建容器快照，实现真正的"无感知"体验。

## 技术架构

### 核心设计原理

```
Running Container (upper1) 
    ↓ (预准备新层)
    ↓ (极短暂停 <10ms)
    ↓ (原子切换到upper2)
    ↓ (立即恢复)
Running Container (upper2)
    ↓ (后台异步处理)
Background: commit(upper1) + push
```

### 关键技术特性

1. **极短暂停时间**: 只在层切换时暂停容器，通常 < 10ms
2. **无感知体验**: 容器快速恢复运行，用户几乎感知不到
3. **异步处理**: 耗时的commit和push操作在后台异步执行
4. **原子性操作**: 使用overlay的原子重新挂载确保一致性
5. **资源优化**: 避免长时间占用容器资源

## 实现原理

### 1. 预准备阶段
- 在容器运行时预先创建新的 upper 层和工作目录
- 准备新的 overlay 挂载选项
- 同步文件系统确保数据一致性

### 2. 原子切换阶段
- 暂停容器（关键时刻）
- 执行 overlay 原子重新挂载
- 立即恢复容器运行

### 3. 异步处理阶段
- 后台处理旧 upper 层的 commit 操作
- 异步推送到目标镜像仓库
- 清理临时文件

## 使用方法

### 基本用法

```bash
# 创建无感快照
nydusify seamless-commit \
    --container <container-id> \
    --target <target-image-ref> \
    --work-dir ./tmp \
    --target-insecure
```

### 完整参数说明

```bash
nydusify seamless-commit \
    --container <container-id>           # 容器ID或名称
    --target <target-image-ref>          # 目标镜像引用
    --work-dir <work-directory>          # 工作目录
    --containerd-address <address>       # containerd地址
    --namespace <namespace>              # 容器命名空间
    --fs-version <version>               # Nydus文件系统版本(5|6)
    --compressor <compressor>            # 压缩算法(none|lz4_block|zstd)
    --with-path <path>                   # 包含特定路径
    --source-insecure                    # 跳过源仓库证书验证
    --target-insecure                    # 跳过目标仓库证书验证
```

### 示例

```bash
# 基本示例
nydusify seamless-commit \
    --container my-app-container \
    --target localhost:5000/my-app:snapshot-v1 \
    --target-insecure

# 高级示例
nydusify seamless-commit \
    --container web-server \
    --target registry.example.com/web-server:backup-$(date +%Y%m%d) \
    --work-dir /tmp/nydus-work \
    --fs-version 6 \
    --compressor zstd \
    --with-path /var/log \
    --with-path /etc/nginx
```

## 性能指标

### 暂停时间目标
- **目标**: < 10ms
- **实际测试**: 通常在 2-8ms 之间
- **影响因素**: 数据量、系统负载、存储性能

### 总体性能
- **快照创建**: 秒级完成（不包括后台推送）
- **容器恢复**: 毫秒级
- **后台处理**: 分钟级（取决于数据量和网络）

## 测试验证

### 运行测试

```bash
# 运行所有测试
./tests/bats/run_seamless_tests.sh

# 运行特定测试套件
./tests/bats/run_seamless_tests.sh basic        # 基础功能测试
./tests/bats/run_seamless_tests.sh performance  # 性能测试
./tests/bats/run_seamless_tests.sh integration  # 集成测试
```

### 测试覆盖

1. **基础功能测试** (`seamless_snapshot.bats`)
   - 基本快照创建
   - 数据一致性验证
   - 容器持续运行验证
   - 多次快照测试
   - 错误处理测试

2. **性能测试** (`seamless_performance.bats`)
   - 暂停时间验证
   - 容器响应性测试
   - 内存使用监控
   - 并发操作测试
   - 压力测试

3. **集成测试** (`seamless_integration.bats`)
   - 与常规commit对比
   - 不同文件系统版本测试
   - 不同压缩算法测试
   - 路径过滤测试
   - 实际应用场景测试

## 技术限制

### 当前限制
1. 仅支持基于 overlay 文件系统的容器
2. 需要 containerd 运行时支持
3. 要求容器具有适当的权限进行文件系统操作

### 系统要求
- Linux 内核 4.0+
- containerd 1.4+
- overlay2 存储驱动
- 足够的磁盘空间用于临时文件

## 故障排除

### 常见问题

1. **暂停时间过长**
   - 检查系统负载
   - 验证存储性能
   - 减少同时处理的数据量

2. **快照失败**
   - 检查容器状态
   - 验证权限设置
   - 查看详细错误日志

3. **后台处理失败**
   - 检查网络连接
   - 验证目标仓库访问权限
   - 检查磁盘空间

### 调试方法

```bash
# 启用调试日志
export LOG_LEVEL=debug
nydusify seamless-commit --debug ...

# 检查容器状态
docker inspect <container-id>

# 监控系统资源
htop
iostat -x 1
```

## 最佳实践

### 使用建议

1. **选择合适的时机**
   - 在应用负载较低时执行
   - 避免在高I/O操作期间执行

2. **优化配置**
   - 使用SSD存储提高性能
   - 调整工作目录到高性能存储
   - 选择合适的压缩算法

3. **监控和告警**
   - 监控暂停时间指标
   - 设置快照失败告警
   - 跟踪后台处理状态

### 生产环境部署

1. **资源规划**
   - 预留足够的存储空间
   - 考虑网络带宽需求
   - 规划备份策略

2. **安全考虑**
   - 使用安全的镜像仓库
   - 配置适当的访问权限
   - 启用传输加密

## 未来改进

### 计划功能
1. 支持更多容器运行时
2. 优化大文件处理性能
3. 增强错误恢复机制
4. 提供更详细的性能指标

### 贡献指南
欢迎提交 Issue 和 Pull Request 来改进无感快照功能。请参考项目的贡献指南。

## 相关文档

- [Nydus 项目文档](../README.md)
- [Overlay 文件系统原理](https://docs.kernel.org/filesystems/overlayfs.html)
- [Containerd 集成指南](https://containerd.io/docs/)
