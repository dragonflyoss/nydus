# 无感快照技术文档

## 📚 文档概览

本目录包含了无感快照（Seamless Snapshot）技术的完整文档，涵盖了从技术概述到API参考的所有内容。

## 🎯 什么是无感快照？

无感快照是一种创新的容器快照技术，能够在极短的时间内（~20µs）对运行中的容器进行快照，同时保证：

- ✅ **极短暂停时间**: ~20µs（0.02ms），用户无感知
- ✅ **数据完整性**: 100%保留用户数据和文件修改
- ✅ **服务连续性**: 容器服务不中断
- ✅ **异步处理**: 后台处理不影响用户体验

## 📖 文档结构

### 1. [技术概述](./seamless-snapshot.md)
- 核心特性和技术优势
- 使用方法和示例
- 性能指标和故障排除
- 与传统方案的对比

### 2. [技术设计](./technical-design.md)
- 详细的架构设计
- 核心算法实现
- 错误处理与恢复机制
- 性能优化策略

### 3. [API参考](./api-reference.md)
- 命令行接口详细说明
- Go API使用指南
- REST API设计（未来扩展）
- 错误代码和监控指标

## 🚀 快速开始

### 安装

```bash
# 克隆项目
git clone <repository>

# 编译
cd contrib/nydusify
go build -o cmd/nydusify cmd/nydusify.go
```

### 基本使用

```bash
# 对运行中的容器执行无感快照
./cmd/nydusify seamless-commit \
    --container mycontainer \
    --target registry.example.com/myimage:snapshot

# 等待后台处理完成
./cmd/nydusify seamless-commit \
    --container mycontainer \
    --target registry.example.com/myimage:snapshot \
    --wait
```

### 验证结果

```bash
# 拉取快照镜像
nerdctl pull registry.example.com/myimage:snapshot

# 运行快照镜像
nerdctl run -it registry.example.com/myimage:snapshot bash

# 验证用户数据是否保留
ls -la /path/to/user/files
```

## 🏗️ 技术架构

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   用户命令行    │───▶│  无感快照核心    │───▶│   后台处理器    │
│   nydusify CLI  │    │ SeamlessSnapshot │    │ BackgroundProc  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   容器运行时    │    │   文件系统层     │    │   镜像仓库      │
│   Containerd    │    │ Overlay FS       │    │   ECR Registry  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 📊 性能指标

| 指标 | 数值 | 说明 |
|------|------|------|
| 容器暂停时间 | ~20µs | 用户无感知的关键指标 |
| 快照响应时间 | ~25ms | 用户命令完成时间 |
| 后台处理时间 | ~1分钟 | 镜像构建和推送时间 |
| 数据保留率 | 100% | 用户数据完整性保证 |

## 🔧 核心特性

### 1. 极短暂停时间
- **目标**: 容器暂停时间 < 10ms
- **实际达成**: ~20µs（0.02ms）
- **技术手段**: 优化的原子操作和文件系统处理

### 2. 数据完整性保证
- **用户文件**: 所有用户创建和修改的文件完整保留
- **应用状态**: 应用程序的运行时状态正确保存
- **文件系统**: overlay文件系统状态一致性保证

### 3. 异步后台处理
- **立即响应**: 快照操作立即返回给用户
- **后台构建**: 镜像构建和推送在后台异步进行
- **状态监控**: 提供完整的处理状态和进度信息

### 4. 错误处理与恢复
- **原子性保证**: 操作要么完全成功，要么完全回滚
- **自动恢复**: 异常情况下自动恢复容器状态
- **详细日志**: 提供完整的错误信息和调试日志

## 🛠️ 开发指南

### 代码结构

```
contrib/nydusify/
├── pkg/committer/
│   ├── seamless_snapshot.go    # 核心实现
│   ├── committer.go           # 基础committer
│   └── manager.go             # 容器管理
├── cmd/
│   └── nydusify.go           # CLI入口
└── docs/
    ├── README.md             # 文档入口
    ├── seamless-snapshot.md  # 技术概述
    ├── technical-design.md   # 技术设计
    └── api-reference.md      # API参考
```

### 核心接口

```go
// 主要接口
type SeamlessSnapshot interface {
    Commit(ctx context.Context, containerID, targetRef string) (*SnapshotResult, error)
    CommitWithWait(ctx context.Context, containerID, targetRef string, timeout time.Duration) (*SnapshotResult, error)
    GetStatus(snapshotID string) (*SnapshotStatus, error)
}

// 结果结构
type SnapshotResult struct {
    SnapshotID   string        `json:"snapshot_id"`
    PauseTime    time.Duration `json:"pause_time"`
    TotalTime    time.Duration `json:"total_time"`
    OldUpperDir  string        `json:"old_upper_dir"`
    NewUpperDir  string        `json:"new_upper_dir"`
}
```

### 测试

```bash
# 运行单元测试
go test ./pkg/committer/...

# 运行集成测试
go test -tags=integration ./...

# 性能测试
go test -bench=. ./pkg/committer/
```

## 🔍 故障排除

### 常见问题

1. **容器暂停时间过长**
   - 检查文件系统状态
   - 查看系统负载

2. **后台处理失败**
   - 检查网络连接
   - 验证registry认证

3. **用户数据丢失**
   - 确保使用最新版本
   - 检查文件系统权限

### 调试方法

```bash
# 启用详细日志
export LOG_LEVEL=debug

# 检查容器状态
nerdctl inspect <container-id>

# 查看快照目录
ls -la /data/containerd/io.containerd.snapshotter.v1.nydus/snapshots/
```

## 🤝 贡献指南

### 开发环境设置

1. **安装依赖**
   ```bash
   # Go 1.19+
   # containerd + nerdctl
   # nydus-snapshotter
   ```

2. **克隆代码**
   ```bash
   git clone <repository>
   cd contrib/nydusify
   ```

3. **编译测试**
   ```bash
   go build -o cmd/nydusify cmd/nydusify.go
   ./cmd/nydusify --help
   ```

### 提交规范

- **功能开发**: `feat: add new feature`
- **问题修复**: `fix: resolve issue with xxx`
- **文档更新**: `docs: update API documentation`
- **性能优化**: `perf: optimize atomic switch performance`

### 代码审查

- 确保所有测试通过
- 添加适当的单元测试
- 更新相关文档
- 遵循Go代码规范

## 📄 许可证

本项目采用 Apache 2.0 许可证。详见 [LICENSE](../LICENSE) 文件。

## 🔗 相关链接

- [Nydus项目主页](https://github.com/dragonflyoss/nydus)
- [Containerd文档](https://containerd.io/docs/)
- [Overlay文件系统](https://www.kernel.org/doc/Documentation/filesystems/overlayfs.txt)

---

**无感快照技术** - 让容器快照真正做到"无感知"！🚀

如有问题或建议，请提交 Issue 或 Pull Request。
