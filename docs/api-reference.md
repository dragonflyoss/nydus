# 无感快照 API 参考

## 命令行接口

### seamless-commit

对运行中的容器执行无感快照操作。

#### 语法

```bash
nydusify seamless-commit [OPTIONS] --container CONTAINER --target TARGET
```

#### 参数

##### 必需参数

| 参数 | 类型 | 描述 |
|------|------|------|
| `--container` | string | 容器ID或名称（支持前缀匹配） |
| `--target` | string | 目标镜像地址 |

##### 可选参数

| 参数 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `--wait` | bool | false | 等待后台处理完成 |
| `--work-dir` | string | /tmp | 工作目录路径 |
| `--fs-version` | string | 6 | Nydus文件系统版本 |
| `--compressor` | string | lz4_block | 压缩算法 |
| `--target-insecure` | bool | false | 允许不安全的registry连接 |
| `--source-insecure` | bool | false | 允许不安全的源registry连接 |

#### 示例

```bash
# 基本用法
nydusify seamless-commit \
    --container mycontainer \
    --target registry.example.com/myimage:snapshot

# 等待后台处理完成
nydusify seamless-commit \
    --container cbd53a12c362 \
    --target 992382636473.dkr.ecr.us-east-1.amazonaws.com/clacky/docker:front-snapshot \
    --wait

# 使用自定义配置
nydusify seamless-commit \
    --container mycontainer \
    --target registry.example.com/myimage:snapshot \
    --work-dir /data/nydus-work \
    --fs-version 6 \
    --compressor zstd
```

#### 返回值

##### 成功响应

```
Seamless snapshot created successfully:
  Snapshot ID: snapshot-1752857512540089368
  Pause Time: 8.72416ms
  Old Upper Dir: /data/containerd/io.containerd.snapshotter.v1.nydus/snapshots/163/fs
  New Upper Dir: /data/containerd/io.containerd.snapshotter.v1.nydus/snapshots/163/fs-new-1752857512506012049
Background commit processing started for snapshot: snapshot-1752857512540089368
```

如果使用 `--wait` 参数：

```
Background processing completed successfully.
```

##### 错误响应

```
FATA[2025-07-18T16:51:52Z] background commit processing failed: <error_message>
```

#### 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 成功 |
| 1 | 一般错误 |
| 2 | 参数错误 |
| 3 | 容器不存在 |
| 4 | 权限错误 |
| 5 | 网络错误 |

## Go API

### SeamlessSnapshot 接口

#### 创建实例

```go
import "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/committer"

// 创建SeamlessSnapshot实例
ss, err := committer.NewSeamlessSnapshot(opt)
if err != nil {
    return err
}
```

#### 核心方法

##### Commit

```go
func (ss *SeamlessSnapshot) Commit(
    ctx context.Context,
    containerID string,
    targetRef string,
) (*SnapshotResult, error)
```

**参数:**
- `ctx`: 上下文对象
- `containerID`: 容器ID
- `targetRef`: 目标镜像引用

**返回值:**
```go
type SnapshotResult struct {
    SnapshotID   string        `json:"snapshot_id"`
    PauseTime    time.Duration `json:"pause_time"`
    TotalTime    time.Duration `json:"total_time"`
    OldUpperDir  string        `json:"old_upper_dir"`
    NewUpperDir  string        `json:"new_upper_dir"`
}
```

**示例:**
```go
result, err := ss.Commit(ctx, "mycontainer", "registry.example.com/myimage:snapshot")
if err != nil {
    return err
}

fmt.Printf("Snapshot ID: %s\n", result.SnapshotID)
fmt.Printf("Pause Time: %v\n", result.PauseTime)
```

##### CommitWithWait

```go
func (ss *SeamlessSnapshot) CommitWithWait(
    ctx context.Context,
    containerID string,
    targetRef string,
    timeout time.Duration,
) (*SnapshotResult, error)
```

等待后台处理完成的版本。

**参数:**
- `timeout`: 等待超时时间

##### GetStatus

```go
func (ss *SeamlessSnapshot) GetStatus(snapshotID string) (*SnapshotStatus, error)
```

获取快照处理状态。

**返回值:**
```go
type SnapshotStatus struct {
    SnapshotID string                 `json:"snapshot_id"`
    State      SnapshotState         `json:"state"`
    Progress   float64               `json:"progress"`
    Error      string                `json:"error,omitempty"`
    StartTime  time.Time             `json:"start_time"`
    EndTime    *time.Time            `json:"end_time,omitempty"`
}

type SnapshotState string

const (
    SnapshotStatePending    SnapshotState = "pending"
    SnapshotStateProcessing SnapshotState = "processing"
    SnapshotStateCompleted  SnapshotState = "completed"
    SnapshotStateFailed     SnapshotState = "failed"
)
```

### 配置选项

#### CommitOptions

```go
type CommitOptions struct {
    // 基本配置
    ContainerID      string   `json:"container_id"`
    WorkDir          string   `json:"work_dir"`
    FsVersion        string   `json:"fs_version"`
    Compressor       string   `json:"compressor"`
    
    // Registry配置
    TargetInsecure   bool     `json:"target_insecure"`
    SourceInsecure   bool     `json:"source_insecure"`
    
    // 路径配置
    WithPaths        []string `json:"with_paths"`
    WithoutPaths     []string `json:"without_paths"`
    
    // 性能配置
    MaximumTimes     int      `json:"maximum_times"`
    BackgroundWorkers int     `json:"background_workers"`
}
```

#### 默认配置

```go
var DefaultCommitOptions = CommitOptions{
    WorkDir:           "/tmp",
    FsVersion:         "6",
    Compressor:        "lz4_block",
    MaximumTimes:      10,
    BackgroundWorkers: 4,
}
```

## REST API (未来扩展)

### 端点

#### POST /api/v1/snapshots

创建无感快照。

**请求体:**
```json
{
    "container_id": "mycontainer",
    "target_ref": "registry.example.com/myimage:snapshot",
    "options": {
        "wait": false,
        "work_dir": "/tmp",
        "fs_version": "6",
        "compressor": "lz4_block"
    }
}
```

**响应:**
```json
{
    "snapshot_id": "snapshot-1752857512540089368",
    "pause_time": "8.72416ms",
    "total_time": "22.802283ms",
    "old_upper_dir": "/data/containerd/io.containerd.snapshotter.v1.nydus/snapshots/163/fs",
    "new_upper_dir": "/data/containerd/io.containerd.snapshotter.v1.nydus/snapshots/163/fs-new-1752857512506012049"
}
```

#### GET /api/v1/snapshots/{snapshot_id}

获取快照状态。

**响应:**
```json
{
    "snapshot_id": "snapshot-1752857512540089368",
    "state": "processing",
    "progress": 0.75,
    "start_time": "2025-07-18T16:51:52Z",
    "end_time": null
}
```

#### GET /api/v1/snapshots

列出所有快照。

**查询参数:**
- `state`: 过滤状态
- `limit`: 限制数量
- `offset`: 偏移量

**响应:**
```json
{
    "snapshots": [
        {
            "snapshot_id": "snapshot-1752857512540089368",
            "state": "completed",
            "progress": 1.0,
            "start_time": "2025-07-18T16:51:52Z",
            "end_time": "2025-07-18T16:52:57Z"
        }
    ],
    "total": 1
}
```

## 错误代码

### 通用错误

| 错误代码 | HTTP状态码 | 描述 |
|----------|------------|------|
| `INVALID_PARAMETER` | 400 | 参数无效 |
| `CONTAINER_NOT_FOUND` | 404 | 容器不存在 |
| `PERMISSION_DENIED` | 403 | 权限不足 |
| `INTERNAL_ERROR` | 500 | 内部错误 |

### 快照特定错误

| 错误代码 | HTTP状态码 | 描述 |
|----------|------------|------|
| `CONTAINER_NOT_RUNNING` | 400 | 容器未运行 |
| `SNAPSHOT_IN_PROGRESS` | 409 | 快照正在进行中 |
| `PAUSE_TIMEOUT` | 500 | 容器暂停超时 |
| `ATOMIC_SWITCH_FAILED` | 500 | 原子切换失败 |
| `BACKGROUND_PROCESSING_FAILED` | 500 | 后台处理失败 |

### 错误响应格式

```json
{
    "error": {
        "code": "CONTAINER_NOT_FOUND",
        "message": "Container with ID 'mycontainer' not found",
        "details": {
            "container_id": "mycontainer",
            "timestamp": "2025-07-18T16:51:52Z"
        }
    }
}
```

## 性能指标

### 监控端点

#### GET /api/v1/metrics

获取性能指标。

**响应:**
```json
{
    "metrics": {
        "total_snapshots": 100,
        "successful_snapshots": 98,
        "failed_snapshots": 2,
        "average_pause_time": "22.5µs",
        "average_total_time": "25.3ms",
        "average_background_time": "58.7s"
    },
    "timestamp": "2025-07-18T16:51:52Z"
}
```

### Prometheus 指标

```
# 快照总数
nydus_seamless_snapshots_total{status="success"} 98
nydus_seamless_snapshots_total{status="failed"} 2

# 暂停时间分布
nydus_seamless_pause_time_seconds{quantile="0.5"} 0.000020
nydus_seamless_pause_time_seconds{quantile="0.95"} 0.000035
nydus_seamless_pause_time_seconds{quantile="0.99"} 0.000050

# 后台处理时间
nydus_seamless_background_time_seconds{quantile="0.5"} 58.7
nydus_seamless_background_time_seconds{quantile="0.95"} 75.2
nydus_seamless_background_time_seconds{quantile="0.99"} 90.1
```

## SDK 示例

### Python SDK (未来扩展)

```python
from nydus_client import SeamlessSnapshotClient

# 创建客户端
client = SeamlessSnapshotClient(base_url="http://localhost:8080")

# 执行快照
result = client.create_snapshot(
    container_id="mycontainer",
    target_ref="registry.example.com/myimage:snapshot",
    wait=True
)

print(f"Snapshot ID: {result.snapshot_id}")
print(f"Pause Time: {result.pause_time}")
```

### JavaScript SDK (未来扩展)

```javascript
const { SeamlessSnapshotClient } = require('@nydus/client');

const client = new SeamlessSnapshotClient({
    baseURL: 'http://localhost:8080'
});

// 执行快照
const result = await client.createSnapshot({
    containerId: 'mycontainer',
    targetRef: 'registry.example.com/myimage:snapshot',
    wait: true
});

console.log(`Snapshot ID: ${result.snapshotId}`);
console.log(`Pause Time: ${result.pauseTime}`);
```

---

本API参考文档提供了无感快照功能的完整接口说明，包括命令行工具、Go API和未来的REST API设计。
