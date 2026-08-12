# nydus 仓库架构评估报告

> 日期：2026-08-12 · 范围：全仓库逐文件通读（nydus-core / nydus / nydusify，约 25k 行）
> 方法：6 个区域并行精读 + 交叉验证，所有结论均有 file:line 证据，死代码均经全 workspace grep 确认零消费者。

## 一、模块地图与依赖关系

### nydus-core（运行时核心库）

| 模块 | 行数 | 职责 | 依赖（实际 use，rustdoc 链接不计） |
|---|---|---|---|
| `utils` | 396 | align / sha256+hex / pread / LE 读写 / umount，纯工具 | 无（叶子） |
| `metadata` | 3264 | EROFS 磁盘格式（superblock/inode/dirent/chunk/device slot）＋两个 nydus 私有 sidecar 格式（blob_meta 1680 行、blob_footer）＋构建期分配器 layout | utils |
| `config` | 216 | YAML 配置模型 | 无（叶子） |
| `tracing` | 162 | 日志 subscriber 安装（stdout + 滚动文件 + panic hook） | 无（叶子） |
| `metrics` | 886 | Prometheus 单例注册表；`trace.rs` 是访问模式记录（另一码事，见 D 节） | metadata、storage（`ReadKind` 类型） |
| `storage` | 5079 | 数据加载域：backend（local / registry + HTTP 栈）、cache（解码缓存 + 组锁 + singleflight）、group_map、prefetch（`PrefetchSource` trait 倒置） | config、metadata、utils（+ 调用 metrics 记录函数，sink 模式） |
| `build` | 2230 | 目录 → nydus 全量 blob 的完整构建管线 | metadata、utils |
| `fs` | 1222 | `ErofsReader`：mmap 元数据走树 + 按需数据读，持有 per-blob 缓存集合 | metadata、storage、metrics::trace |
| `core` | 1074 | `NydusCore`：扁平设备地址空间 + FdRange/fd 交付（pmem/nbd/ublk/uffd 用）；是 `ErofsReader` 之上的门面（组合关系，**确认无平行实现**） | config、fs、storage、metrics::trace |

```
      ┌────────┐
      │  core  │  NydusCore：装载/编排
      └─┬────┬─┘
        ▼    ▼
   ┌──────┐  │            ┌─────────┐ ┌─────────┐
   │  fs  │  │            │ tracing │ │ metrics │
   └─┬──┬─┘  │            └─────────┘ └─┬───────┘
     │  │ impl PrefetchSource     ReadKind│▲ record_*
     │  ▼    ▼                           ▼│（sink 上报）
     │ ┌───────────────────────┐          │
     │ │ storage（+ prefetch） │◄─────────┘
     │ └───────────┬───────────┘
     │             │        ┌────────┐   ┌────────┐
     │             ├───────►│ config │   │ build  │
     ▼             ▼        └────────┘   └─┬──────┘
   ┌───────────────────┐                   │
   │     metadata      │◄──────────────────┘
   └─────────┬─────────┘
             ▼
         ┌───────┐
         │ utils │
         └───────┘
```

### nydus（工具与前端）＋ bin

- 读侧工具：`check`（583，结构巡检 → `CheckReport`）、`unpack`（276，blob→tar）；写侧：`merge`（809，多层→单 bootstrap）。
- 五个前端，全部 feature 门控、互不依赖：
  - `fuse`（617）：唯一走 inode 层的前端，`ErofsFs` 适配 fuser；
  - `fanotify`（2764）：多设备 EROFS + FAN_PRE_ACCESS 拦截冷读，手写 epoll + FetchPool；
  - `nbd`（834）：扁平镜像经 NBD socket 协议暴露，阻塞循环 + 每 socket 一线程；
  - `ublk`（607）：扁平镜像经 libublk/io_uring 暴露，含 mmap 快路径；
  - `uffd`（1455）：microVM virtio-pmem 的 userfaultfd 服务，tokio + SCM_RIGHTS 传 fd。
- 五种并发模型互不相同，**服务循环不可合并（真领域差异）**；真重复见 C 节。
- bin（2804）：12 个子命令，`build`/`merge`/`check` 已是薄壳，**`optimize` 是唯一未下沉的**。

### nydusify（Go，6090 行）

```
main.go ──► checker, converter, oci, remote
checker ──► converter, oci, remote, pkg/converter
converter ──► oci, pkg/converter
remote ──► converter          ← 唯一反向边（只为 IsNydus* 三谓词）
oci / pkg/converter：叶子
```

- `pkg/converter`（830）：公共库——媒体类型/annotation、footer 解析、pack/tar/untar、exec `nydus` 子进程。
- `internal/converter`（1952）：containerd content store 绑定的转换编排（hook、manifest 改写、多源、to-OCI）。
- `internal/checker`（2095）：三规则校验（manifest 结构 / bootstrap shell 给 `nydus check` / 双侧挂载逐条目比对）。
- `internal/remote`（448）：resolver/provider/fetch-push；`internal/oci`（92）：content store 上的 OCI 读取（干净叶子）。
- Go checker 与 Rust check **不重复**：一个答"bootstrap 结构合法吗"，一个答"转换没丢东西吗"。
- **必要的跨语言重复**：`pkg/converter/footer.go:33-39` 硬编码 footer 字节偏移，对应 Rust `blob_footer.rs`——目前无任何防漂移机制。

## 二、正确性问题（建议优先修）

| # | 问题 | 证据 |
|---|---|---|
| A1 | **Go 默认值不一致（实锤 bug）**：`ConvertMultiSource` 的 `CompressSize` 默认 1MiB，其余两处 4MiB；CLI 总传值被掩盖，库调用者静默拿到不同 group 大小 | `internal/converter/multi.go:83` vs `pkg/converter/constants.go:60-62`、`convert.go:47-52` |
| A2 | **`cast_ref<T>` 只查长度不查对齐、无 trait bound**，对 mmap 外部数据裸 cast；`blob_meta` 的 `mapped_chunks/groups` 对 `repr(C)` align=8 结构从 mmap 裸转，且与手写 LE 的 `read_from` 构成两条并行解析路径，一致性只靠 size 断言 | `metadata/mod.rs:110`；`blob_meta.rs:1169-1183` vs `:544/:650` |
| A3 | **trace 双轨互斥**：有实例 recorder 只写实例、否则只写全局 → NydusCore 路径永不出现在 `/trace` 端点，FUSE 路径永不出现在 `core.trace_snapshot()`；无文档，疑似真 bug | `storage/cache/local.rs:268-271` |
| A4 | 常量不归一：uffd 硬编码 4096 不走 `EROFS_BLOCK_SIZE`；core.rs 一处用 `u64::MAX` 而非已 import 的 `EROFS_NULL_ADDR`；另有 4 个 `= EROFS_BLOCK_SIZE` 别名常量 | `uffd/core.rs:13`；`core.rs:818` |
| A5 | **三个树遍历器防护矛盾**：check 防环不防深（爆栈）、unpack 防深不防环（目录环重复展开）、merge 两样皆无 | `check.rs:254+263`、`unpack.rs:52+59`、`merge.rs:281` |
| A6 | Go 用正则抓 `nydus optimize` 的人读 stdout 当机器契约，改一行打印即断；footer 格式亦无跨语言 golden 测试 | `checker/optimize.go:229-233` ↔ `bin/optimize.rs:236-249` |
| A7 | 配置陷阱：被 cfg 掉的字段 + 无 `deny_unknown_fields`，不带 feature 编译时用户 YAML 的 key 被静默忽略 | `storage/backend/proxy.rs:52-54` |
| A8 | merge 的 epoch 计算是死逻辑（build 清零 root mtime → merge 读回恒 0），`SystemTime::now()` fallback 永不生效且是潜在不可复现源；`chunkbits` 参数贯穿三个渲染函数但 `erofs_inode_size` 根本不用 | `merge.rs:104-112,193-197`；`bootstrap.rs:18/30/99` → `inode.rs:122` |
| A9 | unmount 重试逐字重复且行为不一致（nbd 有 `is_not_mounted` 早退，fanotify 没有，信号早到白等 10s）；ublk/uffd 信号线程无次信号逃生（卡死只能 SIGKILL） | `bin/fanotify.rs:201-224` vs `bin/nbd.rs:133-160`；`bin/ublk.rs:79-87`、`bin/uffd.rs:39-47` |

## 三、死代码（grep 验证零消费者）

- `BlobCache::stream_redirect` trait 方法 + 实现（**约 87 行**，与 `stream_redirect_batch` 逐行重复）：`cache/mod.rs:101-109` + `cache/local.rs:649-701`。
- `Pauser` 整套（102 行）"有 API 无触发器"：registry 已识别 `ProxyTooManyRequests`（`registry/mod.rs:367-371`）却从不调 `pause_for`——接线或删除。
- Go：`pkg.Merge` / `pkg.Pack` 仓内零调用（纯外部 API 却与 internal 两份实现并行、无共同执行路径）；`Provider.PlatformMC`（provider.go:96）；`Image.Blobs` 只写不读（image.go:59,117）。
- `NydusCore::{clear_trace(:408), metrics_snapshot(:417)}`、`BlobId::{to_hex, as_bytes, into_bytes}`；`ErofsInode::{is_compact(:252), mtime_nsec(:303)}`；`BlobMeta::chunk_at(:787)`；`BlobWriter::into_file(:107)`；`saved_by_dedup` 恒 0 的 pub 字段（blob_chunk.rs:26）；`EROFS_I_NLINK_1_BIT`；`sha256_file_region`；`GroupMap::ready_count`；`dir.rs:68` 算完即弃的 `dirent_area`。
- uffd proto 客户端侧编解码 6 个函数对外不可达（真客户端是 Go 集成测试自己重写的 wire format）——导出对齐或降 `#[cfg(test)]`：`uffd/proto.rs:269-417`。
- **`nydus-core/src/lib.rs` 根 re-export 33 项中 25 项零根路径消费者**（逐项验证）；两套入口并存制造"哪个是正规 API"的歧义，建议收敛到 8 个真用项（`Config/NydusCore/BlobId/FdRange/ResolveMode/FileType/TraceDocument/TraceEntry`）。
- 零价值包装：`BlobBackend::read_range`、`is_success_status`、`is_redirect`。

## 四、重复逻辑（合并点，按收益排序）

1. **cache/local.rs 批窗口解码 3 份**（`prefetch_all:450-493` / `stream_redirect_batch:366-395` / 待删的 `stream_redirect:662-697`）+ CRC 归因 3 处手写（已有 `validate_group_with_metrics` 不被复用）+ byte-range→group-span 8 行 ×2（`:335-342` vs `:550-557`）。合计可减 100+ 行。
2. **`merge.rs::flatten_node(:480-639)` 是 `build_tree_recursive(inode.rs:266-447)` 的平行实现**（DFS+索引回填+硬链接去重+ino 分配逐项对应），跨 crate 遵守 `InodeInfo` 的隐式契约；"epoch/uuid/设备槽/prefetch xattr/render" 五步收尾抄了 3 遍（build/mod.rs:128-141 / merge.rs:108-124 / merge.rs:193-205）。
3. **chunk 遍历循环 4 份**（fs/data.rs:157-206, 254-319；core.rs:808-852, 899-957）→ 提取 `for_each_chunk_span` 迭代器；flat 地址解析 2 份——**core.rs:926-931 应直接改用已有的 `flat_blob_at`（零风险）**；`chunkbits` 表达式 3 份（fs/data.rs:24、core.rs:801/891、check+merge 各一）→ 做成 `ErofsInode` 方法。
4. **`FdRange→buf` 拷贝 3 份**：nbd `read_at(core.rs:107-143)` ≈ ublk `copy_ranges(core.rs:106-152)` 去掉容错和 mmap 快路径——下沉 nydus-core 后 **nbd 白拿 mmap 快路径**（当前 nbd 每读全量 pread+copy，实打实的性能不对称）。
5. Go：merge 流水线 3 份（`pkg/merge.go:62-118` / `hook.go:231-268` / `multi.go:110-168`，收敛 internal 两处并让 `pkg.Merge` 复用）；stage/extract 文件版 vs store 版 4 函数近乎全等；`ingestBlobFile` 两份（local.go:109 vs checker/optimize.go:240）；默认值 3 份（顺带修 A1）。
6. 基础层：对齐 3 套（`utils::align_up` / `metadata::round_up`——主力却住错层 / 手写 `%`）；`le.rs` 三形态 14 函数 + blob_meta 手写 `to_le_bytes`（zerocopy 方案一并解决）；`sha256_file` 三合一；6 组逐字重复的 `as_bytes`/`zeroed` unsafe；`LocalDirConfig` 两遍（config.rs:56 vs backend/local.rs:76）；`MIB` 两遍；`.blob.meta` 命名规则两处（bin/build.rs:286 vs bin/optimize.rs:213）；mount(2) 骨架两遍（fanotify/mount.rs:34-52 vs nbd/mount.rs:28-45）。

## 五、放错层（搬迁点）

| 项 | 现在 | 应去 | 理由 |
|---|---|---|---|
| `mode_to_erofs_file_type` | `build/inode.rs:107` | `metadata::inode` | 纯 mode→FT 映射，三条只读路径为它依赖 build，分层倒挂 |
| `merge.rs` 整体（含 `rewrite_bootstrap_with_ondemand_blob`） | nydus lib | `nydus-core::build` | 构建域逻辑（见四.2）；移入零新增依赖；与 `assemble_ondemand_artifact` 归位成对 |
| `blob_meta.rs` + `blob_footer.rs` | `metadata/` | 独立 `blob/` 模块 | nydus 私有 sidecar 格式而非 EROFS，与模块文档"全 packed 可零拷贝"矛盾；搬后 metadata 3.3k→1.2k、语义单一 |
| `layout.rs` | `metadata/` | `build/` | 构建期分配器，唯一消费者 build/bootstrap.rs；也是 metadata 唯一没被 glob 导出的模块 |
| `check_inline_fit` | `nydus/check.rs:231` | `metadata::layout` | 同一格式不变式三处表述（layout 强制 / inode 预测 / check 校验），应同居防漂移 |
| `HashingWriter` | `build/mod.rs:275` | `utils` | 通用 IO 组合子 |
| `compression_is_worthwhile` | `build/blob_chunk.rs:298` | `metadata` | 文档自称"build 与 optimize 共享的格式兼容策略" |
| `hex_string` / `parse_sha256_hex` | `utils/digest.rs` | `utils/hex`（或 `hex` crate，已在 lock） | 消费者关心的是 blob id 文本编码 |
| `round_up` | `metadata/mod.rs:116` | `utils/align` | 纯算术；与 `align_up` 是错误契约不同的孪生，8+ 处调用的主力 API |
| `utils/mount.rs` | nydus-core | nydus crate | core 内零引用，纯为上层 bin 存在 |
| `EROFS_BLOB_ID_SIZE` | `chunk.rs:60` | `metadata/mod.rs` 常量区 | 与 chunk index 无关却被广泛引用 |
| **optimize 流水线**（`bin/optimize.rs:103-229`） | bin | 库 | 四子命令唯一未下沉；顺带消掉手写 HTTP/1.0 客户端（`" 200 "` 子串判状态码，`:294-323`）与对 `api_server::parse_unix_address` 的横向依赖 |
| fuse bin 挂载生命周期 ~170 行 | `bin/fuse.rs:23-195` | nydus lib | TermSignalMask / mountinfo 解析 / finish_session 是可测试的系统机制，`unescape_mountinfo` 现在无人能测 |
| `metrics/trace.rs` | `metrics/` | 顶层 `trace`（或随生产者进 storage） | 不 import prometheus、违反 metrics 模块自己声明的契约、产物是 optimize 输入工件而非遥测、与 `tracing` 撞名 |
| Go `IsNydus*` 三谓词 | `internal/converter/layer.go:27-48` | `pkg/converter` | 零依赖谓词；消掉 remote→converter 唯一反向边 |

## 六、其它结构性观察

- `BlobCache` trait：11 方法 9 个默认 `Unsupported`、实现者只有一个——收窄为必需方法或拆 `RedirectSource`。
- 前端门面导出不一致：fanotify/nbd/uffd 的 mod.rs 漏导出（bin 被迫钻 `::service::` 内部路径）；ublk 独自用 `nydus_core::core::` 模块路径而其余用根路径。
- 观测不对称：只有 fuse 打点、只有 fuse 启动 apiserver，四个块设备前端 `/metrics` 无从谈起（`DenyReason` 注释承诺的 metrics 从未接上）；`bin/fuse.rs:376` apiserver 启动失败仅 warn，但 `nydusify mount` 会把不存在的 socket 路径打印给用户。
- Go 小项：`rule.go`(19 行) 并入 checker.go；tar/untar 合一；`exec.Command` 三处丢 ctx（filesystem.go:174 等）；checker/optimize.go:223 子进程输出无条件漏到 stderr；`:260` `content.Copy` 缺 uncompressed label。
- 文档缺陷：nbd/proto.rs:8 描述与实现不符；ublk/core.rs:260 孤儿文档挂到 tests 上；fanotify/core.rs:108 文档挂错对象且 `FanotifyCore` 无文档。
- 既有编译告警（仅 `--all-features` 暴露）：`fanotify/response.rs:191` unused imports；`ublk/core.rs:265` doc comment 后空行。

## 七、看过并否决的合并

- 五个前端服务循环合并——五种并发模型是真领域差异；
- `NydusCore` 与 `ErofsReader` 合并——组合关系；byte-copy vs fd 交付两种根本不同的抽象；
- Go checker 与 Rust check 去重——校验对象不同（结构合法性 vs 转换等价性）；
- `internal/oci` 并入别处——三个包共用的干净叶子；
- utils 小文件合并成单文件——反而退化。

## 八、建议执行批次

1. **速赢批**（零风险，~1 天）：删 `stream_redirect`；死代码清单（三）；常量归一（A4）；core.rs 改用 `flat_blob_at`；lib.rs 根导出收敛；Go 默认值统一（A1）；`mode_to_erofs_file_type`→metadata；`chunkbits` 死参数删除。
2. **搬迁批**：merge→build；`blob/` 拆分；layout→build；trace 独立模块；optimize 下沉；Go `IsNydus*`→pkg。
3. **去重批**：cache 批窗口三合一；`for_each_chunk_span`；`walk_tree` 统一三遍历器（顺带修 A5）；`copy_ranges` 下沉（nbd 提速）；unmount/signal 骨架提取（修 A9）；Go merge 三合一。
4. **zerocopy 批**（独立 PR）：metadata 全模块换 zerocopy，消 15 处 unsafe、双解析路径（A2）与 `le.rs`。
5. **决策批**（需产品拍板）：Pauser 接线还是删；trace 双轨（A3）是 bug 还是特性；`nydus optimize --output-json`（A6）；块设备前端是否接 metrics。
