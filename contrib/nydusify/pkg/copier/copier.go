// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package copier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd/archive/compression"
	"github.com/containerd/containerd/content"
	containerdErrdefs "github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/reference/docker"
	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/containerd/nydus-snapshotter/pkg/remote/remotes"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	nydusifyUtils "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/dustin/go-humanize"
	"github.com/goharbor/acceleration-service/pkg/errdefs"
	"github.com/goharbor/acceleration-service/pkg/platformutil"
	"github.com/goharbor/acceleration-service/pkg/remote"
	"github.com/goharbor/acceleration-service/pkg/utils"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Opt struct {
	WorkDir        string
	NydusImagePath string

	Source string
	Target string

	SourceInsecure bool
	TargetInsecure bool

	SourceBackendType   string
	SourceBackendConfig string

	TargetBackendType   string
	TargetBackendConfig string

	AllPlatforms bool
	Platforms    string

	PushChunkSize int64
}

type output struct {
	Blobs []string
}

func hosts(opt Opt) remote.HostFunc {
	maps := map[string]bool{
		opt.Source: opt.SourceInsecure,
		opt.Target: opt.TargetInsecure,
	}
	return func(ref string) (remote.CredentialFunc, bool, error) {
		return remote.NewDockerConfigCredFunc(), maps[ref], nil
	}
}

func getPushWriter(ctx context.Context, pvd *provider.Provider, desc ocispec.Descriptor, opt Opt) (content.Writer, error) {
	resolver, err := pvd.Resolver(opt.Target)
	if err != nil {
		return nil, errors.Wrap(err, "get resolver")
	}
	ref := opt.Target
	if !strings.Contains(ref, "@") {
		ref = ref + "@" + desc.Digest.String()
	}
	pusher, err := resolver.Pusher(ctx, ref)
	if err != nil {
		return nil, errors.Wrap(err, "create pusher")
	}
	writer, err := pusher.Push(ctx, desc)
	if err != nil {
		if containerdErrdefs.IsAlreadyExists(err) {
			return nil, nil
		}
		return nil, err
	}
	return writer, nil
}

func pushBlobFromBackend(
	ctx context.Context, pvd *provider.Provider, backend backend.Backend, src ocispec.Descriptor, opt Opt,
) ([]ocispec.Descriptor, *ocispec.Descriptor, error) {
	if src.MediaType != ocispec.MediaTypeImageManifest && src.MediaType != images.MediaTypeDockerSchema2Manifest {
		return nil, nil, fmt.Errorf("unsupported media type %s", src.MediaType)
	}
	manifest := ocispec.Manifest{}
	if _, err := utils.ReadJSON(ctx, pvd.ContentStore(), &manifest, src); err != nil {
		return nil, nil, errors.Wrap(err, "read manifest from store")
	}
	bootstrapDesc := parser.FindNydusBootstrapDesc(&manifest)
	if bootstrapDesc == nil {
		return nil, nil, nil
	}
	ra, err := pvd.ContentStore().ReaderAt(ctx, *bootstrapDesc)
	if err != nil {
		return nil, nil, errors.Wrap(err, "prepare reading bootstrap")
	}
	bootstrapPath := filepath.Join(opt.WorkDir, "bootstrap.tgz")
	if err := nydusifyUtils.UnpackFile(io.NewSectionReader(ra, 0, ra.Size()), nydusifyUtils.BootstrapFileNameInLayer, bootstrapPath); err != nil {
		return nil, nil, errors.Wrap(err, "unpack bootstrap layer")
	}
	outputPath := filepath.Join(opt.WorkDir, "output.json")
	builder := tool.NewBuilder(opt.NydusImagePath)
	if err := builder.Check(tool.BuilderOption{
		BootstrapPath:   bootstrapPath,
		DebugOutputPath: outputPath,
	}); err != nil {
		return nil, nil, errors.Wrap(err, "check bootstrap")
	}
	var out output
	bytes, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read output file")
	}
	if err := json.Unmarshal(bytes, &out); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshal output json")
	}

	// Deduplicate the blobs for avoiding uploading repeatedly.
	blobIDs := []string{}
	blobIDMap := map[string]bool{}
	for _, blobID := range out.Blobs {
		if blobIDMap[blobID] {
			continue
		}
		blobIDs = append(blobIDs, blobID)
		blobIDMap[blobID] = true
	}

	sem := semaphore.NewWeighted(int64(provider.LayerConcurrentLimit))
	eg, ctx := errgroup.WithContext(ctx)
	blobDescs := make([]ocispec.Descriptor, len(blobIDs))
	for idx := range blobIDs {
		func(idx int) {
			eg.Go(func() error {
				sem.Acquire(context.Background(), 1)
				defer sem.Release(1)

				blobID := blobIDs[idx]
				blobDigest := digest.Digest("sha256:" + blobID)
				blobSize, err := backend.Size(blobID)
				if err != nil {
					return errors.Wrap(err, "get blob size")
				}
				blobSizeStr := humanize.Bytes(uint64(blobSize))

				logrus.WithField("digest", blobDigest).WithField("size", blobSizeStr).Infof("pushing blob from backend")
				rc, err := backend.Reader(blobID)
				if err != nil {
					return errors.Wrap(err, "get blob reader")
				}
				defer rc.Close()
				blobDescs[idx] = ocispec.Descriptor{
					Digest:    blobDigest,
					Size:      blobSize,
					MediaType: converter.MediaTypeNydusBlob,
					Annotations: map[string]string{
						converter.LayerAnnotationNydusBlob: "true",
					},
				}
				writer, err := getPushWriter(ctx, pvd, blobDescs[idx], opt)
				if err != nil {
					if errdefs.NeedsRetryWithHTTP(err) {
						pvd.UsePlainHTTP()
						writer, err = getPushWriter(ctx, pvd, blobDescs[idx], opt)
					}
					if err != nil {
						return errors.Wrap(err, "get push writer")
					}
				}
				if writer != nil {
					defer writer.Close()
					return content.Copy(ctx, writer, rc, blobSize, blobDigest)
				}

				logrus.WithField("digest", blobDigest).WithField("size", blobSizeStr).Infof("pushed blob from backend")

				return nil
			})
		}(idx)
	}

	if err := eg.Wait(); err != nil {
		return nil, nil, errors.Wrap(err, "push blobs")
	}

	// Update manifest layers
	for idx := range manifest.Layers {
		if manifest.Layers[idx].Annotations != nil {
			// The annotation key is deprecated, but it still exists in some
			// old nydus images, let's clean it up.
			delete(manifest.Layers[idx].Annotations, "containerd.io/snapshot/nydus-blob-ids")
		}
	}
	manifest.Layers = append(blobDescs, manifest.Layers...)

	// Update image config
	blobDigests := []digest.Digest{}
	for idx := range blobDescs {
		blobDigests = append(blobDigests, blobDescs[idx].Digest)
	}
	config := ocispec.Image{}
	if _, err := utils.ReadJSON(ctx, pvd.ContentStore(), &config, manifest.Config); err != nil {
		return nil, nil, errors.Wrap(err, "read config json")
	}
	config.RootFS.DiffIDs = append(blobDigests, config.RootFS.DiffIDs...)
	configDesc, err := utils.WriteJSON(ctx, pvd.ContentStore(), config, manifest.Config, opt.Target, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write config json")
	}
	manifest.Config = *configDesc

	target, err := utils.WriteJSON(ctx, pvd.ContentStore(), &manifest, src, opt.Target, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write manifest json")
	}

	return blobDescs, target, nil
}

func getPlatform(platform *ocispec.Platform) string {
	if platform == nil {
		return platforms.DefaultString()
	}
	return platforms.Format(*platform)
}

// getLocalPath checks if the given reference is a local file path and returns its absolute path.
//
// Parameters:
// - ref: A string which may be a docker reference or a local file path prefixed with "file://".
//
// Returns:
// - isLocalPath: A boolean indicating whether the reference is a local file path.
// - absPath: A string containing the absolute path of the local file, if applicable.
// - err: An error object if any error occurs during the process of getting the absolute path.
func getLocalPath(ref string) (isLocalPath bool, absPath string, err error) {
	if !strings.HasPrefix(ref, "file://") {
		return false, "", nil
	}
	path := strings.TrimPrefix(ref, "file://")
	absPath, err = filepath.Abs(path)
	if err != nil {
		return true, "", err
	}
	return true, absPath, nil
}

// trueStreamCopy 实现真正的流式传输，同时进行拉取和推送
func trueStreamCopy(ctx context.Context, srcReader io.Reader, targetWriter content.Writer, size int64, expectedDigest digest.Digest) error {
	logrus.Infof("开始流式传输，预期大小: %d 字节，预期摘要: %s", size, expectedDigest)

	// 对于小文件，使用简化处理
	if size <= 128 {
		return handleSmallFileTransfer(ctx, srcReader, targetWriter, size, expectedDigest)
	}

	// 使用16MB缓冲区进行高效传输
	return handleLargeFileTransfer(ctx, srcReader, targetWriter, size, expectedDigest)
}

// handleSmallFileTransfer 处理小文件的传输，直接读取全部内容再提交
func handleSmallFileTransfer(ctx context.Context, srcReader io.Reader, targetWriter content.Writer, size int64, expectedDigest digest.Digest) error {
	logrus.Debugf("文件较小(%d字节)，使用简化处理方式", size)

	// 读取全部内容
	data, err := io.ReadAll(srcReader)
	if err != nil {
		return errors.Wrap(err, "读取小文件数据失败")
	}

	// 确保数据大小正确
	if int64(len(data)) != size && size > 0 {
		logrus.Warnf("小文件大小不匹配: 期望 %d 字节, 实际 %d 字节", size, len(data))
	}

	// 计算实际摘要
	actualDigest := digest.FromBytes(data)

	// 检查摘要是否匹配
	if expectedDigest != "" && expectedDigest != actualDigest {
		return fmt.Errorf("小文件摘要不匹配: 期望 %s, 实际 %s", expectedDigest, actualDigest)
	}

	// 写入数据并提交
	if _, err := targetWriter.Write(data); err != nil {
		return errors.Wrap(err, "写入小文件数据失败")
	}

	if err := targetWriter.Commit(ctx, int64(len(data)), actualDigest); err != nil {
		return errors.Wrap(err, "提交小文件内容失败")
	}

	logrus.Infof("小文件传输完成: %d 字节，摘要: %s", len(data), actualDigest)
	return nil
}

// handleLargeFileTransfer 处理大文件的传输，使用分块读取并及时更新进度
func handleLargeFileTransfer(ctx context.Context, srcReader io.Reader, targetWriter content.Writer, size int64, expectedDigest digest.Digest) error {
	bufSize := 16 * 1024 * 1024 // 16MB 缓冲区
	buf := make([]byte, bufSize)
	hasher := sha256.New()
	var totalCopied int64
	lastLoggedProgress := int64(0)
	logInterval := int64(100 * 1024 * 1024) // 每100MB记录一次日志

	for {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// 读取数据
		n, readErr := srcReader.Read(buf)
		if n <= 0 {
			if readErr == io.EOF {
				break
			}
			return errors.Wrap(readErr, "读取数据失败")
		}

		// 计算哈希
		hasher.Write(buf[:n])

		// 写入数据
		writeN, writeErr := targetWriter.Write(buf[:n])
		if writeErr != nil {
			return errors.Wrap(writeErr, "写入数据失败")
		}
		if writeN != n {
			return errors.New("写入的数据长度不符")
		}

		totalCopied += int64(n)

		// 定期记录进度
		if totalCopied-lastLoggedProgress >= logInterval {
			logrus.Infof("流式传输进度: %.2f%% (%s/%s)",
				float64(totalCopied)*100/float64(size),
				humanize.Bytes(uint64(totalCopied)),
				humanize.Bytes(uint64(size)))
			lastLoggedProgress = totalCopied
		}
	}

	// 计算最终摘要
	actualDigest := digest.NewDigestFromBytes(digest.SHA256, hasher.Sum(nil))

	// 检查摘要是否匹配
	if expectedDigest != "" && expectedDigest != actualDigest {
		return fmt.Errorf("摘要不匹配: 期望 %s, 实际 %s", expectedDigest, actualDigest)
	}

	// 检查大小是否匹配
	if size > 0 && size != totalCopied {
		logrus.Warnf("大小不匹配: 期望 %d 字节, 实际 %d 字节, 将使用实际大小", size, totalCopied)
	}

	// 提交内容
	if err := targetWriter.Commit(ctx, totalCopied, actualDigest); err != nil {
		return errors.Wrap(err, "提交内容失败")
	}

	logrus.Infof("流式传输完成: %s, 摘要: %s", humanize.Bytes(uint64(totalCopied)), actualDigest)
	return nil
}

// newStreamContext 创建一个用于流式传输的上下文
func newStreamContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, "useStream", true)
}

// enableStreamTransfer 检查是否应该启用流式传输
func enableStreamTransfer(opt Opt) bool {
	return opt.PushChunkSize > 0
}

// httpModeManager 管理HTTP模式切换的线程安全的实用工具
type httpModeManager struct {
	mu       sync.Mutex
	enabled  bool
	provider *provider.Provider
}

// newHTTPModeManager 创建一个新的HTTP模式管理器
func newHTTPModeManager(pvd *provider.Provider) *httpModeManager {
	return &httpModeManager{
		provider: pvd,
	}
}

// switchToHTTP 切换到HTTP模式，如果已经是HTTP模式则不做任何事情
func (m *httpModeManager) switchToHTTP() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		logrus.Info("全局切换到HTTP模式")
		m.provider.UsePlainHTTP()
		m.enabled = true
	}
}

// isEnabled 检查是否已启用HTTP模式
func (m *httpModeManager) isEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled
}

// streamTransferManager 管理流式传输的组件
type streamTransferManager struct {
	provider    *provider.Provider
	httpManager *httpModeManager
	sourceRef   string
	targetRef   string
	opt         Opt
	// 避免存储接口类型，直接存储操作所需的组件
	sourceFetcher remotes.Fetcher
	targetPusher  remotes.Pusher
}

// newStreamTransferManager 创建流式传输管理器
func newStreamTransferManager(ctx context.Context, pvd *provider.Provider, httpManager *httpModeManager, opt Opt) (*streamTransferManager, error) {
	// 为源准备解析器
	sourceResolver, err := pvd.Resolver(opt.Source)
	if err != nil {
		return nil, errors.Wrap(err, "获取源解析器")
	}

	// 为目标准备解析器
	targetResolver, err := pvd.Resolver(opt.Target)
	if err != nil {
		return nil, errors.Wrap(err, "获取目标解析器")
	}

	// 解析引用获取名称
	sourceName, _, err := sourceResolver.Resolve(ctx, opt.Source)
	if err != nil {
		return nil, errors.Wrap(err, "解析源引用")
	}

	// 获取源镜像的拉取器
	sourceFetcher, err := sourceResolver.Fetcher(ctx, sourceName)
	if err != nil {
		return nil, errors.Wrap(err, "创建源拉取器")
	}

	// 获取目标镜像的推送器
	targetPusher, err := targetResolver.Pusher(ctx, opt.Target)
	if err != nil {
		return nil, errors.Wrap(err, "创建目标推送器")
	}

	return &streamTransferManager{
		sourceFetcher: sourceFetcher,
		targetPusher:  targetPusher,
		httpManager:   httpManager,
		provider:      pvd,
		sourceRef:     opt.Source,
		targetRef:     opt.Target,
		opt:           opt,
	}, nil
}

// refreshPusher 在需要时刷新推送器（如切换到HTTP模式后）
func (m *streamTransferManager) refreshPusher(ctx context.Context) error {
	// 获取新的解析器
	resolver, err := m.provider.Resolver(m.targetRef)
	if err != nil {
		return errors.Wrap(err, "获取新解析器")
	}

	// 获取新的推送器
	newPusher, err := resolver.Pusher(ctx, m.targetRef)
	if err != nil {
		return errors.Wrap(err, "创建新推送器")
	}

	// 更新推送器
	m.targetPusher = newPusher
	return nil
}

// pushContent 推送内容，处理HTTP/HTTPS切换和已存在内容的逻辑
func (m *streamTransferManager) pushContent(ctx context.Context, desc ocispec.Descriptor, reader io.Reader) error {
	writer, err := m.targetPusher.Push(ctx, desc)
	if err != nil {
		// 如果内容已存在，直接返回成功
		if containerdErrdefs.IsAlreadyExists(err) {
			logrus.Infof("内容已存在: %s", desc.Digest)
			return nil
		}

		// 检查是否需要切换到HTTP模式
		if errdefs.NeedsRetryWithHTTP(err) {
			logrus.Warn("切换到HTTP模式重试")
			m.httpManager.switchToHTTP()

			// 刷新推送器
			if err := m.refreshPusher(ctx); err != nil {
				return err
			}

			// 重试推送
			writer, err = m.targetPusher.Push(ctx, desc)
			if err != nil {
				if containerdErrdefs.IsAlreadyExists(err) {
					logrus.Infof("内容已存在: %s", desc.Digest)
					return nil
				}
				return errors.Wrap(err, "HTTP模式推送失败")
			}
		} else {
			return errors.Wrap(err, "推送失败")
		}
	}

	if writer == nil {
		// 内容已存在，无需传输
		return nil
	}

	// 进行流式传输
	if err := trueStreamCopy(ctx, reader, writer, desc.Size, desc.Digest); err != nil {
		return errors.Wrap(err, "流式传输失败")
	}

	return nil
}

// streamTransferLayer 流式传输单个层
func (m *streamTransferManager) streamTransferLayer(ctx context.Context, desc ocispec.Descriptor, info string) error {
	logrus.Infof("开始流式传输 %s: %s，大小: %s",
		info, desc.Digest, humanize.Bytes(uint64(desc.Size)))

	// 获取源内容
	rc, err := m.sourceFetcher.Fetch(ctx, desc)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("获取%s失败", info))
	}
	defer rc.Close()

	// 推送到目标
	if err := m.pushContent(ctx, desc, rc); err != nil {
		return err
	}

	logrus.Infof("完成流式传输 %s: %s", info, desc.Digest)
	return nil
}

// streamPlatformManifest 处理单个平台的清单传输
func (m *streamTransferManager) streamPlatformManifest(ctx context.Context, manifestDesc ocispec.Descriptor) (ocispec.Descriptor, error) {
	platformStr := getPlatform(manifestDesc.Platform)
	logrus.Infof("[%s] 开始处理平台清单", platformStr)

	// 获取清单内容
	rc, err := m.sourceFetcher.Fetch(ctx, manifestDesc)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "获取清单失败")
	}
	defer rc.Close()

	// 读取清单内容
	manifestBytes, err := io.ReadAll(rc)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "读取清单失败")
	}

	// 解析清单
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "解析清单失败")
	}

	// 先传输配置文件
	if err := m.streamTransferLayer(ctx, manifest.Config, "配置文件"); err != nil {
		return ocispec.Descriptor{}, err
	}

	// 创建一个等待组，用于等待所有层处理完成
	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(provider.LayerConcurrentLimit) // 设置最大并发数

	// 处理每一层
	for i, layer := range manifest.Layers {
		i, layer := i, layer // 避免闭包问题
		eg.Go(func() error {
			layerInfo := fmt.Sprintf("第 %d/%d 层", i+1, len(manifest.Layers))
			return m.streamTransferLayer(egCtx, layer, layerInfo)
		})
	}

	// 等待所有层处理完成
	if err := eg.Wait(); err != nil {
		return ocispec.Descriptor{}, err
	}

	// 最后推送清单
	if err := m.pushContent(ctx, manifestDesc, bytes.NewReader(manifestBytes)); err != nil {
		return ocispec.Descriptor{}, err
	}

	logrus.Infof("[%s] 完成平台清单处理", platformStr)
	return manifestDesc, nil
}

// streamManifestList 处理多平台清单列表的传输
func (m *streamTransferManager) streamManifestList(ctx context.Context, indexDesc ocispec.Descriptor, platformDescs []ocispec.Descriptor) error {
	if len(platformDescs) <= 1 {
		return nil // 单平台不需要处理索引
	}

	// 获取源索引内容
	rc, err := m.sourceFetcher.Fetch(ctx, indexDesc)
	if err != nil {
		return errors.Wrap(err, "获取索引失败")
	}
	defer rc.Close()

	// 读取索引内容
	indexBytes, err := io.ReadAll(rc)
	if err != nil {
		return errors.Wrap(err, "读取索引失败")
	}

	// 解析索引
	var index ocispec.Index
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return errors.Wrap(err, "解析索引失败")
	}

	// 更新索引中的清单引用
	index.Manifests = platformDescs

	// 重新序列化索引
	updatedIndexBytes, err := json.Marshal(index)
	if err != nil {
		return errors.Wrap(err, "序列化更新后的索引失败")
	}

	// 创建更新后的索引描述符
	updatedIndexDesc := ocispec.Descriptor{
		Digest:    digest.FromBytes(updatedIndexBytes),
		Size:      int64(len(updatedIndexBytes)),
		MediaType: indexDesc.MediaType,
	}

	// 推送更新后的索引
	if err := m.pushContent(ctx, updatedIndexDesc, bytes.NewReader(updatedIndexBytes)); err != nil {
		return errors.Wrap(err, "推送索引失败")
	}

	logrus.Infof("完成镜像索引推送: %s", updatedIndexDesc.Digest)
	return nil
}

// Copy copies an image from the source to the target.
func Copy(ctx context.Context, opt Opt) error {
	// Containerd image fetch requires a namespace context.
	ctx = namespaces.WithNamespace(ctx, "nydusify")

	platformMC, err := platformutil.ParsePlatforms(opt.AllPlatforms, opt.Platforms)
	if err != nil {
		return err
	}

	var bkd backend.Backend
	if opt.SourceBackendType != "" {
		bkd, err = backend.NewBackend(opt.SourceBackendType, []byte(opt.SourceBackendConfig), nil)
		if err != nil {
			return errors.Wrapf(err, "new backend")
		}
	}

	if _, err := os.Stat(opt.WorkDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(opt.WorkDir, 0755); err != nil {
				return errors.Wrap(err, "prepare work directory")
			}
			// We should only clean up when the work directory not exists
			// before, otherwise it may delete user data by mistake.
			defer os.RemoveAll(opt.WorkDir)
		} else {
			return errors.Wrap(err, "stat work directory")
		}
	}
	tmpDir, err := os.MkdirTemp(opt.WorkDir, "nydusify-")
	if err != nil {
		return errors.Wrap(err, "create temp directory")
	}
	pvd, err := provider.New(tmpDir, hosts(opt), 200, "v1", platformMC, opt.PushChunkSize)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// 检查是否启用流式传输
	useStream := enableStreamTransfer(opt)
	if useStream {
		logrus.Info("已启用流式传输模式（同时拉取和推送）")
	} else {
		logrus.Info("使用传统传输模式（先拉取后推送）")
	}

	// 创建HTTP模式管理器
	httpManager := newHTTPModeManager(pvd)

	isLocalSource, inputPath, err := getLocalPath(opt.Source)
	if err != nil {
		return errors.Wrap(err, "解析源路径")
	}

	var source string
	if isLocalSource {
		logrus.Infof("从本地路径导入源镜像: %s", inputPath)

		f, err := os.Open(inputPath)
		if err != nil {
			return err
		}
		defer f.Close()

		ds, err := compression.DecompressStream(f)
		if err != nil {
			return err
		}
		defer ds.Close()

		if source, err = pvd.Import(ctx, ds); err != nil {
			return errors.Wrap(err, "导入源镜像")
		}
		logrus.Infof("已导入源镜像: %s", source)
	} else {
		sourceNamed, err := docker.ParseDockerRef(opt.Source)
		if err != nil {
			return errors.Wrap(err, "解析源引用")
		}
		source = sourceNamed.String()

		if useStream {
			// 流式传输模式：只获取最小必要的信息
			start := time.Now()
			logrus.Infof("获取镜像 %s 的基本信息", source)

			err := pvd.FetchImageInfo(ctx, source)
			if err != nil && errdefs.NeedsRetryWithHTTP(err) {
				httpManager.switchToHTTP()
				err = pvd.FetchImageInfo(ctx, source)
			}

			if err != nil {
				return errors.Wrap(err, "获取镜像信息失败")
			}

			elapsed := time.Since(start)
			logrus.Infof("获取镜像基本信息耗时: %s", elapsed)
		} else {
			// 传统模式：拉取全部数据
			logrus.Infof("拉取源镜像: %s", source)

			err := pvd.Pull(ctx, source)
			if err != nil && errdefs.NeedsRetryWithHTTP(err) {
				httpManager.switchToHTTP()
				err = pvd.Pull(ctx, source)
			}

			if err != nil {
				return errors.Wrap(err, "拉取源镜像失败")
			}

			logrus.Infof("已完成拉取源镜像: %s", source)
		}
	}

	targetNamed, err := docker.ParseDockerRef(opt.Target)
	if err != nil {
		return errors.Wrap(err, "解析目标引用")
	}
	target := targetNamed.String()

	// 获取源镜像的索引信息
	sourceImage, err := pvd.Image(ctx, source)
	if err != nil {
		return errors.Wrap(err, "查找镜像")
	}

	// 获取所有平台的清单
	sourceDescs, err := utils.GetManifests(ctx, pvd.ContentStore(), *sourceImage, platformMC)
	if err != nil {
		return errors.Wrap(err, "获取镜像清单")
	}
	targetDescs := make([]ocispec.Descriptor, len(sourceDescs))

	// 如果启用了流式传输，使用流式传输模式
	if useStream && !isLocalSource {
		logrus.Info("开始流式传输镜像")
		streamStartTime := time.Now()

		// 创建流式传输管理器
		streamManager, err := newStreamTransferManager(ctx, pvd, httpManager, opt)
		if err != nil {
			return err
		}

		// 为每个平台的清单创建流式传输
		var wg sync.WaitGroup
		errCh := make(chan error, len(sourceDescs))
		var successCount int32

		for idx, sourceDesc := range sourceDescs {
			wg.Add(1)
			go func(idx int, sourceDesc ocispec.Descriptor) {
				defer wg.Done()

				// 创建流式上下文
				streamCtx := newStreamContext(ctx)

				// 处理平台清单
				targetDesc, err := streamManager.streamPlatformManifest(streamCtx, sourceDesc)
				if err != nil {
					errCh <- err
					return
				}

				targetDescs[idx] = targetDesc
				atomic.AddInt32(&successCount, 1)
			}(idx, sourceDesc)
		}

		wg.Wait()

		logrus.Infof("已完成 %d/%d 个平台清单的流式传输", successCount, len(sourceDescs))

		// 检查是否有错误
		select {
		case err := <-errCh:
			return err
		default:
		}

		// 如果有多个平台，推送索引
		if len(targetDescs) > 1 && (sourceImage.MediaType == ocispec.MediaTypeImageIndex ||
			sourceImage.MediaType == images.MediaTypeDockerSchema2ManifestList) {

			indexCtx := newStreamContext(ctx)
			if err := streamManager.streamManifestList(indexCtx, *sourceImage, targetDescs); err != nil {
				return err
			}
		}

		// 计算并打印总耗时
		streamElapsed := time.Since(streamStartTime)
		logrus.Infof("流式传输总耗时: %s", streamElapsed)

		return nil
	}

	// 以下是传统的非流式传输逻辑
	descCh := make(chan int, len(sourceDescs))
	errCh := make(chan error, len(sourceDescs))
	concurrency := 4 // 可根据实际情况调整并发数
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range descCh {
				sourceDesc := sourceDescs[idx]
				targetDesc := &sourceDesc
				if bkd != nil {
					descs, _targetDesc, err := pushBlobFromBackend(ctx, pvd, bkd, sourceDesc, opt)
					if err != nil {
						errCh <- errors.Wrap(err, "获取解析器")
						continue
					}
					if _targetDesc == nil {
						logrus.WithField("platform", getPlatform(sourceDesc.Platform)).Warnf("%s 不是Nydus镜像", source)
					} else {
						targetDesc = _targetDesc
						store := newStore(pvd.ContentStore(), descs)
						pvd.SetContentStore(store)
					}
				}
				targetDescs[idx] = *targetDesc

				logrus.WithField("platform", getPlatform(sourceDesc.Platform)).Infof("推送目标清单 %s", targetDesc.Digest)
				err := pvd.Push(ctx, *targetDesc, target)
				if err != nil && errdefs.NeedsRetryWithHTTP(err) {
					httpManager.switchToHTTP()
					err = pvd.Push(ctx, *targetDesc, target)
				}
				if err != nil {
					errCh <- errors.Wrap(err, "推送目标清单失败")
					continue
				}
				logrus.WithField("platform", getPlatform(sourceDesc.Platform)).Infof("推送目标清单 %s 已完成", targetDesc.Digest)
			}
		}()
	}

	for idx := range sourceDescs {
		descCh <- idx
	}
	close(descCh)
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
	}

	if len(targetDescs) > 1 && (sourceImage.MediaType == ocispec.MediaTypeImageIndex ||
		sourceImage.MediaType == images.MediaTypeDockerSchema2ManifestList) {
		targetIndex := ocispec.Index{}
		if _, err := utils.ReadJSON(ctx, pvd.ContentStore(), &targetIndex, *sourceImage); err != nil {
			return errors.Wrap(err, "读取源清单列表")
		}
		targetIndex.Manifests = targetDescs

		targetImage, err := utils.WriteJSON(ctx, pvd.ContentStore(), targetIndex, *sourceImage, target, nil)
		if err != nil {
			return errors.Wrap(err, "写入目标清单列表")
		}

		err = pvd.Push(ctx, *targetImage, target)
		if err != nil && errdefs.NeedsRetryWithHTTP(err) {
			httpManager.switchToHTTP()
			err = pvd.Push(ctx, *targetImage, target)
		}
		if err != nil {
			return errors.Wrap(err, "推送目标镜像失败")
		}

		logrus.Infof("推送镜像 %s 已完成", target)
	}

	return nil
}
