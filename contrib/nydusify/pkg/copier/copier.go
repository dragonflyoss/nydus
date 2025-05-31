// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package copier

import (
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

// streamCopy 实现边下载边上传的流式传输
func streamCopy(ctx context.Context, srcReader io.Reader, targetWriter content.Writer, size int64, expectedDigest digest.Digest) error {
	logrus.Infof("开始流式传输，预期大小: %d 字节，预期摘要: %s", size, expectedDigest)

	// 使用带有进度报告的io.Copy
	buf := make([]byte, 1024*1024*16) // 16MB 缓冲区
	var totalCopied int64

	for {
		n, readErr := srcReader.Read(buf)
		if n > 0 {
			// 写入数据
			writeN, writeErr := targetWriter.Write(buf[:n])
			if writeErr != nil {
				return errors.Wrap(writeErr, "write data in stream copy")
			}
			if writeN != n {
				return errors.New("short write in stream copy")
			}

			totalCopied += int64(n)

			// 每传输100MB记录一次日志
			if totalCopied%(100*1024*1024) < int64(n) {
				logrus.Infof("流式传输进度: %d/%d 字节 (%.2f%%)",
					totalCopied, size, float64(totalCopied)*100/float64(size))
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return errors.Wrap(readErr, "read data in stream copy")
		}
	}

	logrus.Infof("流式传输完成，总共传输: %d 字节", totalCopied)

	// 检查大小是否匹配，但只发出警告而不中断操作
	if size > 0 && size != totalCopied {
		logrus.Warnf("大小不匹配，期望: %d，实际: %d，将使用实际大小", size, totalCopied)
	}

	if err := targetWriter.Commit(ctx, totalCopied, expectedDigest); err != nil {
		return errors.Wrap(err, "commit target content")
	}
	logrus.Infof("成功提交目标内容，摘要: %s", expectedDigest)

	return nil
}

// trueStreamCopy 实现真正的流式传输，同时进行拉取和推送
func trueStreamCopy(ctx context.Context, srcReader io.Reader, targetWriter content.Writer, size int64, expectedDigest digest.Digest) error {
	logrus.Infof("开始真正的流式传输，预期大小: %d 字节，预期摘要: %s", size, expectedDigest)

	// 对于小文件（小于128字节），直接读取全部内容再提交，避免流式传输的复杂性
	if size <= 128 {
		logrus.Debugf("文件很小(%d字节)，使用简化处理方式", size)
		data, err := io.ReadAll(srcReader)
		if err != nil {
			return errors.Wrap(err, "读取小文件数据失败")
		}

		// 确保数据大小正确
		if int64(len(data)) != size {
			logrus.Warnf("小文件大小不匹配: 期望 %d 字节, 实际 %d 字节", size, len(data))
		}

		// 计算实际摘要
		hasher := sha256.New()
		hasher.Write(data)
		actualDigest := digest.NewDigestFromBytes(digest.SHA256, hasher.Sum(nil))

		// 检查摘要是否匹配
		if expectedDigest != "" && expectedDigest != actualDigest {
			return fmt.Errorf("小文件摘要不匹配: 期望 %s, 实际 %s", expectedDigest, actualDigest)
		}

		// 写入数据
		if _, err := targetWriter.Write(data); err != nil {
			return errors.Wrap(err, "写入小文件数据失败")
		}

		// 提交内容
		if err := targetWriter.Commit(ctx, size, expectedDigest); err != nil {
			return errors.Wrap(err, "提交小文件内容失败")
		}

		logrus.Infof("流式传输完成，总共传输: %d 字节", len(data))
		logrus.Infof("成功提交目标内容，摘要: %s", actualDigest)
		return nil
	}

	// 使用更大的缓冲区大小，减少系统调用次数
	bufSize := 16 * 1024 * 1024 // 16MB 缓冲区

	// 计算哈希值
	hasher := sha256.New()

	// 直接进行内存传输，不使用goroutine和通道，避免多余的内存复制和上下文切换
	buf := make([]byte, bufSize)
	var totalCopied int64

	for {
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// 读取数据
		n, readErr := srcReader.Read(buf)
		if n > 0 {
			// 计算哈希
			hasher.Write(buf[:n])

			// 写入数据
			writeN, writeErr := targetWriter.Write(buf[:n])
			if writeErr != nil {
				return errors.Wrap(writeErr, "write data in stream copy")
			}
			if writeN != n {
				return errors.New("short write in stream copy")
			}

			totalCopied += int64(n)

			// 每传输100MB记录一次日志
			if totalCopied%(100*1024*1024) < int64(n) {
				logrus.Infof("流式传输进度: %d/%d 字节 (%.2f%%)",
					totalCopied, size, float64(totalCopied)*100/float64(size))
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return errors.Wrap(readErr, "read data in stream copy")
		}
	}

	// 计算最终摘要
	actualDigest := digest.NewDigestFromBytes(digest.SHA256, hasher.Sum(nil))
	logrus.Infof("流式传输完成，总共传输: %d 字节", totalCopied)

	// 检查摘要是否匹配
	if expectedDigest != "" && expectedDigest != actualDigest {
		return fmt.Errorf("摘要不匹配，期望: %s，实际: %s", expectedDigest, actualDigest)
	}

	// 检查大小是否匹配，但只发出警告而不中断操作
	if size > 0 && size != totalCopied {
		logrus.Warnf("大小不匹配，期望: %d，实际: %d，将使用实际大小", size, totalCopied)
	}

	// 提交内容
	if err := targetWriter.Commit(ctx, totalCopied, actualDigest); err != nil {
		return errors.Wrap(err, "commit target content")
	}

	logrus.Infof("成功提交目标内容，摘要: %s", actualDigest)
	return nil
}

// newStreamContext 创建一个用于流式传输的上下文
func newStreamContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, "useStream", true)
}

// enableStreamTransfer 检查是否应该启用流式传输
func enableStreamTransfer(opt Opt) bool {
	// 可以根据实际情况添加更多的条件判断
	return opt.PushChunkSize > 0
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

	// 添加全局HTTP模式标志和互斥锁
	var (
		httpModeMutex   sync.Mutex
		httpModeEnabled bool = false
	)

	// 设置HTTP模式的辅助函数
	setHTTPMode := func() {
		httpModeMutex.Lock()
		defer httpModeMutex.Unlock()
		if !httpModeEnabled {
			logrus.Info("全局切换到HTTP模式")
			pvd.UsePlainHTTP()
			httpModeEnabled = true
		}
	}

	// 检查是否启用流式传输
	useStream := enableStreamTransfer(opt)
	if useStream {
		logrus.Info("已启用流式传输模式（同时拉取和推送）")
	} else {
		logrus.Info("使用传统传输模式（先拉取后推送）")
	}

	isLocalSource, inputPath, err := getLocalPath(opt.Source)
	if err != nil {
		return errors.Wrap(err, "parse source path")
	}
	var source string
	if isLocalSource {
		logrus.Infof("importing source image from %s", inputPath)

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
			return errors.Wrap(err, "import source image")
		}
		logrus.Infof("imported source image %s", source)
	} else {
		sourceNamed, err := docker.ParseDockerRef(opt.Source)
		if err != nil {
			return errors.Wrap(err, "parse source reference")
		}
		source = sourceNamed.String()

		if useStream {
			// 流式传输模式：只获取最小必要的信息（清单和索引）
			// 统计一下这一段时间
			start := time.Now()
			logrus.Infof("获取镜像 %s 的基本信息", source)
			if err := pvd.FetchImageInfo(ctx, source); err != nil {
				if errdefs.NeedsRetryWithHTTP(err) {
					setHTTPMode()
					if err := pvd.FetchImageInfo(ctx, source); err != nil {
						return errors.Wrap(err, "获取镜像信息失败")
					}
				} else {
					return errors.Wrap(err, "获取镜像信息失败")
				}
			}
			elapsed := time.Since(start)
			logrus.Infof("获取镜像 %s 的基本信息耗时: %s", source, elapsed)
			logrus.Infof("成功获取镜像 %s 的基本信息", source)
		} else {
			// 传统模式：拉取全部数据
			logrus.Infof("拉取源镜像 %s", source)
			if err := pvd.Pull(ctx, source); err != nil {
				if errdefs.NeedsRetryWithHTTP(err) {
					setHTTPMode()
					if err := pvd.Pull(ctx, source); err != nil {
						return errors.Wrap(err, "拉取镜像失败")
					}
				} else {
					return errors.Wrap(err, "拉取源镜像")
				}
			}
			logrus.Infof("已完成拉取源镜像 %s", source)
		}
	}

	targetNamed, err := docker.ParseDockerRef(opt.Target)
	if err != nil {
		return errors.Wrap(err, "parse target reference")
	}
	target := targetNamed.String()

	// 先获取源镜像的索引信息
	sourceImage, err := pvd.Image(ctx, source)
	if err != nil {
		return errors.Wrap(err, "find image from store")
	}

	// 获取所有平台的清单
	sourceDescs, err := utils.GetManifests(ctx, pvd.ContentStore(), *sourceImage, platformMC)
	if err != nil {
		return errors.Wrap(err, "get image manifests")
	}
	targetDescs := make([]ocispec.Descriptor, len(sourceDescs))

	// 如果启用了流式传输，使用流式传输模式
	if useStream && !isLocalSource {
		logrus.Info("开始流式传输镜像")

		// 为源准备解析器
		sourceResolver, err := pvd.Resolver(opt.Source)
		if err != nil {
			return errors.Wrap(err, "get source resolver")
		}

		// 为目标准备解析器
		targetResolver, err := pvd.Resolver(opt.Target)
		if err != nil {
			return errors.Wrap(err, "get target resolver")
		}

		// 在这里添加进度统计
		var successCount int32

		// 为每个平台的清单创建流式传输
		var wg sync.WaitGroup
		errCh := make(chan error, len(sourceDescs))

		// 记录开始时间
		streamStartTime := time.Now()

		for idx, sourceDesc := range sourceDescs {
			wg.Add(1)
			go func(idx int, sourceDesc ocispec.Descriptor) {
				defer wg.Done()

				platformStr := getPlatform(sourceDesc.Platform)
				logrus.Infof("[%s] 开始处理平台清单", platformStr)

				// 创建流式上下文
				streamCtx := newStreamContext(ctx)

				// 获取源镜像的拉取器
				sourceFetcher, err := sourceResolver.Fetcher(streamCtx, source)
				if err != nil {
					errCh <- errors.Wrap(err, "create source fetcher")
					return
				}

				// 获取目标镜像的推送器
				targetPusher, err := targetResolver.Pusher(streamCtx, target)
				if err != nil {
					errCh <- errors.Wrap(err, "create target pusher")
					return
				}

				// 获取清单数据
				logrus.Infof("[%s] 开始流式传输清单 %s", platformStr, sourceDesc.Digest)

				// 读取清单内容
				rc, err := sourceFetcher.Fetch(streamCtx, sourceDesc)
				if err != nil {
					errCh <- errors.Wrap(err, "fetch source manifest")
					return
				}
				defer rc.Close()

				manifestBytes, err := io.ReadAll(rc)
				if err != nil {
					errCh <- errors.Wrap(err, "read source manifest")
					return
				}

				var manifest ocispec.Manifest
				if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
					errCh <- errors.Wrap(err, "unmarshal manifest")
					return
				}

				// 创建一个子错误通道，用于配置和各层的并行处理
				layerErrCh := make(chan error, len(manifest.Layers)+1) // +1 for config

				// 并行处理配置文件和层
				var layerWg sync.WaitGroup

				// 处理配置文件
				layerWg.Add(1)
				go func() {
					defer layerWg.Done()
					logrus.Infof("[%s] 开始流式传输配置文件 %s，大小: %d 字节",
						platformStr, manifest.Config.Digest, manifest.Config.Size)

					// 通过闭包处理HTTP/HTTPS切换逻辑
					handleConfigTransfer := func() error {
						configRC, err := sourceFetcher.Fetch(streamCtx, manifest.Config)
						if err != nil {
							return errors.Wrap(err, "fetch config")
						}
						defer configRC.Close()

						configWriter, err := targetPusher.Push(streamCtx, manifest.Config)
						if err != nil {
							if containerdErrdefs.IsAlreadyExists(err) {
								logrus.Infof("[%s] 配置文件已存在于目标注册表", platformStr)
								return nil
							}

							if errdefs.NeedsRetryWithHTTP(err) {
								logrus.Warn("将目标注册表连接切换为HTTP (config)")
								setHTTPMode()

								// 重新获取解析器
								newResolver, err := pvd.Resolver(opt.Target)
								if err != nil {
									return errors.Wrap(err, "get new resolver for config")
								}
								targetResolver = newResolver

								// 重新获取推送器
								newPusher, err := targetResolver.Pusher(streamCtx, target)
								if err != nil {
									return errors.Wrap(err, "create new pusher for config")
								}
								targetPusher = newPusher

								// 重试
								configWriter, err = targetPusher.Push(streamCtx, manifest.Config)
								if err != nil {
									if containerdErrdefs.IsAlreadyExists(err) {
										logrus.Infof("[%s] 配置文件已存在于目标注册表", platformStr)
										return nil
									}
									return errors.Wrap(err, "push config after HTTP switch")
								}
							} else {
								return errors.Wrap(err, "push config")
							}
						}

						if configWriter != nil {
							if err := trueStreamCopy(streamCtx, configRC, configWriter, manifest.Config.Size, manifest.Config.Digest); err != nil {
								return errors.Wrap(err, "stream copy config")
							}
						}
						return nil
					}

					if err := handleConfigTransfer(); err != nil {
						layerErrCh <- err
					}
				}()

				// 创建一个等待组，用于等待所有层处理完成
				eg, egCtx := errgroup.WithContext(streamCtx)
				eg.SetLimit(provider.LayerConcurrentLimit) // 设置最大并发数

				// 处理每一层
				for i, layer := range manifest.Layers {
					i, layer := i, layer // 避免闭包问题
					eg.Go(func() error {
						logrus.Infof("[%s] 开始流式传输第 %d/%d 层 %s，大小: %d 字节",
							platformStr, i+1, len(manifest.Layers), layer.Digest, layer.Size)

						// 通过闭包处理HTTP/HTTPS切换逻辑
						handleLayerTransfer := func() error {
							layerRC, err := sourceFetcher.Fetch(egCtx, layer)
							if err != nil {
								return errors.Wrap(err, "fetch layer")
							}
							defer layerRC.Close()

							layerWriter, err := targetPusher.Push(egCtx, layer)
							if err != nil {
								if containerdErrdefs.IsAlreadyExists(err) {
									logrus.Infof("[%s] 第 %d/%d 层已存在于目标注册表",
										platformStr, i+1, len(manifest.Layers))
									return nil
								}

								if errdefs.NeedsRetryWithHTTP(err) {
									logrus.Warn("将目标注册表连接切换为HTTP (layer)")
									setHTTPMode()

									// 重新获取解析器和推送器
									newResolver, err := pvd.Resolver(opt.Target)
									if err != nil {
										return errors.Wrap(err, "get new resolver for layer")
									}
									targetResolver = newResolver

									newPusher, err := targetResolver.Pusher(egCtx, target)
									if err != nil {
										return errors.Wrap(err, "create new pusher for layer")
									}
									targetPusher = newPusher

									// 重试
									layerWriter, err = targetPusher.Push(egCtx, layer)
									if err != nil {
										if containerdErrdefs.IsAlreadyExists(err) {
											logrus.Infof("[%s] 第 %d/%d 层已存在于目标注册表",
												platformStr, i+1, len(manifest.Layers))
											return nil
										}
										return errors.Wrap(err, "push layer after HTTP switch")
									}
								} else {
									return errors.Wrap(err, "push layer")
								}
							}

							if layerWriter != nil {
								if err := trueStreamCopy(egCtx, layerRC, layerWriter, layer.Size, layer.Digest); err != nil {
									return errors.Wrap(err, "stream copy layer")
								}
							}

							logrus.Infof("[%s] 完成流式传输第 %d/%d 层", platformStr, i+1, len(manifest.Layers))
							return nil
						}

						return handleLayerTransfer()
					})
				}

				// 等待所有层处理完成
				if err := eg.Wait(); err != nil {
					errCh <- err
					return
				}

				// 检查是否有错误
				select {
				case err := <-layerErrCh:
					errCh <- err
					return
				default:
				}

				// 最后推送清单
				manifestWriter, err := targetPusher.Push(streamCtx, sourceDesc)
				if err != nil {
					if !containerdErrdefs.IsAlreadyExists(err) {
						// 检查是否需要使用HTTP
						if errdefs.NeedsRetryWithHTTP(err) {
							logrus.Warn("将目标注册表连接切换为HTTP (manifest)")
							setHTTPMode()

							// 重新获取解析器
							newResolver, err := pvd.Resolver(opt.Target)
							if err != nil {
								errCh <- errors.Wrap(err, "get new resolver for manifest")
								return
							}
							targetResolver = newResolver

							// 重新获取推送器
							newPusher, err := targetResolver.Pusher(streamCtx, target)
							if err != nil {
								errCh <- errors.Wrap(err, "create new pusher for manifest")
								return
							}
							targetPusher = newPusher

							// 重试
							manifestWriter, err = targetPusher.Push(streamCtx, sourceDesc)
							if err != nil && !containerdErrdefs.IsAlreadyExists(err) {
								errCh <- errors.Wrap(err, "push manifest after HTTP switch")
								return
							}
						} else {
							errCh <- errors.Wrap(err, "push manifest")
							return
						}
					}
				}

				// 如果没有错误或者资源已存在，继续处理
				if manifestWriter != nil {
					if _, err := manifestWriter.Write(manifestBytes); err != nil {
						errCh <- errors.Wrap(err, "write manifest")
						return
					}
					if err := manifestWriter.Commit(streamCtx, sourceDesc.Size, sourceDesc.Digest); err != nil {
						errCh <- errors.Wrap(err, "commit manifest")
						return
					}
				}

				targetDescs[idx] = sourceDesc
				logrus.Infof("[%s] 完成平台清单处理", platformStr)
				atomic.AddInt32(&successCount, 1)
			}(idx, sourceDesc)
		}

		wg.Wait()

		logrus.Infof("已完成 %d/%d 个平台清单的流式传输", successCount, len(sourceDescs))

		// 计算并打印总耗时
		streamElapsed := time.Since(streamStartTime)
		logrus.Infof("流式传输总耗时: %s", streamElapsed)

		// 检查是否有错误
		select {
		case err := <-errCh:
			return err
		default:
		}

		// 如果有多个平台，推送索引
		if len(targetDescs) > 1 && (sourceImage.MediaType == ocispec.MediaTypeImageIndex ||
			sourceImage.MediaType == images.MediaTypeDockerSchema2ManifestList) {

			// 创建一个新的fetch上下文
			indexFetchCtx := newStreamContext(ctx)

			// 获取源索引文件
			indexFetcher, err := sourceResolver.Fetcher(indexFetchCtx, source)
			if err != nil {
				return errors.Wrap(err, "create index fetcher")
			}

			indexRC, err := indexFetcher.Fetch(indexFetchCtx, *sourceImage)
			if err != nil {
				return errors.Wrap(err, "fetch index")
			}
			defer indexRC.Close()

			indexBytes, err := io.ReadAll(indexRC)
			if err != nil {
				return errors.Wrap(err, "read index")
			}

			var index ocispec.Index
			if err := json.Unmarshal(indexBytes, &index); err != nil {
				return errors.Wrap(err, "unmarshal index")
			}

			// 更新索引中的清单引用
			index.Manifests = targetDescs

			// 重新序列化索引
			updatedIndexBytes, err := json.Marshal(index)
			if err != nil {
				return errors.Wrap(err, "marshal updated index")
			}

			// 推送更新后的索引
			indexDesc := *sourceImage
			indexDesc.Size = int64(len(updatedIndexBytes))
			indexDesc.Digest = digest.FromBytes(updatedIndexBytes)

			// 获取索引文件的推送器
			indexPusher, err := targetResolver.Pusher(indexFetchCtx, target)
			if err != nil {
				return errors.Wrap(err, "create index pusher")
			}

			// 处理索引推送
			handleIndexPush := func() error {
				indexWriter, err := indexPusher.Push(indexFetchCtx, indexDesc)
				if err != nil {
					if containerdErrdefs.IsAlreadyExists(err) {
						return nil
					}

					if errdefs.NeedsRetryWithHTTP(err) {
						logrus.Warn("将目标注册表连接切换为HTTP (index)")
						setHTTPMode()

						// 重新获取解析器和推送器
						newResolver, err := pvd.Resolver(opt.Target)
						if err != nil {
							return errors.Wrap(err, "get new index resolver")
						}
						targetResolver = newResolver

						newPusher, err := targetResolver.Pusher(indexFetchCtx, target)
						if err != nil {
							return errors.Wrap(err, "create new index pusher")
						}
						indexPusher = newPusher

						// 重试
						indexWriter, err = indexPusher.Push(indexFetchCtx, indexDesc)
						if err != nil && !containerdErrdefs.IsAlreadyExists(err) {
							return errors.Wrap(err, "push index after HTTP switch")
						}
					} else {
						return errors.Wrap(err, "push index")
					}
				}

				// 如果没有错误或者资源已存在，继续处理
				if indexWriter != nil {
					if _, err := indexWriter.Write(updatedIndexBytes); err != nil {
						return errors.Wrap(err, "write index")
					}
					if err := indexWriter.Commit(indexFetchCtx, indexDesc.Size, indexDesc.Digest); err != nil {
						return errors.Wrap(err, "commit index")
					}
				}
				return nil
			}

			if err := handleIndexPush(); err != nil {
				return err
			}

			logrus.Infof("流式传输镜像索引 %s 已完成", target)
		}

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
						errCh <- errors.Wrap(err, "get resolver")
						continue
					}
					if _targetDesc == nil {
						logrus.WithField("platform", getPlatform(sourceDesc.Platform)).Warnf("%s is not a nydus image", source)
					} else {
						targetDesc = _targetDesc
						store := newStore(pvd.ContentStore(), descs)
						pvd.SetContentStore(store)
					}
				}
				targetDescs[idx] = *targetDesc

				logrus.WithField("platform", getPlatform(sourceDesc.Platform)).Infof("推送目标清单 %s", targetDesc.Digest)
				if err := pvd.Push(ctx, *targetDesc, target); err != nil {
					if errdefs.NeedsRetryWithHTTP(err) {
						setHTTPMode()
						if err := pvd.Push(ctx, *targetDesc, target); err != nil {
							errCh <- errors.Wrap(err, "try to push image manifest")
							continue
						}
					} else {
						errCh <- errors.Wrap(err, "push target image manifest")
						continue
					}
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
			return errors.Wrap(err, "read source manifest list")
		}
		targetIndex.Manifests = targetDescs

		targetImage, err := utils.WriteJSON(ctx, pvd.ContentStore(), targetIndex, *sourceImage, target, nil)
		if err != nil {
			return errors.Wrap(err, "write target manifest list")
		}
		if err := pvd.Push(ctx, *targetImage, target); err != nil {
			if errdefs.NeedsRetryWithHTTP(err) {
				setHTTPMode()
				if err := pvd.Push(ctx, *targetImage, target); err != nil {
					return errors.Wrap(err, "try to push image")
				}
			} else {
				return errors.Wrap(err, "push target image")
			}
		}
		logrus.Infof("推送镜像 %s 已完成", target)
	}

	return nil
}
