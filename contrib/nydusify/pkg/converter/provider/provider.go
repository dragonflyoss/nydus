// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images/archive"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/goharbor/acceleration-service/pkg/cache"
	"github.com/goharbor/acceleration-service/pkg/remote"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// LayerConcurrentLimit 控制并发层处理数量
var LayerConcurrentLimit = 4

// Provider 提供镜像内容的存储和操作能力
type Provider struct {
	mutex        sync.RWMutex // 保护状态的读写锁
	usePlainHTTP bool         // 是否使用纯HTTP模式
	images       map[string]*ocispec.Descriptor
	store        content.Store           // 内容存储
	hosts        remote.HostFunc         // 主机配置函数
	platformMC   platforms.MatchComparer // 平台匹配器
	cacheSize    int                     // 缓存大小
	cacheVersion string                  // 缓存版本
	chunkSize    int64                   // 传输块大小
}

// New 创建一个新的Provider实例
func New(root string, hosts remote.HostFunc, cacheSize uint, cacheVersion string, platformMC platforms.MatchComparer, chunkSize int64) (*Provider, error) {
	// 使用内存内容存储
	store := NewMemoryContentStore()

	return &Provider{
		images:       make(map[string]*ocispec.Descriptor),
		store:        store,
		hosts:        hosts,
		cacheSize:    int(cacheSize),
		platformMC:   platformMC,
		cacheVersion: cacheVersion,
		chunkSize:    chunkSize,
	}, nil
}

// newHTTPClient 创建HTTP客户端，支持配置TLS验证
func newHTTPClient(skipTLSVerify bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
			DisableKeepAlives:     true,
			TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipTLSVerify,
			},
		},
	}
}

// newResolver 创建远程内容解析器
func newResolver(insecure, plainHTTP bool, credFunc remote.CredentialFunc, chunkSize int64) remotes.Resolver {
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		if plainHTTP {
			logrus.Debugf("创建纯HTTP模式解析器")
		} else {
			logrus.Debugf("创建标准HTTPS模式解析器")
		}
	}

	registryHosts := docker.ConfigureDefaultRegistries(
		docker.WithAuthorizer(
			docker.NewDockerAuthorizer(
				docker.WithAuthClient(newHTTPClient(insecure)),
				docker.WithAuthCreds(credFunc),
			),
		),
		docker.WithClient(newHTTPClient(insecure)),
		docker.WithPlainHTTP(func(_ string) (bool, error) {
			return plainHTTP, nil
		}),
		docker.WithChunkSize(chunkSize),
	)

	return docker.NewResolver(docker.ResolverOptions{
		Hosts: registryHosts,
	})
}

// UsePlainHTTP 设置使用纯HTTP模式进行传输
func (pvd *Provider) UsePlainHTTP() {
	pvd.mutex.Lock()
	defer pvd.mutex.Unlock()

	if !pvd.usePlainHTTP {
		pvd.usePlainHTTP = true
		logrus.Info("已切换至HTTP模式，所有后续连接将使用HTTP协议")
	}
}

// Resolver 获取指定引用的解析器
func (pvd *Provider) Resolver(ref string) (remotes.Resolver, error) {
	credFunc, insecure, err := pvd.hosts(ref)
	if err != nil {
		return nil, err
	}

	// 获取当前HTTP设置状态
	pvd.mutex.RLock()
	usePlainHTTP := pvd.usePlainHTTP
	pvd.mutex.RUnlock()

	resolver := newResolver(insecure, usePlainHTTP, credFunc, pvd.chunkSize)

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		if usePlainHTTP {
			logrus.Debugf("为 %s 创建了HTTP连接解析器", ref)
		} else {
			logrus.Debugf("为 %s 创建了HTTPS连接解析器", ref)
		}
	}

	return resolver, nil
}

// Pull 拉取指定引用的镜像
func (pvd *Provider) Pull(ctx context.Context, ref string) error {
	resolver, err := pvd.Resolver(ref)
	if err != nil {
		return err
	}

	rc := &containerd.RemoteContext{
		Resolver:               resolver,
		PlatformMatcher:        pvd.platformMC,
		MaxConcurrentDownloads: LayerConcurrentLimit,
	}

	img, err := fetch(ctx, pvd.store, rc, ref, 0)
	if err != nil {
		return err
	}

	pvd.mutex.Lock()
	defer pvd.mutex.Unlock()
	pvd.images[ref] = &img.Target

	return nil
}

// Push 推送指定的内容描述符到目标引用
func (pvd *Provider) Push(ctx context.Context, desc ocispec.Descriptor, ref string) error {
	resolver, err := pvd.Resolver(ref)
	if err != nil {
		return err
	}

	rc := &containerd.RemoteContext{
		Resolver:                    resolver,
		PlatformMatcher:             pvd.platformMC,
		MaxConcurrentUploadedLayers: LayerConcurrentLimit,
	}

	return push(ctx, pvd.store, rc, desc, ref)
}

// Import 从读取器导入镜像
func (pvd *Provider) Import(ctx context.Context, reader io.Reader) (string, error) {
	iopts := importOpts{
		dgstRefT: func(dgst digest.Digest) string {
			return "nydus" + "@" + dgst.String()
		},
		skipDgstRef:     func(name string) bool { return name != "" },
		platformMatcher: pvd.platformMC,
	}

	images, err := load(ctx, reader, pvd.store, iopts)
	if err != nil {
		return "", err
	}

	if len(images) != 1 {
		return "", errors.New("不正确的tar包格式")
	}
	image := images[0]

	pvd.mutex.Lock()
	defer pvd.mutex.Unlock()
	pvd.images[image.Name] = &image.Target

	return image.Name, nil
}

// Export 导出镜像到写入器
func (pvd *Provider) Export(ctx context.Context, writer io.Writer, img *ocispec.Descriptor, name string) error {
	opts := []archive.ExportOpt{archive.WithManifest(*img, name), archive.WithPlatform(pvd.platformMC)}
	return archive.Export(ctx, pvd.store, writer, opts...)
}

// Image 获取指定引用的镜像描述符
func (pvd *Provider) Image(_ context.Context, ref string) (*ocispec.Descriptor, error) {
	pvd.mutex.RLock()
	defer pvd.mutex.RUnlock()

	if desc, ok := pvd.images[ref]; ok {
		return desc, nil
	}
	return nil, errdefs.ErrNotFound
}

// ContentStore 获取内容存储
func (pvd *Provider) ContentStore() content.Store {
	return pvd.store
}

// SetContentStore 设置内容存储
func (pvd *Provider) SetContentStore(store content.Store) {
	pvd.store = store
}

// NewRemoteCache 创建远程缓存
func (pvd *Provider) NewRemoteCache(ctx context.Context, ref string) (context.Context, *cache.RemoteCache) {
	if ref != "" {
		return cache.New(ctx, ref, "", pvd.cacheSize, pvd)
	}
	return ctx, nil
}

// FetchImageInfo 仅获取镜像基本信息而不下载全部内容
func (pvd *Provider) FetchImageInfo(ctx context.Context, ref string) error {
	resolver, err := pvd.Resolver(ref)
	if err != nil {
		return err
	}

	// 解析引用获取描述符
	name, desc, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return errors.Wrap(err, "解析引用")
	}

	// 创建拉取器
	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return errors.Wrap(err, "创建拉取器")
	}

	// 获取顶层索引/清单
	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return errors.Wrap(err, "获取描述符")
	}
	defer rc.Close()

	// 读取内容
	data, err := io.ReadAll(rc)
	if err != nil {
		return errors.Wrap(err, "读取描述符内容")
	}

	// 将内容写入存储
	if err := content.WriteBlob(ctx, pvd.store, desc.Digest.String(), bytes.NewReader(data), desc); err != nil {
		return errors.Wrap(err, "写入描述符内容")
	}

	// 处理索引和清单
	if err := pvd.fetchDescriptorChildren(ctx, fetcher, data, desc); err != nil {
		return err
	}

	// 存储镜像描述符
	pvd.mutex.Lock()
	defer pvd.mutex.Unlock()
	pvd.images[ref] = &desc

	return nil
}

// fetchDescriptorChildren 获取描述符的子内容（如清单和配置）
func (pvd *Provider) fetchDescriptorChildren(ctx context.Context, fetcher remotes.Fetcher, data []byte, desc ocispec.Descriptor) error {
	// 如果是索引类型，获取其中的清单
	if desc.MediaType == ocispec.MediaTypeImageIndex || desc.MediaType == "application/vnd.docker.distribution.manifest.list.v2+json" {
		var index ocispec.Index
		if err := json.Unmarshal(data, &index); err != nil {
			return errors.Wrap(err, "解析索引")
		}

		// 获取每个清单
		for _, manifestDesc := range index.Manifests {
			if err := pvd.fetchManifest(ctx, fetcher, manifestDesc); err != nil {
				return err
			}
		}
	} else if desc.MediaType == ocispec.MediaTypeImageManifest || desc.MediaType == "application/vnd.docker.distribution.manifest.v2+json" {
		// 对于单一清单，直接处理
		return pvd.processManifest(ctx, fetcher, data)
	}

	return nil
}

// fetchManifest 获取清单及其配置
func (pvd *Provider) fetchManifest(ctx context.Context, fetcher remotes.Fetcher, manifestDesc ocispec.Descriptor) error {
	rc, err := fetcher.Fetch(ctx, manifestDesc)
	if err != nil {
		return errors.Wrap(err, "获取清单")
	}

	manifestData, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return errors.Wrap(err, "读取清单")
	}

	if err := content.WriteBlob(ctx, pvd.store, manifestDesc.Digest.String(), bytes.NewReader(manifestData), manifestDesc); err != nil {
		return errors.Wrap(err, "写入清单")
	}

	return pvd.processManifest(ctx, fetcher, manifestData)
}

// processManifest 处理清单数据，获取配置
func (pvd *Provider) processManifest(ctx context.Context, fetcher remotes.Fetcher, manifestData []byte) error {
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return errors.Wrap(err, "解析清单")
	}

	// 获取配置
	rc, err := fetcher.Fetch(ctx, manifest.Config)
	if err != nil {
		return errors.Wrap(err, "获取配置")
	}

	configData, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		return errors.Wrap(err, "读取配置")
	}

	if err := content.WriteBlob(ctx, pvd.store, manifest.Config.Digest.String(), bytes.NewReader(configData), manifest.Config); err != nil {
		return errors.Wrap(err, "写入配置")
	}

	return nil
}
