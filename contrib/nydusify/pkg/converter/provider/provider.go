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

var LayerConcurrentLimit = 5

type Provider struct {
	mutex        sync.Mutex
	usePlainHTTP bool
	images       map[string]*ocispec.Descriptor
	store        content.Store
	hosts        remote.HostFunc
	platformMC   platforms.MatchComparer
	cacheSize    int
	cacheVersion string
	chunkSize    int64
}

func New(root string, hosts remote.HostFunc, cacheSize uint, cacheVersion string, platformMC platforms.MatchComparer, chunkSize int64) (*Provider, error) {
	// contentDir := filepath.Join(root, "content")
	// if err := os.MkdirAll(contentDir, 0755); err != nil {
	// 	return nil, err
	// }
	// store, err := accelcontent.NewContent(hosts, contentDir, root, "0MB")
	// if err != nil {
	// 	return nil, err
	// }

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

func newDefaultClient(skipTLSVerify bool) *http.Client {
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

func newResolver(insecure, plainHTTP bool, credFunc remote.CredentialFunc, chunkSize int64) remotes.Resolver {
	// 强制记录调试信息
	if plainHTTP {
		logrus.Debugf("创建纯HTTP模式解析器，所有请求将使用HTTP协议")
	} else {
		logrus.Debugf("创建标准HTTPS模式解析器")
	}

	registryHosts := docker.ConfigureDefaultRegistries(
		docker.WithAuthorizer(
			docker.NewDockerAuthorizer(
				docker.WithAuthClient(newDefaultClient(insecure)),
				docker.WithAuthCreds(credFunc),
			),
		),
		docker.WithClient(newDefaultClient(insecure)),
		docker.WithPlainHTTP(func(_ string) (bool, error) {
			// 保证始终返回当前设置的HTTP模式
			return plainHTTP, nil
		}),
		docker.WithChunkSize(chunkSize),
	)

	return docker.NewResolver(docker.ResolverOptions{
		Hosts: registryHosts,
	})
}

func (pvd *Provider) UsePlainHTTP() {
	pvd.mutex.Lock()
	defer pvd.mutex.Unlock()
	if !pvd.usePlainHTTP {
		pvd.usePlainHTTP = true
		logrus.Debug("已设置使用纯HTTP模式，所有后续连接将使用HTTP协议")
	}
}

func (pvd *Provider) Resolver(ref string) (remotes.Resolver, error) {
	credFunc, insecure, err := pvd.hosts(ref)
	if err != nil {
		return nil, err
	}

	// 获取当前HTTP设置状态，避免竞态条件
	pvd.mutex.Lock()
	usePlainHTTP := pvd.usePlainHTTP
	pvd.mutex.Unlock()

	// 使用当前HTTP设置创建解析器
	resolver := newResolver(insecure, usePlainHTTP, credFunc, pvd.chunkSize)

	// 记录当前连接模式
	if usePlainHTTP {
		logrus.Debugf("为 %s 创建了纯HTTP连接解析器", ref)
	} else {
		logrus.Debugf("为 %s 创建了标准HTTPS连接解析器", ref)
	}

	return resolver, nil
}

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
		return "", errors.New("incorrect tarball format")
	}
	image := images[0]

	pvd.mutex.Lock()
	defer pvd.mutex.Unlock()
	pvd.images[image.Name] = &image.Target

	return image.Name, nil
}

func (pvd *Provider) Export(ctx context.Context, writer io.Writer, img *ocispec.Descriptor, name string) error {
	opts := []archive.ExportOpt{archive.WithManifest(*img, name), archive.WithPlatform(pvd.platformMC)}
	return archive.Export(ctx, pvd.store, writer, opts...)
}

func (pvd *Provider) Image(_ context.Context, ref string) (*ocispec.Descriptor, error) {
	pvd.mutex.Lock()
	defer pvd.mutex.Unlock()
	if desc, ok := pvd.images[ref]; ok {
		return desc, nil
	}
	return nil, errdefs.ErrNotFound
}

func (pvd *Provider) ContentStore() content.Store {
	return pvd.store
}

func (pvd *Provider) SetContentStore(store content.Store) {
	pvd.store = store
}

func (pvd *Provider) NewRemoteCache(ctx context.Context, ref string) (context.Context, *cache.RemoteCache) {
	if ref != "" {
		return cache.New(ctx, ref, "", pvd.cacheSize, pvd)
	}
	return ctx, nil
}

// FetchImageInfo fetches basic image information without downloading all content
func (pvd *Provider) FetchImageInfo(ctx context.Context, ref string) error {
	resolver, err := pvd.Resolver(ref)
	if err != nil {
		return err
	}

	name, desc, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return errors.Wrap(err, "resolve reference")
	}

	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return errors.Wrap(err, "create fetcher")
	}

	// 获取并存储顶层索引/清单
	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return errors.Wrap(err, "fetch descriptor")
	}
	defer rc.Close()

	// 读取内容
	data, err := io.ReadAll(rc)
	if err != nil {
		return errors.Wrap(err, "read descriptor content")
	}

	// 将内容写入内容存储
	if err := content.WriteBlob(ctx, pvd.store, desc.Digest.String(), bytes.NewReader(data), desc); err != nil {
		return errors.Wrap(err, "write descriptor content")
	}

	// 如果是索引类型，还需要获取其中的清单
	if desc.MediaType == ocispec.MediaTypeImageIndex || desc.MediaType == "application/vnd.docker.distribution.manifest.list.v2+json" {
		var index ocispec.Index
		if err := json.Unmarshal(data, &index); err != nil {
			return errors.Wrap(err, "unmarshal index")
		}

		// 获取每个清单
		for _, manifestDesc := range index.Manifests {
			rc, err := fetcher.Fetch(ctx, manifestDesc)
			if err != nil {
				return errors.Wrap(err, "fetch manifest")
			}

			manifestData, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return errors.Wrap(err, "read manifest")
			}

			if err := content.WriteBlob(ctx, pvd.store, manifestDesc.Digest.String(), bytes.NewReader(manifestData), manifestDesc); err != nil {
				return errors.Wrap(err, "write manifest")
			}

			// 解析清单获取配置描述符
			var manifest ocispec.Manifest
			if err := json.Unmarshal(manifestData, &manifest); err != nil {
				return errors.Wrap(err, "unmarshal manifest")
			}

			// 获取配置
			rc, err = fetcher.Fetch(ctx, manifest.Config)
			if err != nil {
				return errors.Wrap(err, "fetch config")
			}

			configData, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return errors.Wrap(err, "read config")
			}

			if err := content.WriteBlob(ctx, pvd.store, manifest.Config.Digest.String(), bytes.NewReader(configData), manifest.Config); err != nil {
				return errors.Wrap(err, "write config")
			}
		}
	} else if desc.MediaType == ocispec.MediaTypeImageManifest || desc.MediaType == "application/vnd.docker.distribution.manifest.v2+json" {
		// 对于单一清单，获取配置
		var manifest ocispec.Manifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			return errors.Wrap(err, "unmarshal manifest")
		}

		// 获取配置
		rc, err := fetcher.Fetch(ctx, manifest.Config)
		if err != nil {
			return errors.Wrap(err, "fetch config")
		}

		configData, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return errors.Wrap(err, "read config")
		}

		if err := content.WriteBlob(ctx, pvd.store, manifest.Config.Digest.String(), bytes.NewReader(configData), manifest.Config); err != nil {
			return errors.Wrap(err, "write config")
		}
	}

	// 存储镜像描述符
	pvd.mutex.Lock()
	defer pvd.mutex.Unlock()
	pvd.images[ref] = &desc

	return nil
}
