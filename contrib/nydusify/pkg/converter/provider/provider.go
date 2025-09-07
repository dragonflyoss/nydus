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
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/images/archive"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/goharbor/acceleration-service/pkg/cache"
	"github.com/goharbor/acceleration-service/pkg/remote"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var LayerConcurrentLimit = 4

type Provider struct {
	mutex          sync.RWMutex
	usePlainHTTP   bool
	images         map[string]*ocispec.Descriptor
	store          content.Store
	hosts          remote.HostFunc
	platformMC     platforms.MatchComparer
	cacheSize      int
	cacheVersion   string
	chunkSize      int64
	pushRetryCount int
	pushRetryDelay time.Duration
}

func New(_ string, hosts remote.HostFunc, cacheSize uint, cacheVersion string, platformMC platforms.MatchComparer, chunkSize int64) (*Provider, error) {
	store := NewMemoryContentStore()

	return &Provider{
		images:         make(map[string]*ocispec.Descriptor),
		store:          store,
		hosts:          hosts,
		cacheSize:      int(cacheSize),
		platformMC:     platformMC,
		cacheVersion:   cacheVersion,
		chunkSize:      chunkSize,
		pushRetryCount: 3,
		pushRetryDelay: 5 * time.Second,
	}, nil
}

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

func newResolver(insecure, plainHTTP bool, credFunc remote.CredentialFunc, chunkSize int64) remotes.Resolver {
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		if plainHTTP {
			logrus.Debugf("create plain HTTP resolver")
		} else {
			logrus.Debugf("create HTTPS resolver")
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

func (pvd *Provider) UsePlainHTTP() {
	pvd.mutex.Lock()
	defer pvd.mutex.Unlock()

	if !pvd.usePlainHTTP {
		pvd.usePlainHTTP = true
	}
}

func (pvd *Provider) Resolver(ref string) (remotes.Resolver, error) {
	credFunc, insecure, err := pvd.hosts(ref)
	if err != nil {
		return nil, err
	}

	pvd.mutex.RLock()
	usePlainHTTP := pvd.usePlainHTTP
	pvd.mutex.RUnlock()

	resolver := newResolver(insecure, usePlainHTTP, credFunc, pvd.chunkSize)

	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		if usePlainHTTP {
			logrus.Debugf("create HTTP resolver for %s", ref)
		} else {
			logrus.Debugf("create HTTPS resolver for %s", ref)
		}
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

func (pvd *Provider) SetPushRetryConfig(count int, delay time.Duration) {
	pvd.mutex.Lock()
	defer pvd.mutex.Unlock()
	pvd.pushRetryCount = count
	pvd.pushRetryDelay = delay
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

	err = utils.WithRetry(func() error {
		return push(ctx, pvd.store, rc, desc, ref)
	}, pvd.pushRetryCount, pvd.pushRetryDelay)

	if err != nil {
		logrus.WithError(err).Error("Push failed after all attempts")
	}

	return err
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
		return "", errors.New("invalid tar format")
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
	pvd.mutex.RLock()
	defer pvd.mutex.RUnlock()

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

func (pvd *Provider) FetchImageInfo(ctx context.Context, ref string) error {
	resolver, err := pvd.Resolver(ref)
	if err != nil {
		return errors.Wrap(err, "create resolver")
	}

	name, desc, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return errors.Wrap(err, "resolve reference")
	}

	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return errors.Wrap(err, "create fetcher")
	}

	rc, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return errors.Wrap(err, "fetch descriptor")
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return errors.Wrap(err, "read descriptor content")
	}

	if err := content.WriteBlob(ctx, pvd.store, desc.Digest.String(), bytes.NewReader(data), desc); err != nil {
		return errors.Wrap(err, "write descriptor content")
	}

	if err := pvd.fetchDescriptorChildren(ctx, fetcher, data, desc); err != nil {
		return err
	}

	pvd.mutex.Lock()
	defer pvd.mutex.Unlock()
	pvd.images[ref] = &desc

	return nil
}

func (pvd *Provider) fetchDescriptorChildren(ctx context.Context, fetcher remotes.Fetcher, data []byte, desc ocispec.Descriptor) error {
	switch desc.MediaType {
	case ocispec.MediaTypeImageIndex, images.MediaTypeDockerSchema2ManifestList:
		var index ocispec.Index
		if err := json.Unmarshal(data, &index); err != nil {
			return errors.Wrap(err, "unmarshal index")
		}

		for _, manifestDesc := range index.Manifests {
			if err := pvd.fetchManifest(ctx, fetcher, manifestDesc); err != nil {
				return err
			}
		}
	case ocispec.MediaTypeImageManifest, images.MediaTypeDockerSchema2Manifest:
		return pvd.processManifest(ctx, fetcher, data)
	}
	return nil
}

func (pvd *Provider) fetchManifest(ctx context.Context, fetcher remotes.Fetcher, manifestDesc ocispec.Descriptor) error {
	rc, err := fetcher.Fetch(ctx, manifestDesc)
	if err != nil {
		return errors.Wrap(err, "fetch manifest")
	}
	defer rc.Close()

	manifestData, err := io.ReadAll(rc)
	if err != nil {
		return errors.Wrap(err, "read manifest")
	}

	if err := content.WriteBlob(ctx, pvd.store, manifestDesc.Digest.String(), bytes.NewReader(manifestData), manifestDesc); err != nil {
		return errors.Wrap(err, "write manifest")
	}

	return pvd.processManifest(ctx, fetcher, manifestData)
}

func (pvd *Provider) processManifest(ctx context.Context, fetcher remotes.Fetcher, manifestData []byte) error {
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return errors.Wrap(err, "unmarshal manifest")
	}

	rc, err := fetcher.Fetch(ctx, manifest.Config)
	if err != nil {
		return errors.Wrap(err, "fetch config")
	}
	defer rc.Close()

	configData, err := io.ReadAll(rc)
	if err != nil {
		return errors.Wrap(err, "read config")
	}

	if err := content.WriteBlob(ctx, pvd.store, manifest.Config.Digest.String(), bytes.NewReader(configData), manifest.Config); err != nil {
		return errors.Wrap(err, "write config")
	}

	return nil
}
