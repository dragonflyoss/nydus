// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images/archive"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/goharbor/acceleration-service/pkg/cache"
	accelcontent "github.com/goharbor/acceleration-service/pkg/content"
	"github.com/goharbor/acceleration-service/pkg/remote"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var LayerConcurrentLimit = 5

type Provider struct {
	mutex          sync.Mutex
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

func New(root string, hosts remote.HostFunc, cacheSize uint, cacheVersion string, platformMC platforms.MatchComparer, chunkSize int64) (*Provider, error) {
	contentDir := filepath.Join(root, "content")
	if err := os.MkdirAll(contentDir, 0755); err != nil {
		return nil, err
	}
	store, err := accelcontent.NewContent(hosts, contentDir, root, "0MB")
	if err != nil {
		return nil, err
	}

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
	registryHosts := docker.ConfigureDefaultRegistries(
		docker.WithAuthorizer(
			docker.NewDockerAuthorizer(
				docker.WithAuthClient(newDefaultClient(insecure)),
				docker.WithAuthCreds(credFunc),
			),
		),
		docker.WithClient(newDefaultClient(insecure)),
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
	pvd.usePlainHTTP = true
}

func (pvd *Provider) Resolver(ref string) (remotes.Resolver, error) {
	credFunc, insecure, err := pvd.hosts(ref)
	if err != nil {
		return nil, err
	}
	return newResolver(insecure, pvd.usePlainHTTP, credFunc, pvd.chunkSize), nil
}

func (pvd *Provider) Pull(ctx context.Context, ref string) error {
	resolver, err := pvd.Resolver(ref)
	if err != nil {
		return err
	}
	rc := &client.RemoteContext{
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

// SetPushRetryConfig sets the retry configuration for push operations
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
	rc := &client.RemoteContext{
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
