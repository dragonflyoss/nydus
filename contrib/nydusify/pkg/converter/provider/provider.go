// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"
	"github.com/goharbor/acceleration-service/pkg/cache"
	accelcontent "github.com/goharbor/acceleration-service/pkg/content"
	"github.com/goharbor/acceleration-service/pkg/remote"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
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
	contentDir := filepath.Join(root, "content")
	if err := os.MkdirAll(contentDir, 0755); err != nil {
		return nil, err
	}
	store, err := accelcontent.NewContent(hosts, contentDir, root, "0MB")
	if err != nil {
		return nil, err
	}

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
