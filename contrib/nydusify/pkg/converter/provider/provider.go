// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"sync"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/content/local"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/remotes"
	"github.com/goharbor/acceleration-service/pkg/remote"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Provider struct {
	mutex        sync.Mutex
	usePlainHTTP bool
	images       map[string]*ocispec.Descriptor
	store        content.Store
	hosts        remote.HostFunc
	platformMC   platforms.MatchComparer
}

func New(root string, hosts remote.HostFunc, platformMC platforms.MatchComparer) (*Provider, error) {
	store, err := local.NewLabeledStore(root, newMemoryLabelStore())
	if err != nil {
		return nil, err
	}

	return &Provider{
		images:     make(map[string]*ocispec.Descriptor),
		store:      store,
		hosts:      hosts,
		platformMC: platformMC,
	}, nil
}

func (pvd *Provider) UsePlainHTTP() {
	pvd.usePlainHTTP = true
}

func (pvd *Provider) Resolver(ref string) (remotes.Resolver, error) {
	credFunc, insecure, err := pvd.hosts(ref)
	if err != nil {
		return nil, err
	}
	return remote.NewResolver(insecure, pvd.usePlainHTTP, credFunc), nil
}

func (pvd *Provider) Pull(ctx context.Context, ref string) error {
	resolver, err := pvd.Resolver(ref)
	if err != nil {
		return err
	}
	rc := &containerd.RemoteContext{
		Resolver:        resolver,
		PlatformMatcher: pvd.platformMC,
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
		Resolver:        resolver,
		PlatformMatcher: pvd.platformMC,
	}

	return push(ctx, pvd.store, rc, desc, ref)
}

func (pvd *Provider) Image(ctx context.Context, ref string) (*ocispec.Descriptor, error) {
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
