/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package remote provides a content store and resolver for pulling and pushing
// images from remote registries.
package remote

import (
	"context"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
)

// fetch resolves ref and downloads the whole image (index/manifests/config/
// layers) for the platforms matched by platformMC into store. It returns the
// resolved root descriptor.
//
// Adapted from containerd's client pull flow.
func fetch(ctx context.Context, store content.Store, resolver remotes.Resolver, ref string, platformMC platforms.MatchComparer) (ocispec.Descriptor, error) {
	name, desc, err := resolver.Resolve(ctx, ref)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrapf(err, "resolve %q", ref)
	}

	fetcher, err := resolver.Fetcher(ctx, name)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrapf(err, "get fetcher for %q", name)
	}

	if desc.MediaType == images.MediaTypeDockerSchema1Manifest {
		return ocispec.Descriptor{}, errors.Wrap(errdefs.ErrNotImplemented, "docker schema1 manifests are not supported")
	}

	childrenHandler := images.ChildrenHandler(store)
	childrenHandler = images.FilterPlatforms(childrenHandler, platformMC)

	appendDistSrc, err := docker.AppendDistributionSourceLabel(store, ref)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "build distribution source label handler")
	}

	handler := images.Handlers(
		fetchHandler(store, fetcher),
		childrenHandler,
		appendDistSrc,
	)

	if err := images.Dispatch(ctx, handler, nil, desc); err != nil {
		return ocispec.Descriptor{}, errors.Wrapf(err, "fetch %q", ref)
	}
	return desc, nil
}

func fetchHandler(ingester content.Ingester, fetcher remotes.Fetcher) images.HandlerFunc {
	return func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if desc.MediaType == images.MediaTypeDockerSchema1Manifest {
			return nil, errors.Errorf("%v not supported", desc.MediaType)
		}
		err := remotes.Fetch(ctx, ingester, fetcher, desc)
		if errdefs.IsAlreadyExists(err) {
			return nil, nil
		}
		return nil, err
	}
}

// push uploads desc and all of its content from store to the registry under
// ref.
//
// Adapted from containerd's client push flow.
func push(ctx context.Context, store content.Store, resolver remotes.Resolver, desc ocispec.Descriptor, ref string, platformMC platforms.MatchComparer) error {
	pushRef := ref
	if pushRef == "" {
		return errors.New("empty push reference")
	}
	pusher, err := resolver.Pusher(ctx, pushRef)
	if err != nil {
		return errors.Wrapf(err, "create pusher for %q", pushRef)
	}
	return remotes.PushContent(ctx, pusher, desc, store, nil, platformMC, nil)
}
