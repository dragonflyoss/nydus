// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/remotes"
	"github.com/containerd/containerd/remotes/docker"

	// nolint:staticcheck
	"github.com/containerd/containerd/remotes/docker/schema1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/semaphore"
)

// Ported from containerd project, copyright The containerd Authors.
// github.com/containerd/containerd/blob/main/pull.go
func fetch(ctx context.Context, store content.Store, rCtx *containerd.RemoteContext, ref string, limit int) (images.Image, error) {
	name, desc, err := rCtx.Resolver.Resolve(ctx, ref)
	if err != nil {
		return images.Image{}, fmt.Errorf("failed to resolve reference %q: %w", ref, err)
	}

	fetcher, err := rCtx.Resolver.Fetcher(ctx, name)
	if err != nil {
		return images.Image{}, fmt.Errorf("failed to get fetcher for %q: %w", name, err)
	}

	var (
		handler images.Handler

		isConvertible bool
		converterFunc func(context.Context, ocispec.Descriptor) (ocispec.Descriptor, error)
		limiter       *semaphore.Weighted
	)

	// nolint:staticcheck
	if desc.MediaType == images.MediaTypeDockerSchema1Manifest && rCtx.ConvertSchema1 {
		schema1Converter := schema1.NewConverter(store, fetcher)

		handler = images.Handlers(append(rCtx.BaseHandlers, schema1Converter)...)

		isConvertible = true

		converterFunc = func(ctx context.Context, _ ocispec.Descriptor) (ocispec.Descriptor, error) {
			return schema1Converter.Convert(ctx)
		}
	} else {
		// Get all the children for a descriptor
		childrenHandler := images.ChildrenHandler(store)
		// Set any children labels for that content
		childrenHandler = images.SetChildrenMappedLabels(store, childrenHandler, rCtx.ChildLabelMap)
		if rCtx.AllMetadata {
			// Filter manifests by platforms but allow to handle manifest
			// and configuration for not-target platforms
			childrenHandler = remotes.FilterManifestByPlatformHandler(childrenHandler, rCtx.PlatformMatcher)
		} else {
			// Filter children by platforms if specified.
			childrenHandler = images.FilterPlatforms(childrenHandler, rCtx.PlatformMatcher)
		}
		// Sort and limit manifests if a finite number is needed
		if limit > 0 {
			childrenHandler = images.LimitManifests(childrenHandler, rCtx.PlatformMatcher, limit)
		}

		// set isConvertible to true if there is application/octet-stream media type
		convertibleHandler := images.HandlerFunc(
			func(_ context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
				if desc.MediaType == docker.LegacyConfigMediaType {
					isConvertible = true
				}

				return []ocispec.Descriptor{}, nil
			},
		)

		appendDistSrcLabelHandler, err := docker.AppendDistributionSourceLabel(store, ref)
		if err != nil {
			return images.Image{}, err
		}

		handlers := append(rCtx.BaseHandlers,
			remotes.FetchHandler(store, fetcher),
			convertibleHandler,
			childrenHandler,
			appendDistSrcLabelHandler,
		)

		handler = images.Handlers(handlers...)

		converterFunc = func(ctx context.Context, desc ocispec.Descriptor) (ocispec.Descriptor, error) {
			return docker.ConvertManifest(ctx, store, desc)
		}
	}

	if rCtx.HandlerWrapper != nil {
		handler = rCtx.HandlerWrapper(handler)
	}

	if rCtx.MaxConcurrentDownloads > 0 {
		limiter = semaphore.NewWeighted(int64(rCtx.MaxConcurrentDownloads))
	}

	if err := images.Dispatch(ctx, handler, limiter, desc); err != nil {
		return images.Image{}, err
	}

	if isConvertible {
		if desc, err = converterFunc(ctx, desc); err != nil {
			return images.Image{}, err
		}
	}

	return images.Image{
		Name:   name,
		Target: desc,
		Labels: rCtx.Labels,
	}, nil
}

// Ported from containerd project, copyright The containerd Authors.
// github.com/containerd/containerd/blob/main/client.go
func push(ctx context.Context, store content.Store, pushCtx *containerd.RemoteContext, desc ocispec.Descriptor, ref string) error {
	if pushCtx.PlatformMatcher == nil {
		if len(pushCtx.Platforms) > 0 {
			var ps []ocispec.Platform
			for _, platform := range pushCtx.Platforms {
				p, err := platforms.Parse(platform)
				if err != nil {
					return fmt.Errorf("invalid platform %s: %w", platform, err)
				}
				ps = append(ps, p)
			}
			pushCtx.PlatformMatcher = platforms.Any(ps...)
		} else {
			pushCtx.PlatformMatcher = platforms.All
		}
	}

	// Annotate ref with digest to push only push tag for single digest
	if !strings.Contains(ref, "@") {
		ref = ref + "@" + desc.Digest.String()
	}

	pusher, err := pushCtx.Resolver.Pusher(ctx, ref)
	if err != nil {
		return err
	}

	var wrapper func(images.Handler) images.Handler

	if len(pushCtx.BaseHandlers) > 0 {
		wrapper = func(h images.Handler) images.Handler {
			h = images.Handlers(append(pushCtx.BaseHandlers, h)...)
			if pushCtx.HandlerWrapper != nil {
				h = pushCtx.HandlerWrapper(h)
			}
			return h
		}
	} else if pushCtx.HandlerWrapper != nil {
		wrapper = pushCtx.HandlerWrapper
	}

	var limiter *semaphore.Weighted
	if pushCtx.MaxConcurrentUploadedLayers > 0 {
		limiter = semaphore.NewWeighted(int64(pushCtx.MaxConcurrentUploadedLayers))
	}

	return remotes.PushContent(ctx, pusher, desc, store, limiter, pushCtx.PlatformMatcher, wrapper)
}
