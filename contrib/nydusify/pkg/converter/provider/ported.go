// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/archive"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sync/semaphore"
)

type importOpts struct {
	indexName       string
	imageRefT       func(string) string
	dgstRefT        func(digest.Digest) string
	skipDgstRef     func(string) bool
	platformMatcher platforms.MatchComparer
	compress        bool
	discardLayers   bool
	skipMissing     bool
	imageLabels     map[string]string
}

// Ported from containerd project, copyright The containerd Authors.
// github.com/containerd/containerd/blob/main/client/pull.go
func fetch(ctx context.Context, store content.Store, rCtx *client.RemoteContext, ref string, limit int) (images.Image, error) {
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

	if desc.MediaType == images.MediaTypeDockerSchema1Manifest {
		return images.Image{}, fmt.Errorf("%w: media type %q is no longer supported since containerd v2.1, please rebuild the image as %q or %q",
			errdefs.ErrNotImplemented,
			images.MediaTypeDockerSchema1Manifest, images.MediaTypeDockerSchema2Manifest, ocispec.MediaTypeImageManifest)
	}
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
// github.com/containerd/containerd/blob/main/client/client.go
func push(ctx context.Context, store content.Store, pushCtx *client.RemoteContext, desc ocispec.Descriptor, ref string) error {
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

// Ported from containerd project, copyright The containerd Authors.
// github.com/containerd/containerd/blob/main/client/import.go
func load(ctx context.Context, reader io.Reader, store content.Store, iopts importOpts) ([]images.Image, error) {
	var aio []archive.ImportOpt
	if iopts.compress {
		aio = append(aio, archive.WithImportCompression())
	}

	index, err := archive.ImportIndex(ctx, store, reader, aio...)
	if err != nil {
		return nil, err
	}

	var imgs []images.Image

	if iopts.indexName != "" {
		imgs = append(imgs, images.Image{
			Name:   iopts.indexName,
			Target: index,
		})
	}
	var platformMatcher = iopts.platformMatcher

	var handler images.HandlerFunc = func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		// Only save images at top level
		if desc.Digest != index.Digest {
			// Don't set labels on missing content.
			children, err := images.Children(ctx, store, desc)
			if iopts.skipMissing && errdefs.IsNotFound(err) {
				return nil, images.ErrSkipDesc
			}
			return children, err
		}

		var idx ocispec.Index
		p, err := content.ReadBlob(ctx, store, desc)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(p, &idx); err != nil {
			return nil, err
		}

		for _, m := range idx.Manifests {
			name := imageName(m.Annotations, iopts.imageRefT)
			if name != "" {
				imgs = append(imgs, images.Image{
					Name:   name,
					Target: m,
				})
			}
			if iopts.skipDgstRef != nil {
				if iopts.skipDgstRef(name) {
					continue
				}
			}
			if iopts.dgstRefT != nil {
				ref := iopts.dgstRefT(m.Digest)
				if ref != "" {
					imgs = append(imgs, images.Image{
						Name:   ref,
						Target: m,
					})
				}
			}
		}

		return idx.Manifests, nil
	}

	handler = images.FilterPlatforms(handler, platformMatcher)
	if iopts.discardLayers {
		handler = images.SetChildrenMappedLabels(store, handler, images.ChildGCLabelsFilterLayers)
	} else {
		handler = images.SetChildrenLabels(store, handler)
	}
	if err := images.WalkNotEmpty(ctx, handler, index); err != nil {
		return nil, err
	}

	for i := range imgs {
		if iopts.imageLabels != nil {
			imgs[i].Labels = iopts.imageLabels
		}
	}

	return imgs, nil
}

func imageName(annotations map[string]string, ociCleanup func(string) string) string {
	name := annotations[images.AnnotationImageName]
	if name != "" {
		return name
	}
	name = annotations[ocispec.AnnotationRefName]
	if name != "" {
		if ociCleanup != nil {
			name = ociCleanup(name)
		}
	}
	return name
}
