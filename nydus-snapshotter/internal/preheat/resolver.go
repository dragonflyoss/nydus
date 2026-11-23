/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

//go:generate mockgen -destination mocks/resolver_mock.go -source resolver.go -package mocks

package preheat

import (
	"context"
	"fmt"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/image-spec/identity"

	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/fs"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/registry"
	"github.com/dragonflyoss/nydus/nydus-snapshotter/internal/snapshot"
)

// Resolver resolves the image a preheat names.
type Resolver interface {
	// Resolve returns the nydus image of a reference containerd has pulled
	// into a namespace: its normalized reference and the bootstrap layer
	// this snapshotter unpacked.
	Resolve(ctx context.Context, namespace, ref string) (*fs.Image, error)
}

// resolver asks containerd for the layers of an image and the snapshotter
// for the bootstrap layer among them, as containerd tells whether an image
// is unpacked, refer to
// https://github.com/containerd/containerd/blob/v2.2.10/client/image.go.
//
//	reference ─▶ image ─▶ diff IDs ─▶ chain IDs ─▶ bootstrap snapshot
//	      containerd                             snapshotter
type resolver struct {
	// addr is containerd's socket.
	addr string

	// snapshotter finds the bootstrap layer.
	snapshotter snapshot.Snapshotter
}

// NewResolver returns a resolver asking the containerd at addr.
func NewResolver(addr string, snapshotter snapshot.Snapshotter) Resolver {
	return &resolver{addr: addr, snapshotter: snapshotter}
}

// Resolve returns the nydus image of a reference containerd has pulled into
// a namespace: its normalized reference and the bootstrap layer this
// snapshotter unpacked.
func (r *resolver) Resolve(ctx context.Context, namespace, ref string) (*fs.Image, error) {
	named, err := registry.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, errdefs.ErrInvalidArgument) //nolint:errorlint // the cause is named, only the class is wrapped
	}

	// A preheat is rare, so the connection lives for one request, as the
	// installer's check of containerd does.
	client, err := containerd.New(r.addr)
	if err != nil {
		return nil, fmt.Errorf("connect to containerd at %s: %v: %w", r.addr, err, errdefs.ErrUnavailable) //nolint:errorlint // the cause is named, only the class is wrapped
	}
	defer client.Close()

	// The namespace is set on the context: the client's default is skipped
	// when the incoming request carries a namespace, which is not forwarded
	// to containerd.
	ctx = namespaces.WithNamespace(ctx, namespace)
	image, err := client.GetImage(ctx, named.Name)
	if err != nil {
		return nil, fmt.Errorf("get image %s in namespace %s: %w", named.Name, namespace, err)
	}

	diffIDs, err := image.RootFS(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the layers of image %s: %w", named.Name, err)
	}

	digests := identity.ChainIDs(diffIDs)
	chainIDs := make([]string, 0, len(digests))
	for _, d := range digests {
		chainIDs = append(chainIDs, d.String())
	}

	nydusImage, err := r.snapshotter.NydusImage(ctx, chainIDs)
	if errdefs.IsNotFound(err) {
		return nil, fmt.Errorf("image %s is not a nydus image this snapshotter unpacked: %w", named.Name, errdefs.ErrFailedPrecondition)
	}

	if err != nil {
		return nil, err
	}
	nydusImage.Ref = named.Name

	return nydusImage, nil
}
