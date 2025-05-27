// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package copier

import (
	"context"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type store struct {
	content.Store
	remotes []ocispec.Descriptor
}

func newStore(base content.Store, remotes []ocispec.Descriptor) *store {
	return &store{
		Store:   base,
		remotes: remotes,
	}
}

func (s *store) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
	info, err := s.Store.Info(ctx, dgst)
	if err != nil {
		if !errdefs.IsNotFound(err) {
			return content.Info{}, err
		}
		for _, desc := range s.remotes {
			if desc.Digest == dgst {
				return content.Info{
					Digest: desc.Digest,
					Size:   desc.Size,
				}, nil
			}
		}
		return content.Info{}, err
	}
	return info, nil
}
