// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package copier

import (
	"github.com/containerd/containerd/v2/core/content"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func newStore(base content.Store, remotes []ocispec.Descriptor) StreamStore {
	return NewStreamStore(base, remotes)
}
