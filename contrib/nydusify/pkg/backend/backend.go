// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"fmt"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Backend transers artifacts generated during image conversion to a backend storage such as:
//		1. registry: complying to OCI distribution specification, push blob file
//		   to registry and use the registry as a storage.
//		2. oss: A object storage backend, which uses its SDK to transer blob file.
type Backend interface {
	// TODO: Hopefully, we can pass `Layer` struct in, thus to be able to cook both
	// file handle and file path.
	Upload(ctx context.Context, blobID, blobPath string, blobSize int64, forcePush bool) (*ocispec.Descriptor, error)
	Check(blobID string) (bool, error)
	Type() BackendType
}

// TODO: Directly forward blob data to storage backend

type BackendType = int

const (
	OssBackend BackendType = iota
	RegistryBackend
)

func blobDesc(size int64, blobId string) ocispec.Descriptor {
	blobDigest := digest.NewDigestFromEncoded(digest.SHA256, blobId)
	desc := ocispec.Descriptor{
		Digest:    blobDigest,
		Size:      size,
		MediaType: utils.MediaTypeNydusBlob,
		Annotations: map[string]string{
			// Use `utils.LayerAnnotationUncompressed` to generate
			// DiffID of layer defined in OCI spec
			utils.LayerAnnotationUncompressed: blobDigest.String(),
			utils.LayerAnnotationNydusBlob:    "true",
		},
	}

	return desc
}

// Nydusify majorly works for registry backend, which means blob is stored in
// registry as per OCI distribution specification. But nydus can also make OSS
// as rafs backend storage. Therefore, nydusify better have the ability to upload
// blob into OSS. OSS is configured via a json string input. Currently, it has
// no effect to registry backend now.
// Save byte slice here because I don't find a way to represent
// all the backend types at the same time
func NewBackend(bt string, config []byte, remote *remote.Remote) (Backend, error) {
	switch bt {
	case "oss":
		return newOSSBackend(config)
	case "registry":
		return newRegistryBackend(config, remote)
	default:
		return nil, fmt.Errorf("unsupported backend type %s", bt)
	}
}
