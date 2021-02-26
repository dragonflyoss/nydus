// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"encoding/json"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func MarshalToDesc(data interface{}, mediaType string) (*ocispec.Descriptor, []byte, error) {
	bytes, err := json.Marshal(data)
	if err != nil {
		return nil, nil, err
	}

	dataDigest := digest.FromBytes(bytes)
	desc := ocispec.Descriptor{
		Digest:    dataDigest,
		Size:      int64(len(bytes)),
		MediaType: mediaType,
	}

	return &desc, bytes, nil
}
