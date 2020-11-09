// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"contrib/nydusify/utils"
	"io"
	"os"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type Layer struct {
	mediaType       types.MediaType
	annotations     map[string]string
	progressHandler func(int)

	compressedPath     string
	decompressedPath   string
	compressedDigest   *v1.Hash
	decompressedDigest *v1.Hash
}

func (layer *Layer) Digest() (v1.Hash, error) {
	if layer.compressedDigest != nil {
		return *layer.compressedDigest, nil
	}

	file, err := os.Open(layer.compressedPath)
	if err != nil {
		return v1.Hash{}, err
	}
	defer file.Close()

	hash, _, err := v1.SHA256(file)
	if err != nil {
		return v1.Hash{}, err
	}

	layer.compressedDigest = &hash

	return hash, nil
}

func (layer *Layer) DiffID() (v1.Hash, error) {
	if layer.decompressedDigest != nil {
		return *layer.decompressedDigest, nil
	}

	file, err := os.Open(layer.decompressedPath)
	if err != nil {
		return v1.Hash{}, err
	}
	defer file.Close()

	hash, _, err := v1.SHA256(file)
	if err != nil {
		return v1.Hash{}, err
	}

	layer.decompressedDigest = &hash

	return hash, nil
}

func (layer *Layer) Size() (int64, error) {
	file, err := os.Open(layer.compressedPath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return 0, err
	}

	return stat.Size(), nil
}

func (layer *Layer) MediaType() (types.MediaType, error) {
	return types.MediaType(layer.mediaType), nil
}

func (layer *Layer) Compressed() (io.ReadCloser, error) {
	reader, err := os.Open(layer.compressedPath)
	if err != nil {
		return nil, err
	}

	var total int
	pr := utils.NewProgressReader(reader, func(count int) {
		total += count
		if layer.progressHandler != nil {
			layer.progressHandler(total)
		}
	})

	return pr, nil
}

func (layer *Layer) Uncompressed() (io.ReadCloser, error) {
	return os.Open(layer.decompressedPath)
}

func (layer *Layer) SetProgressHandler(handler func(int)) {
	layer.progressHandler = handler
}
