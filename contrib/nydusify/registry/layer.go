// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"contrib/nydusify/utils"
	"io"
	"io/ioutil"
	"os"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type Layer struct {
	name            string
	sourcePath      string
	mediaType       types.MediaType
	annotations     map[string]string
	progressHandler func(int)

	compressedSize     *int64
	compressedDigest   *v1.Hash
	decompressedDigest *v1.Hash
}

func (layer *Layer) sourceReader() (io.ReadCloser, error) {
	return os.Open(layer.sourcePath)
}

func (layer *Layer) isCompressedType() bool {
	return (strings.HasSuffix(string(layer.mediaType), "+gzip") ||
		strings.HasSuffix(string(layer.mediaType), ".gzip"))
}

// Digest returns the Hash of the compressed (.tar.gz) layer.
func (layer *Layer) Digest() (v1.Hash, error) {
	if layer.compressedDigest != nil {
		return *layer.compressedDigest, nil
	}

	reader, err := layer.sourceReader()
	if err != nil {
		return v1.Hash{}, err
	}
	defer reader.Close()

	if layer.isCompressedType() {
		reader, err = utils.CompressTargz(layer.sourcePath, layer.name, true)
		if err != nil {
			return v1.Hash{}, err
		}
	}

	hash, _, err := v1.SHA256(reader)
	if err != nil {
		return v1.Hash{}, err
	}

	layer.compressedDigest = &hash

	return hash, nil
}

// DiffID returns the Hash of the uncompressed (.tar) layer.
func (layer *Layer) DiffID() (v1.Hash, error) {
	if layer.decompressedDigest != nil {
		return *layer.decompressedDigest, nil
	}

	if !layer.isCompressedType() {
		return layer.Digest()
	}

	tarReader, err := utils.CompressTargz(layer.sourcePath, layer.name, false)
	if err != nil {
		return v1.Hash{}, err
	}

	hash, _, err := v1.SHA256(tarReader)
	if err != nil {
		return v1.Hash{}, err
	}

	layer.decompressedDigest = &hash

	return hash, nil
}

// Size returns the compressed (.tar.gz) size of the Layer.
func (layer *Layer) Size() (int64, error) {
	if layer.compressedSize != nil {
		return *layer.compressedSize, nil
	}

	if !layer.isCompressedType() {
		fi, err := os.Stat(layer.sourcePath)
		if err != nil {
			return 0, err
		}
		size := fi.Size()
		layer.compressedSize = &size
		return size, nil
	}

	gzipReader, err := utils.CompressTargz(layer.sourcePath, layer.name, true)
	if err != nil {
		return 0, err
	}

	written, err := io.Copy(ioutil.Discard, gzipReader)
	if err != nil {
		return 0, err
	}

	layer.compressedSize = &written

	return written, nil
}

// Compressed returns an io.ReadCloser for the compressed (.tar.gz) layer contents.
func (layer *Layer) Compressed() (io.ReadCloser, error) {
	reader, err := layer.sourceReader()
	if err != nil {
		return nil, err
	}

	if layer.isCompressedType() {
		reader, err = utils.CompressTargz(layer.sourcePath, layer.name, true)
		if err != nil {
			return nil, err
		}
	}

	pr := utils.NewProgressReader(reader, func(total int) {
		if layer.progressHandler != nil {
			layer.progressHandler(total)
		}
	})

	return pr, nil
}

// Uncompressed returns an io.ReadCloser for the uncompressed (.tar) layer contents.
func (layer *Layer) Uncompressed() (io.ReadCloser, error) {
	if !layer.isCompressedType() {
		return layer.sourceReader()
	}
	return utils.CompressTargz(layer.sourcePath, layer.name, false)
}

// MediaType returns the media type of the Layer.
func (layer *Layer) MediaType() (types.MediaType, error) {
	return types.MediaType(layer.mediaType), nil
}

// SetProgressHandler sets progress handler for layer pull or push
func (layer *Layer) SetProgressHandler(handler func(int)) {
	layer.progressHandler = handler
}
