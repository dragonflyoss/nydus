// Copyright 2020 Ant Group. All rights reserved.
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
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Layer struct {
	name       string
	sourcePath string
	mediaType  types.MediaType

	compressedSize     *int64
	compressedDigest   *v1.Hash
	decompressedDigest *v1.Hash

	compressedReader io.ReadCloser
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
		defer reader.Close()
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
	defer tarReader.Close()

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
	defer gzipReader.Close()

	written, err := io.Copy(ioutil.Discard, gzipReader)
	if err != nil {
		return 0, err
	}

	layer.compressedSize = &written

	return written, nil
}

// Compressed returns an io.ReadCloser for the compressed (.tar.gz) layer contents.
func (layer *Layer) Compressed() (io.ReadCloser, error) {
	if layer.compressedReader != nil {
		return layer.compressedReader, nil
	}

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

	return reader, nil
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

func DescToLayer(desc ocispec.Descriptor, diffID digest.Digest, compressedReader io.ReadCloser) (*Layer, error) {
	layerDigest, err := v1.NewHash(desc.Digest.String())
	if err != nil {
		return nil, err
	}
	layerDiffID, err := v1.NewHash(diffID.String())
	if err != nil {
		return nil, err
	}
	return &Layer{
		mediaType:          types.MediaType(desc.MediaType),
		compressedSize:     &desc.Size,
		compressedDigest:   &layerDigest,
		decompressedDigest: &layerDiffID,
		compressedReader:   compressedReader,
	}, nil
}

func (layer *Layer) Desc() (*ocispec.Descriptor, error) {
	mediaType, err := layer.MediaType()
	if err != nil {
		return nil, err
	}

	layerDigest, err := layer.Digest()
	if err != nil {
		return nil, err
	}

	size, err := layer.Size()
	if err != nil {
		return nil, err
	}

	return &ocispec.Descriptor{
		MediaType: string(mediaType),
		Digest:    digest.Digest(layerDigest.String()),
		Size:      size,
	}, nil
}
