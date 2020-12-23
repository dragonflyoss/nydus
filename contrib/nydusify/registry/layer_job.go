// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"contrib/nydusify/utils"
	"fmt"
	"io"
	"path/filepath"

	blobbackend "contrib/nydusify/backend"

	"github.com/dustin/go-humanize"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	MethodPull = iota
	MethodPush
)

const (
	LayerSource = iota
	LayerTarget
)

type LayerJob struct {
	Source *Image
	Target *Image

	SourceLayerChainID   digest.Digest
	SourceLayer          v1.Layer
	TargetBlobLayer      *Layer
	TargetBootstrapLayer *Layer
	Cached               bool
	Parent               *LayerJob

	Backend blobbackend.Backend
}

func (job *LayerJob) SetSourceLayer(sourceLayer v1.Layer) {
	job.SourceLayer = sourceLayer
}

func (job *LayerJob) SetTargetBlobLayer(
	sourcePath,
	name string,
	mediaType types.MediaType,
) {
	layer := Layer{
		name:       name,
		sourcePath: sourcePath,
		mediaType:  mediaType,
	}
	job.TargetBlobLayer = &layer
}

func (job *LayerJob) SetTargetBootstrapLayer(
	sourcePath,
	name string,
	mediaType types.MediaType,
) {
	layer := Layer{
		name:       name,
		sourcePath: sourcePath,
		mediaType:  mediaType,
	}
	job.TargetBootstrapLayer = &layer
}

func (job *LayerJob) Pull() error {
	sourceLayerDigest, err := job.SourceLayer.Digest()
	if err != nil {
		return err
	}
	sourceLayerSize, err := job.SourceLayer.Size()
	if err != nil {
		return err
	}
	sourceLayerHumanizeSize := humanize.Bytes(uint64(sourceLayerSize))
	logrus.WithField("Digest", sourceLayerDigest).
		WithField("Size", sourceLayerHumanizeSize).Infof("[SOUR] Pulling")

	// Pull the layer from source, we need to retry in case of
	// the layer is compressed or uncompressed
	var reader io.ReadCloser
	reader, err = job.SourceLayer.Compressed()
	if err != nil {
		reader, err = job.SourceLayer.Uncompressed()
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("decompress source layer %s", sourceLayerDigest.String()))
		}
	}

	// Decompress layer from source stream
	layerDir := filepath.Join(job.Source.WorkDir, sourceLayerDigest.String())
	if err := utils.DecompressTargz(layerDir, reader); err != nil {
		return errors.Wrap(err, fmt.Sprintf("decompress source layer %s", sourceLayerDigest.String()))
	}

	logrus.WithField("Digest", sourceLayerDigest).
		WithField("Size", sourceLayerHumanizeSize).Infof("[SOUR] Pulled")

	return nil
}

func (job *LayerJob) Push() error {
	if job.TargetBlobLayer == nil {
		return nil
	}

	target := job.Target.Ref.Context()
	authKeychain := remote.WithAuthFromKeychain(withDefaultAuth())

	blobDigest, err := job.TargetBlobLayer.Digest()
	if err != nil {
		return errors.Wrap(err, "get blob layer digest before upload")
	}
	blobSize, err := job.TargetBlobLayer.Size()
	if err != nil {
		return errors.Wrap(err, "get blob layer size before upload")
	}
	blobHumanizeSize := humanize.Bytes(uint64(blobSize))

	if job.Backend != nil {
		// Upload blob layer to foreign storage backend
		logrus.WithField("Digest", blobDigest).
			WithField("Size", blobHumanizeSize).Infof("[BLOB] Uploading")
		if err := job.Backend.Upload(blobDigest.Hex, job.TargetBlobLayer.sourcePath); err != nil {
			return errors.Wrap(err, "upload blob layer")
		}
		logrus.WithField("Digest", blobDigest).
			WithField("Size", blobHumanizeSize).Infof("[BLOB] Uploaded")
	} else {
		// Upload blob layer to remote registry
		logrus.WithField("Digest", blobDigest).
			WithField("Size", blobHumanizeSize).Infof("[BLOB] Pushing")
		if err := remote.WriteLayer(target, job.TargetBlobLayer, authKeychain); err != nil {
			return errors.Wrap(err, "push target blob layer")
		}
		logrus.WithField("Digest", blobDigest).
			WithField("Size", blobHumanizeSize).Infof("[BLOB] Pushed")
	}

	// Upload boostrap layer to remote registry
	bootstrapDesc, err := job.TargetBootstrapLayer.Desc()
	if err != nil {
		return errors.Wrap(err, "get bootstrap layer desc before upload")
	}
	bootstrapSize := humanize.Bytes(uint64(bootstrapDesc.Size))
	logrus.WithField("Digest", bootstrapDesc.Digest).
		WithField("Size", bootstrapSize).Infof("[BOOT] Pushing")
	if err := remote.WriteLayer(target, job.TargetBootstrapLayer, authKeychain); err != nil {
		return errors.Wrap(err, "push target bootstrap layer")
	}
	logrus.WithField("Digest", bootstrapDesc.Digest).
		WithField("Size", bootstrapSize).Infof("[BOOT] Pushed")

	return nil
}

func (job *LayerJob) Do(method int) error {
	switch method {
	case MethodPull:
		return job.Pull()
	case MethodPush:
		return job.Push()
	}
	return nil
}
