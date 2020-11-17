// Copyright 2020 Ant Financial. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"contrib/nydusify/utils"
	"fmt"
	"io"
	"path/filepath"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"
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
	Progress *Progress

	Source *Image
	Target *Image

	SourceLayer v1.Layer
	TargetLayer v1.Layer
}

func NewLayerJob(source *Image, target *Image) (*LayerJob, error) {
	layerJob := LayerJob{
		Source: source,
		Target: target,
	}

	return &layerJob, nil
}

func (job *LayerJob) SetProgress(layerFor int, name string) error {
	var layer *v1.Layer
	if layerFor == LayerSource {
		layer = &job.SourceLayer
	} else {
		layer = &job.TargetLayer
	}

	size, err := (*layer).Size()
	if err != nil {
		return errors.Wrap(err, "get image layer size")
	}

	hash, err := (*layer).Digest()
	if err != nil {
		return errors.Wrap(err, "get image layer digest")
	}

	progress, err := NewProgress(hash.String(), name, StatusPulling, int(size))
	if err != nil {
		return err
	}

	job.Progress = progress

	return nil
}

func (job *LayerJob) SetSourceLayer(sourceLayer v1.Layer) {
	job.SourceLayer = sourceLayer
}

func (job *LayerJob) SetTargetLayer(
	sourcePath,
	name string,
	mediaType types.MediaType,
	annotations map[string]string,
) {
	layer := Layer{
		name:        name,
		sourcePath:  sourcePath,
		mediaType:   mediaType,
		annotations: annotations,
	}
	job.TargetLayer = &layer
}

func (job *LayerJob) Pull() error {
	hash, err := job.SourceLayer.Digest()
	if err != nil {
		return err
	}

	// Pull the layer from source, we need to retry in case of
	// the layer is compressed or uncompressed
	var reader io.ReadCloser
	reader, err = job.SourceLayer.Compressed()
	if err != nil {
		reader, err = job.SourceLayer.Uncompressed()
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("decompress source layer %s", hash.String()))
		}
	}

	pr := utils.NewProgressReader(reader, func(total int) {
		job.Progress.SetCurrent(int(total))
	})

	// Decompress layer from source stream
	layerDir := filepath.Join(job.Source.WorkDir, hash.String())
	if err := utils.DecompressTargz(layerDir, pr); err != nil {
		return errors.Wrap(err, fmt.Sprintf("decompress source layer %s", hash.String()))
	}

	job.Progress.SetFinish()

	return nil
}

func (job *LayerJob) Push() error {
	job.Progress.SetStatus(StatusPushing)
	size, err := job.TargetLayer.Size()
	if err != nil {
		return err
	}
	job.Progress.SetTotal(int(size))

	job.TargetLayer.(*Layer).SetProgressHandler(func(cur int) {
		job.Progress.SetCurrent(cur)
	})

	target := job.Target.Ref.Context()

	if err := remote.WriteLayer(target, job.TargetLayer, remote.WithAuthFromKeychain(withDefaultAuth())); err != nil {
		return errors.Wrap(err, "push target layer")
	}

	targetImage, err := mutate.Append(*job.Target.Img, mutate.Addendum{
		Layer: job.TargetLayer,
		History: v1.History{
			CreatedBy: fmt.Sprintf("nydusify"),
		},
		Annotations: job.TargetLayer.(*Layer).annotations,
	})
	if err != nil {
		return errors.Wrap(err, "append target layer")
	}
	*job.Target.Img = targetImage

	job.Progress.SetFinish()
	job.Progress.SetStatus(StatusPushed)

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
