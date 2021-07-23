// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/build"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
)

// PullWorkerCount specifies source layer pull concurrency
var PullWorkerCount uint = 5

// PushWorkerCount specifies Nydus layer push concurrency
var PushWorkerCount uint = 5

var logger provider.ProgressLogger

var (
	errInvalidCache = errors.New("Invalid cache")
)

type mountJob struct {
	err    error
	ctx    context.Context
	layer  *buildLayer
	umount func() error
}

func (job *mountJob) Do() error {
	var umount func() error
	umount, job.err = job.layer.Mount(job.ctx)
	job.umount = umount
	return job.err
}

func (job *mountJob) Err() error {
	return job.err
}

func (job *mountJob) Umount() error {
	return job.umount()
}

// This is the main entrypoint for whom want to leverage the ability to convert a OCI image
// Usually by importing this package and construct `Opt`
type Opt struct {
	Logger provider.ProgressLogger

	// SourceProviders should be a slice, which means it can support multi-platforms,
	// for example `linux/amd64` and `linux/arm64`, Nydusify will pick one or more
	// to convert to Nydus image in the future.
	SourceProviders []provider.SourceProvider

	TargetRemote *remote.Remote

	CacheRemote     *remote.Remote
	CacheMaxRecords uint
	CacheVersion    string

	NydusImagePath string
	WorkDir        string
	PrefetchDir    string

	MultiPlatform  bool
	DockerV2Format bool

	BackendType      string
	BackendConfig    string
	BackendForcePush bool

	NydusifyVersion string
	Source          string
}

type Converter struct {
	Logger          provider.ProgressLogger
	SourceProviders []provider.SourceProvider

	TargetRemote *remote.Remote

	CacheRemote     *remote.Remote
	CacheMaxRecords uint
	CacheVersion    string

	NydusImagePath string
	WorkDir        string
	PrefetchDir    string

	MultiPlatform  bool
	DockerV2Format bool

	BackendForcePush bool

	NydusifyVersion string
	Source          string

	storageBackend backend.Backend
}

func New(opt Opt) (*Converter, error) {
	// TODO: Add parameters sanity check here
	// Built layer has to go somewhere. Storage backend is the media holing layer blob.
	backend, err := backend.NewBackend(opt.BackendType, []byte(opt.BackendConfig), opt.TargetRemote)
	if err != nil {
		return nil, err
	}

	return &Converter{
		Logger:           opt.Logger,
		SourceProviders:  opt.SourceProviders,
		TargetRemote:     opt.TargetRemote,
		CacheRemote:      opt.CacheRemote,
		CacheMaxRecords:  opt.CacheMaxRecords,
		CacheVersion:     opt.CacheVersion,
		NydusImagePath:   opt.NydusImagePath,
		WorkDir:          opt.WorkDir,
		PrefetchDir:      opt.PrefetchDir,
		MultiPlatform:    opt.MultiPlatform,
		DockerV2Format:   opt.DockerV2Format,
		BackendForcePush: opt.BackendForcePush,
		NydusifyVersion:  opt.NydusifyVersion,
		Source:           opt.Source,

		storageBackend: backend,
	}, nil
}

func (cvt *Converter) convert(ctx context.Context) error {
	logger = cvt.Logger

	logrus.Infof("Converting to %s", cvt.TargetRemote.Ref)

	// Try to pull Nydus cache image from remote registry
	cg, err := newCacheGlue(
		ctx, cvt.CacheMaxRecords, cvt.CacheVersion, cvt.DockerV2Format, cvt.TargetRemote, cvt.CacheRemote, cvt.storageBackend,
	)
	if err != nil {
		return errors.Wrap(err, "Pull cache image")
	}

	// BuildWorkflow builds nydus blob/bootstrap layer by layer
	bootstrapsDir := filepath.Join(cvt.WorkDir, "bootstraps")
	if err := os.RemoveAll(bootstrapsDir); err != nil {
		return errors.Wrap(err, "Remove bootstrap directory")
	}
	if err := os.MkdirAll(bootstrapsDir, 0755); err != nil {
		return errors.Wrap(err, "Create bootstrap directory")
	}
	buildWorkflow, err := build.NewWorkflow(build.WorkflowOption{
		NydusImagePath: cvt.NydusImagePath,
		PrefetchDir:    cvt.PrefetchDir,
		TargetDir:      cvt.WorkDir,
	})
	if err != nil {
		return errors.Wrap(err, "Create build flow")
	}

	if cvt.SourceProviders == nil || len(cvt.SourceProviders) == 0 {
		return errors.New("Invalid source provider")
	}

	// In fact, during parsing image manifest, only one interested tag is inserted.
	if len(cvt.SourceProviders) != 1 {
		return errors.New("Should have only one source image")
	}

	sourceProvider := cvt.SourceProviders[0]
	sourceLayers, err := sourceProvider.Layers(ctx)
	if err != nil {
		return errors.Wrap(err, "Get source layers")
	}
	pullWorker := utils.NewQueueWorkerPool(PullWorkerCount, uint(len(sourceLayers)))
	pushWorker := utils.NewWorkerPool(PushWorkerCount, uint(len(sourceLayers)))
	buildLayers := []*buildLayer{}

	// Pull and mount source layer in pull worker
	var parentBuildLayer *buildLayer
	for idx, sourceLayer := range sourceLayers {
		buildLayer := &buildLayer{
			index:          idx,
			buildWorkflow:  buildWorkflow,
			bootstrapsDir:  bootstrapsDir,
			cacheGlue:      cg,
			remote:         cvt.TargetRemote,
			source:         sourceLayer,
			parent:         parentBuildLayer,
			dockerV2Format: cvt.DockerV2Format,
			backend:        cvt.storageBackend,
			forcePush:      cvt.BackendForcePush,
		}
		parentBuildLayer = buildLayer
		buildLayers = append(buildLayers, buildLayer)
		job := mountJob{
			ctx:   ctx,
			layer: buildLayer,
		}

		if err := pullWorker.Put(&job); err != nil {
			return errors.Wrap(err, "Put layer pull job to worker")
		}
	}

	// Build source layer to Nydus layer (bootstrap & blob) once the first source
	// layer be mounted in pull worker, and then put Nydus layer to the push worker,
	// it can be uploaded to remote registry
	for _, jobChan := range pullWorker.Waiter() {
		select {
		case _job := <-jobChan:
			if _job.Err() != nil {
				return errors.Wrap(_job.Err(), "Pull source layer")
			}
			job := _job.(*mountJob)

			// Skip building if we found the cache record in cache image
			if job.layer.Cached() {
				continue
			}

			// Build source layer to Nydus layer by invoking Nydus image builder
			err := job.layer.Build(ctx)

			go func() {
				// Umount source layer after building in order to save the disk
				// space during building, useful for default source provider
				if err := job.Umount(); err != nil {
					logrus.Warnf("Failed to umount layer %s: %s", job.layer.source.Digest(), err)
				}
			}()

			if err != nil {
				return errors.Wrap(err, "Build source layer")
			}

			// Push Nydus layer (bootstrap & blob) to target registry
			pushWorker.Put(func() error {
				return job.layer.Push(ctx)
			})
		case err := <-pushWorker.Err():
			// Should throw the error as soon as possible instead
			// of waiting for all pull jobs to finish
			if err != nil {
				return errors.Wrap(err, "Push Nydus layer in worker")
			}
		}
	}

	// Wait all layer push job finish, then we can push image manifest on next
	if err := <-pushWorker.Waiter(); err != nil {
		return errors.Wrap(err, "Push Nydus layer in wait")
	}

	// Collect all meta information of current build environment, it will be
	// written to manifest annotations of Nydus image for easy debugging and
	// troubleshooting afterwards.
	buildInfo := NewBuildInfo()
	buildInfo.SetBuilderVersion(buildWorkflow.BuilderVersion)
	buildInfo.SetNydusifyVersion(cvt.NydusifyVersion)
	sourceManifest, err := sourceProvider.Manifest(ctx)
	if err != nil {
		return errors.Wrap(err, "Get source manifest")
	}
	buildInfo.SetSourceReference(SourceReference{
		Reference: cvt.Source,
		Digest:    sourceManifest.Digest.String(),
	})

	// Push OCI manifest, Nydus manifest and manifest index
	mm := &manifestManager{
		sourceProvider: sourceProvider,
		remote:         cvt.TargetRemote,
		backend:        cvt.storageBackend,
		multiPlatform:  cvt.MultiPlatform,
		dockerV2Format: cvt.DockerV2Format,
		buildInfo:      buildInfo,
	}
	pushDone := logger.Log(ctx, "[MANI] Push manifest", nil)
	if err := mm.Push(ctx, buildLayers); err != nil {
		// When encounter http 400 error during pushing manifest to remote registry, means the
		// manifest is invalid, maybe the cache layer is not available in registry with a high
		// probability caused by registry GC, for example the cache image be overwritten by another
		// conversion progress, and the registry GC be triggered in the same time
		if cvt.CacheRemote != nil && strings.Contains(err.Error(), "400") {
			logrus.Warnf("Push manifest: %s", err)
			return pushDone(errInvalidCache)
		}
		return pushDone(errors.Wrap(err, "Push target manifest"))
	}
	pushDone(nil)

	// Push Nydus cache image to remote registry
	if err := cg.Export(ctx, buildLayers); err != nil {
		return errors.Wrap(err, "Get cache record")
	}

	logrus.Infof("Converted to %s", cvt.TargetRemote.Ref)

	return nil
}

// Convert converts source image to target (Nydus) image
func (cvt *Converter) Convert(ctx context.Context) error {
	if err := cvt.convert(ctx); err != nil {
		if errors.Is(err, errInvalidCache) {
			// Retry to convert without cache if the cache is invalid. we can't ensure the
			// cache is always valid during conversion progress, the registry will refuse
			// the Nydus manifest included invalid layer (purged by registry GC) pulled from
			// cache record, so retry without cache is a middle ground at this point
			cvt.CacheRemote = nil
			retryDone := logger.Log(ctx, "Retrying to convert without cache", nil)
			return retryDone(cvt.convert(ctx))
		}
		return errors.Wrap(err, "Failed to convert")
	}
	return nil
}
