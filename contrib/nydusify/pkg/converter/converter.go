// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"context"
	"os"

	"github.com/containerd/containerd/namespaces"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/converter/provider"
	"github.com/goharbor/acceleration-service/pkg/converter"
	"github.com/goharbor/acceleration-service/pkg/platformutil"
	"github.com/pkg/errors"
)

type Opt struct {
	WorkDir           string
	ContainerdAddress string
	NydusImagePath    string

	Source       string
	Target       string
	ChunkDictRef string

	SourceInsecure    bool
	TargetInsecure    bool
	ChunkDictInsecure bool

	CacheRef        string
	CacheInsecure   bool
	CacheVersion    string
	CacheMaxRecords uint

	BackendType      string
	BackendConfig    string
	BackendForcePush bool

	MergePlatform    bool
	Docker2OCI       bool
	FsVersion        string
	FsAlignChunk     bool
	Compressor       string
	ChunkSize        string
	BatchSize        string
	PrefetchPatterns string
	OCIRef           bool
	WithReferrer     bool

	AllPlatforms bool
	Platforms    string

	OutputJSON string
}

func Convert(ctx context.Context, opt Opt) error {
	ctx = namespaces.WithNamespace(ctx, "nydusify")
	platformMC, err := platformutil.ParsePlatforms(opt.AllPlatforms, opt.Platforms)
	if err != nil {
		return err
	}

	if _, err := os.Stat(opt.WorkDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(opt.WorkDir, 0755); err != nil {
				return errors.Wrap(err, "prepare work directory")
			}
			// We should only clean up when the work directory not exists
			// before, otherwise it may delete user data by mistake.
			defer os.RemoveAll(opt.WorkDir)
		} else {
			return errors.Wrap(err, "stat work directory")
		}
	}
	tmpDir, err := os.MkdirTemp(opt.WorkDir, "nydusify-")
	if err != nil {
		return errors.Wrap(err, "create temp directory")
	}
	pvd, err := provider.New(tmpDir, hosts(opt), opt.CacheMaxRecords, opt.CacheVersion, platformMC)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	cvt, err := converter.New(
		converter.WithProvider(pvd),
		converter.WithDriver("nydus", getConfig(opt)),
		converter.WithPlatform(platformMC),
	)
	if err != nil {
		return err
	}

	metric, err := cvt.Convert(ctx, opt.Source, opt.Target, opt.CacheRef)
	if opt.OutputJSON != "" {
		dumpMetric(metric, opt.OutputJSON)
	}
	return err
}
