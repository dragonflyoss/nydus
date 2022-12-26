// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"context"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/converter/provider"
	"github.com/goharbor/acceleration-service/pkg/converter"
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

	TargetPlatform   string
	MultiPlatform    bool
	DockerV2Format   bool
	FsVersion        string
	FsAlignChunk     bool
	Compressor       string
	ChunkSize        string
	PrefetchPatterns string
}

func Convert(ctx context.Context, opt Opt) error {
	pvd, err := provider.New(opt.WorkDir, hosts(opt))
	if err != nil {
		return err
	}

	cvt, err := converter.NewLocalConverter(
		converter.WithProvider(pvd),
		converter.WithDriver("nydus", getConfig(opt)),
	)
	if err != nil {
		return err
	}

	return cvt.Convert(ctx, opt.Source, opt.Target)
}
