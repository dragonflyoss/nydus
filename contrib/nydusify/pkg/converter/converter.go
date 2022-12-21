// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"context"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/defaults"
	"github.com/goharbor/acceleration-service/pkg/content"
	"github.com/goharbor/acceleration-service/pkg/converter"
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
	if opt.ContainerdAddress == "" {
		opt.ContainerdAddress = defaults.DefaultAddress
	}
	client, err := containerd.New(
		opt.ContainerdAddress,
		containerd.WithDefaultNamespace("nydusify"),
	)
	if err != nil {
		return errors.Wrap(err, "connect to containerd")
	}

	provider, err := content.NewLocalProvider(client, hosts(opt))
	if err != nil {
		return errors.Wrap(err, "create content provider")
	}

	cvt, err := converter.NewLocalConverter(
		converter.WithProvider(provider),
		converter.WithDriver("nydus", getConfig(opt)),
	)
	if err != nil {
		return err
	}

	return cvt.Convert(ctx, opt.Source, opt.Target)
}
