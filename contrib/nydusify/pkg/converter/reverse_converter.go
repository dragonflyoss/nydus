// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"context"
	"os"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/platforms"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/converter/provider"
	"github.com/goharbor/acceleration-service/pkg/platformutil"

	// Import snapshotter converter package for Unpack function
	snapshotterConverter "github.com/containerd/nydus-snapshotter/pkg/converter"
)

// ReverseConvert converts Nydus image to OCI image
func ReverseConvert(ctx context.Context, opt Opt) error {
	start := time.Now()
	logrus.Warn("note: conversion from Nydus to OCI is currently experimental")
	logrus.Infof("Starting reverse conversion from Nydus image %s to OCI image %s", opt.Source, opt.Target)

	ctx = namespaces.WithNamespace(ctx, "nydusify")
	platformMC, err := platformutil.ParsePlatforms(opt.AllPlatforms, opt.Platforms)
	if err != nil {
		return errors.Wrap(err, "parse platforms")
	}

	// Prepare work directory
	if _, err := os.Stat(opt.WorkDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.MkdirAll(opt.WorkDir, 0755); err != nil {
				return errors.Wrap(err, "prepare work directory")
			}
			defer os.RemoveAll(opt.WorkDir)
		} else {
			return errors.Wrap(err, "stat work directory")
		}
	}

	tmpDir, err := os.MkdirTemp(opt.WorkDir, "nydusify-reverse-")
	if err != nil {
		return errors.Wrap(err, "create temp directory")
	}
	defer os.RemoveAll(tmpDir)

	// Create provider for registry operations (reuse hosts for consistent credential/insecure handling)
	pvd, err := provider.New(tmpDir, hosts(opt), 0, "", platformMC, 0, nil)
	if err != nil {
		return err
	}

	// Parse retry delay using duration string like "5s", "1m"
	retryDelay, err := time.ParseDuration(opt.PushRetryDelay)
	if err != nil {
		return errors.Wrap(err, "parse push retry delay")
	}

	pvd.SetPushRetryConfig(opt.PushRetryCount, retryDelay)

	// Align plain HTTP behavior with other converter usages
	if opt.WithPlainHTTP {
		pvd.UsePlainHTTP()
	}

	// Step 1: Pull source and resolve root descriptor (manifest/index)
	if err := pvd.Pull(ctx, opt.Source); err != nil {
		return errors.Wrap(err, "provider pull source")
	}
	logrus.Infof("Pulled source image: %s", opt.Source)
	rootDesc, err := pvd.Image(ctx, opt.Source)
	if err != nil {
		return errors.Wrap(err, "get source image descriptor")
	}

	// Step 2: Use reconverter to convert Nydus -> OCI in content store
	dstDesc, err := reconvertWithSnapshotter(ctx, pvd, platformMC, tmpDir, *rootDesc, opt)
	if err != nil {
		return errors.Wrap(err, "reconvert image with snapshotter")
	}

	// Step 3: Push the converted descriptor to target using provider
	if dstDesc == nil {
		return errors.New("reconverter returned nil descriptor")
	}
	logrus.Infof("Pushing converted descriptor to target: %s", opt.Target)
	if err := pvd.Push(ctx, *dstDesc, opt.Target); err != nil {
		return errors.Wrap(err, "push oci image")
	}

	logrus.Infof("Successfully converted Nydus image %s to OCI image %s (duration=%s)", opt.Source, opt.Target, time.Since(start))
	return nil
}

// reconvertWithSnapshotter wires reconverter default functions with snapshotter layer reconvert func.
// It converts the pulled source descriptor in provider's content store and returns the new descriptor.
func reconvertWithSnapshotter(
	ctx context.Context,
	pvd *provider.Provider,
	platformMC platforms.MatchComparer,
	workDir string,
	srcDescs ocispec.Descriptor,
	opt Opt,
) (*ocispec.Descriptor, error) {
	logrus.Debugf("Start reconvertWithSnapshotter: mediaType=%s digest=%s workDir=%s", srcDescs.MediaType, srcDescs.Digest.String(), workDir)
	cs := pvd.ContentStore()

	// Prepare layer reconvert func: Nydus blob/bootstrap -> OCI tar layer
	layerFn := snapshotterConverter.LayerReconvertFunc(snapshotterConverter.UnpackOption{
		BuilderPath: opt.NydusImagePath,
		WorkDir:     workDir,
		Stream:      false,
		Compressor:  opt.Compressor,
	})

	// Prepare index/manifest convert func using reconverter default
	indexFn := snapshotterConverter.DefaultIndexConvertFunc(layerFn, false, platformMC)

	// Convert the source descriptor (manifest/index)
	logrus.Debugf("Convert descriptor: mediaType=%s digest=%s", srcDescs.MediaType, srcDescs.Digest.String())
	dstDesc, err := indexFn(ctx, cs, srcDescs)
	if err != nil {
		return nil, errors.Wrap(err, "convert descriptor")
	}

	if dstDesc == nil {
		return nil, errors.New("converter returned nil descriptor")
	}

	return dstDesc, nil
}
