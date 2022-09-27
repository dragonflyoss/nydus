// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"context"
	"path/filepath"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/hook"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func (cvt *Converter) newHookInfo(ctx context.Context, buildLayers []*buildLayer) (*hook.Info, error) {
	blobs := []hook.Blob{}
	for _, layer := range buildLayers {
		record := layer.GetCacheRecord()
		if record.NydusBlobDesc != nil {
			blobs = append(blobs, hook.Blob{
				ID:   record.NydusBlobDesc.Digest.Hex(),
				Size: record.NydusBlobDesc.Size,
			})
		}
	}
	bootstrapLayer := buildLayers[len(buildLayers)-1]
	bootstrapPath := bootstrapLayer.bootstrapPath

	if bootstrapPath == "" {
		cache := bootstrapLayer.cacheGlue
		// If we can't find bootstrap file in local, try to pull
		// it from cache image.
		if cache != nil && cache.remote != nil {
			record := bootstrapLayer.GetCacheRecord()
			reader, err := cache.remote.Pull(ctx, *record.NydusBootstrapDesc, true)
			if err != nil {
				return nil, errors.Wrap(err, "Pull cached bootstrap layer")
			}
			defer reader.Close()

			bootstrapPath = filepath.Join(cvt.WorkDir, "bootstraps", "bootstrap_for_hook")
			if err := utils.UnpackFile(reader, utils.BootstrapFileNameInLayer, bootstrapPath); err != nil {
				return nil, errors.Wrap(err, "Unpack cached bootstrap layer")
			}
		}
	}

	info := hook.Info{
		BootstrapPath: bootstrapPath,
		SourceRef:     cvt.SourceRemote.Ref,
		TargetRef:     cvt.TargetRemote.Ref,
		Blobs:         blobs,
	}

	return &info, nil
}

func (cvt *Converter) hookBeforePushManifest(ctx context.Context, info *hook.Info) error {
	if hook.Caller == nil {
		return nil
	}

	logrus.Info("[HOOK] Call hook 'BeforePushManifest'")

	if err := hook.Caller.BeforePushManifest(info); err != nil {
		return errors.Wrap(err, "Failed to call hook 'BeforePushManifest'")
	}

	return nil
}

func (cvt *Converter) hookAfterPushManifest(ctx context.Context, info *hook.Info) error {
	if hook.Caller == nil {
		return nil
	}

	logrus.Info("[HOOK] Call hook 'AfterPushManifest'")

	if err := hook.Caller.AfterPushManifest(info); err != nil {
		return errors.Wrap(err, "Failed to call hook 'AfterPushManifest'")
	}

	return nil
}
