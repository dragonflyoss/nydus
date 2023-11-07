// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package copier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/content"
	containerdErrdefs "github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/reference/docker"
	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/parser"
	nydusifyUtils "github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
	"github.com/dustin/go-humanize"
	"github.com/goharbor/acceleration-service/pkg/errdefs"
	"github.com/goharbor/acceleration-service/pkg/platformutil"
	"github.com/goharbor/acceleration-service/pkg/remote"
	"github.com/goharbor/acceleration-service/pkg/utils"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type Opt struct {
	WorkDir        string
	NydusImagePath string

	Source string
	Target string

	SourceInsecure bool
	TargetInsecure bool

	SourceBackendType   string
	SourceBackendConfig string

	TargetBackendType   string
	TargetBackendConfig string

	AllPlatforms bool
	Platforms    string
}

type output struct {
	Blobs []string
}

func hosts(opt Opt) remote.HostFunc {
	maps := map[string]bool{
		opt.Source: opt.SourceInsecure,
		opt.Target: opt.TargetInsecure,
	}
	return func(ref string) (remote.CredentialFunc, bool, error) {
		return remote.NewDockerConfigCredFunc(), maps[ref], nil
	}
}

func getPushWriter(ctx context.Context, pvd *provider.Provider, desc ocispec.Descriptor, opt Opt) (content.Writer, error) {
	resolver, err := pvd.Resolver(opt.Target)
	if err != nil {
		return nil, errors.Wrap(err, "get resolver")
	}
	ref := opt.Target
	if !strings.Contains(ref, "@") {
		ref = ref + "@" + desc.Digest.String()
	}
	pusher, err := resolver.Pusher(ctx, ref)
	if err != nil {
		return nil, errors.Wrap(err, "create pusher")
	}
	writer, err := pusher.Push(ctx, desc)
	if err != nil {
		if containerdErrdefs.IsAlreadyExists(err) {
			return nil, nil
		}
		return nil, err
	}
	return writer, nil
}

func pushBlobFromBackend(
	ctx context.Context, pvd *provider.Provider, backend backend.Backend, src ocispec.Descriptor, opt Opt,
) ([]ocispec.Descriptor, *ocispec.Descriptor, error) {
	if src.MediaType != ocispec.MediaTypeImageManifest && src.MediaType != images.MediaTypeDockerSchema2Manifest {
		return nil, nil, fmt.Errorf("unsupported media type %s", src.MediaType)
	}
	manifest := ocispec.Manifest{}
	if _, err := utils.ReadJSON(ctx, pvd.ContentStore(), &manifest, src); err != nil {
		return nil, nil, errors.Wrap(err, "read manifest from store")
	}
	bootstrapDesc := parser.FindNydusBootstrapDesc(&manifest)
	if bootstrapDesc == nil {
		return nil, nil, nil
	}
	ra, err := pvd.ContentStore().ReaderAt(ctx, *bootstrapDesc)
	if err != nil {
		return nil, nil, errors.Wrap(err, "prepare reading bootstrap")
	}
	bootstrapPath := filepath.Join(opt.WorkDir, "bootstrap.tgz")
	if err := nydusifyUtils.UnpackFile(io.NewSectionReader(ra, 0, ra.Size()), nydusifyUtils.BootstrapFileNameInLayer, bootstrapPath); err != nil {
		return nil, nil, errors.Wrap(err, "unpack bootstrap layer")
	}
	outputPath := filepath.Join(opt.WorkDir, "output.json")
	builder := tool.NewBuilder(opt.NydusImagePath)
	if err := builder.Check(tool.BuilderOption{
		BootstrapPath:   bootstrapPath,
		DebugOutputPath: outputPath,
	}); err != nil {
		return nil, nil, errors.Wrap(err, "check bootstrap")
	}
	var out output
	bytes, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read output file")
	}
	if err := json.Unmarshal(bytes, &out); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshal output json")
	}

	// Deduplicate the blobs for avoiding uploading repeatedly.
	blobIDs := []string{}
	blobIDMap := map[string]bool{}
	for _, blobID := range out.Blobs {
		if blobIDMap[blobID] {
			continue
		}
		blobIDs = append(blobIDs, blobID)
		blobIDMap[blobID] = true
	}

	sem := semaphore.NewWeighted(int64(provider.LayerConcurrentLimit))
	eg, ctx := errgroup.WithContext(ctx)
	blobDescs := make([]ocispec.Descriptor, len(blobIDs))
	for idx := range blobIDs {
		func(idx int) {
			eg.Go(func() error {
				sem.Acquire(context.Background(), 1)
				defer sem.Release(1)

				blobID := blobIDs[idx]
				blobDigest := digest.Digest("sha256:" + blobID)
				blobSize, err := backend.Size(blobID)
				if err != nil {
					return errors.Wrap(err, "get blob size")
				}
				blobSizeStr := humanize.Bytes(uint64(blobSize))

				logrus.WithField("digest", blobDigest).WithField("size", blobSizeStr).Infof("pushing blob from backend")
				rc, err := backend.Reader(blobID)
				if err != nil {
					return errors.Wrap(err, "get blob reader")
				}
				defer rc.Close()
				blobDescs[idx] = ocispec.Descriptor{
					Digest:    blobDigest,
					Size:      blobSize,
					MediaType: converter.MediaTypeNydusBlob,
					Annotations: map[string]string{
						converter.LayerAnnotationNydusBlob: "true",
					},
				}
				writer, err := getPushWriter(ctx, pvd, blobDescs[idx], opt)
				if err != nil {
					if errdefs.NeedsRetryWithHTTP(err) {
						pvd.UsePlainHTTP()
						writer, err = getPushWriter(ctx, pvd, blobDescs[idx], opt)
					}
					if err != nil {
						return errors.Wrap(err, "get push writer")
					}
				}
				if writer != nil {
					defer writer.Close()
					return content.Copy(ctx, writer, rc, blobSize, blobDigest)
				}

				logrus.WithField("digest", blobDigest).WithField("size", blobSizeStr).Infof("pushed blob from backend")

				return nil
			})
		}(idx)
	}

	if err := eg.Wait(); err != nil {
		return nil, nil, errors.Wrap(err, "push blobs")
	}

	// Update manifest layers
	for idx := range manifest.Layers {
		if manifest.Layers[idx].Annotations != nil {
			// The annotation key is deprecated, but it still exists in some
			// old nydus images, let's clean it up.
			delete(manifest.Layers[idx].Annotations, "containerd.io/snapshot/nydus-blob-ids")
		}
	}
	manifest.Layers = append(blobDescs, manifest.Layers...)

	// Update image config
	blobDigests := []digest.Digest{}
	for idx := range blobDescs {
		blobDigests = append(blobDigests, blobDescs[idx].Digest)
	}
	config := ocispec.Image{}
	if _, err := utils.ReadJSON(ctx, pvd.ContentStore(), &config, manifest.Config); err != nil {
		return nil, nil, errors.Wrap(err, "read config json")
	}
	config.RootFS.DiffIDs = append(blobDigests, config.RootFS.DiffIDs...)
	configDesc, err := utils.WriteJSON(ctx, pvd.ContentStore(), config, manifest.Config, opt.Target, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write config json")
	}
	manifest.Config = *configDesc

	target, err := utils.WriteJSON(ctx, pvd.ContentStore(), &manifest, src, opt.Target, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write manifest json")
	}

	return blobDescs, target, nil
}

func getPlatform(platform *ocispec.Platform) string {
	if platform == nil {
		return platforms.DefaultString()
	}
	return platforms.Format(*platform)
}

func Copy(ctx context.Context, opt Opt) error {
	// Containerd image fetch requires a namespace context.
	ctx = namespaces.WithNamespace(ctx, "nydusify")

	platformMC, err := platformutil.ParsePlatforms(opt.AllPlatforms, opt.Platforms)
	if err != nil {
		return err
	}

	var bkd backend.Backend
	if opt.SourceBackendType != "" {
		bkd, err = backend.NewBackend(opt.SourceBackendType, []byte(opt.SourceBackendConfig), nil)
		if err != nil {
			return errors.Wrapf(err, "new backend")
		}
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
	pvd, err := provider.New(tmpDir, hosts(opt), 200, "v1", platformMC)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	sourceNamed, err := docker.ParseDockerRef(opt.Source)
	if err != nil {
		return errors.Wrap(err, "parse source reference")
	}
	targetNamed, err := docker.ParseDockerRef(opt.Target)
	if err != nil {
		return errors.Wrap(err, "parse target reference")
	}
	source := sourceNamed.String()
	target := targetNamed.String()

	logrus.Infof("pulling source image %s", source)
	if err := pvd.Pull(ctx, source); err != nil {
		if errdefs.NeedsRetryWithHTTP(err) {
			pvd.UsePlainHTTP()
			if err := pvd.Pull(ctx, source); err != nil {
				return errors.Wrap(err, "try to pull image")
			}
		} else {
			return errors.Wrap(err, "pull source image")
		}
	}
	logrus.Infof("pulled source image %s", source)

	sourceImage, err := pvd.Image(ctx, source)
	if err != nil {
		return errors.Wrap(err, "find image from store")
	}

	sourceDescs, err := utils.GetManifests(ctx, pvd.ContentStore(), *sourceImage, platformMC)
	if err != nil {
		return errors.Wrap(err, "get image manifests")
	}
	targetDescs := make([]ocispec.Descriptor, len(sourceDescs))

	sem := semaphore.NewWeighted(1)
	eg := errgroup.Group{}
	for idx := range sourceDescs {
		func(idx int) {
			eg.Go(func() error {
				sem.Acquire(context.Background(), 1)
				defer sem.Release(1)

				sourceDesc := sourceDescs[idx]
				targetDesc := &sourceDesc
				if bkd != nil {
					descs, _targetDesc, err := pushBlobFromBackend(ctx, pvd, bkd, sourceDesc, opt)
					if err != nil {
						return errors.Wrap(err, "get resolver")
					}
					if _targetDesc == nil {
						logrus.WithField("platform", getPlatform(sourceDesc.Platform)).Warnf("%s is not a nydus image", source)
					} else {
						targetDesc = _targetDesc
						store := newStore(pvd.ContentStore(), descs)
						pvd.SetContentStore(store)
					}
				}
				targetDescs[idx] = *targetDesc

				logrus.WithField("platform", getPlatform(sourceDesc.Platform)).Infof("pushing target manifest %s", targetDesc.Digest)
				if err := pvd.Push(ctx, *targetDesc, target); err != nil {
					if errdefs.NeedsRetryWithHTTP(err) {
						pvd.UsePlainHTTP()
						if err := pvd.Push(ctx, *targetDesc, target); err != nil {
							return errors.Wrap(err, "try to push image manifest")
						}
					} else {
						return errors.Wrap(err, "push target image manifest")
					}
				}
				logrus.WithField("platform", getPlatform(sourceDesc.Platform)).Infof("pushed target manifest %s", targetDesc.Digest)

				return nil
			})
		}(idx)
	}
	if err := eg.Wait(); err != nil {
		return errors.Wrap(err, "push image manifests")
	}

	if sourceImage.MediaType == ocispec.MediaTypeImageIndex ||
		sourceImage.MediaType == images.MediaTypeDockerSchema2ManifestList {
		targetIndex := ocispec.Index{}
		if _, err := utils.ReadJSON(ctx, pvd.ContentStore(), &targetIndex, *sourceImage); err != nil {
			return errors.Wrap(err, "read source manifest list")
		}
		targetIndex.Manifests = targetDescs

		targetImage, err := utils.WriteJSON(ctx, pvd.ContentStore(), targetIndex, *sourceImage, target, nil)
		if err != nil {
			return errors.Wrap(err, "write target manifest list")
		}
		if err := pvd.Push(ctx, *targetImage, target); err != nil {
			if errdefs.NeedsRetryWithHTTP(err) {
				pvd.UsePlainHTTP()
				if err := pvd.Push(ctx, *targetImage, target); err != nil {
					return errors.Wrap(err, "try to push image")
				}
			} else {
				return errors.Wrap(err, "push target image")
			}
		}
		logrus.Infof("pushed image %s", target)
	}

	return nil
}
