// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package copier

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BraveY/snapshotter-converter/converter"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	containerdErrdefs "github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/distribution/reference"
	"github.com/dustin/go-humanize"
	accelcontent "github.com/goharbor/acceleration-service/pkg/content"
	"github.com/goharbor/acceleration-service/pkg/errdefs"
	"github.com/goharbor/acceleration-service/pkg/platformutil"
	"github.com/goharbor/acceleration-service/pkg/remote"
	"github.com/goharbor/acceleration-service/pkg/utils"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	nydusifyUtils "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
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

	PushChunkSize int64
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

func getPusherInChunked(ctx context.Context, pvd *provider.Provider, desc ocispec.Descriptor, opt Opt) (remotes.PusherInChunked, error) {
	resolver, err := pvd.Resolver(opt.Target)
	if err != nil {
		return nil, errors.Wrap(err, "get resolver")
	}
	ref := opt.Target
	if !strings.Contains(ref, "@") {
		ref = ref + "@" + desc.Digest.String()
	}

	pusherInChunked, err := resolver.PusherInChunked(ctx, ref)
	if err != nil {
		return nil, errors.Wrap(err, "create pusher in chunked")
	}

	return pusherInChunked, nil
}

func loadManifestAndBlobIDs(
	ctx context.Context, pvd *provider.Provider, src ocispec.Descriptor, opt Opt,
) (*ocispec.Manifest, []string, *ocispec.Descriptor, error) {
	if src.MediaType != ocispec.MediaTypeImageManifest && src.MediaType != images.MediaTypeDockerSchema2Manifest {
		return nil, nil, nil, fmt.Errorf("unsupported media type %s", src.MediaType)
	}

	manifest := &ocispec.Manifest{}
	if _, err := utils.ReadJSON(ctx, pvd.ContentStore(), manifest, src); err != nil {
		return nil, nil, nil, errors.Wrap(err, "read manifest from store")
	}

	bootstrapDesc := parser.FindNydusBootstrapDesc(manifest)
	if bootstrapDesc == nil {
		return manifest, nil, nil, nil
	}

	workDir, err := os.MkdirTemp(opt.WorkDir, "copy-bootstrap-")
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "create temp directory")
	}
	defer os.RemoveAll(workDir)

	ra, err := pvd.ContentStore().ReaderAt(ctx, *bootstrapDesc)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "prepare reading bootstrap")
	}
	bootstrapPath := filepath.Join(workDir, "bootstrap.tgz")
	if err := nydusifyUtils.UnpackFile(io.NewSectionReader(ra, 0, ra.Size()), nydusifyUtils.BootstrapFileNameInLayer, bootstrapPath); err != nil {
		return nil, nil, nil, errors.Wrap(err, "unpack bootstrap layer")
	}
	outputPath := filepath.Join(workDir, "output.json")
	builder := tool.NewBuilder(opt.NydusImagePath)
	if err := builder.Check(tool.BuilderOption{
		BootstrapPath:   bootstrapPath,
		DebugOutputPath: outputPath,
	}); err != nil {
		return nil, nil, nil, errors.Wrap(err, "check bootstrap")
	}

	var out output
	bytes, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, "read output file")
	}
	if err := json.Unmarshal(bytes, &out); err != nil {
		return nil, nil, nil, errors.Wrap(err, "unmarshal output json")
	}

	blobIDs := make([]string, 0, len(out.Blobs))
	blobIDMap := map[string]bool{}
	for _, blobID := range out.Blobs {
		if blobIDMap[blobID] {
			continue
		}
		blobIDs = append(blobIDs, blobID)
		blobIDMap[blobID] = true
	}

	return manifest, blobIDs, bootstrapDesc, nil
}

func pushReader(ctx context.Context, pvd *provider.Provider, desc ocispec.Descriptor, opt Opt, reader io.Reader) error {
	return nydusifyUtils.RetryWithAttempts(func() error {
		pusher, err := getPusherInChunked(ctx, pvd, desc, opt)
		if err != nil {
			if errdefs.NeedsRetryWithHTTP(err) {
				pvd.UsePlainHTTP()
				pusher, err = getPusherInChunked(ctx, pvd, desc, opt)
			}
			if err != nil {
				return errors.Wrapf(err, "get push writer: %s", desc.Digest)
			}
		}

		writer, err := pusher.Push(ctx, desc)
		if err != nil {
			if containerdErrdefs.IsAlreadyExists(err) {
				return nil
			}
			return errors.Wrapf(err, "get push writer: %s", desc.Digest)
		}
		if writer == nil {
			return nil
		}
		defer writer.Close()

		if err := content.Copy(ctx, writer, reader, desc.Size, desc.Digest); err != nil {
			if containerdErrdefs.IsAlreadyExists(err) {
				return nil
			}
			return errors.Wrapf(err, "push content: %s", desc.Digest)
		}

		return nil
	}, 3)
}

func blobPathFromReader(ctx context.Context, opt Opt, blobID string, reader io.Reader) (string, int64, error) {
	file, err := os.CreateTemp(opt.WorkDir, "copy-blob-"+blobID+"-")
	if err != nil {
		return "", 0, errors.Wrap(err, "create blob temp file")
	}

	size, copyErr := io.Copy(file, reader)
	closeErr := file.Close()
	if copyErr != nil {
		os.Remove(file.Name())
		return "", 0, errors.Wrap(copyErr, "write blob temp file")
	}
	if closeErr != nil {
		os.Remove(file.Name())
		return "", 0, errors.Wrap(closeErr, "close blob temp file")
	}

	return file.Name(), size, nil
}

func blobPathFromDesc(ctx context.Context, pvd *provider.Provider, desc ocispec.Descriptor, opt Opt) (string, int64, error) {
	ra, err := pvd.ContentStore().ReaderAt(ctx, desc)
	if err != nil {
		return "", 0, errors.Wrap(err, "prepare reading blob")
	}
	return blobPathFromReader(ctx, opt, desc.Digest.Encoded(), io.NewSectionReader(ra, 0, ra.Size()))
}

func removeBootstrapBackendConfig(workDir string) error {
	backendConfigPath := filepath.Join(workDir, nydusifyUtils.BackendFileNameInLayer)
	err := os.Remove(backendConfigPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Wrap(err, "remove bootstrap backend config")
	}
	return nil
}

func repackBootstrapLayer(
	ctx context.Context, pvd *provider.Provider, bootstrapDesc ocispec.Descriptor, opt Opt,
) (*ocispec.Descriptor, digest.Digest, error) {
	workDir, err := os.MkdirTemp(opt.WorkDir, "copy-bootstrap-layer-")
	if err != nil {
		return nil, "", errors.Wrap(err, "create bootstrap temp directory")
	}
	defer os.RemoveAll(workDir)

	ra, err := pvd.ContentStore().ReaderAt(ctx, bootstrapDesc)
	if err != nil {
		return nil, "", errors.Wrap(err, "prepare reading bootstrap layer")
	}
	if err := nydusifyUtils.UnpackTargz(ctx, workDir, io.NewSectionReader(ra, 0, ra.Size()), false); err != nil {
		return nil, "", errors.Wrap(err, "unpack bootstrap targz")
	}

	if err := removeBootstrapBackendConfig(workDir); err != nil {
		return nil, "", err
	}

	archivePath := filepath.Join(workDir, "bootstrap.tar.gz")
	archive, err := os.Create(archivePath)
	if err != nil {
		return nil, "", errors.Wrap(err, "create bootstrap archive")
	}

	compressedDigester := digest.Canonical.Digester()
	uncompressedDigester := digest.Canonical.Digester()
	gzWriter := gzip.NewWriter(io.MultiWriter(archive, compressedDigester.Hash()))
	tarWriter := tar.NewWriter(io.MultiWriter(gzWriter, uncompressedDigester.Hash()))

	var relPaths []string
	if err := filepath.Walk(workDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == workDir || path == archivePath {
			return nil
		}
		relPath, err := filepath.Rel(workDir, path)
		if err != nil {
			return err
		}
		relPaths = append(relPaths, relPath)
		return nil
	}); err != nil {
		archive.Close()
		return nil, "", errors.Wrap(err, "walk bootstrap files")
	}
	sort.Strings(relPaths)

	for _, relPath := range relPaths {
		path := filepath.Join(workDir, relPath)
		info, err := os.Lstat(path)
		if err != nil {
			archive.Close()
			return nil, "", errors.Wrap(err, "stat bootstrap file")
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			archive.Close()
			return nil, "", errors.Wrap(err, "build bootstrap tar header")
		}
		hdr.Name = filepath.ToSlash(relPath)
		if info.IsDir() {
			hdr.Name += "/"
		}
		if err := tarWriter.WriteHeader(hdr); err != nil {
			archive.Close()
			return nil, "", errors.Wrap(err, "write bootstrap tar header")
		}
		if info.Mode().IsRegular() {
			file, err := os.Open(path)
			if err != nil {
				archive.Close()
				return nil, "", errors.Wrap(err, "open bootstrap file")
			}
			if _, err := io.Copy(tarWriter, file); err != nil {
				file.Close()
				archive.Close()
				return nil, "", errors.Wrap(err, "write bootstrap tar body")
			}
			file.Close()
		}
	}

	if err := tarWriter.Close(); err != nil {
		archive.Close()
		return nil, "", errors.Wrap(err, "close bootstrap tar writer")
	}
	if err := gzWriter.Close(); err != nil {
		archive.Close()
		return nil, "", errors.Wrap(err, "close bootstrap gzip writer")
	}
	if err := archive.Close(); err != nil {
		return nil, "", errors.Wrap(err, "close bootstrap archive")
	}

	archiveInfo, err := os.Stat(archivePath)
	if err != nil {
		return nil, "", errors.Wrap(err, "stat bootstrap archive")
	}

	bootstrapTargetDesc := bootstrapDesc
	bootstrapTargetDesc.Digest = compressedDigester.Digest()
	bootstrapTargetDesc.Size = archiveInfo.Size()

	reader, err := os.Open(archivePath)
	if err != nil {
		return nil, "", errors.Wrap(err, "open bootstrap archive")
	}
	defer reader.Close()

	if err := pushReader(ctx, pvd, bootstrapTargetDesc, opt, reader); err != nil {
		return nil, "", errors.Wrap(err, "push bootstrap layer")
	}

	return &bootstrapTargetDesc, uncompressedDigester.Digest(), nil
}

func rewriteManifestForTargetBackend(
	manifest *ocispec.Manifest, config *ocispec.Image, bootstrapDesc ocispec.Descriptor, bootstrapDiffID digest.Digest,
) {
	manifest.Layers = []ocispec.Descriptor{bootstrapDesc}
	config.RootFS.DiffIDs = []digest.Digest{bootstrapDiffID}
}

func pushBlobFromBackend(
	ctx context.Context, pvd *provider.Provider, backend backend.Backend, src ocispec.Descriptor, opt Opt,
) ([]ocispec.Descriptor, *ocispec.Descriptor, error) {
	manifest, blobIDs, bootstrapDesc, err := loadManifestAndBlobIDs(ctx, pvd, src, opt)
	if err != nil {
		return nil, nil, err
	}
	if bootstrapDesc == nil {
		return nil, nil, nil
	}

	sem := semaphore.NewWeighted(int64(provider.LayerConcurrentLimit))
	eg, groupCtx := errgroup.WithContext(ctx)
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
				blobDescs[idx] = ocispec.Descriptor{
					Digest:    blobDigest,
					Size:      blobSize,
					MediaType: converter.MediaTypeNydusBlob,
					Annotations: map[string]string{
						converter.LayerAnnotationNydusBlob: "true",
					},
				}

				if err := nydusifyUtils.RetryWithAttempts(func() error {
					pusher, err := getPusherInChunked(groupCtx, pvd, blobDescs[idx], opt)
					if err != nil {
						if errdefs.NeedsRetryWithHTTP(err) {
							pvd.UsePlainHTTP()
							pusher, err = getPusherInChunked(groupCtx, pvd, blobDescs[idx], opt)
						}
						if err != nil {
							return errors.Wrapf(err, "get push writer: %s", blobDigest)
						}
					}

					push := func() error {
						if blobSize > opt.PushChunkSize {
							rr, err := backend.RangeReader(blobID)
							if err != nil {
								return errors.Wrapf(err, "get push reader: %s", blobDigest)
							}
							if err := pusher.PushInChunked(groupCtx, blobDescs[idx], rr); err != nil {
								return errors.Wrapf(err, "push blob in chunked: %s", blobDigest)
							}
						} else {
							rc, err := backend.Reader(blobID)
							if err != nil {
								return errors.Wrap(err, "get blob reader")
							}
							defer rc.Close()
							writer, err := pusher.Push(groupCtx, blobDescs[idx])
							if err != nil {
								return errors.Wrapf(err, "get push writer: %s", blobDigest)
							}
							if writer != nil {
								defer writer.Close()
								if err := content.Copy(groupCtx, writer, rc, blobSize, blobDigest); err != nil {
									return errors.Wrapf(err, "push blob: %s", blobDigest)
								}
							}
						}
						return nil
					}

					if err := push(); err != nil {
						if containerdErrdefs.IsAlreadyExists(err) {
							logrus.WithField("digest", blobDigest).WithField("size", blobSizeStr).Infof("pushed blob from backend (exists)")
							return nil
						}
						return errors.Wrapf(err, "copy blob content: %s", blobDigest)
					}
					logrus.WithField("digest", blobDigest).WithField("size", blobSizeStr).Infof("pushed blob from backend")

					return nil
				}, 3); err != nil {
					return errors.Wrapf(err, "push blob: %s", blobDigest)
				}

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

func pushBlobToBackend(
	ctx context.Context, pvd *provider.Provider, sourceBackend backend.Backend, targetBackend backend.Backend, src ocispec.Descriptor, opt Opt,
) ([]ocispec.Descriptor, *ocispec.Descriptor, error) {
	manifest, blobIDs, bootstrapDesc, err := loadManifestAndBlobIDs(ctx, pvd, src, opt)
	if err != nil {
		return nil, nil, err
	}
	if bootstrapDesc == nil {
		return nil, nil, nil
	}

	layerByDigest := make(map[digest.Digest]ocispec.Descriptor, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		layerByDigest[layer.Digest] = layer
	}

	blobDescs := make([]ocispec.Descriptor, len(blobIDs))
	sem := semaphore.NewWeighted(int64(provider.LayerConcurrentLimit))
	eg, groupCtx := errgroup.WithContext(ctx)
	finalized := false
	defer func() {
		if !finalized {
			if err := targetBackend.Finalize(true); err != nil {
				logrus.WithError(err).Warn("cancel target backend upload")
			}
		}
	}()

	for idx := range blobIDs {
		func(idx int) {
			eg.Go(func() error {
				sem.Acquire(context.Background(), 1)
				defer sem.Release(1)

				blobID := blobIDs[idx]
				blobDigest := digest.Digest("sha256:" + blobID)

				var (
					blobPath string
					blobSize int64
				)
				if sourceBackend != nil {
					reader, err := sourceBackend.Reader(blobID)
					if err != nil {
						return errors.Wrap(err, "get source backend blob reader")
					}
					defer reader.Close()

					blobPath, blobSize, err = blobPathFromReader(groupCtx, opt, blobID, reader)
					if err != nil {
						return err
					}
				} else {
					layerDesc, ok := layerByDigest[blobDigest]
					if !ok {
						return errors.Errorf("blob layer %s not found in manifest", blobDigest)
					}
					var err error
					blobPath, blobSize, err = blobPathFromDesc(groupCtx, pvd, layerDesc, opt)
					if err != nil {
						return err
					}
				}
				defer os.Remove(blobPath)

				blobSizeStr := humanize.Bytes(uint64(blobSize))
				logrus.WithField("digest", blobDigest).WithField("size", blobSizeStr).Infof("pushing blob to backend")

				desc, err := targetBackend.Upload(groupCtx, blobID, blobPath, blobSize, false)
				if err != nil {
					return errors.Wrapf(err, "push blob to backend: %s", blobDigest)
				}
				blobDescs[idx] = *desc

				logrus.WithField("digest", blobDigest).WithField("size", blobSizeStr).Infof("pushed blob to backend")
				return nil
			})
		}(idx)
	}

	if err := eg.Wait(); err != nil {
		return nil, nil, errors.Wrap(err, "push blobs to backend")
	}
	if err := targetBackend.Finalize(false); err != nil {
		return nil, nil, errors.Wrap(err, "finalize target backend upload")
	}
	finalized = true

	targetBootstrapDesc, bootstrapDiffID, err := repackBootstrapLayer(ctx, pvd, *bootstrapDesc, opt)
	if err != nil {
		return nil, nil, err
	}

	config := ocispec.Image{}
	if _, err := utils.ReadJSON(ctx, pvd.ContentStore(), &config, manifest.Config); err != nil {
		return nil, nil, errors.Wrap(err, "read config json")
	}
	rewriteManifestForTargetBackend(manifest, &config, *targetBootstrapDesc, bootstrapDiffID)
	configDesc, err := utils.WriteJSON(ctx, pvd.ContentStore(), config, manifest.Config, opt.Target, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write config json")
	}
	manifest.Config = *configDesc

	target, err := utils.WriteJSON(ctx, pvd.ContentStore(), manifest, src, opt.Target, nil)
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

// getLocalPath checks if the given reference is a local file path and returns its absolute path.
//
// Parameters:
// - ref: A string which may be a docker reference or a local file path prefixed with "file://".
//
// Returns:
// - isLocalPath: A boolean indicating whether the reference is a local file path.
// - absPath: A string containing the absolute path of the local file, if applicable.
// - err: An error object if any error occurs during the process of getting the absolute path.
func getLocalPath(ref string) (isLocalPath bool, absPath string, err error) {
	if !strings.HasPrefix(ref, "file://") {
		return false, "", nil
	}
	path := strings.TrimPrefix(ref, "file://")
	absPath, err = filepath.Abs(path)
	if err != nil {
		return true, "", err
	}
	return true, absPath, nil
}

// Copy copies an image from the source to the target.
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

	var targetBkd backend.Backend
	if opt.TargetBackendType != "" {
		targetBkd, err = backend.NewBackend(opt.TargetBackendType, []byte(opt.TargetBackendConfig), nil)
		if err != nil {
			return errors.Wrapf(err, "new target backend")
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

	// Use stream-based content store: avoids local ingestion of pulled layer data, reads remotely on demand
	baseStore, err := accelcontent.NewContent(hosts(opt), filepath.Join(tmpDir, "content"), tmpDir, "0MB")
	if err != nil {
		return err
	}
	streamStore := provider.NewStreamContent(baseStore, hosts(opt))

	pvd, err := provider.New(tmpDir, hosts(opt), 200, "v1", platformMC, opt.PushChunkSize, streamStore)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	isLocalSource, inputPath, err := getLocalPath(opt.Source)
	if err != nil {
		return errors.Wrap(err, "parse source path")
	}
	var source string
	if isLocalSource {
		logrus.Infof("importing source image from %s", inputPath)

		f, err := os.Open(inputPath)
		if err != nil {
			return err
		}
		defer f.Close()

		ds, err := compression.DecompressStream(f)
		if err != nil {
			return err
		}
		defer ds.Close()

		var sourceImage images.Image
		if sourceImage, err = pvd.Import(ctx, ds); err != nil {
			return errors.Wrap(err, "import source image")
		}
		source = sourceImage.Name
		logrus.Infof("imported source image %s", source)
	} else {
		sourceNamed, err := reference.ParseDockerRef(opt.Source)
		if err != nil {
			return errors.Wrap(err, "parse source reference")
		}
		source = sourceNamed.String()

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
	}

	sourceImage, err := pvd.Image(ctx, source)
	if err != nil {
		return errors.Wrap(err, "find image from store")
	}

	isLocalTarget, outputPath, err := getLocalPath(opt.Target)
	if err != nil {
		return errors.Wrap(err, "parse target path")
	}
	if isLocalTarget {
		logrus.Infof("exporting source image to %s", outputPath)
		f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := pvd.Export(ctx, f, sourceImage, source); err != nil {
			return errors.Wrap(err, "export source image to target tar file")
		}
		logrus.Infof("exported image %s", source)
		return nil
	}

	sourceDescs, err := utils.GetManifests(ctx, pvd.ContentStore(), *sourceImage, platformMC)
	if err != nil {
		return errors.Wrap(err, "get image manifests")
	}
	targetDescs := make([]ocispec.Descriptor, len(sourceDescs))

	targetNamed, err := reference.ParseDockerRef(opt.Target)
	if err != nil {
		return errors.Wrap(err, "parse target reference")
	}
	target := targetNamed.String()

	sem := semaphore.NewWeighted(1)
	eg := errgroup.Group{}
	for idx := range sourceDescs {
		func(idx int) {
			eg.Go(func() error {
				sem.Acquire(context.Background(), 1)
				defer sem.Release(1)

				sourceDesc := sourceDescs[idx]
				targetDesc := &sourceDesc
				if targetBkd != nil {
					descs, _targetDesc, err := pushBlobToBackend(ctx, pvd, bkd, targetBkd, sourceDesc, opt)
					if err != nil {
						return errors.Wrap(err, "push blobs to target backend")
					}
					if _targetDesc == nil {
						logrus.WithField("platform", getPlatform(sourceDesc.Platform)).Warnf("%s is not a nydus image", source)
					} else {
						targetDesc = _targetDesc
						store := newStore(pvd.ContentStore(), descs)
						pvd.SetContentStore(store)
					}
				} else if bkd != nil {
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

	if len(targetDescs) > 1 && (sourceImage.MediaType == ocispec.MediaTypeImageIndex ||
		sourceImage.MediaType == images.MediaTypeDockerSchema2ManifestList) {
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
