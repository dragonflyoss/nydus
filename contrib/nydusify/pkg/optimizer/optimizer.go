// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package optimizer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/distribution/reference"
	accerr "github.com/goharbor/acceleration-service/pkg/errdefs"
	"github.com/goharbor/acceleration-service/pkg/platformutil"
	accremote "github.com/goharbor/acceleration-service/pkg/remote"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/committer"
	converterpvd "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

const (
	EntryBootstrap     = "image.boot"
	EntryPrefetchFiles = "prefetch.files"
)

type Opt struct {
	WorkDir        string
	NydusImagePath string

	Source string
	Target string

	SourceInsecure bool
	TargetInsecure bool

	OptimizePolicy    string
	PrefetchFilesPath string

	AllPlatforms bool
	Platforms    string

	PushChunkSize int64
}

// the information generated during building
type BuildInfo struct {
	SourceImage      parser.Image
	BuildDir         string
	BlobDir          string
	PrefetchBlobID   string
	NewBootstrapPath string
}

type File struct {
	Name   string
	Reader io.Reader
	Size   int64
}

type bootstrapInfo struct {
	bootstrapDesc   ocispec.Descriptor
	bootstrapDiffID digest.Digest
}

func hosts(opt Opt) accremote.HostFunc {
	maps := map[string]bool{
		opt.Source: opt.SourceInsecure,
		opt.Target: opt.TargetInsecure,
	}
	return func(ref string) (accremote.CredentialFunc, bool, error) {
		return accremote.NewDockerConfigCredFunc(), maps[ref], nil
	}
}

func remoter(opt Opt) (*remote.Remote, error) {
	targetRef, err := committer.ValidateRef(opt.Target)
	if err != nil {
		return nil, errors.Wrap(err, "validate target reference")
	}
	remoter, err := provider.DefaultRemote(targetRef, opt.TargetInsecure)
	if err != nil {
		return nil, errors.Wrap(err, "create remote")
	}
	return remoter, nil
}

func makeDesc(x interface{}, oldDesc ocispec.Descriptor) ([]byte, *ocispec.Descriptor, error) {
	data, err := json.MarshalIndent(x, "", "  ")
	if err != nil {
		return nil, nil, errors.Wrap(err, "json marshal")
	}
	dgst := digest.SHA256.FromBytes(data)

	newDesc := oldDesc
	newDesc.Size = int64(len(data))
	newDesc.Digest = dgst

	return data, &newDesc, nil
}

// packToTar packs files to .tar(.gz) stream then return reader.
//
//	ported from https://github.com/containerd/nydus-snapshotter/blob/5f948e4498151b51c742d2ee0b3f7b96f86a26f7/pkg/converter/utils.go#L92
func packToTar(files []File, compress bool) io.ReadCloser {
	dirHdr := &tar.Header{
		Name:     "image",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}

	pr, pw := io.Pipe()

	go func() {
		// Prepare targz writer
		var tw *tar.Writer
		var gw *gzip.Writer
		var err error

		if compress {
			gw = gzip.NewWriter(pw)
			tw = tar.NewWriter(gw)
		} else {
			tw = tar.NewWriter(pw)
		}

		defer func() {
			err1 := tw.Close()
			var err2 error
			if gw != nil {
				err2 = gw.Close()
			}

			var finalErr error

			// Return the first error encountered to the other end and ignore others.
			switch {
			case err != nil:
				finalErr = err
			case err1 != nil:
				finalErr = err1
			case err2 != nil:
				finalErr = err2
			}

			pw.CloseWithError(finalErr)
		}()

		// Write targz stream
		if err = tw.WriteHeader(dirHdr); err != nil {
			return
		}

		for _, file := range files {
			hdr := tar.Header{
				Name: filepath.Join("image", file.Name),
				Mode: 0444,
				Size: file.Size,
			}
			if err = tw.WriteHeader(&hdr); err != nil {
				return
			}
			if _, err = io.Copy(tw, file.Reader); err != nil {
				return
			}
		}
	}()

	return pr
}

func getOriginalBlobLayers(nydusImage parser.Image) []ocispec.Descriptor {
	originalBlobLayers := []ocispec.Descriptor{}
	for idx := range nydusImage.Manifest.Layers {
		layer := nydusImage.Manifest.Layers[idx]
		if layer.MediaType == utils.MediaTypeNydusBlob {
			originalBlobLayers = append(originalBlobLayers, layer)
		}
	}
	return originalBlobLayers
}

func fetchBlobs(ctx context.Context, opt Opt, buildDir string) error {
	logrus.Infof("pulling source image")
	start := time.Now()
	platformMC, err := platformutil.ParsePlatforms(opt.AllPlatforms, opt.Platforms)
	if err != nil {
		return err
	}
	pvd, err := converterpvd.New(buildDir, hosts(opt), 200, "v1", platformMC, opt.PushChunkSize)
	if err != nil {
		return err
	}

	sourceNamed, err := reference.ParseDockerRef(opt.Source)
	if err != nil {
		return errors.Wrap(err, "parse source reference")
	}
	source := sourceNamed.String()

	if err := pvd.Pull(ctx, source); err != nil {
		if accerr.NeedsRetryWithHTTP(err) {
			pvd.UsePlainHTTP()
			if err := pvd.Pull(ctx, source); err != nil {
				return errors.Wrap(err, "try to pull image")
			}
		} else {
			return errors.Wrap(err, "pull source image")
		}
	}
	logrus.Infof("pulled source image, elapsed: %s", time.Since(start))
	return nil
}

// Optimize coverts and push a new optimized nydus image
func Optimize(ctx context.Context, opt Opt) error {
	ctx = namespaces.WithNamespace(ctx, "nydusify")

	sourceRemote, err := provider.DefaultRemote(opt.Source, opt.SourceInsecure)
	if err != nil {
		return errors.Wrap(err, "Init source image parser")
	}
	sourceParser, err := parser.New(sourceRemote, runtime.GOARCH)
	if err != nil {
		return errors.Wrap(err, "failed to create parser")
	}

	sourceParsed, err := sourceParser.Parse(ctx)
	if err != nil {
		return errors.Wrap(err, "parse source image")
	}
	sourceNydusImage := sourceParsed.NydusImage

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
	buildDir, err := os.MkdirTemp(opt.WorkDir, "nydusify-")
	if err != nil {
		return errors.Wrap(err, "create temp directory")
	}
	defer os.RemoveAll(buildDir)

	if err := fetchBlobs(ctx, opt, buildDir); err != nil {
		return errors.Wrap(err, "prepare nydus blobs")
	}

	originalBootstrap := filepath.Join(buildDir, "nydus_bootstrap")
	bootstrapDesc := parser.FindNydusBootstrapDesc(&sourceNydusImage.Manifest)
	if bootstrapDesc == nil {
		return fmt.Errorf("not found Nydus bootstrap layer in manifest")
	}
	bootstrapReader, err := sourceParser.Remote.Pull(ctx, *bootstrapDesc, true)
	if err != nil {
		return errors.Wrap(err, "pull Nydus originalBootstrap layer")
	}
	defer bootstrapReader.Close()
	if err := utils.UnpackFile(bootstrapReader, utils.BootstrapFileNameInLayer, originalBootstrap); err != nil {
		return errors.Wrap(err, "unpack Nydus originalBootstrap layer")
	}

	compressAlgo := bootstrapDesc.Digest.Algorithm().String()
	blobDir := filepath.Join(buildDir + "/content/blobs/" + compressAlgo)
	outPutJSONPath := filepath.Join(buildDir, "output.json")
	newBootstrapPath := filepath.Join(buildDir, "optimized_bootstrap")
	builderOpt := BuildOption{
		BuilderPath:         opt.NydusImagePath,
		PrefetchFilesPath:   opt.PrefetchFilesPath,
		BootstrapPath:       originalBootstrap,
		BlobDir:             blobDir,
		OutputBootstrapPath: newBootstrapPath,
		OutputJSONPath:      outPutJSONPath,
	}
	logrus.Infof("begin to build new prefetch blob and bootstrap")
	start := time.Now()
	prefetchBlobID, err := Build(builderOpt)
	if err != nil {
		return errors.Wrap(err, "optimize nydus image")
	}
	logrus.Infof("builded new prefetch blob and bootstrap, elapsed: %s", time.Since(start))

	buildInfo := BuildInfo{
		SourceImage:      *sourceParsed.NydusImage,
		BuildDir:         buildDir,
		BlobDir:          blobDir,
		PrefetchBlobID:   prefetchBlobID,
		NewBootstrapPath: newBootstrapPath,
	}

	if err := pushNewImage(ctx, opt, buildInfo); err != nil {
		return errors.Wrap(err, "push new image")
	}
	return nil
}

// push blob
func pushBlob(ctx context.Context, opt Opt, buildInfo BuildInfo) (*ocispec.Descriptor, error) {
	blobDir := buildInfo.BlobDir
	blobID := buildInfo.PrefetchBlobID
	remoter, err := remoter(opt)
	if err != nil {
		return nil, errors.Wrap(err, "create remote")
	}

	blobRa, err := local.OpenReader(filepath.Join(blobDir, blobID))
	if err != nil {
		return nil, errors.Wrap(err, "open reader for upper blob")
	}

	blobDigest := digest.NewDigestFromEncoded(digest.SHA256, blobID)
	blobDesc := ocispec.Descriptor{
		Digest:    blobDigest,
		Size:      blobRa.Size(),
		MediaType: utils.MediaTypeNydusBlob,
		Annotations: map[string]string{
			utils.LayerAnnotationNydusBlob: "true",
		},
	}

	if err := remoter.Push(ctx, blobDesc, true, io.NewSectionReader(blobRa, 0, blobRa.Size())); err != nil {
		if utils.RetryWithHTTP(err) {
			remoter.MaybeWithHTTP(err)
			if err := remoter.Push(ctx, blobDesc, true, io.NewSectionReader(blobRa, 0, blobRa.Size())); err != nil {
				return nil, errors.Wrap(err, "push blob")
			}
		} else {
			return nil, errors.Wrap(err, "push blob")
		}
	}
	return &blobDesc, nil
}

func pushNewBootstrap(ctx context.Context, opt Opt, buildInfo BuildInfo) (*bootstrapInfo, error) {
	remoter, err := remoter(opt)
	if err != nil {
		return nil, errors.Wrap(err, "create remote")
	}
	bootstrapRa, err := local.OpenReader(buildInfo.NewBootstrapPath)
	if err != nil {
		return nil, errors.Wrap(err, "open reader for bootstrap")
	}
	prefetchfilesRa, err := local.OpenReader(opt.PrefetchFilesPath)
	if err != nil {
		return nil, errors.Wrap(err, "open reader for prefetch files")
	}
	files := []File{
		{
			Name:   EntryBootstrap,
			Reader: content.NewReader(bootstrapRa),
			Size:   bootstrapRa.Size(),
		}, {
			Name:   EntryPrefetchFiles,
			Reader: content.NewReader(prefetchfilesRa),
			Size:   prefetchfilesRa.Size(),
		},
	}
	rc := packToTar(files, false)
	defer rc.Close()

	bootstrapTarPath := filepath.Join(buildInfo.BuildDir, "bootstrap.tar")
	bootstrapTar, err := os.Create(bootstrapTarPath)
	if err != nil {
		return nil, errors.Wrap(err, "create bootstrap tar file")
	}
	defer bootstrapTar.Close()

	tarDigester := digest.SHA256.Digester()
	if _, err := io.Copy(io.MultiWriter(bootstrapTar, tarDigester.Hash()), rc); err != nil {
		return nil, errors.Wrap(err, "get tar digest")
	}
	bootstrapDiffID := tarDigester.Digest()

	bootstrapTarRa, err := os.Open(bootstrapTarPath)
	if err != nil {
		return nil, errors.Wrap(err, "open bootstrap tar file")
	}
	defer bootstrapTarRa.Close()

	bootstrapTarGzPath := filepath.Join(buildInfo.BuildDir, "bootstrap.tar.gz")
	bootstrapTarGz, err := os.Create(bootstrapTarGzPath)
	if err != nil {
		return nil, errors.Wrap(err, "create bootstrap tar.gz file")
	}
	defer bootstrapTarGz.Close()
	gzDigester := digest.SHA256.Digester()
	gzWriter := gzip.NewWriter(io.MultiWriter(bootstrapTarGz, gzDigester.Hash()))
	if _, err := io.Copy(gzWriter, bootstrapTarRa); err != nil {
		return nil, errors.Wrap(err, "compress bootstrap & prefetchfiles to tar.gz")
	}
	if err := gzWriter.Close(); err != nil {
		return nil, errors.Wrap(err, "close gzip writer")
	}

	bootstrapTarGzRa, err := local.OpenReader(bootstrapTarGzPath)
	if err != nil {
		return nil, errors.Wrap(err, "open reader for upper blob")
	}
	defer bootstrapTarGzRa.Close()

	oldBootstrapDesc := parser.FindNydusBootstrapDesc(&buildInfo.SourceImage.Manifest)
	if oldBootstrapDesc == nil {
		return nil, fmt.Errorf("not found originial Nydus bootstrap layer in manifest")
	}

	annotations := oldBootstrapDesc.Annotations
	annotations[utils.LayerAnnotationNyudsPrefetchBlob] = buildInfo.PrefetchBlobID

	// push bootstrap
	bootstrapDesc := ocispec.Descriptor{
		Digest:      gzDigester.Digest(),
		Size:        bootstrapTarGzRa.Size(),
		MediaType:   ocispec.MediaTypeImageLayerGzip,
		Annotations: annotations,
	}

	bootstrapRc, err := os.Open(bootstrapTarGzPath)
	if err != nil {
		return nil, errors.Wrapf(err, "open bootstrap %s", bootstrapTarGzPath)
	}
	defer bootstrapRc.Close()
	if err := remoter.Push(ctx, bootstrapDesc, true, bootstrapRc); err != nil {
		return nil, errors.Wrap(err, "push bootstrap layer")
	}
	return &bootstrapInfo{
		bootstrapDesc:   bootstrapDesc,
		bootstrapDiffID: bootstrapDiffID,
	}, nil
}

func pushConfig(ctx context.Context, opt Opt, buildInfo BuildInfo, bootstrapDiffID digest.Digest) (*ocispec.Descriptor, error) {
	nydusImage := buildInfo.SourceImage
	remoter, err := remoter(opt)
	if err != nil {
		return nil, errors.Wrap(err, "create remote")
	}
	config := nydusImage.Config

	originalBlobLayers := getOriginalBlobLayers(nydusImage)
	config.RootFS.DiffIDs = []digest.Digest{}
	for idx := range originalBlobLayers {
		config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, originalBlobLayers[idx].Digest)
	}
	prefetchBlobDigest := digest.NewDigestFromEncoded(digest.SHA256, buildInfo.PrefetchBlobID)
	config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, prefetchBlobDigest)
	// Note: bootstrap diffid is tar
	config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, bootstrapDiffID)

	configBytes, configDesc, err := makeDesc(config, nydusImage.Manifest.Config)
	if err != nil {
		return nil, errors.Wrap(err, "make config desc")
	}

	if err := remoter.Push(ctx, *configDesc, true, bytes.NewReader(configBytes)); err != nil {
		if utils.RetryWithHTTP(err) {
			remoter.MaybeWithHTTP(err)
			if err := remoter.Push(ctx, *configDesc, true, bytes.NewReader(configBytes)); err != nil {
				return nil, errors.Wrap(err, "push image config")
			}
		} else {
			return nil, errors.Wrap(err, "push image config")
		}
	}

	return configDesc, nil

}

func pushNewImage(ctx context.Context, opt Opt, buildInfo BuildInfo) error {
	logrus.Infof("pushing new image")
	start := time.Now()

	remoter, err := remoter(opt)
	if err != nil {
		return errors.Wrap(err, "create remote")
	}
	nydusImage := buildInfo.SourceImage

	prefetchBlob, err := pushBlob(ctx, opt, buildInfo)
	if err != nil {
		return errors.Wrap(err, "create and push hot blob desc")
	}

	bootstrapInfo, err := pushNewBootstrap(ctx, opt, buildInfo)
	if err != nil {
		return errors.Wrap(err, "create and push bootstrap desc")
	}

	configDesc, err := pushConfig(ctx, opt, buildInfo, bootstrapInfo.bootstrapDiffID)
	if err != nil {
		return errors.Wrap(err, "create and push bootstrap desc")
	}

	// push image manifest
	layers := getOriginalBlobLayers(nydusImage)
	layers = append(layers, *prefetchBlob)
	layers = append(layers, bootstrapInfo.bootstrapDesc)
	nydusImage.Manifest.Config = *configDesc
	nydusImage.Manifest.Layers = layers

	manifestBytes, manifestDesc, err := makeDesc(nydusImage.Manifest, nydusImage.Desc)
	if err != nil {
		return errors.Wrap(err, "make config desc")
	}
	if err := remoter.Push(ctx, *manifestDesc, false, bytes.NewReader(manifestBytes)); err != nil {
		return errors.Wrap(err, "push image manifest")
	}
	logrus.Infof("pushed new image, elapsed: %s", time.Since(start))
	return nil
}
