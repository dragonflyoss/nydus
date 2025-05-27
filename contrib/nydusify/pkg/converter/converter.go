// Copyright 2022 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	snapConv "github.com/BraveY/snapshotter-converter/converter"
	modelspec "github.com/CloudNativeAI/model-spec/specs-go/v1"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/goharbor/acceleration-service/pkg/converter"
	"github.com/goharbor/acceleration-service/pkg/platformutil"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/external/modctl"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	pkgPvd "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

type Opt struct {
	WorkDir           string
	ContainerdAddress string
	NydusImagePath    string

	Source       string
	Target       string
	ChunkDictRef string

	SourceBackendType   string
	SourceBackendConfig string

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
	WithPlainHTTP    bool

	AllPlatforms bool
	Platforms    string

	OutputJSON string

	PushRetryCount int
	PushRetryDelay string
}

type SourceBackendConfig struct {
	Context string `json:"context"`
	WorkDir string `json:"work_dir"`
}

func Convert(ctx context.Context, opt Opt) error {
	if opt.SourceBackendType == "modelfile" {
		return convertModelFile(ctx, opt)
	}

	if opt.SourceBackendType == "model-artifact" {
		return convertModelArtifact(ctx, opt)
	}

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
	pvd, err := provider.New(tmpDir, hosts(opt), opt.CacheMaxRecords, opt.CacheVersion, platformMC, 0)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Parse retry delay
	retryDelay, err := time.ParseDuration(opt.PushRetryDelay)
	if err != nil {
		return errors.Wrap(err, "parse push retry delay")
	}

	// Set push retry configuration
	pvd.SetPushRetryConfig(opt.PushRetryCount, retryDelay)

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

func convertModelFile(ctx context.Context, opt Opt) error {
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
	defer os.RemoveAll(tmpDir)
	attributesPath := filepath.Join(tmpDir, ".nydusattributes")
	backendMetaPath := filepath.Join(tmpDir, ".backend.meta")
	backendConfigPath := filepath.Join(tmpDir, ".backend.json")

	var srcBkdCfg SourceBackendConfig
	if err := json.Unmarshal([]byte(opt.SourceBackendConfig), &srcBkdCfg); err != nil {
		return errors.Wrap(err, "unmarshal source backend config")
	}
	modctlHandler, err := newModctlHandler(opt, srcBkdCfg.WorkDir)
	if err != nil {
		return errors.Wrap(err, "create modctl handler")
	}

	if err := external.Handle(context.Background(), external.Options{
		Dir:              srcBkdCfg.WorkDir,
		Handler:          modctlHandler,
		MetaOutput:       backendMetaPath,
		BackendOutput:    backendConfigPath,
		AttributesOutput: attributesPath,
	}); err != nil {
		return errors.Wrap(err, "handle modctl")
	}

	// Make nydus layer with external blob
	packOption := snapConv.PackOption{
		BuilderPath:    opt.NydusImagePath,
		Compressor:     opt.Compressor,
		FsVersion:      opt.FsVersion,
		ChunkSize:      opt.ChunkSize,
		FromDir:        srcBkdCfg.Context,
		AttributesPath: attributesPath,
	}
	_, externalBlobDigest, err := packWithAttributes(ctx, packOption, tmpDir)
	if err != nil {
		return errors.Wrap(err, "pack to blob")
	}

	bootStrapTarPath, err := packFinalBootstrap(tmpDir, backendConfigPath, externalBlobDigest)
	if err != nil {
		return errors.Wrap(err, "pack final bootstrap")
	}

	modelCfg, err := buildModelConfig(modctlHandler)
	if err != nil {
		return errors.Wrap(err, "build model config")
	}

	modelLayers := modctlHandler.GetLayers()

	nydusImage := buildNydusImage()
	return pushManifest(context.Background(), opt, *modelCfg, modelLayers, *nydusImage, bootStrapTarPath)
}

func convertModelArtifact(ctx context.Context, opt Opt) error {
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
	defer os.RemoveAll(tmpDir)
	contextDir, err := os.MkdirTemp(tmpDir, "context-")
	if err != nil {
		return errors.Wrap(err, "create temp directory")
	}
	defer os.RemoveAll(contextDir)

	attributesPath := filepath.Join(tmpDir, ".nydusattributes")
	backendMetaPath := filepath.Join(tmpDir, ".backend.meta")
	backendConfigPath := filepath.Join(tmpDir, ".backend.json")

	handler, err := modctl.NewRemoteHandler(ctx, opt.Source, opt.WithPlainHTTP)
	if err != nil {
		return errors.Wrap(err, "create modctl handler")
	}
	if err := external.RemoteHandle(ctx, external.Options{
		ContextDir:       contextDir,
		RemoteHandler:    handler,
		MetaOutput:       backendMetaPath,
		BackendOutput:    backendConfigPath,
		AttributesOutput: attributesPath,
	}); err != nil {
		return errors.Wrap(err, "remote handle")
	}

	// Make nydus layer with external blob
	packOption := snapConv.PackOption{
		BuilderPath:    opt.NydusImagePath,
		Compressor:     opt.Compressor,
		FsVersion:      opt.FsVersion,
		ChunkSize:      opt.ChunkSize,
		FromDir:        contextDir,
		AttributesPath: attributesPath,
	}
	_, externalBlobDigest, err := packWithAttributes(ctx, packOption, tmpDir)
	if err != nil {
		return errors.Wrap(err, "pack to blob")
	}

	bootStrapTarPath, err := packFinalBootstrap(tmpDir, backendConfigPath, externalBlobDigest)
	if err != nil {
		return errors.Wrap(err, "pack final bootstrap")
	}

	modelCfg, err := handler.GetModelConfig()
	if err != nil {
		return errors.Wrap(err, "build model config")
	}

	modelLayers := handler.GetLayers()

	nydusImage := buildNydusImage()
	return pushManifest(context.Background(), opt, *modelCfg, modelLayers, *nydusImage, bootStrapTarPath)
}

func newModctlHandler(opt Opt, workDir string) (*modctl.Handler, error) {
	chunkSizeStr := strings.TrimPrefix(opt.ChunkSize, "0x")
	chunkSize, err := strconv.ParseUint(chunkSizeStr, 16, 64)
	if err != nil {
		return nil, errors.Wrap(err, "parse chunk size to uint64")
	}
	modctlOpt, err := modctl.GetOption(opt.Source, workDir, chunkSize)
	if err != nil {
		return nil, errors.Wrap(err, "parse modctl option")
	}
	return modctl.NewHandler(*modctlOpt)
}

func packWithAttributes(ctx context.Context, packOption snapConv.PackOption, blobDir string) (digest.Digest, digest.Digest, error) {
	blob, err := os.CreateTemp(blobDir, "blob-")
	if err != nil {
		return "", "", errors.Wrap(err, "create temp file for blob")
	}
	defer blob.Close()

	externalBlob, err := os.CreateTemp(blobDir, "external-blob-")
	if err != nil {
		return "", "", errors.Wrap(err, "create temp file for external blob")
	}
	defer externalBlob.Close()

	blobDigester := digest.Canonical.Digester()
	blobWriter := io.MultiWriter(blob, blobDigester.Hash())
	externalBlobDigester := digest.Canonical.Digester()
	packOption.ExternalBlobWriter = io.MultiWriter(externalBlob, externalBlobDigester.Hash())
	_, err = snapConv.Pack(ctx, blobWriter, packOption)
	if err != nil {
		return "", "", errors.Wrap(err, "pack to blob")
	}

	blobDigest := blobDigester.Digest()
	err = os.Rename(blob.Name(), filepath.Join(blobDir, blobDigest.Hex()))
	if err != nil {
		return "", "", errors.Wrap(err, "rename blob file")
	}

	externalBlobDigest := externalBlobDigester.Digest()
	err = os.Rename(externalBlob.Name(), filepath.Join(blobDir, externalBlobDigest.Hex()))
	if err != nil {
		return "", "", errors.Wrap(err, "rename external blob file")
	}

	return blobDigest, externalBlobDigest, nil
}

// Pack bootstrap and backend config into final bootstrap tar file.
func packFinalBootstrap(workDir, backendConfigPath string, externalBlobDigest digest.Digest) (string, error) {
	bkdCfg, err := os.ReadFile(backendConfigPath)
	if err != nil {
		return "", errors.Wrap(err, "read backend config file")
	}
	bkdReader := bytes.NewReader(bkdCfg)
	files := []snapConv.File{
		{
			Name:   "backend.json",
			Reader: bkdReader,
			Size:   int64(len(bkdCfg)),
		},
	}

	externalBlobRa, err := local.OpenReader(filepath.Join(workDir, externalBlobDigest.Hex()))
	if err != nil {
		return "", errors.Wrap(err, "open reader for upper blob")
	}
	bootstrap, err := os.CreateTemp(workDir, "bootstrap-")
	if err != nil {
		return "", errors.Wrap(err, "create temp file for bootstrap")
	}
	defer bootstrap.Close()

	if _, err := snapConv.UnpackEntry(externalBlobRa, snapConv.EntryBootstrap, bootstrap); err != nil {
		return "", errors.Wrap(err, "unpack bootstrap from nydus")
	}

	files = append(files, snapConv.File{
		Name:   snapConv.EntryBootstrap,
		Reader: content.NewReader(externalBlobRa),
		Size:   externalBlobRa.Size(),
	})

	bootStrapTarPath := fmt.Sprintf("%s-final.tar", bootstrap.Name())
	bootstrapTar, err := os.Create(bootStrapTarPath)
	if err != nil {
		return "", errors.Wrap(err, "open bootstrap tar file")
	}
	defer bootstrap.Close()
	rc := snapConv.PackToTar(files, false)
	defer rc.Close()
	println("copy bootstrap to tar file")
	if _, err = io.Copy(bootstrapTar, rc); err != nil {
		return "", errors.Wrap(err, "copy merged bootstrap")
	}
	return bootStrapTarPath, nil
}

func buildNydusImage() *parser.Image {
	manifest := ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: modelspec.ArtifactTypeModelManifest,
		Config: ocispec.Descriptor{
			MediaType: modelspec.MediaTypeModelConfig,
		},
	}
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
	}
	nydusImage := &parser.Image{
		Manifest: manifest,
		Desc:     desc,
	}
	return nydusImage
}

func buildModelConfig(modctlHandler *modctl.Handler) (*modelspec.Model, error) {
	cfgBytes, err := modctlHandler.GetConfig()
	if err != nil {
		return nil, errors.Wrap(err, "get modctl config")
	}
	var modelCfg modelspec.Model
	if err := json.Unmarshal(cfgBytes, &modelCfg); err != nil {
		return nil, errors.Wrap(err, "unmarshal modctl config")
	}
	return &modelCfg, nil
}

func pushManifest(
	ctx context.Context, opt Opt, modelCfg modelspec.Model, modelLayers []ocispec.Descriptor, nydusImage parser.Image, bootstrapTarPath string,
) error {

	// Push image config
	configBytes, configDesc, err := makeDesc(modelCfg, nydusImage.Manifest.Config)
	if err != nil {
		return errors.Wrap(err, "make config desc")
	}

	remoter, err := pkgPvd.DefaultRemote(opt.Target, opt.TargetInsecure)
	if err != nil {
		return errors.Wrap(err, "create remote")
	}

	if opt.WithPlainHTTP {
		remoter.WithHTTP()
	}

	if err := remoter.Push(ctx, *configDesc, true, bytes.NewReader(configBytes)); err != nil {
		if utils.RetryWithHTTP(err) {
			remoter.MaybeWithHTTP(err)
			if err := remoter.Push(ctx, *configDesc, true, bytes.NewReader(configBytes)); err != nil {
				return errors.Wrap(err, "push image config")
			}
		} else {
			return errors.Wrap(err, "push image config")
		}
	}

	// Push bootstrap layer
	bootstrapTar, err := os.Open(bootstrapTarPath)
	if err != nil {
		return errors.Wrap(err, "open bootstrap tar file")
	}

	bootstrapTarGzPath := bootstrapTarPath + ".gz"
	bootstrapTarGz, err := os.Create(bootstrapTarGzPath)
	if err != nil {
		return errors.Wrap(err, "create bootstrap tar.gz file")
	}
	defer bootstrapTarGz.Close()

	digester := digest.SHA256.Digester()
	gzWriter := gzip.NewWriter(io.MultiWriter(bootstrapTarGz, digester.Hash()))
	if _, err := io.Copy(gzWriter, bootstrapTar); err != nil {
		return errors.Wrap(err, "compress bootstrap tar to tar.gz")
	}
	if err := gzWriter.Close(); err != nil {
		return errors.Wrap(err, "close gzip writer")
	}

	ra, err := local.OpenReader(bootstrapTarGzPath)
	if err != nil {
		return errors.Wrap(err, "open reader for upper blob")
	}
	defer ra.Close()

	bootstrapDesc := ocispec.Descriptor{
		Digest:    digester.Digest(),
		Size:      ra.Size(),
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Annotations: map[string]string{
			snapConv.LayerAnnotationFSVersion:         opt.FsVersion,
			snapConv.LayerAnnotationNydusBootstrap:    "true",
			snapConv.LayerAnnotationNydusArtifactType: modelspec.ArtifactTypeModelManifest,
		},
	}

	bootstrapRc, err := os.Open(bootstrapTarGzPath)
	if err != nil {
		return errors.Wrapf(err, "open bootstrap %s", bootstrapTarGzPath)
	}
	defer bootstrapRc.Close()
	if err := remoter.Push(ctx, bootstrapDesc, true, bootstrapRc); err != nil {
		return errors.Wrap(err, "push bootstrap layer")
	}

	// Push image manifest
	layers := make([]ocispec.Descriptor, 0, len(modelLayers)+1)
	layers = append(layers, modelLayers...)
	layers = append(layers, bootstrapDesc)

	subject, err := getSourceManifestSubject(ctx, opt.Source, opt.SourceInsecure, opt.WithPlainHTTP)
	if err != nil {
		return errors.Wrap(err, "get source manifest subject")
	}

	nydusImage.Manifest.Config = *configDesc
	nydusImage.Manifest.Layers = layers
	nydusImage.Manifest.Subject = subject

	manifestBytes, manifestDesc, err := makeDesc(nydusImage.Manifest, nydusImage.Desc)
	if err != nil {
		return errors.Wrap(err, "make manifest desc")
	}

	if err := remoter.Push(ctx, *manifestDesc, false, bytes.NewReader(manifestBytes)); err != nil {
		return errors.Wrap(err, "push image manifest")
	}
	return nil
}

func getSourceManifestSubject(ctx context.Context, sourceRef string, inscure, plainHTTP bool) (*ocispec.Descriptor, error) {
	remoter, err := pkgPvd.DefaultRemote(sourceRef, inscure)
	if err != nil {
		return nil, errors.Wrap(err, "create remote")
	}
	if plainHTTP {
		remoter.WithHTTP()
	}
	desc, err := remoter.Resolve(ctx)
	if utils.RetryWithHTTP(err) {
		remoter.MaybeWithHTTP(err)
		desc, err = remoter.Resolve(ctx)
	}
	if err != nil {
		return nil, errors.Wrap(err, "resolve source manifest subject")
	}
	return desc, nil
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
