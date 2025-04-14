// Copyright 2025 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0
package modctl

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strconv"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	modelspec "github.com/CloudNativeAI/model-spec/specs-go/v1"
	pkgPvd "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type RemoteInterface interface {
	Resolve(ctx context.Context) (*ocispec.Descriptor, error)
	Pull(ctx context.Context, desc ocispec.Descriptor, plainHTTP bool) (io.ReadCloser, error)
	ReadSeekCloser(ctx context.Context, desc ocispec.Descriptor, plainHTTP bool) (io.ReadSeekCloser, error)
	WithHTTP()
	MaybeWithHTTP(err error)
}

type RemoteHandler struct {
	ctx      context.Context
	imageRef string
	remoter  RemoteInterface
	manifest ocispec.Manifest
	// convert from the manifest.Layers, same order as manifest.Layers
	blobs []backend.Blob
}

type FileCrcList struct {
	Files []FileCrcInfo `json:"files"`
}

type FileCrcInfo struct {
	FilePath  string `json:"file_path"`
	ChunkCrcs string `json:"chunk_crcs"`
}

const (
	filePathKey = "org.cnai.model.filepath"
	crcsKey     = "org.cnai.nydus.crcs"
)

func NewRemoteHandler(ctx context.Context, imageRef string, plainHTTP bool) (*RemoteHandler, error) {
	remoter, err := pkgPvd.DefaultRemote(imageRef, true)
	if err != nil {
		return nil, errors.Wrap(err, "new remote failed")
	}
	if plainHTTP {
		remoter.WithHTTP()
	}
	handler := &RemoteHandler{
		ctx:      ctx,
		imageRef: imageRef,
		remoter:  remoter,
	}
	if err := initRemoteHandler(handler); err != nil {
		return nil, errors.Wrap(err, "init remote handler failed")
	}
	return handler, nil
}

func initRemoteHandler(handler *RemoteHandler) error {
	if err := handler.setManifest(); err != nil {
		return errors.Wrap(err, "set manifest failed")
	}
	handler.blobs = convertToBlobs(&handler.manifest)
	return nil
}

func (handler *RemoteHandler) Handle(ctx context.Context) (*backend.Backend, []backend.FileAttribute, error) {
	var fileAttrs []backend.FileAttribute
	for idx, layer := range handler.manifest.Layers {
		fa, err := handler.handle(ctx, layer, int32(idx))
		if err != nil {
			return nil, nil, errors.Wrap(err, "handle layer failed")
		}
		fileAttrs = append(fileAttrs, fa...)
	}
	bkd, err := handler.backend()
	if err != nil {
		return nil, nil, errors.Wrap(err, "get backend failed")
	}

	return bkd, fileAttrs, nil
}

func (handler *RemoteHandler) GetModelConfig() (*modelspec.Model, error) {
	var modelCfg modelspec.Model
	rc, err := handler.remoter.Pull(handler.ctx, handler.manifest.Config, true)
	if err != nil {
		return nil, errors.Wrap(err, "pull model config failed")
	}
	defer rc.Close()
	var buf bytes.Buffer
	if _, err = io.Copy(&buf, rc); err != nil {
		return nil, errors.Wrap(err, "copy model config failed")
	}
	if err = json.Unmarshal(buf.Bytes(), &modelCfg); err != nil {
		return nil, errors.Wrap(err, "unmarshal model config failed")
	}
	return &modelCfg, nil
}

func (handler *RemoteHandler) GetLayers() []ocispec.Descriptor {
	return handler.manifest.Layers
}

func (handler *RemoteHandler) setManifest() error {
	maniDesc, err := handler.remoter.Resolve(handler.ctx)
	if utils.RetryWithHTTP(err) {
		handler.remoter.MaybeWithHTTP(err)
		maniDesc, err = handler.remoter.Resolve(handler.ctx)
	}
	if err != nil {
		return errors.Wrap(err, "resolve image manifest failed")
	}

	rc, err := handler.remoter.Pull(handler.ctx, *maniDesc, true)
	if err != nil {
		return errors.Wrap(err, "pull manifest failed")
	}
	defer rc.Close()
	var buf bytes.Buffer
	io.Copy(&buf, rc)
	var manifest ocispec.Manifest
	if err = json.Unmarshal(buf.Bytes(), &manifest); err != nil {
		return errors.Wrap(err, "unmarshal manifest failed")
	}
	handler.manifest = manifest
	return nil
}

func (handler *RemoteHandler) backend() (*backend.Backend, error) {
	bkd := backend.Backend{
		Version: "v1",
	}
	bkd.Backends = []backend.Config{
		{
			Type: "registry",
		},
	}
	bkd.Blobs = handler.blobs
	return &bkd, nil
}

func (handler *RemoteHandler) handle(ctx context.Context, layer ocispec.Descriptor, index int32) ([]backend.FileAttribute, error) {
	logrus.Debugf("handle layer: %s", layer.Digest.String())
	chunkSize := getChunkSizeByMediaType(layer.MediaType)
	rsc, err := handler.remoter.ReadSeekCloser(ctx, layer, true)
	if err != nil {
		return nil, errors.Wrap(err, "read seek closer failed")
	}
	defer rsc.Close()
	files, err := readTarBlob(rsc)
	if err != nil {
		return nil, errors.Wrap(err, "read tar blob failed")
	}

	var fileCrcList = FileCrcList{}
	var fileCrcMap = make(map[string]string)
	if layer.Annotations != nil {
		if c, ok := layer.Annotations[crcsKey]; ok {
			if err := json.Unmarshal([]byte(c), &fileCrcList); err != nil {
				return nil, errors.Wrap(err, "unmarshal crcs failed")
			}
			for _, f := range fileCrcList.Files {
				fileCrcMap[f.FilePath] = f.ChunkCrcs
			}
		}
	}

	blobInfo := handler.blobs[index].Config
	fileAttrs := make([]backend.FileAttribute, len(files))
	hackFile := os.Getenv("HACK_FILE")
	for idx, f := range files {
		if hackFile != "" && f.name == hackFile {
			hackFileWrapper(&f)
		}

		fileAttrs[idx] = backend.FileAttribute{
			BlobID:                 blobInfo.Digest,
			BlobIndex:              uint32(index),
			BlobSize:               blobInfo.Size,
			FileSize:               f.size,
			Chunk0CompressedOffset: f.offset,
			ChunkSize:              chunkSize,
			RelativePath:           f.name,
			Type:                   "external",
			Mode:                   f.mode,
		}
		if crcs, ok := fileCrcMap[f.name]; ok {
			fileAttrs[idx].Crcs = crcs
		}
	}
	return fileAttrs, nil
}

func hackFileWrapper(f *fileInfo) {
	// HACK to chmod config.json to 0640
	hackMode := uint32(0640)
	// etc 640.
	hackModeStr := os.Getenv("HACK_MODE")
	if hackModeStr != "" {
		modeValue, err := strconv.ParseUint(hackModeStr, 8, 32)
		if err != nil {
			logrus.Errorf("Invalid HACK_MODE value: %s, using default 0640", hackModeStr)
		} else {
			hackMode = uint32(modeValue)
		}
	}
	f.mode = hackMode
	logrus.Infof("hack file: %s mode: %o", f.name, f.mode)
}
