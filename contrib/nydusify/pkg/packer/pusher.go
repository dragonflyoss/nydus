package packer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
)

type Pusher struct {
	Artifact
	cfg         BackendConfig
	blobBackend backend.Backend
	metaBackend backend.Backend
	logger      *logrus.Logger
}

type PushRequest struct {
	Meta string
	Blob string

	ParentBlobs []string
}

type PushResult struct {
	RemoteMeta string
	RemoteBlob string
}

type NewPusherOpt struct {
	Artifact
	BackendConfig BackendConfig
	Logger        *logrus.Logger
}

func NewPusher(opt NewPusherOpt) (*Pusher, error) {
	if utils.IsEmptyString(opt.OutputDir) {
		return nil, errors.New("outputDir is required")
	}
	if !utils.IsPathExists(opt.OutputDir) {
		return nil, errors.Errorf("outputDir %q does not exists", opt.OutputDir)
	}

	metaBackend, err := backend.NewBackend("oss", opt.BackendConfig.rawMetaBackendCfg(), nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to init backend for bootstrap blob")
	}
	blobBackend, err := backend.NewBackend("oss", opt.BackendConfig.rawBlobBackendCfg(), nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to init backend for data blob")
	}

	return &Pusher{
		Artifact:    opt.Artifact,
		logger:      opt.Logger,
		metaBackend: metaBackend,
		blobBackend: blobBackend,
		cfg:         opt.BackendConfig,
	}, nil
}

// Push will push the meta and blob file to remote backend
// at this moment, oss is the only possible backend, the meta file name is user defined
// and blob file name is the hash of the blobfile that is extracted from output.json
func (p *Pusher) Push(req PushRequest) (PushResult, error) {
	p.logger.Info("start to push meta and blob to remote backend")
	// todo: add a suitable timeout
	ctx := context.Background()
	// todo: use blob desc to build manifest

	for _, blob := range req.ParentBlobs {
		// try push parent blobs
		if _, err := p.blobBackend.Upload(ctx, blob, p.blobFilePath(blob, true), 0, false); err != nil {
			return PushResult{}, errors.Wrap(err, "failed to put blobfile to remote")
		}
	}

	p.logger.Infof("push blob %s", req.Blob)
	if req.Blob != "" {
		if _, err := p.blobBackend.Upload(ctx, req.Blob, p.blobFilePath(req.Blob, true), 0, false); err != nil {
			return PushResult{}, errors.Wrap(err, "failed to put blobfile to remote")
		}
	}
	if _, err := p.metaBackend.Upload(ctx, req.Meta, p.bootstrapPath(req.Meta), 0, true); err != nil {
		return PushResult{}, errors.Wrapf(err, "failed to put metafile to remote")
	}

	return PushResult{
		RemoteMeta: fmt.Sprintf("oss://%s/%s/%s", p.cfg.BucketName, p.cfg.MetaPrefix, req.Meta),
		RemoteBlob: fmt.Sprintf("oss://%s/%s/%s", p.cfg.BucketName, p.cfg.BlobPrefix, req.Blob),
	}, nil
}

func ParseBackendConfig(backendConfigFile string) (BackendConfig, error) {
	var cfg BackendConfig
	cfgFile, err := os.Open(backendConfigFile)
	if err != nil {
		return BackendConfig{}, errors.Wrapf(err, "failed to open backend-config %s", backendConfigFile)
	}
	defer cfgFile.Close()
	if err = json.NewDecoder(cfgFile).Decode(&cfg); err != nil {
		return BackendConfig{}, errors.Wrapf(err, "failed to decode backend-config %s", backendConfigFile)
	}
	cfg.MetaPrefix = strings.TrimSuffix(cfg.MetaPrefix, "/")
	cfg.BlobPrefix = strings.TrimSuffix(cfg.BlobPrefix, "/")
	return cfg, nil
}

func ParseBackendConfigString(backendConfigContent string) (BackendConfig, error) {
	var cfg BackendConfig
	if err := json.Unmarshal([]byte(backendConfigContent), &cfg); err != nil {
		return BackendConfig{}, errors.Wrapf(err, "failed to decode backend-config %s", backendConfigContent)
	}
	cfg.MetaPrefix = strings.TrimSuffix(cfg.MetaPrefix, "/")
	cfg.BlobPrefix = strings.TrimSuffix(cfg.BlobPrefix, "/")
	return cfg, nil
}
