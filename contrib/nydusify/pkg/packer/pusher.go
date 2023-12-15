package packer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
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
	backendConfig := opt.BackendConfig

	metaBackend, err := backend.NewBackend(backendConfig.backendType(), backendConfig.rawMetaBackendCfg(), nil)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to init backend for bootstrap blob")
	}
	blobBackend, err := backend.NewBackend(backendConfig.backendType(), backendConfig.rawBlobBackendCfg(), nil)
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
// at this moment, only oss and s3 are the possible backends, the meta file name is user defined
// and blob file name is the hash of the blobfile that is extracted from output.json
func (p *Pusher) Push(req PushRequest) (pushResult PushResult, retErr error) {
	p.logger.Info("start to push meta and blob to remote backend")
	// todo: add a suitable timeout
	ctx := context.Background()
	// todo: use blob desc to build manifest

	defer func() {
		if retErr != nil {
			if err := p.blobBackend.Finalize(true); err != nil {
				logrus.WithError(err).Warnf("Cancel blob backend upload")
			}
			if err := p.metaBackend.Finalize(true); err != nil {
				logrus.WithError(err).Warnf("Cancel meta backend upload")
			}
		}
	}()

	for _, blob := range req.ParentBlobs {
		// try push parent blobs
		if _, err := p.blobBackend.Upload(ctx, blob, p.blobFilePath(blob, true), 0, false); err != nil {
			return PushResult{}, errors.Wrap(err, "failed to put blobfile to remote")
		}
	}

	p.logger.Infof("push blob %s", req.Blob)
	if req.Blob != "" {
		desc, err := p.blobBackend.Upload(ctx, req.Blob, p.blobFilePath(req.Blob, true), 0, false)
		if err != nil {
			return PushResult{}, errors.Wrap(err, "failed to put blobfile to remote")
		}
		if len(desc.URLs) > 0 {
			pushResult.RemoteBlob = desc.URLs[0]
		}
	}
	if retErr = p.blobBackend.Finalize(false); retErr != nil {
		return PushResult{}, errors.Wrap(retErr, "Finalize blob backend upload")
	}

	desc, retErr := p.metaBackend.Upload(ctx, req.Meta, p.bootstrapPath(req.Meta), 0, true)
	if retErr != nil {
		return PushResult{}, errors.Wrapf(retErr, "failed to put metafile to remote")
	}
	if len(desc.URLs) != 0 {
		pushResult.RemoteMeta = desc.URLs[0]
	}
	if retErr = p.metaBackend.Finalize(false); retErr != nil {
		return PushResult{}, errors.Wrap(retErr, "Finalize meta backend upload")
	}

	return
}

func ParseBackendConfig(backendType, backendConfigFile string) (BackendConfig, error) {

	cfgFile, err := os.Open(backendConfigFile)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open backend-config %s", backendConfigFile)
	}
	defer cfgFile.Close()
	switch strings.ToLower(backendType) {
	case "oss":
		var cfg OssBackendConfig
		if err = json.NewDecoder(cfgFile).Decode(&cfg); err != nil {
			return nil, errors.Wrapf(err, "failed to decode backend-config %s", backendConfigFile)
		}
		return &cfg, nil
	case "s3":
		var cfg S3BackendConfig
		if err = json.NewDecoder(cfgFile).Decode(&cfg); err != nil {
			return nil, errors.Wrapf(err, "failed to decode backend-config %s", backendConfigFile)
		}
		return &cfg, nil
	default:
		return nil, fmt.Errorf("unsupported backend type %s", backendType)
	}
}

func ParseBackendConfigString(backendType, backendConfigContent string) (BackendConfig, error) {
	switch strings.ToLower(backendType) {
	case "oss":
		var cfg OssBackendConfig
		if err := json.Unmarshal([]byte(backendConfigContent), &cfg); err != nil {
			return nil, errors.Wrapf(err, "failed to decode backend-config %s", backendConfigContent)
		}
		return &cfg, nil

	case "s3":
		var cfg S3BackendConfig
		if err := json.Unmarshal([]byte(backendConfigContent), &cfg); err != nil {
			return nil, errors.Wrapf(err, "failed to decode backend-config %s", backendConfigContent)
		}
		return &cfg, nil
	default:
		return nil, fmt.Errorf("unsupported backend type %s", backendType)
	}
}
