package packer

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

type Pusher struct {
	Artifact
	cfg    BackendConfig
	bucket OSSPusher
	logger *logrus.Logger
}

type OSSPusher interface {
	PutObject(string, io.Reader, ...oss.Option) error
}

type PushRequest struct {
	Meta string
	Blob string
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

	ossClient, err := oss.New(opt.BackendConfig.Endpoint, opt.BackendConfig.AccessKeyId, opt.BackendConfig.AccessKeySecret)
	if err != nil {
		return nil, errors.Wrap(err, "failed to init oss client")
	}
	bucket, err := ossClient.Bucket(opt.BackendConfig.BucketName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get bucket %s", opt.BackendConfig.BucketName)
	}
	return &Pusher{
		Artifact: opt.Artifact,
		logger:   opt.Logger,
		bucket:   bucket,
		cfg:      opt.BackendConfig,
	}, nil
}

// Push will push the meta and blob file to remote backend
// at this moment, oss is the only possible backend, the meta file name is user defined
// and blob file name is the hash of the blobfile that is extracted from output.json
func (p *Pusher) Push(req PushRequest) (PushResult, error) {
	p.logger.Info("start to push meta and blob to remote backend")
	blobHash, err := p.getBlobHash()
	if err != nil {
		return PushResult{}, errors.Wrapf(err, "failed to get blob hash from output json")
	}
	p.logger.Infof("get blob hash %s", blobHash)
	var (
		metaKey = fmt.Sprintf("%s/%s", p.cfg.MetaPrefix, req.Meta)
		blobKey = fmt.Sprintf("%s/%s", p.cfg.BlobPrefix, blobHash)
	)
	if err = p.putObject(metaKey, p.bootstrapPath(req.Meta)); err != nil {
		return PushResult{}, errors.Wrap(err, "failed to put metafile to remote")
	}
	if err = p.putObject(blobKey, p.blobFilePath(req.Blob)); err != nil {
		return PushResult{}, errors.Wrap(err, "failed to put blobfile to remote")
	}

	return PushResult{
		RemoteMeta: fmt.Sprintf("oss://%s/%s", p.cfg.BucketName, metaKey),
		RemoteBlob: fmt.Sprintf("oss://%s/%s", p.cfg.BucketName, blobKey),
	}, nil
}

func (p *Pusher) putObject(key, path string) error {
	metaFile, err := os.Open(path)
	if err != nil {
		return errors.Wrapf(err, "failed to open file from %s", path)
	}
	defer metaFile.Close()
	return p.bucket.PutObject(key, metaFile)
}

// getBlobHash will get blobs hash from output.json, the hash will be
// used oss key as blob
func (p *Pusher) getBlobHash() (string, error) {
	content, err := ioutil.ReadFile(p.outputJsonPath())
	if err != nil {
		return "", err
	}
	var manifest BlobManifest
	if err = json.Unmarshal(content, &manifest); err != nil {
		return "", err
	}
	if len(manifest.Blobs) == 0 {
		return "", ErrInvalidBlobManifest
	}
	// return the first blob hash
	return manifest.Blobs[0], nil
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
