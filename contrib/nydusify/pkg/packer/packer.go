package packer

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/build"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/utils"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	nydusBinaryName  = "nydus-image"
	defaultOutputDir = "./.nydus-build-output"
	defaultLogLevel  = "info"
)

var (
	ErrNydusImageBinaryNotFound = errors.New("failed to find nydus-image binary")
)

type Opt struct {
	LogLevel       string
	NydusImagePath string
	OutputDir      string
	BackendConfig  *BackendConfig
}

type Builder interface {
	Run(option build.BuilderOption) error
}

type Packer struct {
	logger               *logrus.Logger
	nydusImagePath       string
	BackendConfig        *BackendConfig
	pusher               *Pusher
	builder              Builder
	Artifact
}

type BlobManifest struct {
	Blobs []string `json:"blobs,omitempty"`
}

type BackendConfig struct {
	Endpoint        string `json:"endpoint"`
	AccessKeyId     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	BucketName      string `json:"bucket_name"`
	MetaPrefix      string `json:"meta_prefix"`
	BlobPrefix      string `json:"blob_prefix"`
}

func (cfg *BackendConfig) rawMetaBackendCfg() []byte {
	configMap := map[string]string{
		"endpoint":          cfg.Endpoint,
		"access_key_id":     cfg.AccessKeyId,
		"access_key_secret": cfg.AccessKeySecret,
		"bucket_name":       cfg.BucketName,
		"object_prefix":     cfg.MetaPrefix + "/",
	}
	b, _ := json.Marshal(configMap)
	return b
}

func (cfg *BackendConfig) rawBlobBackendCfg() []byte {
	configMap := map[string]string{
		"endpoint":          cfg.Endpoint,
		"access_key_id":     cfg.AccessKeyId,
		"access_key_secret": cfg.AccessKeySecret,
		"bucket_name":       cfg.BucketName,
		"object_prefix":     cfg.BlobPrefix + "/",
	}
	b, _ := json.Marshal(configMap)
	return b
}

type PackRequest struct {
	TargetDir string
	Meta      string
	Parent    string
	// PushBlob whether to push blob and meta to remote backend
	PushBlob bool
}

type PackResult struct {
	Meta string
	Blob string
}

func New(opt Opt) (*Packer, error) {
	logger, err := initLogger(opt.LogLevel)
	if err != nil {
		return nil, errors.Wrap(err, "failed to init logger")
	}
	artifact, err := NewArtifact(opt.OutputDir)
	if err != nil {
		return nil, errors.Wrap(err, "failed to init artifact")
	}
	p := &Packer{
		logger:         logger,
		nydusImagePath: opt.NydusImagePath,
		Artifact:       artifact,
		BackendConfig:  opt.BackendConfig,
	}
	if err = p.ensureNydusImagePath(); err != nil {
		return nil, err
	}
	p.builder = build.NewBuilder(p.nydusImagePath)
	if p.BackendConfig != nil {
		p.pusher, err = NewPusher(NewPusherOpt{
			Artifact:      artifact,
			BackendConfig: *opt.BackendConfig,
			Logger:        p.logger,
		})
		if err != nil {
			return nil, errors.Wrap(err, "failed to initialize pusher")
		}
	}
	return p, nil
}

// get blobs from parent bootstrap
func (p *Packer) loadParentBlobs(parent string) ([]string, error) {
	var parentBlobs []string
	if parent == "" {
		return []string{}, nil
	}
	inspector := tool.NewInspector(p.nydusImagePath)
	item, err := inspector.Inspect(tool.InspectOption{
		Operation: tool.GetBlobs,
		Bootstrap: parent,
	})
	if err != nil {
		return []string{}, err
	}
	blobsInfo, _ := item.(tool.BlobInfoList)
	p.logger.Infof("get parent blobs %v", blobsInfo)
	for _, blobInfo := range blobsInfo {
		parentBlobs = append(parentBlobs, blobInfo.BlobID)
	}

	return parentBlobs, nil
}

// getBlobHash will get blobs hash from output.json, the hash will be
// used oss key as blob
// ignore blobs already exist
func (p *Packer) getNewBlobsHash(exists []string) (string, error) {
	// build tmp lookup map
	m := make(map[string]bool)
	for _, blob := range exists {
		m[blob] = true
	}
	content, err := ioutil.ReadFile(p.outputJsonPath())
	if err != nil {
		return "", err
	}
	var manifest BlobManifest
	if err = json.Unmarshal(content, &manifest); err != nil {
		return "", err
	}
	for _, blob := range manifest.Blobs {
		if _, ok := m[blob]; !ok {
			return blob, nil
		}
	}
	// return the latest blob hash
	return "", nil
}

func (p *Packer) Pack(_ context.Context, req PackRequest) (PackResult, error) {
	p.logger.Infof("start to pack source directory %q", req.TargetDir)
	blobPath := p.blobFilePath(blobFileName(req.Meta))
	parentBlobs, err := p.loadParentBlobs(req.Parent)
	if err != nil {
		return PackResult{}, err
	}
	if err = p.builder.Run(build.BuilderOption{
		ParentBootstrapPath: req.Parent,
		BootstrapPath:       p.bootstrapPath(req.Meta),
		RootfsPath:          req.TargetDir,
		WhiteoutSpec:        "oci",
		OutputJSONPath:      p.outputJsonPath(),
		BlobPath:            blobPath,
	}); err != nil {
		return PackResult{}, errors.Wrapf(err, "failed to Pack targetDir %s", req.TargetDir)
	}
	newBlobHash, err := p.getNewBlobsHash(parentBlobs)
	if err != nil {
		return PackResult{}, errors.Wrap(err, "failed to get blobs hash")
	}
	if req.Parent != "" {
		p.logger.Infof("should make sure parent blobs already exists on oss or local")
		if newBlobHash != "" {
			if err = os.Rename(blobPath, p.blobFilePath(newBlobHash)); err != nil {
				return PackResult{}, errors.Wrap(err, "failed to rename blob file")
			}
			blobPath = p.blobFilePath(newBlobHash)
		} else {
			blobPath = ""
		}
	}
	if !req.PushBlob {
		// if we don't need to push meta and blob to remote, just return the local build artifact
		return PackResult{
			Meta: p.bootstrapPath(req.Meta),
			Blob: blobPath,
		}, nil
	}

	// if pusher is empty, that means backend config is not provided
	if p.pusher == nil {
		return PackResult{}, errors.New("failed to push blob to remote as missing BackendConfig")
	}
	pushResult, err := p.pusher.Push(PushRequest{
		Meta: req.Meta,
		Blob: newBlobHash,
	})
	if err != nil {
		return PackResult{}, errors.Wrap(err, "failed to push pack result to remote")
	}
	return PackResult{
		Meta: pushResult.RemoteMeta,
		Blob: pushResult.RemoteBlob,
	}, nil
}

// ensureNydusImagePath ensure nydus-image binary exists, the Precedence for nydus-image is as follow
// 1. if nydusImagePath is specified try nydusImagePath first
// 2. if nydusImagePath not exists, try to find nydus-image from $PATH
// 3. return ErrNydusImageBinaryNotFound
func (p *Packer) ensureNydusImagePath() error {
	// if NydusImagePath is not empty, check if binary exists
	if strings.TrimSpace(p.nydusImagePath) != "" {
		// if we found nydus Image Path from
		if _, err := os.Stat(p.nydusImagePath); err == nil {
			p.logger.Infof("found nydus-image from %s", p.nydusImagePath)
			return nil
		}
		// if NydusImagePath not exists, check if nydus-image can be found in PATH
		if nydusBinaryPath, err := exec.LookPath(nydusBinaryName); err == nil {
			p.logger.Infof("found nydus-image from %s", nydusBinaryPath)
			p.nydusImagePath = nydusBinaryPath
			return nil
		}
	}
	return ErrNydusImageBinaryNotFound
}

// blobFileName build blobfile name from meta filename
// eg: meta=system.meta, then blobFileName is system.blob
func blobFileName(meta string) string {
	return fmt.Sprintf("%s.blob", strings.TrimSuffix(meta, filepath.Ext(meta)))
}

func initLogger(logLevel string) (*logrus.Logger, error) {
	if utils.IsEmptyString(logLevel) {
		logLevel = defaultLogLevel
	}
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return nil, err
	}
	logger := logrus.New()
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	return logger, nil
}
