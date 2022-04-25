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
	"github.com/dragonflyoss/image-service/contrib/nydusify/pkg/compactor"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	nydusBinaryName  = "nydus-image"
	defaultOutputDir = "./.nydus-build-output"
)

var (
	ErrNydusImageBinaryNotFound = errors.New("failed to find nydus-image binary")
	ErrInvalidChunkDictArgs     = errors.New("invalid chunk-dict args")
	ErrNoSupport                = errors.New("no support")
)

type Opt struct {
	LogLevel       logrus.Level
	NydusImagePath string
	OutputDir      string
	BackendConfig  *BackendConfig
}

type Builder interface {
	Run(option build.BuilderOption) error
}

type Packer struct {
	logger         *logrus.Logger
	nydusImagePath string
	BackendConfig  *BackendConfig
	pusher         *Pusher
	builder        Builder
	Artifact
}

type BlobManifest struct {
	Blobs []string `json:"blobs,omitempty"`
}

type BackendConfig struct {
	Endpoint        string `json:"endpoint"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	BucketName      string `json:"bucket_name"`
	MetaPrefix      string `json:"meta_prefix"`
	BlobPrefix      string `json:"blob_prefix"`
}

func (cfg *BackendConfig) rawMetaBackendCfg() []byte {
	configMap := map[string]string{
		"endpoint":          cfg.Endpoint,
		"access_key_id":     cfg.AccessKeyID,
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
		"access_key_id":     cfg.AccessKeyID,
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
	ChunkDict string
	// PushBlob whether to push blob and meta to remote backend
	PushBlob bool

	TryCompact        bool
	CompactConfigPath string
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

// get blobs from bootstrap
func (p *Packer) getBlobsFromBootstrap(bootstrap string) ([]string, error) {
	var blobs []string
	if bootstrap == "" {
		return []string{}, nil
	}
	inspector := tool.NewInspector(p.nydusImagePath)
	item, err := inspector.Inspect(tool.InspectOption{
		Operation: tool.GetBlobs,
		Bootstrap: bootstrap,
	})
	if err != nil {
		return []string{}, err
	}
	blobsInfo, _ := item.(tool.BlobInfoList)
	p.logger.Infof("get blobs %v", blobsInfo)
	for _, blobInfo := range blobsInfo {
		blobs = append(blobs, blobInfo.BlobID)
	}

	return blobs, nil
}

func (p *Packer) getChunkDictBlobs(chunkDict string) ([]string, error) {
	if chunkDict == "" {
		return []string{}, nil
	}
	// get chunk-dict file
	info := strings.Split(chunkDict, "=")
	if len(info) != 2 {
		return []string{}, ErrInvalidChunkDictArgs
	}
	switch info[0] {
	case "bootstrap":
		return p.getBlobsFromBootstrap(info[1])
	default:
		return []string{}, ErrNoSupport
	}
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
	content, err := ioutil.ReadFile(p.outputJSONPath())
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

func (p *Packer) dumpBlobBackendConfig(filePath string) (func(), error) {
	file, err := os.OpenFile(filePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	n, err := file.Write(p.BackendConfig.rawBlobBackendCfg())
	if err != nil {
		return nil, err
	}
	return func() {
		zeros := make([]byte, n)
		file, err = os.OpenFile(filePath, os.O_WRONLY, 0644)
		if err != nil {
			logrus.Errorf("open config file %s failed err = %v", filePath, err)
			return
		}
		file.Write(zeros)
		file.Close()
		os.Remove(filePath)
	}, nil
}

func (p *Packer) tryCompactParent(req *PackRequest) error {
	if !req.TryCompact || req.Parent == "" || p.BackendConfig == nil {
		return nil
	}
	// dumps backend config file
	backendConfigPath := filepath.Join(p.OutputDir, "backend-config.json")
	destroy, err := p.dumpBlobBackendConfig(backendConfigPath)
	if err != nil {
		return errors.Wrap(err, "dump backend config file failed")
	}
	// destroy backend config file, because there are secrets
	defer destroy()
	c, err := compactor.NewCompactor(p.nydusImagePath, p.OutputDir, req.CompactConfigPath)
	if err != nil {
		return errors.Wrap(err, "new compactor failed")
	}
	// only support oss now
	outputBootstrap, err := c.Compact(req.Parent, req.ChunkDict, "oss", backendConfigPath)
	if err != nil {
		return errors.Wrap(err, "compact parent failed")
	}
	// check output bootstrap
	_, err = os.Stat(outputBootstrap)
	if err != nil && !os.IsNotExist(err) {
		return errors.Wrapf(err, "stat target bootstrap failed")
	}
	if err == nil {
		// parent --> output bootstrap
		p.logger.Infof("compact bootstrap %s successfully, use parent %s", req.Parent, outputBootstrap)
		req.Parent = outputBootstrap
	}

	return nil
}

func (p *Packer) Pack(_ context.Context, req PackRequest) (PackResult, error) {
	p.logger.Infof("start to pack source directory %q", req.TargetDir)
	if err := p.tryCompactParent(&req); err != nil {
		p.logger.Errorf("try compact parent bootstrap err %v", err)
		return PackResult{}, err
	}
	blobPath := p.blobFilePath(blobFileName(req.Meta))
	parentBlobs, err := p.getBlobsFromBootstrap(req.Parent)
	if err != nil {
		return PackResult{}, errors.Wrap(err, "get blobs from parent bootstrap failed")
	}
	chunkDictBlobs, err := p.getChunkDictBlobs(req.ChunkDict)
	if err != nil {
		return PackResult{}, errors.Wrap(err, "get blobs from chunk-dict failed")
	}
	if err = p.builder.Run(build.BuilderOption{
		ParentBootstrapPath: req.Parent,
		ChunkDict:           req.ChunkDict,
		BootstrapPath:       p.bootstrapPath(req.Meta),
		RootfsPath:          req.TargetDir,
		WhiteoutSpec:        "oci",
		OutputJSONPath:      p.outputJSONPath(),
		BlobPath:            blobPath,
	}); err != nil {
		return PackResult{}, errors.Wrapf(err, "failed to Pack targetDir %s", req.TargetDir)
	}
	newBlobHash, err := p.getNewBlobsHash(append(parentBlobs, chunkDictBlobs...))
	if err != nil {
		return PackResult{}, errors.Wrap(err, "failed to get blobs hash")
	}
	if newBlobHash == "" {
		blobPath = ""
	} else {
		if req.Parent != "" || req.PushBlob {
			p.logger.Infof("rename blob file into sha256 csum")
			if err = os.Rename(blobPath, p.blobFilePath(newBlobHash)); err != nil {
				return PackResult{}, errors.Wrap(err, "failed to rename blob file")
			}
			blobPath = p.blobFilePath(newBlobHash)
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

		ParentBlobs: parentBlobs,
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

func initLogger(logLevel logrus.Level) (*logrus.Logger, error) {
	logger := logrus.New()
	logger.SetLevel(logLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	return logger, nil
}
