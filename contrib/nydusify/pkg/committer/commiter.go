// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package committer

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/content/local"
	"github.com/containerd/containerd/reference/docker"
	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/committer/diff"
	parserPkg "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/dustin/go-humanize"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type Opt struct {
	WorkDir           string
	ContainerdAddress string
	NydusImagePath    string

	ContainerID    string
	SourceInsecure bool
	TargetRef      string
	TargetInsecure bool
	MaximumTimes   int
	FsVersion      string
	Compressor     string

	WithPaths    []string
	WithoutPaths []string
}

type Committer struct {
	workDir string
	builder string
	manager *Manager
}

func NewCommitter(opt Opt) (*Committer, error) {
	if err := os.MkdirAll(opt.WorkDir, 0755); err != nil {
		return nil, errors.Wrap(err, "prepare work dir")
	}

	workDir, err := os.MkdirTemp(opt.WorkDir, "nydusify-commiter-")
	if err != nil {
		return nil, errors.Wrap(err, "create temp dir")
	}

	cm, err := NewManager(opt.ContainerdAddress)
	if err != nil {
		return nil, errors.Wrap(err, "new container manager")
	}
	return &Committer{
		workDir: workDir,
		builder: opt.NydusImagePath,
		manager: cm,
	}, nil
}

func (cm *Committer) Commit(ctx context.Context, opt Opt) error {
	targetRef, err := ValidateRef(opt.TargetRef)
	if err != nil {
		return errors.Wrap(err, "parse target image name")
	}

	inspect, err := cm.manager.Inspect(ctx, opt.ContainerID)
	if err != nil {
		return errors.Wrap(err, "inspect container")
	}

	logrus.Infof("pulling base bootstrap")
	start := time.Now()
	image, committedLayers, err := cm.pullBootstrap(ctx, inspect.Image, "bootstrap-base", opt.SourceInsecure)
	if err != nil {
		return errors.Wrap(err, "pull base bootstrap")
	}
	logrus.Infof("pulled base bootstrap, elapsed: %s", time.Since(start))

	if committedLayers >= opt.MaximumTimes {
		return fmt.Errorf("reached maximum committed times %d", opt.MaximumTimes)
	}
	if opt.FsVersion, opt.Compressor, err = cm.obtainBootStrapInfo(ctx, "bootstrap-base"); err != nil {
		return errors.Wrap(err, "obtain bootstrap FsVersion and Compressor")
	}

	mountList := NewMountList()

	var upperBlob *Blob
	mountBlobs := make([]Blob, len(opt.WithPaths))
	commit := func() error {
		eg := errgroup.Group{}
		eg.Go(func() error {
			var upperBlobDigest *digest.Digest
			if err := withRetry(func() error {
				upperBlobDigest, err = cm.commitUpperByDiff(ctx, mountList.Add, opt.WithPaths, opt.WithoutPaths, inspect.LowerDirs, inspect.UpperDir, "blob-upper", opt.FsVersion, opt.Compressor)
				return err
			}, 3); err != nil {
				return errors.Wrap(err, "commit upper")
			}
			logrus.Infof("pushing blob for upper")
			start := time.Now()
			upperBlobDesc, err := cm.pushBlob(ctx, "blob-upper", *upperBlobDigest, opt.TargetRef, opt.TargetInsecure)
			if err != nil {
				return errors.Wrap(err, "push upper blob")
			}
			upperBlob = &Blob{
				Name: "blob-upper",
				Desc: *upperBlobDesc,
			}
			logrus.Infof("pushed blob for upper, elapsed: %s", time.Since(start))
			return nil
		})

		if len(opt.WithPaths) > 0 {
			for idx := range opt.WithPaths {
				func(idx int) {
					eg.Go(func() error {
						withPath := opt.WithPaths[idx]
						name := fmt.Sprintf("blob-mount-%d", idx)
						var mountBlobDigest *digest.Digest
						if err := withRetry(func() error {
							mountBlobDigest, err = cm.commitMountByNSEnter(ctx, inspect.Pid, withPath, name, opt.FsVersion, opt.Compressor)
							return err
						}, 3); err != nil {
							return errors.Wrap(err, "commit mount")
						}
						logrus.Infof("pushing blob for mount")
						start := time.Now()
						mountBlobDesc, err := cm.pushBlob(ctx, name, *mountBlobDigest, opt.TargetRef, opt.TargetInsecure)
						if err != nil {
							return errors.Wrap(err, "push mount blob")
						}
						mountBlobs[idx] = Blob{
							Name: name,
							Desc: *mountBlobDesc,
						}
						logrus.Infof("pushed blob for mount, elapsed: %s", time.Since(start))
						return nil
					})
				}(idx)
			}
		}

		if err := eg.Wait(); err != nil {
			return err
		}

		appendedEg := errgroup.Group{}
		appendedMutex := sync.Mutex{}
		if len(mountList.paths) > 0 {
			logrus.Infof("need commit appened mount path: %s", strings.Join(mountList.paths, ", "))
		}
		for idx := range mountList.paths {
			func(idx int) {
				appendedEg.Go(func() error {
					mountPath := mountList.paths[idx]
					name := fmt.Sprintf("blob-appended-mount-%d", idx)
					var mountBlobDigest *digest.Digest
					if err := withRetry(func() error {
						mountBlobDigest, err = cm.commitMountByNSEnter(ctx, inspect.Pid, mountPath, name, opt.FsVersion, opt.Compressor)
						return err
					}, 3); err != nil {
						return errors.Wrap(err, "commit appended mount")
					}
					logrus.Infof("pushing blob for appended mount")
					start := time.Now()
					mountBlobDesc, err := cm.pushBlob(ctx, name, *mountBlobDigest, opt.TargetRef, opt.TargetInsecure)
					if err != nil {
						return errors.Wrap(err, "push appended mount blob")
					}
					appendedMutex.Lock()
					mountBlobs = append(mountBlobs, Blob{
						Name: name,
						Desc: *mountBlobDesc,
					})
					appendedMutex.Unlock()
					logrus.Infof("pushed blob for appended mount, elapsed: %s", time.Since(start))
					return nil
				})
			}(idx)
		}

		return appendedEg.Wait()
	}

	if err := cm.pause(ctx, opt.ContainerID, commit); err != nil {
		return errors.Wrap(err, "pause container to commit")
	}

	logrus.Infof("merging base and upper bootstraps")
	_, bootstrapDiffID, err := cm.mergeBootstrap(ctx, *upperBlob, mountBlobs, "bootstrap-base", "bootstrap-merged.tar")
	if err != nil {
		return errors.Wrap(err, "merge bootstrap")
	}

	logrus.Infof("pushing committed image to %s", targetRef)
	if err := cm.pushManifest(ctx, *image, *bootstrapDiffID, targetRef, "bootstrap-merged.tar", opt.FsVersion, upperBlob, mountBlobs, opt.TargetInsecure); err != nil {
		return errors.Wrap(err, "push manifest")
	}

	return nil
}

func (cm *Committer) pullBootstrap(ctx context.Context, ref, bootstrapName string, insecure bool) (*parserPkg.Image, int, error) {
	remoter, err := provider.DefaultRemote(ref, insecure)
	if err != nil {
		return nil, 0, errors.Wrap(err, "create remote")
	}

	parser, err := parserPkg.New(remoter, runtime.GOARCH)
	if err != nil {
		return nil, 0, errors.Wrap(err, "create parser")
	}

	var parsed *parserPkg.Parsed
	parsed, err = parser.Parse(ctx)
	if err != nil {
		if utils.RetryWithHTTP(err) {
			remoter.MaybeWithHTTP(err)
			parsed, err = parser.Parse(ctx)
			if err != nil {
				return nil, 0, errors.Wrap(err, "parse nydus image")
			}
		} else {
			return nil, 0, errors.Wrap(err, "parse nydus image")
		}
	}
	if parsed.NydusImage == nil {
		return nil, 0, fmt.Errorf("not a nydus image: %s", ref)
	}

	bootstrapDesc := parserPkg.FindNydusBootstrapDesc(&parsed.NydusImage.Manifest)
	if bootstrapDesc == nil {
		return nil, 0, fmt.Errorf("not found nydus bootstrap layer")
	}
	committedLayers := 0
	_commitBlobs := bootstrapDesc.Annotations[utils.LayerAnnotationNydusCommitBlobs]
	if _commitBlobs != "" {
		committedLayers = len(strings.Split(_commitBlobs, ","))
		logrus.Infof("detected the committed layers: %d", committedLayers)
	}

	target := filepath.Join(cm.workDir, bootstrapName)
	reader, err := parser.PullNydusBootstrap(ctx, parsed.NydusImage)
	if err != nil {
		return nil, 0, errors.Wrap(err, "pull bootstrap layer")
	}
	defer reader.Close()

	if err := utils.UnpackFile(reader, utils.BootstrapFileNameInLayer, target); err != nil {
		return nil, 0, errors.Wrap(err, "unpack bootstrap layer")
	}

	return parsed.NydusImage, committedLayers, nil
}

func (cm *Committer) commitUpperByDiff(ctx context.Context, appendMount func(path string), withPaths []string, withoutPaths []string, lowerDirs, upperDir, blobName, fsversion, compressor string) (*digest.Digest, error) {
	logrus.Infof("committing upper")
	start := time.Now()

	blobPath := filepath.Join(cm.workDir, blobName)
	blob, err := os.Create(blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "create upper blob file")
	}
	defer blob.Close()

	digester := digest.SHA256.Digester()
	counter := Counter{}
	tarWc, err := converter.Pack(ctx, io.MultiWriter(blob, digester.Hash(), &counter), converter.PackOption{
		WorkDir:     cm.workDir,
		FsVersion:   fsversion,
		Compressor:  compressor,
		BuilderPath: cm.builder,
	})
	if err != nil {
		return nil, errors.Wrap(err, "initialize pack to blob")
	}

	if err := diff.Diff(ctx, appendMount, withPaths, withoutPaths, tarWc, lowerDirs, upperDir); err != nil {
		return nil, errors.Wrap(err, "make diff")
	}

	if err := tarWc.Close(); err != nil {
		return nil, errors.Wrap(err, "pack to blob")
	}

	blobDigest := digester.Digest()
	logrus.Infof("committed upper, size: %s, elapsed: %s", humanize.Bytes(uint64(counter.Size())), time.Since(start))

	return &blobDigest, nil
}

func (cm *Committer) pushBlob(ctx context.Context, blobName string, blobDigest digest.Digest, targetRef string, insecure bool) (*ocispec.Descriptor, error) {
	blobRa, err := local.OpenReader(filepath.Join(cm.workDir, blobName))
	if err != nil {
		return nil, errors.Wrap(err, "open reader for upper blob")
	}

	blobDesc := ocispec.Descriptor{
		Digest:    blobDigest,
		Size:      blobRa.Size(),
		MediaType: utils.MediaTypeNydusBlob,
		Annotations: map[string]string{
			utils.LayerAnnotationUncompressed: blobDigest.String(),
			utils.LayerAnnotationNydusBlob:    "true",
		},
	}

	remoter, err := provider.DefaultRemote(targetRef, insecure)
	if err != nil {
		return nil, errors.Wrap(err, "create remote")
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

func (cm *Committer) pause(ctx context.Context, containerID string, handle func() error) error {
	logrus.Infof("pausing container: %s", containerID)
	if err := cm.manager.Pause(ctx, containerID); err != nil {
		return errors.Wrap(err, "pause container")
	}

	if err := handle(); err != nil {
		logrus.Infof("unpausing container: %s", containerID)
		if err := cm.manager.UnPause(ctx, containerID); err != nil {
			logrus.Errorf("unpause container: %s", containerID)
		}
		return err
	}

	logrus.Infof("unpausing container: %s", containerID)
	return cm.manager.UnPause(ctx, containerID)
}

func (cm *Committer) pushManifest(
	ctx context.Context, nydusImage parserPkg.Image, bootstrapDiffID digest.Digest, targetRef, bootstrapName, fsversion string, upperBlob *Blob, mountBlobs []Blob, insecure bool,
) error {
	lowerBlobLayers := []ocispec.Descriptor{}
	for idx := range nydusImage.Manifest.Layers {
		layer := nydusImage.Manifest.Layers[idx]
		if layer.MediaType == utils.MediaTypeNydusBlob {
			lowerBlobLayers = append(lowerBlobLayers, layer)
		}
	}

	// Push image config
	config := nydusImage.Config

	config.RootFS.DiffIDs = []digest.Digest{}
	for idx := range lowerBlobLayers {
		config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, lowerBlobLayers[idx].Digest)
	}
	for idx := range mountBlobs {
		mountBlob := mountBlobs[idx]
		config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, mountBlob.Desc.Digest)
	}
	config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, upperBlob.Desc.Digest)
	config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, bootstrapDiffID)

	configBytes, configDesc, err := cm.makeDesc(config, nydusImage.Manifest.Config)
	if err != nil {
		return errors.Wrap(err, "make config desc")
	}

	remoter, err := provider.DefaultRemote(targetRef, insecure)
	if err != nil {
		return errors.Wrap(err, "create remote")
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
	bootstrapTarPath := filepath.Join(cm.workDir, bootstrapName)
	bootstrapTar, err := os.Open(bootstrapTarPath)
	if err != nil {
		return errors.Wrap(err, "open bootstrap tar file")
	}

	bootstrapTarGzPath := filepath.Join(cm.workDir, bootstrapName+".gz")
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

	commitBlobs := []string{}
	for idx := range mountBlobs {
		mountBlob := mountBlobs[idx]
		commitBlobs = append(commitBlobs, mountBlob.Desc.Digest.String())
	}
	commitBlobs = append(commitBlobs, upperBlob.Desc.Digest.String())

	bootstrapDesc := ocispec.Descriptor{
		Digest:    digester.Digest(),
		Size:      ra.Size(),
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Annotations: map[string]string{
			converter.LayerAnnotationFSVersion:      fsversion,
			converter.LayerAnnotationNydusBootstrap: "true",
			utils.LayerAnnotationNydusCommitBlobs:   strings.Join(commitBlobs, ","),
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
	layers := lowerBlobLayers
	for idx := range mountBlobs {
		mountBlob := mountBlobs[idx]
		layers = append(layers, mountBlob.Desc)
	}
	layers = append(layers, upperBlob.Desc)
	layers = append(layers, bootstrapDesc)

	nydusImage.Manifest.Config = *configDesc
	nydusImage.Manifest.Layers = layers

	manifestBytes, manifestDesc, err := cm.makeDesc(nydusImage.Manifest, nydusImage.Desc)
	if err != nil {
		return errors.Wrap(err, "make config desc")
	}
	if err := remoter.Push(ctx, *manifestDesc, false, bytes.NewReader(manifestBytes)); err != nil {
		return errors.Wrap(err, "push image manifest")
	}

	return nil
}

func (cm *Committer) makeDesc(x interface{}, oldDesc ocispec.Descriptor) ([]byte, *ocispec.Descriptor, error) {
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

func (cm *Committer) commitMountByNSEnter(ctx context.Context, containerPid int, sourceDir, name, fsversion, compressor string) (*digest.Digest, error) {
	logrus.Infof("committing mount: %s", sourceDir)
	start := time.Now()

	blobPath := filepath.Join(cm.workDir, name)
	blob, err := os.Create(blobPath)
	if err != nil {
		return nil, errors.Wrap(err, "create mount blob file")
	}
	defer blob.Close()

	digester := digest.SHA256.Digester()
	counter := Counter{}
	tarWc, err := converter.Pack(ctx, io.MultiWriter(blob, &counter, digester.Hash()), converter.PackOption{
		WorkDir:     cm.workDir,
		FsVersion:   fsversion,
		Compressor:  compressor,
		BuilderPath: cm.builder,
	})
	if err != nil {
		return nil, errors.Wrap(err, "initialize pack to blob")
	}

	if err := copyFromContainer(ctx, containerPid, sourceDir, tarWc); err != nil {
		return nil, errors.Wrapf(err, "copy %s from pid %d", sourceDir, containerPid)
	}

	if err := tarWc.Close(); err != nil {
		return nil, errors.Wrap(err, "pack to blob")
	}

	mountBlobDigest := digester.Digest()

	logrus.Infof("committed mount: %s, size: %s, elapsed %s", sourceDir, humanize.Bytes(uint64(counter.Size())), time.Since(start))

	return &mountBlobDigest, nil
}

func (cm *Committer) mergeBootstrap(
	ctx context.Context, upperBlob Blob, mountBlobs []Blob, baseBootstrapName, mergedBootstrapName string,
) ([]digest.Digest, *digest.Digest, error) {
	baseBootstrap := filepath.Join(cm.workDir, baseBootstrapName)
	upperBlobRa, err := local.OpenReader(filepath.Join(cm.workDir, upperBlob.Name))
	if err != nil {
		return nil, nil, errors.Wrap(err, "open reader for upper blob")
	}

	mergedBootstrap := filepath.Join(cm.workDir, mergedBootstrapName)
	bootstrap, err := os.Create(mergedBootstrap)
	if err != nil {
		return nil, nil, errors.Wrap(err, "create upper blob file")
	}
	defer bootstrap.Close()

	digester := digest.SHA256.Digester()
	writer := io.MultiWriter(bootstrap, digester.Hash())

	layers := []converter.Layer{}
	layers = append(layers, converter.Layer{
		Digest:   upperBlob.Desc.Digest,
		ReaderAt: upperBlobRa,
	})
	for idx := range mountBlobs {
		mountBlob := mountBlobs[idx]
		mountBlobRa, err := local.OpenReader(filepath.Join(cm.workDir, mountBlob.Name))
		if err != nil {
			return nil, nil, errors.Wrap(err, "open reader for mount blob")
		}
		layers = append(layers, converter.Layer{
			Digest:   mountBlob.Desc.Digest,
			ReaderAt: mountBlobRa,
		})
	}

	blobDigests, err := converter.Merge(ctx, layers, writer, converter.MergeOption{
		WorkDir:             cm.workDir,
		ParentBootstrapPath: baseBootstrap,
		WithTar:             true,
		BuilderPath:         cm.builder,
	})
	if err != nil {
		return nil, nil, errors.Wrap(err, "merge bootstraps")
	}
	bootstrapDiffID := digester.Digest()

	return blobDigests, &bootstrapDiffID, nil
}

func copyFromContainer(ctx context.Context, containerPid int, source string, target io.Writer) error {
	config := &Config{
		Mount:  true,
		Target: containerPid,
	}

	stderr, err := config.ExecuteContext(ctx, target, "tar", "--xattrs", "--ignore-failed-read", "--absolute-names", "-cf", "-", source)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("execute tar: %s", strings.TrimSpace(stderr)))
	}
	if stderr != "" {
		logrus.Warnf("from container: %s", stderr)
	}

	return nil
}

type MountList struct {
	mutex sync.Mutex
	paths []string
}

func NewMountList() *MountList {
	return &MountList{
		paths: make([]string, 0),
	}
}

func (ml *MountList) Add(path string) {
	ml.mutex.Lock()
	defer ml.mutex.Unlock()

	ml.paths = append(ml.paths, path)
}

type Blob struct {
	Name          string
	BootstrapName string
	Desc          ocispec.Descriptor
}

func withRetry(handle func() error, total int) error {
	for {
		total--
		err := handle()
		if err == nil {
			return nil
		}

		if total > 0 {
			logrus.WithError(err).Warnf("retry (remain %d times)", total)
			continue
		}

		return err
	}
}

// ValidateRef validate the target image reference.
func ValidateRef(ref string) (string, error) {
	named, err := docker.ParseDockerRef(ref)
	if err != nil {
		return "", errors.Wrapf(err, "invalid image reference: %s", ref)
	}
	if _, ok := named.(docker.Digested); ok {
		return "", fmt.Errorf("unsupported digested image reference: %s", ref)
	}
	named = docker.TagNameOnly(named)
	return named.String(), nil
}

type outputJSON struct {
	FsVersion  string `json:"fs_version"`
	Compressor string `json:"compressor"`
}

func (cm *Committer) obtainBootStrapInfo(ctx context.Context, BootstrapName string) (string, string, error) {
	targetBootstrapPath := filepath.Join(cm.workDir, BootstrapName)
	outputJSONPath := filepath.Join(cm.workDir, "output.json")
	defer os.Remove(outputJSONPath)

	args := []string{
		"check",
		"--log-level",
		"warn",
		"--bootstrap",
		targetBootstrapPath,
		"--output-json",
		outputJSONPath,
	}

	logrus.Debugf("\tCommand: %s", args)
	cmd := exec.CommandContext(ctx, cm.builder, args...)

	if err := cmd.Run(); err != nil {
		return "", "", errors.Wrap(err, "run merge command")
	}

	outputBytes, err := os.ReadFile(outputJSONPath)
	if err != nil {
		return "", "", errors.Wrapf(err, "read file %s", outputJSONPath)
	}
	var output outputJSON
	err = json.Unmarshal(outputBytes, &output)
	if err != nil {
		return "", "", errors.Wrapf(err, "unmarshal output json file %s", outputJSONPath)
	}
	return output.FsVersion, strings.ToLower(output.Compressor), nil
}
