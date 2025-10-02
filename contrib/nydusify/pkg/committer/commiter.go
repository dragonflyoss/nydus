// Copyright 2024 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package committer

import (
	"archive/tar"
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
	"syscall"
	"time"

	"github.com/BraveY/snapshotter-converter/converter"
	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/labels"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/fifo"
	"github.com/distribution/reference"
	"github.com/dustin/go-humanize"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	parserPkg "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

// Opt defines the options for committing container changes
type Opt struct {
	WorkDir           string
	ContainerdAddress string
	NydusImagePath    string
	Namespace         string

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

// NewCommitter creates a new Committer instance
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
	// Resolve container ID first
	if err := cm.resolveContainerID(ctx, &opt); err != nil {
		return errors.Wrap(err, "failed to resolve container ID")
	}

	ctx = namespaces.WithNamespace(ctx, opt.Namespace)
	targetRef, err := ValidateRef(opt.TargetRef)
	if err != nil {
		return errors.Wrap(err, "parse target image name")
	}

	inspect, err := cm.manager.Inspect(ctx, opt.ContainerID)
	if err != nil {
		return errors.Wrap(err, "inspect container")
	}

	originalSourceRef := inspect.Image

	logrus.Infof("pulling base bootstrap")
	start := time.Now()
	image, committedLayers, err := cm.pullBootstrap(ctx, originalSourceRef, "bootstrap-base", opt.SourceInsecure)
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

	// Push lower blobs
	for idx, layer := range image.Manifest.Layers {
		if layer.MediaType == utils.MediaTypeNydusBlob {
			name := fmt.Sprintf("blob-mount-%d", idx)
			if _, err := cm.pushBlob(ctx, name, layer.Digest, originalSourceRef, targetRef, opt.TargetInsecure, image); err != nil {
				return errors.Wrap(err, "push lower blob")
			}
		}
	}

	mountList := NewMountList()

	var upperBlob *Blob
	mountBlobs := make([]Blob, len(opt.WithPaths))
	commit := func() error {
		eg := errgroup.Group{}
		eg.Go(func() error {
			var upperBlobDigest *digest.Digest
			var upperBootstrapPath string
			if err := withRetry(func() error {
				upperBlobDigest, upperBootstrapPath, err = cm.commitUpperByDiff(ctx, mountList.Add, opt.WithPaths, opt.WithoutPaths, inspect.LowerDirs, inspect.UpperDir, "blob-upper", opt.FsVersion, opt.Compressor)
				return err
			}, 3); err != nil {
				return errors.Wrap(err, "commit upper")
			}
			logrus.Infof("pushing blob for upper")
			start := time.Now()
			upperBlobDesc, err := cm.pushBlob(ctx, "blob-upper", *upperBlobDigest, originalSourceRef, targetRef, opt.TargetInsecure, image)
			if err != nil {
				return errors.Wrap(err, "push upper blob")
			}
			upperBlob = &Blob{
				Name:          "blob-upper",
				BootstrapPath: upperBootstrapPath,
				Desc:          *upperBlobDesc,
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
						var mountBootstrapPath string
						if err := withRetry(func() error {
							mountBlobDigest, mountBootstrapPath, err = cm.commitMountByNSEnter(ctx, inspect.Pid, withPath, name, opt.FsVersion, opt.Compressor)
							return err
						}, 3); err != nil {
							return errors.Wrap(err, "commit mount")
						}
						logrus.Infof("pushing blob for mount")
						start := time.Now()
						mountBlobDesc, err := cm.pushBlob(ctx, name, *mountBlobDigest, originalSourceRef, targetRef, opt.TargetInsecure, image)
						if err != nil {
							return errors.Wrap(err, "push mount blob")
						}
						mountBlobs[idx] = Blob{
							Name:          name,
							BootstrapPath: mountBootstrapPath,
							Desc:          *mountBlobDesc,
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
			logrus.Infof("need commit appended mount path: %s", strings.Join(mountList.paths, ", "))
		}
		for idx := range mountList.paths {
			func(idx int) {
				appendedEg.Go(func() error {
					mountPath := mountList.paths[idx]
					name := fmt.Sprintf("blob-appended-mount-%d", idx)
					var mountBlobDigest *digest.Digest
					var mountBootstrapPath string
					if err := withRetry(func() error {
						mountBlobDigest, mountBootstrapPath, err = cm.commitMountByNSEnter(ctx, inspect.Pid, mountPath, name, opt.FsVersion, opt.Compressor)
						return err
					}, 3); err != nil {
						return errors.Wrap(err, "commit appended mount")
					}
					logrus.Infof("pushing blob for appended mount")
					start := time.Now()
					mountBlobDesc, err := cm.pushBlob(ctx, name, *mountBlobDigest, originalSourceRef, targetRef, opt.TargetInsecure, image)
					if err != nil {
						return errors.Wrap(err, "push appended mount blob")
					}
					appendedMutex.Lock()
					mountBlobs = append(mountBlobs, Blob{
						Name:          name,
						BootstrapPath: mountBootstrapPath,
						Desc:          *mountBlobDesc,
					})
					appendedMutex.Unlock()
					logrus.Infof("pushed blob for appended mount, elapsed: %s", time.Since(start))
					return nil
				})
			}(idx)
		}

		return appendedEg.Wait()
	}

	// Ensure filesystem changes are written to disk before committing
	// This prevents issues where changes are still in memory buffers
	// and not yet visible in the overlay filesystem's upper directory
	logrus.Infof("syncing filesystem before commit")
	if err := cm.syncFilesystem(ctx, opt.ContainerID); err != nil {
		return errors.Wrap(err, "failed to sync filesystem")
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
		logrus.Infof("detected committed layers: %d", committedLayers)
	}

	target := filepath.Join(cm.workDir, bootstrapName)
	reader, err := parser.PullNydusBootstrap(ctx, parsed.NydusImage)
	if err != nil {
		return nil, 0, errors.Wrap(err, "pull bootstrap layer")
	}
	var closeErr error
	defer func() {
		if err := reader.Close(); err != nil {
			closeErr = errors.Wrap(err, "close bootstrap reader")
		}
	}()

	if err := utils.UnpackFile(reader, utils.BootstrapFileNameInLayer, target); err != nil {
		return nil, 0, errors.Wrap(err, "unpack bootstrap layer")
	}

	if closeErr != nil {
		return nil, 0, closeErr
	}

	return parsed.NydusImage, committedLayers, nil
}

func (cm *Committer) commitUpperByDiff(ctx context.Context, appendMount func(path string), withPaths []string, withoutPaths []string, lowerDirs, upperDir, blobName, fsversion, compressor string) (*digest.Digest, string, error) {
	logrus.Infof("committing upper")
	start := time.Now()

	blobPath := filepath.Join(cm.workDir, blobName)
	bootstrapPath := filepath.Join(cm.workDir, blobName+".bootstrap")

	// Create output file for blob
	blobFile, err := os.Create(blobPath)
	if err != nil {
		return nil, "", errors.Wrap(err, "create upper blob file")
	}
	defer blobFile.Close()

	// Create FIFO for nydus-image to write to
	blobFifoPath := filepath.Join(cm.workDir, blobName+".fifo")
	blobFifo, err := fifo.OpenFifo(ctx, blobFifoPath, syscall.O_CREAT|syscall.O_RDONLY|syscall.O_NONBLOCK, 0640)
	if err != nil {
		return nil, "", errors.Wrap(err, "create fifo for blob")
	}
	defer blobFifo.Close()

	// Set up digest calculation and size counting
	digester := digest.SHA256.Digester()
	counter := Counter{}

	// Copy from FIFO to file and digest concurrently with nydus-image
	copyDone := make(chan error, 1)
	go func() {
		defer close(copyDone)
		_, err := io.Copy(io.MultiWriter(blobFile, digester.Hash(), &counter), blobFifo)
		copyDone <- err
	}()

	// Use nydus-image create directly on the overlay filesystem, writing to FIFO
	args := []string{
		"create",
		"--whiteout-spec", "overlayfs",
		"--fs-version", fsversion,
		"--compressor", compressor,
		"--blob", blobFifoPath,
		"--bootstrap", bootstrapPath,
		// TODO investigate if we need this
		"--external-blob", "/dev/null",
		upperDir,
	}

	logrus.Debugf("executing: %s %s", cm.builder, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, cm.builder, args...)
	cmd.Stdout = logrus.StandardLogger().Writer()
	cmd.Stderr = logrus.StandardLogger().Writer()

	if err := cmd.Run(); err != nil {
		return nil, "", errors.Wrapf(err, "run nydus-image create on upper directory %s", upperDir)
	}

	// Wait for copy to complete
	if err := <-copyDone; err != nil {
		return nil, "", errors.Wrap(err, "copy from fifo")
	}

	blobDigest := digester.Digest()
	logrus.Infof("committed upper, size: %s, elapsed: %s", humanize.Bytes(uint64(counter.Size())), time.Since(start))

	return &blobDigest, bootstrapPath, nil
}

// getDistributionSourceLabel returns the source label key and value for the image distribution
func getDistributionSourceLabel(sourceRef string) (string, string) {
	named, err := reference.ParseDockerRef(sourceRef)
	if err != nil {
		return "", ""
	}
	host := reference.Domain(named)
	labelValue := reference.Path(named)
	labelKey := fmt.Sprintf("%s.%s", labels.LabelDistributionSource, host)

	return labelKey, labelValue
}

// pushBlob pushes a blob to the target registry
func (cm *Committer) pushBlob(ctx context.Context, blobName string, blobDigest digest.Digest, sourceRef string, targetRef string, insecure bool, image *parserPkg.Image) (*ocispec.Descriptor, error) {
	logrus.Infof("pushing blob: %s, digest: %s", blobName, blobDigest)

	targetRemoter, err := provider.DefaultRemote(targetRef, insecure)
	if err != nil {
		return nil, errors.Wrap(err, "create target remote")
	}

	// Check if this is a lower blob (starts with "blob-mount-" but not in workDir)
	isLowerBlob := strings.HasPrefix(blobName, "blob-mount-")
	blobPath := filepath.Join(cm.workDir, blobName)

	var blobDesc ocispec.Descriptor
	var reader io.Reader
	var readerCloser io.Closer
	var closeErr error

	defer func() {
		if readerCloser != nil {
			if err := readerCloser.Close(); err != nil {
				closeErr = errors.Wrap(err, "close blob reader")
			}
		}
	}()

	if isLowerBlob {
		logrus.Debugf("handling lower blob: %s", blobName)
		// For lower blobs, use remote access
		blobDesc = ocispec.Descriptor{
			Digest:    blobDigest,
			MediaType: utils.MediaTypeNydusBlob,
		}

		// Find corresponding layer in source manifest to get size
		var sourceLayer *ocispec.Descriptor
		for _, layer := range image.Manifest.Layers {
			if layer.Digest == blobDigest {
				sourceLayer = &layer
				blobDesc.Size = layer.Size
				break
			}
		}

		if sourceLayer == nil {
			return nil, fmt.Errorf("layer not found in source image: %s", blobDigest)
		}

		if blobDesc.Size <= 0 {
			return nil, fmt.Errorf("invalid blob size: %d", blobDesc.Size)
		}
		logrus.Debugf("lower blob size: %d", blobDesc.Size)

		// Use source image remoter to get blob data
		sourceRemoter, err := provider.DefaultRemote(sourceRef, insecure)
		if err != nil {
			return nil, errors.Wrap(err, "create source remote")
		}

		// Get ReaderAt for remote blob
		readerAt, err := sourceRemoter.ReaderAt(ctx, *sourceLayer, true)
		if err != nil {
			return nil, errors.Wrap(err, "create remote reader for lower blob")
		}
		if readerAt == nil {
			return nil, fmt.Errorf("got nil reader for lower blob: %s", blobName)
		}
		reader = io.NewSectionReader(readerAt, 0, readerAt.Size())
		if closer, ok := readerAt.(io.Closer); ok {
			readerCloser = closer
		}

		// Add required annotations
		blobDesc.Annotations = map[string]string{
			utils.LayerAnnotationUncompressed: blobDigest.String(),
			utils.LayerAnnotationNydusBlob:    "true",
		}
	} else {
		logrus.Debugf("handling local blob: %s", blobName)
		// Handle local blob
		blobRa, err := local.OpenReader(blobPath)
		if err != nil {
			return nil, errors.Wrap(err, "open reader for blob")
		}
		if blobRa == nil {
			return nil, fmt.Errorf("got nil reader for local blob: %s", blobName)
		}
		size := blobRa.Size()
		if size <= 0 {
			blobRa.Close()
			return nil, fmt.Errorf("invalid local blob size: %d", size)
		}
		logrus.Debugf("local blob size: %d", size)
		reader = io.NewSectionReader(blobRa, 0, size)
		readerCloser = blobRa

		blobDesc = ocispec.Descriptor{
			Digest:    blobDigest,
			Size:      size,
			MediaType: utils.MediaTypeNydusBlob,
			Annotations: map[string]string{
				utils.LayerAnnotationUncompressed: blobDigest.String(),
				utils.LayerAnnotationNydusBlob:    "true",
			},
		}
	}

	// Add distribution source label
	distributionSourceLabel, distributionSourceLabelValue := getDistributionSourceLabel(sourceRef)
	if distributionSourceLabel != "" {
		if blobDesc.Annotations == nil {
			blobDesc.Annotations = make(map[string]string)
		}
		blobDesc.Annotations[distributionSourceLabel] = distributionSourceLabelValue
	}

	logrus.Debugf("pushing blob: digest=%s, size=%d", blobDesc.Digest, blobDesc.Size)

	if err := targetRemoter.Push(ctx, blobDesc, true, reader); err != nil {
		if utils.RetryWithHTTP(err) {
			targetRemoter.MaybeWithHTTP(err)
			logrus.Debugf("retrying push with HTTP")
			if err := targetRemoter.Push(ctx, blobDesc, true, reader); err != nil {
				return nil, errors.Wrap(err, "push blob with HTTP")
			}
		} else {
			return nil, errors.Wrap(err, "push blob")
		}
	}

	if closeErr != nil {
		return nil, closeErr
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

// syncFilesystem forces filesystem sync to ensure all changes are written to disk.
// This is crucial for overlay filesystems where changes may still be in memory
// buffers and not yet visible in the upper directory when committing.
func (cm *Committer) syncFilesystem(ctx context.Context, containerID string) error {
	inspect, err := cm.manager.Inspect(ctx, containerID)
	if err != nil {
		return errors.Wrap(err, "inspect container for sync")
	}

	// Use nsenter to execute sync command in the container's namespace
	config := &Config{
		Mount:  true,
		PID:    true,
		Target: inspect.Pid,
	}

	stderr, err := config.ExecuteContext(ctx, io.Discard, "sync")
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("execute sync in container namespace: %s", strings.TrimSpace(stderr)))
	}

	// Also sync the host filesystem to ensure overlay changes are written
	cmd := exec.CommandContext(ctx, "sync")
	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "execute host sync")
	}

	return nil
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

func (cm *Committer) commitMountByNSEnter(ctx context.Context, containerPid int, sourceDir, name, fsversion, compressor string) (*digest.Digest, string, error) {
	logrus.Infof("committing mount: %s", sourceDir)
	start := time.Now()

	blobPath := filepath.Join(cm.workDir, name)
	bootstrapPath := filepath.Join(cm.workDir, name+".bootstrap")

	// Create output file for blob
	blobFile, err := os.Create(blobPath)
	if err != nil {
		return nil, "", errors.Wrap(err, "create mount blob file")
	}
	defer blobFile.Close()

	// Create FIFO for nydus-image to write to
	blobFifoPath := filepath.Join(cm.workDir, name+".fifo")
	blobFifo, err := fifo.OpenFifo(ctx, blobFifoPath, syscall.O_CREAT|syscall.O_RDONLY|syscall.O_NONBLOCK, 0640)
	if err != nil {
		return nil, "", errors.Wrap(err, "create fifo for blob")
	}
	defer blobFifo.Close()

	// Set up digest calculation and size counting
	digester := digest.SHA256.Digester()
	counter := Counter{}

	// Copy from FIFO to file and digest concurrently
	copyDone := make(chan error, 1)
	go func() {
		defer close(copyDone)
		_, err := io.Copy(io.MultiWriter(blobFile, digester.Hash(), &counter), blobFifo)
		copyDone <- err
	}()

	// Create temporary directory to extract mount data
	tempDir, err := os.MkdirTemp(cm.workDir, name+"-temp-")
	if err != nil {
		return nil, "", errors.Wrap(err, "create temp directory for mount")
	}
	defer os.RemoveAll(tempDir)

	// Copy data from container to temp directory
	tempTarPath := filepath.Join(tempDir, "mount.tar")
	tempTarFile, err := os.Create(tempTarPath)
	if err != nil {
		return nil, "", errors.Wrap(err, "create temp tar file")
	}

	if err := copyFromContainer(ctx, containerPid, sourceDir, tempTarFile); err != nil {
		tempTarFile.Close()
		return nil, "", errors.Wrapf(err, "copy %s from pid %d", sourceDir, containerPid)
	}
	tempTarFile.Close()

	// Extract tar to temp directory
	extractDir := filepath.Join(tempDir, "extracted")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return nil, "", errors.Wrap(err, "create extract directory")
	}

	extractCmd := exec.CommandContext(ctx, "tar", "-xf", tempTarPath, "-C", extractDir)
	if err := extractCmd.Run(); err != nil {
		return nil, "", errors.Wrap(err, "extract tar file")
	}

	// Use nydus-image create on extracted directory, writing to FIFO
	args := []string{
		"create",
		"--fs-version", fsversion,
		"--compressor", compressor,
		"--blob", blobFifoPath,
		"--bootstrap", bootstrapPath,
		extractDir,
	}

	logrus.Debugf("executing: %s %s", cm.builder, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, cm.builder, args...)
	cmd.Stdout = logrus.StandardLogger().Writer()
	cmd.Stderr = logrus.StandardLogger().Writer()

	if err := cmd.Run(); err != nil {
		return nil, "", errors.Wrapf(err, "run nydus-image create on mount directory %s", extractDir)
	}

	// Wait for copy to complete
	if err := <-copyDone; err != nil {
		return nil, "", errors.Wrap(err, "copy from fifo")
	}

	mountBlobDigest := digester.Digest()
	logrus.Infof("committed mount: %s, size: %s, elapsed %s", sourceDir, humanize.Bytes(uint64(counter.Size())), time.Since(start))

	return &mountBlobDigest, bootstrapPath, nil
}

func (cm *Committer) mergeBootstrap(
	ctx context.Context, upperBlob Blob, mountBlobs []Blob, baseBootstrapName, mergedBootstrapName string,
) ([]digest.Digest, *digest.Digest, error) {
	baseBootstrap := filepath.Join(cm.workDir, baseBootstrapName)
	rawBootstrapPath := filepath.Join(cm.workDir, mergedBootstrapName+".raw")
	tarBootstrapPath := filepath.Join(cm.workDir, mergedBootstrapName)

	// Collect all bootstrap paths to merge
	sourceBootstrapPaths := []string{}
	blobDigests := []digest.Digest{}

	// Add mount blob bootstraps first
	for _, mountBlob := range mountBlobs {
		if mountBlob.BootstrapPath != "" {
			sourceBootstrapPaths = append(sourceBootstrapPaths, mountBlob.BootstrapPath)
			blobDigests = append(blobDigests, mountBlob.Desc.Digest)
		}
	}

	// Add upper blob bootstrap
	if upperBlob.BootstrapPath != "" {
		sourceBootstrapPaths = append(sourceBootstrapPaths, upperBlob.BootstrapPath)
		blobDigests = append(blobDigests, upperBlob.Desc.Digest)
	}

	// Use nydus-image merge command to create raw bootstrap file
	args := []string{
		"merge",
		"--log-level", "warn",
		"--prefetch-policy", "fs",
		"--bootstrap", rawBootstrapPath, // Write to .raw file first
	}

	if baseBootstrap != "" {
		args = append(args, "--parent-bootstrap", baseBootstrap)
	}

	// Add source bootstrap paths
	args = append(args, sourceBootstrapPaths...)

	logrus.Debugf("executing: %s %s", cm.builder, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, cm.builder, args...)
	cmd.Stdout = logrus.StandardLogger().Writer()
	cmd.Stderr = logrus.StandardLogger().Writer()

	if err := cmd.Run(); err != nil {
		return nil, nil, errors.Wrapf(err, "run nydus-image merge")
	}

	// Package the raw bootstrap file into a tar with the correct internal structure
	tarFile, err := os.Create(tarBootstrapPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "create bootstrap tar file")
	}
	defer tarFile.Close()

	digester := digest.SHA256.Digester()
	writer := io.MultiWriter(tarFile, digester.Hash())
	tarWriter := tar.NewWriter(writer)
	defer tarWriter.Close()

	// Add the merged bootstrap file to the tar as image/image.boot
	bootstrapContent, err := os.ReadFile(rawBootstrapPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read merged bootstrap file")
	}

	// Create image directory entry
	imageDir := &tar.Header{
		Name:     "image",
		Mode:     0755,
		Typeflag: tar.TypeDir,
	}
	if err := tarWriter.WriteHeader(imageDir); err != nil {
		return nil, nil, errors.Wrap(err, "write image directory header")
	}

	// Create bootstrap file entry
	bootstrapHeader := &tar.Header{
		Name: utils.BootstrapFileNameInLayer, // "image/image.boot"
		Mode: 0644,
		Size: int64(len(bootstrapContent)),
	}
	if err := tarWriter.WriteHeader(bootstrapHeader); err != nil {
		return nil, nil, errors.Wrap(err, "write bootstrap file header")
	}

	if _, err := tarWriter.Write(bootstrapContent); err != nil {
		return nil, nil, errors.Wrap(err, "write bootstrap file content")
	}

	if err := tarWriter.Close(); err != nil {
		return nil, nil, errors.Wrap(err, "close tar writer")
	}

	// Clean up the temporary raw bootstrap file
	os.Remove(rawBootstrapPath)

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
	BootstrapPath string // Path to separate bootstrap file
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
	named, err := reference.ParseDockerRef(ref)
	if err != nil {
		return "", errors.Wrapf(err, "invalid image reference: %s", ref)
	}
	if _, ok := named.(reference.Digested); ok {
		return "", fmt.Errorf("unsupported digested image reference: %s", ref)
	}
	named = reference.TagNameOnly(named)
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

// resolveContainerID resolves the container ID to its full ID
func (cm *Committer) resolveContainerID(ctx context.Context, opt *Opt) error {
	// If the ID is already a full ID (64 characters), return it directly
	if len(opt.ContainerID) == 64 {
		logrus.Debugf("container ID %s is already a full ID", opt.ContainerID)
		return nil
	}

	logrus.Infof("resolving container ID prefix %s to full ID", opt.ContainerID)

	var (
		fullID     string
		matchCount int
	)

	// Create containerd client directly
	client, err := client.New(cm.manager.address)
	if err != nil {
		return fmt.Errorf("failed to create containerd client: %w", err)
	}
	defer client.Close()

	// Set namespace in context
	ctx = namespaces.WithNamespace(ctx, opt.Namespace)

	walker := NewContainerWalker(client, func(_ context.Context, found Found) error {
		fullID = found.Container.ID()
		matchCount = found.MatchCount
		return nil
	})

	n, err := walker.Walk(ctx, opt.ContainerID)
	if err != nil {
		return fmt.Errorf("failed to walk containers: %w", err)
	}

	if n == 0 {
		return fmt.Errorf("no container found with ID : %s", opt.ContainerID)
	}

	if matchCount > 1 {
		return fmt.Errorf("ambiguous container ID  '%s' matches multiple containers, please provide a more specific ID", opt.ContainerID)
	}

	opt.ContainerID = fullID
	logrus.Infof("resolved container ID to full ID: %s", fullID)
	return nil
}
