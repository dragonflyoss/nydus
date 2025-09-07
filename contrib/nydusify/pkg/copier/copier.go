// Copyright 2023 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package copier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/containerd/containerd/archive/compression"
	"github.com/containerd/containerd/content"
	containerdErrdefs "github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/reference/docker"
	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/containerd/nydus-snapshotter/pkg/remote/remotes"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	nydusifyUtils "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/dustin/go-humanize"
	"github.com/goharbor/acceleration-service/pkg/errdefs"
	"github.com/goharbor/acceleration-service/pkg/platformutil"
	"github.com/goharbor/acceleration-service/pkg/remote"
	"github.com/goharbor/acceleration-service/pkg/utils"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// contextKey is a type for context keys to avoid conflicts
type contextKey string

const (
	streamContextKey contextKey = "useStream"
)

type Opt struct {
	WorkDir        string
	NydusImagePath string

	Source string
	Target string

	SourceInsecure bool
	TargetInsecure bool

	SourceBackendType   string
	SourceBackendConfig string

	TargetBackendType   string
	TargetBackendConfig string

	AllPlatforms bool
	Platforms    string

	PushChunkSize    int64
	EnableStreamCopy bool
}

type output struct {
	Blobs []string
}

// newStreamContext creates a context for stream transfer
func newStreamContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, streamContextKey, true)
}

func StreamCopy(ctx context.Context, srcReader io.Reader, targetWriter content.Writer, size int64, expectedDigest digest.Digest, pushChunkSize int64) error {
	// for small files, use simplified handling
	if size <= 128 {
		return handleSmallFileTransfer(ctx, srcReader, targetWriter, size, expectedDigest)
	}

	// use buffer for efficient transfer
	return handleLargeFileTransfer(ctx, srcReader, targetWriter, size, expectedDigest, pushChunkSize)
}

func handleSmallFileTransfer(ctx context.Context, srcReader io.Reader, targetWriter content.Writer, size int64, expectedDigest digest.Digest) error {
	data, err := io.ReadAll(srcReader)
	if err != nil {
		return errors.Wrap(err, "read small file data failed")
	}

	if int64(len(data)) != size && size > 0 {
		logrus.Warnf("small file size mismatch: expected %d bytes, actual %d bytes", size, len(data))
	}
	actualDigest := digest.FromBytes(data)

	if expectedDigest != "" && expectedDigest != actualDigest {
		return fmt.Errorf("small file digest mismatch: expected %s, actual %s", expectedDigest, actualDigest)
	}

	if _, err := targetWriter.Write(data); err != nil {
		return errors.Wrap(err, "write small file data failed")
	}

	if err := targetWriter.Commit(ctx, int64(len(data)), actualDigest); err != nil {
		return errors.Wrap(err, "commit small file content failed")
	}

	return nil
}

func handleLargeFileTransfer(ctx context.Context, srcReader io.Reader, targetWriter content.Writer, size int64, expectedDigest digest.Digest, pushChunkSize int64) error {
	bufSize := 16 * 1024 * 1024 // 默认 16MB
	if pushChunkSize > 0 {
		bufSize = int(pushChunkSize)
	}
	buf := make([]byte, bufSize)
	hasher := sha256.New()
	var totalCopied int64
	lastLoggedProgress := int64(0)
	logInterval := int64(100 * 1024 * 1024)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// read data
		n, readErr := srcReader.Read(buf)
		if n <= 0 {
			if readErr == io.EOF {
				break
			}
			return errors.Wrap(readErr, "read data failed")
		}

		// calculate hash
		hasher.Write(buf[:n])

		// write data
		writeN, writeErr := targetWriter.Write(buf[:n])
		if writeErr != nil {
			return errors.Wrap(writeErr, "write data failed")
		}

		if writeN != n {
			return errors.New("write data length mismatch")
		}

		totalCopied += int64(n)

		// log progress periodically
		if totalCopied-lastLoggedProgress >= logInterval {
			if size > 0 {
				logrus.Infof("stream copy progress: %.2f%% (%s/%s)",
					float64(totalCopied)*100/float64(size),
					humanize.Bytes(uint64(totalCopied)),
					humanize.Bytes(uint64(size)))
			} else {
				logrus.Infof("stream copy progress: %s copied",
					humanize.Bytes(uint64(totalCopied)))
			}
			lastLoggedProgress = totalCopied
		}
	}

	// calculate final digest
	actualDigest := digest.NewDigestFromBytes(digest.SHA256, hasher.Sum(nil))

	// check if digest matches
	if expectedDigest != "" && expectedDigest != actualDigest {
		return fmt.Errorf("digest mismatch: expected %s, actual %s", expectedDigest, actualDigest)
	}

	// check if size matches
	if size > 0 && size != totalCopied {
		logrus.Warnf("size mismatch: expected %d bytes, actual %d bytes, using actual size", size, totalCopied)
	}

	// commit content
	if err := targetWriter.Commit(ctx, totalCopied, actualDigest); err != nil {
		return errors.Wrap(err, "commit content failed")
	}

	return nil
}

func enableStreamCopy(opt Opt) bool {
	return opt.EnableStreamCopy
}

func hosts(opt Opt) remote.HostFunc {
	maps := map[string]bool{
		opt.Source: opt.SourceInsecure,
		opt.Target: opt.TargetInsecure,
	}
	return func(ref string) (remote.CredentialFunc, bool, error) {
		return remote.NewDockerConfigCredFunc(), maps[ref], nil
	}
}

func pushBlobFromBackend(
	ctx context.Context, pvd *provider.Provider, backend backend.Backend, src ocispec.Descriptor, opt Opt,
) ([]ocispec.Descriptor, *ocispec.Descriptor, error) {
	if src.MediaType != ocispec.MediaTypeImageManifest && src.MediaType != images.MediaTypeDockerSchema2Manifest {
		return nil, nil, fmt.Errorf("unsupported media type %s", src.MediaType)
	}
	manifest := ocispec.Manifest{}
	if _, err := utils.ReadJSON(ctx, pvd.ContentStore(), &manifest, src); err != nil {
		return nil, nil, errors.Wrap(err, "read manifest from store")
	}
	bootstrapDesc := parser.FindNydusBootstrapDesc(&manifest)
	if bootstrapDesc == nil {
		return nil, nil, nil
	}
	ra, err := pvd.ContentStore().ReaderAt(ctx, *bootstrapDesc)
	if err != nil {
		return nil, nil, errors.Wrap(err, "prepare reading bootstrap")
	}
	bootstrapPath := filepath.Join(opt.WorkDir, "bootstrap.tgz")
	if err := nydusifyUtils.UnpackFile(io.NewSectionReader(ra, 0, ra.Size()), nydusifyUtils.BootstrapFileNameInLayer, bootstrapPath); err != nil {
		return nil, nil, errors.Wrap(err, "unpack bootstrap layer")
	}
	outputPath := filepath.Join(opt.WorkDir, "output.json")
	builder := tool.NewBuilder(opt.NydusImagePath)
	if err := builder.Check(tool.BuilderOption{
		BootstrapPath:   bootstrapPath,
		DebugOutputPath: outputPath,
	}); err != nil {
		return nil, nil, errors.Wrap(err, "check bootstrap")
	}
	var out output
	bytes, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read output file")
	}
	if err := json.Unmarshal(bytes, &out); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshal output json")
	}

	// Deduplicate the blobs for avoiding uploading repeatedly.
	blobIDs := []string{}
	blobIDMap := map[string]bool{}
	for _, blobID := range out.Blobs {
		if blobIDMap[blobID] {
			continue
		}
		blobIDs = append(blobIDs, blobID)
		blobIDMap[blobID] = true
	}

	sem := semaphore.NewWeighted(int64(provider.LayerConcurrentLimit))
	eg, ctx := errgroup.WithContext(ctx)
	blobDescs := make([]ocispec.Descriptor, len(blobIDs))
	for idx := range blobIDs {
		func(idx int) {
			eg.Go(func() error {
				sem.Acquire(context.Background(), 1)
				defer sem.Release(1)

				blobID := blobIDs[idx]
				blobDigest := digest.Digest("sha256:" + blobID)
				blobSize, err := backend.Size(blobID)
				if err != nil {
					return errors.Wrap(err, "get blob size")
				}
				blobSizeStr := humanize.Bytes(uint64(blobSize))

				logrus.WithField("digest", blobDigest).WithField("size", blobSizeStr).Infof("pushing blob from backend")
				blobDescs[idx] = ocispec.Descriptor{
					Digest:    blobDigest,
					Size:      blobSize,
					MediaType: converter.MediaTypeNydusBlob,
					Annotations: map[string]string{
						converter.LayerAnnotationNydusBlob: "true",
					},
				}

				if err := nydusifyUtils.RetryWithAttempts(func() error {
					resolver, err := pvd.Resolver(opt.Target)
					if err != nil {
						if errdefs.NeedsRetryWithHTTP(err) {
							pvd.UsePlainHTTP()
							resolver, err = pvd.Resolver(opt.Target)
						}
						if err != nil {
							return errors.Wrapf(err, "get resolver: %s", blobDigest)
						}
					}

					ref := opt.Target
					if !strings.Contains(ref, "@") {
						ref = ref + "@" + blobDescs[idx].Digest.String()
					}

					pusher, err := resolver.Pusher(ctx, ref)
					if err != nil {
						return errors.Wrapf(err, "get pusher: %s", blobDigest)
					}

					push := func() error {
						rc, err := backend.Reader(blobID)
						if err != nil {
							return errors.Wrap(err, "get blob reader")
						}
						defer rc.Close()
						writer, err := pusher.Push(ctx, blobDescs[idx])
						if err != nil {
							return errors.Wrapf(err, "get push writer: %s", blobDigest)
						}
						if writer != nil {
							defer writer.Close()
							if err := content.Copy(ctx, writer, rc, blobSize, blobDigest); err != nil {
								return errors.Wrapf(err, "push blob: %s", blobDigest)
							}
						}
						return nil
					}

					if err := push(); err != nil {
						if containerdErrdefs.IsAlreadyExists(err) {
							logrus.WithField("digest", blobDigest).WithField("size", blobSizeStr).Infof("pushed blob from backend (exists)")
							return nil
						}
						return errors.Wrapf(err, "copy blob content: %s", blobDigest)
					}
					logrus.WithField("digest", blobDigest).WithField("size", blobSizeStr).Infof("pushed blob from backend")

					return nil
				}, 3); err != nil {
					return errors.Wrapf(err, "push blob: %s", blobDigest)
				}

				return nil
			})
		}(idx)
	}

	if err := eg.Wait(); err != nil {
		return nil, nil, errors.Wrap(err, "push blobs")
	}

	// Update manifest layers
	for idx := range manifest.Layers {
		if manifest.Layers[idx].Annotations != nil {
			// The annotation key is deprecated, but it still exists in some
			// old nydus images, let's clean it up.
			delete(manifest.Layers[idx].Annotations, "containerd.io/snapshot/nydus-blob-ids")
		}
	}
	manifest.Layers = append(blobDescs, manifest.Layers...)

	// Update image config
	blobDigests := []digest.Digest{}
	for idx := range blobDescs {
		blobDigests = append(blobDigests, blobDescs[idx].Digest)
	}
	config := ocispec.Image{}
	if _, err := utils.ReadJSON(ctx, pvd.ContentStore(), &config, manifest.Config); err != nil {
		return nil, nil, errors.Wrap(err, "read config json")
	}
	config.RootFS.DiffIDs = append(blobDigests, config.RootFS.DiffIDs...)
	configDesc, err := utils.WriteJSON(ctx, pvd.ContentStore(), config, manifest.Config, opt.Target, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write config json")
	}
	manifest.Config = *configDesc

	target, err := utils.WriteJSON(ctx, pvd.ContentStore(), &manifest, src, opt.Target, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write manifest json")
	}

	return blobDescs, target, nil
}

func getPlatform(platform *ocispec.Platform) string {
	if platform == nil {
		return platforms.DefaultString()
	}
	return platforms.Format(*platform)
}

// getLocalPath checks if the given reference is a local file path and returns its absolute path.
//
// Parameters:
// - ref: A string which may be a docker reference or a local file path prefixed with "file://".
//
// Returns:
// - isLocalPath: A boolean indicating whether the reference is a local file path.
// - absPath: A string containing the absolute path of the local file, if applicable.
// - err: An error object if any error occurs during the process of getting the absolute path.
func getLocalPath(ref string) (isLocalPath bool, absPath string, err error) {
	if !strings.HasPrefix(ref, "file://") {
		return false, "", nil
	}
	path := strings.TrimPrefix(ref, "file://")
	absPath, err = filepath.Abs(path)
	if err != nil {
		return true, "", err
	}
	return true, absPath, nil
}

// enableStreamTransfer checks if stream transfer should be enabled
func enableStreamTransfer(opt Opt) bool {
	return false
	// return opt.PushChunkSize > 0
}

// httpModeManager manages thread-safe HTTP mode switching
type httpModeManager struct {
	mu       sync.Mutex
	enabled  bool
	provider *provider.Provider
}

func newHTTPModeManager(pvd *provider.Provider) *httpModeManager {
	return &httpModeManager{
		provider: pvd,
	}
}

// switchToHTTP switch to HTTP mode, if already in HTTP mode, do nothing
func (m *httpModeManager) switchToHTTP() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		m.provider.UsePlainHTTP()
		m.enabled = true
	}
}

// streamTransferManager manages the components for stream transfer
type streamTransferManager struct {
	provider    *provider.Provider
	httpManager *httpModeManager
	sourceRef   string
	targetRef   string
	opt         Opt
	// avoid storing interface types, directly store components needed for operations
	sourceFetcher remotes.Fetcher
	targetPusher  remotes.Pusher
}

// newStreamTransferManager creates a stream transfer manager
func newStreamTransferManager(ctx context.Context, pvd *provider.Provider, httpManager *httpModeManager, opt Opt) (*streamTransferManager, error) {
	// prepare source resolver
	sourceResolver, err := pvd.Resolver(opt.Source)
	if err != nil {
		return nil, errors.Wrap(err, "get source resolver")
	}

	// prepare target resolver
	targetResolver, err := pvd.Resolver(opt.Target)
	if err != nil {
		return nil, errors.Wrap(err, "get target resolver")
	}

	// parse reference to get name
	sourceName, _, err := sourceResolver.Resolve(ctx, opt.Source)
	if err != nil {
		return nil, errors.Wrap(err, "parse source reference")
	}

	// get source image fetcher
	sourceFetcher, err := sourceResolver.Fetcher(ctx, sourceName)
	if err != nil {
		return nil, errors.Wrap(err, "create source fetcher")
	}

	// get target image pusher
	targetPusher, err := targetResolver.Pusher(ctx, opt.Target)
	if err != nil {
		return nil, errors.Wrap(err, "create target pusher")
	}

	return &streamTransferManager{
		sourceFetcher: sourceFetcher,
		targetPusher:  targetPusher,
		httpManager:   httpManager,
		provider:      pvd,
		sourceRef:     opt.Source,
		targetRef:     opt.Target,
		opt:           opt,
	}, nil
}

// refreshPusher refreshes the pusher when needed (e.g. after switching to HTTP mode)
func (m *streamTransferManager) refreshPusher(ctx context.Context) error {
	// get new resolver
	resolver, err := m.provider.Resolver(m.targetRef)
	if err != nil {
		return errors.Wrap(err, "get new resolver")
	}

	// get new pusher
	newPusher, err := resolver.Pusher(ctx, m.targetRef)
	if err != nil {
		return errors.Wrap(err, "create new pusher")
	}

	// update pusher
	m.targetPusher = newPusher
	return nil
}

// pushContent pushes content, handles HTTP/HTTPS switch and existing content logic
func (m *streamTransferManager) pushContent(ctx context.Context, desc ocispec.Descriptor, reader io.Reader) error {
	writer, err := m.targetPusher.Push(ctx, desc)
	if err != nil {
		// if content already exists, return success
		if containerdErrdefs.IsAlreadyExists(err) {
			logrus.Infof("content already exists: %s", desc.Digest)
			return nil
		}

		// check if need to switch to HTTP mode
		if errdefs.NeedsRetryWithHTTP(err) {
			logrus.Warn("switch to HTTP mode and retry")
			m.httpManager.switchToHTTP()

			// refresh pusher
			if err := m.refreshPusher(ctx); err != nil {
				return err
			}

			// retry push
			writer, err = m.targetPusher.Push(ctx, desc)
			if err != nil {
				if containerdErrdefs.IsAlreadyExists(err) {
					logrus.Infof("content already exists: %s", desc.Digest)
					return nil
				}
				return errors.Wrap(err, "push failed in HTTP mode")
			}
		} else {
			return errors.Wrap(err, "push failed")
		}
	}

	if writer == nil {
		// content already exists, no need to transfer
		return nil
	}

	// stream transfer
	if err := StreamCopy(ctx, reader, writer, desc.Size, desc.Digest, m.opt.PushChunkSize); err != nil {
		return errors.Wrap(err, "stream transfer failed")
	}

	return nil
}

// streamTransferLayer stream transfer a single layer
func (m *streamTransferManager) streamTransferLayer(ctx context.Context, desc ocispec.Descriptor, info string) error {
	logrus.Infof("start stream transfer %s: %s, size: %s",
		info, desc.Digest, humanize.Bytes(uint64(desc.Size)))

	// get source content
	rc, err := m.sourceFetcher.Fetch(ctx, desc)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("get %s failed", info))
	}
	defer rc.Close()

	// push to target
	if err := m.pushContent(ctx, desc, rc); err != nil {
		return err
	}

	return nil
}

// streamPlatformManifest handles the transfer of a single platform manifest
func (m *streamTransferManager) streamPlatformManifest(ctx context.Context, manifestDesc ocispec.Descriptor) (ocispec.Descriptor, error) {
	// get manifest content
	rc, err := m.sourceFetcher.Fetch(ctx, manifestDesc)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "get manifest failed")
	}
	defer rc.Close()

	// read manifest content
	manifestBytes, err := io.ReadAll(rc)
	if err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "read manifest failed")
	}

	// parse manifest
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return ocispec.Descriptor{}, errors.Wrap(err, "parse manifest failed")
	}

	// transfer config file first
	if err := m.streamTransferLayer(ctx, manifest.Config, "config file"); err != nil {
		return ocispec.Descriptor{}, err
	}

	// create a wait group to wait for all layers to be processed
	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(provider.LayerConcurrentLimit) // set max concurrency

	// process each layer
	for i, layer := range manifest.Layers {
		i, layer := i, layer // avoid closure problem
		eg.Go(func() error {
			layerInfo := fmt.Sprintf("%d/%d layer", i+1, len(manifest.Layers))
			return m.streamTransferLayer(egCtx, layer, layerInfo)
		})
	}

	// wait for all layers to be processed
	if err := eg.Wait(); err != nil {
		return ocispec.Descriptor{}, err
	}

	// push manifest last
	if err := m.pushContent(ctx, manifestDesc, bytes.NewReader(manifestBytes)); err != nil {
		return ocispec.Descriptor{}, err
	}

	return manifestDesc, nil
}

// streamManifestList handles the transfer of a multi-platform manifest list
func (m *streamTransferManager) streamManifestList(ctx context.Context, indexDesc ocispec.Descriptor, platformDescs []ocispec.Descriptor) error {
	if len(platformDescs) <= 1 {
		return nil // single platform, no need to process index
	}

	// get source index content
	rc, err := m.sourceFetcher.Fetch(ctx, indexDesc)
	if err != nil {
		return errors.Wrap(err, "get index failed")
	}
	defer rc.Close()

	// read index content
	indexBytes, err := io.ReadAll(rc)
	if err != nil {
		return errors.Wrap(err, "read index failed")
	}

	// parse index
	var index ocispec.Index
	if err := json.Unmarshal(indexBytes, &index); err != nil {
		return errors.Wrap(err, "parse index failed")
	}

	// update manifest references in index
	index.Manifests = platformDescs

	// re-serialize index
	updatedIndexBytes, err := json.Marshal(index)
	if err != nil {
		return errors.Wrap(err, "serialize updated index failed")
	}

	// create updated index descriptor
	updatedIndexDesc := ocispec.Descriptor{
		Digest:    digest.FromBytes(updatedIndexBytes),
		Size:      int64(len(updatedIndexBytes)),
		MediaType: indexDesc.MediaType,
	}

	// push updated index
	if err := m.pushContent(ctx, updatedIndexDesc, bytes.NewReader(updatedIndexBytes)); err != nil {
		return errors.Wrap(err, "push index failed")
	}

	return nil
}

// Copy copies an image from the source to the target.
func Copy(ctx context.Context, opt Opt) error {
	// Containerd image fetch requires a namespace context.
	ctx = namespaces.WithNamespace(ctx, "nydusify")

	platformMC, err := platformutil.ParsePlatforms(opt.AllPlatforms, opt.Platforms)
	if err != nil {
		return err
	}

	var bkd backend.Backend
	if opt.SourceBackendType != "" {
		bkd, err = backend.NewBackend(opt.SourceBackendType, []byte(opt.SourceBackendConfig), nil)
		if err != nil {
			return errors.Wrapf(err, "new backend")
		}
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
	pvd, err := provider.New(tmpDir, hosts(opt), 200, "v1", platformMC, opt.PushChunkSize)
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	useStream := enableStreamCopy(opt)

	isLocalSource, inputPath, err := getLocalPath(opt.Source)
	if err != nil {
		return errors.Wrap(err, "parse source path")
	}

	var source string
	if isLocalSource {
		f, err := os.Open(inputPath)
		if err != nil {
			return err
		}
		defer f.Close()

		ds, err := compression.DecompressStream(f)
		if err != nil {
			return err
		}
		defer ds.Close()

		if source, err = pvd.Import(ctx, ds); err != nil {
			return errors.Wrap(err, "import source image")
		}
	} else {
		sourceNamed, err := reference.ParseDockerRef(opt.Source)
		if err != nil {
			return errors.Wrap(err, "parse source reference")
		}
		source = sourceNamed.String()

		if useStream {
			err := pvd.FetchImageInfo(ctx, source)
			if err != nil && errdefs.NeedsRetryWithHTTP(err) {
				pvd.UsePlainHTTP()
				err = pvd.FetchImageInfo(ctx, source)
			}

			if err != nil {
				return errors.Wrap(err, "fetch image info failed")
			}
		} else {
			logrus.Infof("pulling source image %s", source)
			if err := pvd.Pull(ctx, source); err != nil {
				if errdefs.NeedsRetryWithHTTP(err) {
					pvd.UsePlainHTTP()
					if err := pvd.Pull(ctx, source); err != nil {
						return errors.Wrap(err, "try to pull image")
					}
				} else {
					return errors.Wrap(err, "pull source image")
				}
			}
			logrus.Infof("pulled source image %s", source)
		}
	}

	targetNamed, err := docker.ParseDockerRef(opt.Target)
	if err != nil {
		return errors.Wrap(err, "parse target reference")
	}
	target := targetNamed.String()

	// Setup stream context if stream copy is enabled and source is remote
	if useStream && !isLocalSource {
		ctx = newStreamContext(ctx)
	}

	// get source image index info
	sourceImage, err := pvd.Image(ctx, source)
	if err != nil {
		return errors.Wrap(err, "find image")
	}

	isLocalTarget, outputPath, err := getLocalPath(opt.Target)
	if err != nil {
		return errors.Wrap(err, "parse target path")
	}
	if isLocalTarget {
		logrus.Infof("exporting source image to %s", outputPath)
		f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		if err := pvd.Export(ctx, f, sourceImage, source); err != nil {
			return errors.Wrap(err, "export source image to target tar file")
		}
		logrus.Infof("exported image %s", source)
		return nil
	}

	// get all platform manifests
	sourceDescs, err := utils.GetManifests(ctx, pvd.ContentStore(), *sourceImage, platformMC)
	if err != nil {
		return errors.Wrap(err, "get image manifests")
	}
	targetDescs := make([]ocispec.Descriptor, len(sourceDescs))

	// if stream transfer is enabled, use stream transfer mode
	if useStream && !isLocalSource {
		// create http mode manager
		httpManager := newHTTPModeManager(pvd)

		// create stream transfer manager
		streamManager, err := newStreamTransferManager(ctx, pvd, httpManager, opt)
		if err != nil {
			return err
		}

		// create stream transfer for each platform manifest
		var wg sync.WaitGroup
		errCh := make(chan error, len(sourceDescs))
		var successCount int32

		for idx, sourceDesc := range sourceDescs {
			wg.Add(1)
			go func(idx int, sourceDesc ocispec.Descriptor) {
				defer wg.Done()

				// create stream context
				streamCtx := newStreamContext(ctx)

				// process platform manifest
				targetDesc, err := streamManager.streamPlatformManifest(streamCtx, sourceDesc)
				if err != nil {
					errCh <- err
					return
				}

				targetDescs[idx] = targetDesc
				atomic.AddInt32(&successCount, 1)
			}(idx, sourceDesc)
		}

		wg.Wait()

		// check if there are errors
		select {
		case err := <-errCh:
			return err
		default:
		}

		// if there are multiple platforms, push index
		if len(targetDescs) > 1 && (sourceImage.MediaType == ocispec.MediaTypeImageIndex ||
			sourceImage.MediaType == images.MediaTypeDockerSchema2ManifestList) {

			indexCtx := newStreamContext(ctx)
			if err := streamManager.streamManifestList(indexCtx, *sourceImage, targetDescs); err != nil {
				return err
			}
		}

		return nil
	}

	// non-stream transfer logic
	descCh := make(chan int, len(sourceDescs))
	errCh := make(chan error, len(sourceDescs))
	concurrency := 4
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range descCh {
				sourceDesc := sourceDescs[idx]
				targetDesc := &sourceDesc
				if bkd != nil {
					descs, _targetDesc, err := pushBlobFromBackend(ctx, pvd, bkd, sourceDesc, opt)
					if err != nil {
						errCh <- errors.Wrap(err, "get resolver")
						continue
					}
					if _targetDesc == nil {
						logrus.WithField("platform", getPlatform(sourceDesc.Platform)).Warnf("%s is not a Nydus image", source)
					} else {
						targetDesc = _targetDesc
						// Use StreamStore that can handle both regular and stream transfer
						streamStore := newStore(pvd.ContentStore(), descs)
						pvd.SetContentStore(streamStore)
					}
				}
				targetDescs[idx] = *targetDesc

				err := pvd.Push(ctx, *targetDesc, target)
				if err != nil && errdefs.NeedsRetryWithHTTP(err) {
					pvd.UsePlainHTTP()
					err = pvd.Push(ctx, *targetDesc, target)
				}
				if err != nil {
					errCh <- errors.Wrap(err, "push manifest failed")
					continue
				}
			}
		}()
	}

	for idx := range sourceDescs {
		descCh <- idx
	}
	close(descCh)
	wg.Wait()

	select {
	case err := <-errCh:
		return err
	default:
	}

	if len(targetDescs) > 1 && (sourceImage.MediaType == ocispec.MediaTypeImageIndex ||
		sourceImage.MediaType == images.MediaTypeDockerSchema2ManifestList) {
		targetIndex := ocispec.Index{}
		if _, err := utils.ReadJSON(ctx, pvd.ContentStore(), &targetIndex, *sourceImage); err != nil {
			return errors.Wrap(err, "read source manifest list")
		}
		targetIndex.Manifests = targetDescs

		targetImage, err := utils.WriteJSON(ctx, pvd.ContentStore(), targetIndex, *sourceImage, target, nil)
		if err != nil {
			return errors.Wrap(err, "write target manifest list")
		}

		err = pvd.Push(ctx, *targetImage, target)
		if err != nil && errdefs.NeedsRetryWithHTTP(err) {
			pvd.UsePlainHTTP()
			err = pvd.Push(ctx, *targetImage, target)
		}
		if err != nil {
			return errors.Wrap(err, "push target image failed")
		}

	}

	return nil
}
