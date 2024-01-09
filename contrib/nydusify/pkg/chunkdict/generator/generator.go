package generator

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/containerd/containerd/namespaces"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/backend"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/build"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	originprovider "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/goharbor/acceleration-service/pkg/remote"

	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/converter/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/dustin/go-humanize"
	"github.com/goharbor/acceleration-service/pkg/platformutil"
	serverutils "github.com/goharbor/acceleration-service/pkg/utils"
	"github.com/opencontainers/go-digest"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/containerd/containerd/content"
	containerdErrdefs "github.com/containerd/containerd/errdefs"
	"github.com/goharbor/acceleration-service/pkg/errdefs"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Opt defines Chunkdict generate options.
// Note: sources is one or more Nydus image references.
type Opt struct {
	Sources        []string
	Target         string
	SourceInsecure bool
	TargetInsecure bool

	BackendType      string
	BackendConfig    string
	BackendForcePush bool

	WorkDir        string
	NydusImagePath string
	ExpectedArch   string

	AllPlatforms bool
	Platforms    string
}

// Generator generates chunkdict by deduplicating multiple nydus images
// invoking "nydus-image chunkdict save" to save image information into database.
type Generator struct {
	Opt
	sourcesParser []*parser.Parser
}

type output struct {
	Blobs []string
}

// New creates Generator instance.
func New(opt Opt) (*Generator, error) {
	// TODO: support sources image resolver
	var sourcesParser []*parser.Parser
	for _, source := range opt.Sources {
		sourcesRemote, err := originprovider.DefaultRemote(source, opt.SourceInsecure)
		if err != nil {
			return nil, errors.Wrap(err, "Init source image parser")
		}
		sourceParser, err := parser.New(sourcesRemote, opt.ExpectedArch)
		sourcesParser = append(sourcesParser, sourceParser)
		if err != nil {
			return nil, errors.Wrap(err, "Failed to create parser")
		}
	}

	generator := &Generator{
		Opt:           opt,
		sourcesParser: sourcesParser,
	}

	return generator, nil
}

// Generate saves multiple Nydus bootstraps into the database one by one.
func (generator *Generator) Generate(ctx context.Context) error {
	var bootstrapPaths []string
	bootstrapPaths, err := generator.pull(ctx)

	if err != nil {
		if utils.RetryWithHTTP(err) {
			for index := range generator.Sources {
				generator.sourcesParser[index].Remote.MaybeWithHTTP(err)
			}
		}
		bootstrapPaths, err = generator.pull(ctx)
		if err != nil {
			return err
		}
	}

	chunkdictBootstrapPath, outputPath, err := generator.generate(ctx, bootstrapPaths)
	if err != nil {
		return err
	}

	if err := generator.push(ctx, chunkdictBootstrapPath, outputPath); err != nil {
		return err
	}

	// return os.RemoveAll(generator.WorkDir)
	return nil 
}

// Pull the bootstrap of nydus image
func (generator *Generator) pull(ctx context.Context) ([]string, error) {
	var bootstrapPaths []string
	for index := range generator.Sources {
		sourceParsed, err := generator.sourcesParser[index].Parse(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "parse Nydus image")
		}

		// Create a directory to store the image bootstrap
		nydusImageName := strings.Replace(generator.Sources[index], "/", ":", -1)
		bootstrapDirPath := filepath.Join(generator.WorkDir, nydusImageName)
		if err := os.MkdirAll(bootstrapDirPath, fs.ModePerm); err != nil {
			return nil, errors.Wrap(err, "creat work directory")
		}
		if err := generator.Output(ctx, sourceParsed, bootstrapDirPath, index); err != nil {
			return nil, errors.Wrap(err, "output image information")
		}
		bootstrapPath := filepath.Join(bootstrapDirPath, "nydus_bootstrap")
		bootstrapPaths = append(bootstrapPaths, bootstrapPath)
	}
	return bootstrapPaths, nil
}

func (generator *Generator) generate(_ context.Context, bootstrapSlice []string) (string, string, error) {
	// Invoke "nydus-image chunkdict generate" command
	currentDir, _ := os.Getwd()
	builder := build.NewBuilder(generator.NydusImagePath)

	chunkdictBootstrapPath := filepath.Join(generator.WorkDir, "chunkdict_bootstrap")
	databaseType := "sqlite"
	var databasePath string
	if strings.HasPrefix(generator.WorkDir, "/") {
		databasePath = databaseType + "://" + filepath.Join(generator.WorkDir, "database.db")
	} else {
		databasePath = databaseType + "://" + filepath.Join(currentDir, generator.WorkDir, "database.db")
	}
	outputPath := filepath.Join(generator.WorkDir, "nydus_bootstrap_output.json")

	if err := builder.Generate(build.GenerateOption{
		BootstrapPaths:         bootstrapSlice,
		ChunkdictBootstrapPath: chunkdictBootstrapPath,
		DatabasePath:           databasePath,
		OutputPath:             outputPath,
	}); err != nil {
		return "", "", errors.Wrap(err, "invalid nydus bootstrap format")
	}

	logrus.Infof("Successfully generate image chunk dictionary")
	return chunkdictBootstrapPath, outputPath, nil
}

func hosts(generator *Generator) remote.HostFunc {
	maps := make(map[string]bool)
	for _, source := range generator.Sources {
		maps[source] = generator.SourceInsecure
	}

	maps[generator.Target] = generator.TargetInsecure
	return func(ref string) (remote.CredentialFunc, bool, error) {
		return remote.NewDockerConfigCredFunc(), maps[ref], nil
	}
}

func (generator *Generator) push(ctx context.Context, chunkdictBootstrapPath string, outputPath string) error {
	// Basic configuration
	ctx = namespaces.WithNamespace(ctx, "nydusify")
	platformMC, err := platformutil.ParsePlatforms(generator.AllPlatforms, generator.Platforms)
	if err != nil {
		return err
	}

	pvd, err := provider.New(generator.WorkDir, hosts(generator), 200, "v1", platformMC, 0)
	if err != nil {
		return err
	}

	var bkd backend.Backend
	if generator.BackendType != "" {
		bkd, err = backend.NewBackend(generator.BackendType, []byte(generator.BackendConfig), nil)
		if err != nil {
			return errors.Wrapf(err, "new backend")
		}
	}

	// Pull source image 
	for index := range generator.Sources {
		if err := pvd.Pull(ctx, generator.Sources[index]); err != nil {
			if errdefs.NeedsRetryWithHTTP(err) {
				pvd.UsePlainHTTP()
				if err := pvd.Pull(ctx, generator.Sources[index]); err != nil {
					return errors.Wrap(err, "try to pull image")
				}
			} else {
				return errors.Wrap(err, "pull source image")
			}
		}
	}
	
	logrus.Infof("pulled source image %s", generator.Sources[0])
	sourceImage, err := pvd.Image(ctx, generator.Sources[0])
	if err != nil {
		return errors.Wrap(err, "find image from store")
	}
	sourceDescs, err := serverutils.GetManifests(ctx, pvd.ContentStore(), *sourceImage, platformMC)
	if err != nil {
		return errors.Wrap(err, "get image manifests")
	}

	targetDescs := make([]ocispec.Descriptor, len(sourceDescs))

	sem := semaphore.NewWeighted(1)
	eg := errgroup.Group{}
	for idx := range sourceDescs {
		func(idx int) {
			eg.Go(func() error {
				sem.Acquire(context.Background(), 1)
				defer sem.Release(1)
				sourceDesc := sourceDescs[idx]
				targetDesc := &sourceDesc

				// Get the blob from backend
				descs, _targetDesc, err := pushBlobFromBackend(ctx, pvd, bkd, sourceDesc, *generator, chunkdictBootstrapPath, outputPath)
				if err != nil {
					return errors.Wrap(err, "get resolver")
				}
				if _targetDesc != nil {
					targetDesc = _targetDesc
					store := newStore(pvd.ContentStore(), descs)
					pvd.SetContentStore(store)
				}

				targetDescs[idx] = *targetDesc

				if err := pvd.Push(ctx, *targetDesc, generator.Target); err != nil {
					if errdefs.NeedsRetryWithHTTP(err) {
						pvd.UsePlainHTTP()
						if err := pvd.Push(ctx, *targetDesc, generator.Target); err != nil {
							return errors.Wrap(err, "try to push image manifest")
						}
					} else {
						return errors.Wrap(err, "push target image manifest")
					}
				}
				return nil
			})
		}(idx)
	}
	if err := eg.Wait(); err != nil {
		return errors.Wrap(err, "push image manifests")
	}
	return nil
}

func pushBlobFromBackend(
	ctx context.Context, pvd *provider.Provider, bkd backend.Backend, src ocispec.Descriptor, generator Generator, bootstrapPath string, outputPath string,
) ([]ocispec.Descriptor, *ocispec.Descriptor, error) {
	manifest := ocispec.Manifest{}
	if _, err := serverutils.ReadJSON(ctx, pvd.ContentStore(), &manifest, src); err != nil {
		return nil, nil, errors.Wrap(err, "read manifest from store")
	}
	fsversion := src.Annotations["containerd.io/snapshot/nydus-fs-version"]
	// Read the Nydusify output JSON to get the list of blobs
	var out output
	bytes, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "read output file")
	}
	if err := json.Unmarshal(bytes, &out); err != nil {
		return nil, nil, errors.Wrap(err, "unmarshal output json")
	}

	blobIDs := []string{}
	blobIDMap := map[string]bool{}
	for _, blobID := range out.Blobs {
		if blobIDMap[blobID] {
			continue
		}
		blobIDs = append(blobIDs, blobID)
		blobIDMap[blobID] = true
	}
	blobDescs := make([]ocispec.Descriptor, len(blobIDs))

	eg, ctx := errgroup.WithContext(ctx)
	sem := semaphore.NewWeighted(int64(provider.LayerConcurrentLimit))
	for idx := range blobIDs {
		func(idx int) {
			eg.Go(func() error {
				sem.Acquire(context.Background(), 1)
				defer sem.Release(1)

				blobID := blobIDs[idx]
				blobDigest := digest.Digest("sha256:" + blobID)

				var blobSize int64
				var rc io.ReadCloser

				if bkd != nil {
					rc, err = bkd.Reader(blobID)
					if err != nil {
						return errors.Wrap(err, "get blob reader")
					}
					blobSize, err = bkd.Size(blobID)
					if err != nil {
						return errors.Wrap(err, "get blob size")
					}
				} else {
					imageDesc, err := generator.sourcesParser[0].Remote.Resolve(ctx)
					if err != nil {
						if strings.Contains(err.Error(), "x509: certificate signed by unknown authority") {
							logrus.Warningln("try to enable \"--source-insecure\" / \"--target-insecure\" option")
						}
						return errors.Wrap(err, "resolve image")
					}
					rc, err = generator.sourcesParser[0].Remote.Pull(ctx, *imageDesc, true)
					if err != nil {
						return errors.Wrap(err, "get blob reader")
					}
					blobInfo, err := pvd.ContentStore().Info(ctx, blobDigest)
					if err != nil {
						return errors.Wrap(err, "get info from content store")
					}
					blobSize = blobInfo.Size
				}
				defer rc.Close()

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
				writer, err := getPushWriter(ctx, pvd, blobDescs[idx], generator.Opt)
				if err != nil {
					if errdefs.NeedsRetryWithHTTP(err) {
						pvd.UsePlainHTTP()
						writer, err = getPushWriter(ctx, pvd, blobDescs[idx], generator.Opt)
					}
					if err != nil {
						return errors.Wrap(err, "get push writer")
					}
				}
				if writer != nil {
					defer writer.Close()
					return content.Copy(ctx, writer, rc, blobSize, blobDigest)
				}

				logrus.WithField("digest", blobDigest).WithField("size", blobSizeStr).Infof("pushed blob from backend")

				return nil

			})
		}(idx)
	}

	if err := eg.Wait(); err != nil {
		return nil, nil, errors.Wrap(err, "push blobs")
	}

	// Update manifest blob layers
	manifest.Layers = nil
	manifest.Layers = append(blobDescs, manifest.Layers...)

	// Update bootstrap
	cw, err := content.OpenWriter(ctx, pvd.ContentStore(), content.WithRef("merge-bootstrap"))
	if err != nil {
		return nil, nil, errors.Wrap(err, "open content store writer")
	}
	defer cw.Close()

	bootstrapPathTar := "image/image.boot"
	rc, err := utils.PackTargz(bootstrapPath, bootstrapPathTar, false)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get bootstrap reader")
	}
	defer rc.Close()

	gw := gzip.NewWriter(cw)
	uncompressedDgst := digest.SHA256.Digester()
	compressed := io.MultiWriter(gw, uncompressedDgst.Hash())

	buffer := make([]byte, 32*1024)
	if _, err := io.CopyBuffer(compressed, rc, buffer); err != nil {
		return nil, nil, errors.Wrapf(err, "copy bootstrap targz into content store")
	}
	if err := gw.Close(); err != nil {
		return nil, nil, errors.Wrap(err, "close gzip writer")
	}

	compressedDgst := cw.Digest()
	if err := cw.Commit(ctx, 0, compressedDgst, content.WithLabels(map[string]string{
		"containerd.io/uncompressed": uncompressedDgst.Digest().String(),
	})); err != nil {
		if !containerdErrdefs.IsAlreadyExists(err) {
			return nil, nil, errors.Wrap(err, "commit to content store")
		}
	}
	if err := cw.Close(); err != nil {
		return nil, nil, errors.Wrap(err, "close content store writer")
	}

	bootstrapInfo, err := pvd.ContentStore().Info(ctx, compressedDgst)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get info from content store")
	}
	bootstrapSize := bootstrapInfo.Size

	bootstrapDesc := ocispec.Descriptor{
		Digest:    compressedDgst,
		Size:      bootstrapSize,
		MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
		Annotations: map[string]string{
			"containerd.io/snapshot/nydus-bootstrap":  "true",
			"containerd.io/snapshot/nydus-fs-version": fsversion,
		},
	}
	manifest.Layers = append(manifest.Layers, bootstrapDesc)

	// Update image config
	blobDigests := []digest.Digest{}
	for idx := range blobDescs {
		blobDigests = append(blobDigests, blobDescs[idx].Digest)
	}

	config := ocispec.Image{}
	if _, err := serverutils.ReadJSON(ctx, pvd.ContentStore(), &config, manifest.Config); err != nil {
		return nil, nil, errors.Wrap(err, "read config json")
	}
	config.RootFS.DiffIDs = nil
	config.RootFS.DiffIDs = append(blobDigests, config.RootFS.DiffIDs...)
	config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, digest.Digest(uncompressedDgst.Digest().String()))
	configDesc, err := serverutils.WriteJSON(ctx, pvd.ContentStore(), config, manifest.Config, generator.Target, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write config json")
	}
	manifest.Config = *configDesc
	target, err := serverutils.WriteJSON(ctx, pvd.ContentStore(), &manifest, src, generator.Target, nil)
	if err != nil {
		return nil, nil, errors.Wrap(err, "write manifest json")
	}

	return blobDescs, target, nil
}

func getPushWriter(ctx context.Context, pvd *provider.Provider, desc ocispec.Descriptor, opt Opt) (content.Writer, error) {
	resolver, err := pvd.Resolver(opt.Target)
	if err != nil {
		return nil, errors.Wrap(err, "get resolver")
	}

	ref := opt.Target
	if !strings.Contains(ref, "@") {
		ref = ref + "@" + desc.Digest.String()
	}
	pusher, err := resolver.Pusher(ctx, ref)
	if err != nil {
		return nil, errors.Wrap(err, "create pusher")
	}
	writer, err := pusher.Push(ctx, desc)
	if err != nil {
		if containerdErrdefs.IsAlreadyExists(err) {
			return nil, nil
		}
		return nil, err
	}

	return writer, nil
}

type store struct {
	content.Store
	remotes []ocispec.Descriptor
}

func newStore(base content.Store, remotes []ocispec.Descriptor) *store {
	return &store{
		Store:   base,
		remotes: remotes,
	}
}

func (s *store) Info(ctx context.Context, dgst digest.Digest) (content.Info, error) {
	info, err := s.Store.Info(ctx, dgst)
	if err != nil {
		if !containerdErrdefs.IsNotFound(err) {
			return content.Info{}, err
		}
		for _, desc := range s.remotes {
			if desc.Digest == dgst {
				return content.Info{
					Digest: desc.Digest,
					Size:   desc.Size,
				}, nil
			}
		}
		return content.Info{}, err
	}
	return info, nil
}
