package tests

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	modelspec "github.com/CloudNativeAI/model-spec/specs-go/v1"

	"github.com/containerd/containerd/content/local"
	"github.com/containerd/log"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/converter"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/pkg/errors"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/external/modctl"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

const testModctlRepoDir = "/home/bravey/.modctl/"
const modelContextDir = "/home/bravey/ai/llm/Qwen2.5-0.5B-Instruct"

func walk(t *testing.T, ctx tool.Context, root string) map[string]*tool.File {
	tree := map[string]*tool.File{}

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		require.Nil(t, err)

		targetPath, err := filepath.Rel(root, path)
		require.NoError(t, err)

		file := tool.NewFile(t, path, targetPath)
		tree[targetPath] = file

		return nil
	})
	require.NoError(t, err)

	return tree
}

func check(t *testing.T, ctx tool.Context, root1, root2 string) {
	tree1 := walk(t, ctx, root1)
	tree2 := walk(t, ctx, root2)

	for path, file := range tree1 {
		if tree2[path] != nil {
			tree2[path].Compare(t, file)
		} else {
			t.Fatalf("not found file %s in tree2", path)
		}
	}

	for path, file := range tree2 {
		if tree1[path] != nil {
			tree1[path].Compare(t, file)
		} else {
			t.Fatalf("not found file %s in tree1", path)
		}
	}
}

func verify(t *testing.T, ctx tool.Context) {
	config := tool.NydusdConfig{
		EnablePrefetch: ctx.Runtime.EnablePrefetch,
		NydusdPath:     ctx.Binary.Nydusd,
		BootstrapPath:  ctx.Env.BootstrapPath,
		ConfigPath:     filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		BackendType:    "localfs",
		BackendConfig:  fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		ExternalBackend: fmt.Sprintf(`
		[
			{
				"patch": {
					"repository": "https://zeta.alipay.com/zeta/model-test"
				},
				"type": "zeta",
				"config": {
					"auth": "%s"
				}
			}
		]
	`, os.Getenv("ZETA_AUTH")),
		BlobCacheDir:    ctx.Env.CacheDir,
		APISockPath:     filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		MountPath:       ctx.Env.MountDir,
		CacheType:       ctx.Runtime.CacheType,
		CacheCompressed: ctx.Runtime.CacheCompressed,
		RafsMode:        ctx.Runtime.RafsMode,
		DigestValidate:  false,
		AmplifyIO:       ctx.Runtime.AmplifyIO,
	}

	nydusd, err := tool.NewNydusd(config)
	require.NoError(t, err)
	err = nydusd.Mount()
	require.NoError(t, err)

	fmt.Println("mountpoint:", ctx.Env.MountDir)
	time.Sleep(time.Second * 10000)

	check(t, ctx, testModctlRepoDir, ctx.Env.MountDir)

	defer func() {
		if err := nydusd.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()
}

func mergeLayers(t *testing.T, ctx tool.Context, mergeOption converter.MergeOption, layers []converter.Layer) ([]digest.Digest, string, *digest.Digest) {
	for idx := range layers {
		ra, err := local.OpenReader(filepath.Join(ctx.Env.BlobDir, layers[idx].Digest.Hex()))
		require.NoError(t, err)
		defer ra.Close()
		layers[idx].ReaderAt = ra
	}

	bootstrap, err := os.CreateTemp(ctx.Env.WorkDir, "bootstrap-")
	require.NoError(t, err)
	defer bootstrap.Close()
	digester := digest.SHA256.Digester()
	writer := io.MultiWriter(bootstrap, digester.Hash())
	actualDigests, err := converter.Merge(context.Background(), layers, writer, mergeOption)
	require.NoError(t, err)
	bootstrapDiffID := digester.Digest()
	return actualDigests, bootstrap.Name(), &bootstrapDiffID
}

func packWithAttributes(t *testing.T, packOption converter.PackOption, blobDir, sourceDir string) (digest.Digest, digest.Digest) {
	blob, err := os.CreateTemp(blobDir, "blob-")
	require.NoError(t, err)
	defer blob.Close()

	externalBlob, err := os.CreateTemp(blobDir, "external-blob-")
	require.NoError(t, err)
	defer externalBlob.Close()

	blobDigester := digest.Canonical.Digester()
	blobWriter := io.MultiWriter(blob, blobDigester.Hash())
	externalBlobDigester := digest.Canonical.Digester()
	packOption.FromDir = sourceDir
	packOption.ExternalBlobWriter = io.MultiWriter(externalBlob, externalBlobDigester.Hash())
	_, err = converter.Pack(context.Background(), blobWriter, packOption)
	require.NoError(t, err)

	blobDigest := blobDigester.Digest()
	err = os.Rename(blob.Name(), filepath.Join(blobDir, blobDigest.Hex()))
	require.NoError(t, err)

	externalBlobDigest := externalBlobDigester.Digest()
	err = os.Rename(externalBlob.Name(), filepath.Join(blobDir, externalBlobDigest.Hex()))
	require.NoError(t, err)

	return blobDigest, externalBlobDigest
}

func pushManifest(
	ctx context.Context, modelCfg modelspec.Model, nydusImage parser.Image, bootstrapDiffID digest.Digest, targetRef, bootstrapTarPath, fsversion string, insecure bool,
) error {

	// Push image config
	modelCfg.ModelFS.DiffIDs = []digest.Digest{
		bootstrapDiffID,
	}

	configBytes, configDesc, err := makeDesc(modelCfg, nydusImage.Manifest.Config)
	if err != nil {
		return errors.Wrap(err, "make config desc")
	}
	fmt.Printf("config bytes %s\n", string(configBytes))
	fmt.Printf("traget_ref %s\n", targetRef)
	remoter, err := provider.DefaultRemote(targetRef, insecure)
	if err != nil {
		return errors.Wrap(err, "create remote")
	}

	fmt.Printf("config desc digest %s\n", configDesc.Digest)
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
	bootstrapTar, err := os.Open(bootstrapTarPath)
	if err != nil {
		return errors.Wrap(err, "open bootstrap tar file")
	}

	bootstrapTarGzPath := bootstrapTarPath + ".gz"
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

	bootstrapDesc := ocispec.Descriptor{
		Digest:    digester.Digest(),
		Size:      ra.Size(),
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Annotations: map[string]string{
			converter.LayerAnnotationFSVersion:      fsversion,
			converter.LayerAnnotationNydusBootstrap: "true"},
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
	var layers []ocispec.Descriptor
	layers = append(layers, bootstrapDesc)

	nydusImage.Manifest.Config = *configDesc
	nydusImage.Manifest.Layers = layers

	manifestBytes, manifestDesc, err := makeDesc(nydusImage.Manifest, nydusImage.Desc)
	if err != nil {
		return errors.Wrap(err, "make manifest desc")
	}
	fmt.Printf("manifest Bytes %s, digest: %s type: %s \n", string(manifestBytes), manifestDesc.Digest, manifestDesc.MediaType)
	if err := remoter.Push(ctx, *manifestDesc, false, bytes.NewReader(manifestBytes)); err != nil {
		return errors.Wrap(err, "push image manifest")
	}

	return nil
}

func buildNydusImage() *parser.Image {
	manifest := ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: modelspec.ArtifactTypeModelManifest,
		Config: ocispec.Descriptor{
			MediaType: modelspec.MediaTypeModelConfig,
		},
		Annotations: map[string]string{
			"containerd.io/snapshot/nydus-artifact-type": modelspec.ArtifactTypeModelManifest,
		},
	}
	desc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
	}
	nydusImage := &parser.Image{
		Manifest: manifest,
		Desc:     desc,
	}
	return nydusImage
}

func makeDesc(x interface{}, oldDesc ocispec.Descriptor) ([]byte, *ocispec.Descriptor, error) {
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

type ModctlTestConfig struct {
	Option    modctl.Option `json:"option"`
	TargetRef string        `json:"target_ref"`
}

// sudo WORK_DIR=/tmp \
// NYDUS_BUILDER=/home/imeoer/nydus-rs/target/release/nydus-image \
// NYDUS_NYDUSD=/home/imeoer/nydus-rs/target/release/nydusd \
// ./test -test.run ^TestExternal$
func TestModctlExternal(t *testing.T) {
	// Prepare work directory
	ctx := tool.DefaultContext(t)
	ctx.PrepareWorkDir(t)
	// defer ctx.Destroy(t)

	// Prepare backend meta file
	attributesPath := filepath.Join(ctx.Env.WorkDir, ".nydusattributes")
	backendMetaPath := filepath.Join(ctx.Env.CacheDir, ".backend.meta")
	backendConfigPath := filepath.Join(ctx.Env.CacheDir, ".backend.json")
	optPath := "./modctl.json"
	optBytes, err := os.ReadFile(optPath)
	require.NoError(t, err)
	var cfg ModctlTestConfig
	json.Unmarshal([]byte(optBytes), &cfg)
	handler, err := modctl.NewHandler(cfg.Option)
	require.NoError(t, err)
	err = external.Handle(context.Background(), external.Options{
		Dir:              testModctlRepoDir,
		Handler:          handler,
		MetaOutput:       backendMetaPath,
		BackendOutput:    backendConfigPath,
		AttributesOutput: attributesPath,
	})
	require.NoError(t, err)

	// Make nydus layer with external blob
	packOption := converter.PackOption{
		BuilderPath:    ctx.Binary.Builder,
		Compressor:     ctx.Build.Compressor,
		FsVersion:      ctx.Build.FSVersion,
		ChunkSize:      ctx.Build.ChunkSize,
		FromDir:        modelContextDir,
		AttributesPath: attributesPath,
	}
	fmt.Printf("env: %+v \n", ctx.Env)
	blobDigest, externalBlobDigest := packWithAttributes(t, packOption, ctx.Env.BlobDir, modelContextDir)

	err = os.Rename(backendMetaPath, filepath.Join(ctx.Env.CacheDir, externalBlobDigest.Hex()+".backend.meta"))
	require.NoError(t, err)

	bkdPath := filepath.Join(ctx.Env.CacheDir, externalBlobDigest.Hex()+".backend.json")
	err = os.Rename(backendConfigPath, bkdPath)
	require.NoError(t, err)

	mergeOption := converter.MergeOption{
		BuilderPath: ctx.Binary.Builder,
		WithTar:     true,
		AppendFiles: []converter.File{},
	}
	bkdCfg, err := os.ReadFile(bkdPath)
	require.NoError(t, err)
	bkdReader := bytes.NewReader(bkdCfg)
	mergeOption.AppendFiles = append(mergeOption.AppendFiles, converter.File{
		Name:   "backend.json",
		Reader: bkdReader,
		Size:   int64(len(bkdCfg)),
	})
	actualDigests, mergedBootstrap, bootstrapDiffID := mergeLayers(t, *ctx, mergeOption, []converter.Layer{
		{
			Digest: blobDigest,
		},
		{
			Digest: externalBlobDigest,
		},
	})
	require.Equal(t, []digest.Digest{blobDigest, externalBlobDigest}, actualDigests)
	fmt.Printf("mergedBootstrap: %s", mergedBootstrap)
	bootStrapTarPath := mergedBootstrap + ".tar"
	os.Rename(mergedBootstrap, bootStrapTarPath)

	cfgBytes, err := handler.GetConfig()
	require.NoError(t, err)
	var modelCfg modelspec.Model
	err = json.Unmarshal(cfgBytes, &modelCfg)
	require.NoError(t, err)

	nydusImage := buildNydusImage()
	err = pushManifest(context.Background(), modelCfg, *nydusImage, *bootstrapDiffID, cfg.TargetRef, bootStrapTarPath, ctx.Build.FSVersion, true)
	require.NoError(t, err)

	// build manifest

	// push

	// // Verify layer mounted by nydusd
	// ctx.Env.BootstrapPath = mergedBootstrap
	// verify(t, *ctx)
}
