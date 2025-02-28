package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/pkg/errors"

	"github.com/containerd/containerd/content/local"
	"github.com/containerd/log"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/external/modctl"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/converter"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

var modelctlWorkDir = os.Getenv("NYDUS_MODELCTL_WORK_DIR")
var modelctlContextDir = os.Getenv("NYDUS_MODELCTL_CONTEXT_DIR")
var modelRegistryAuth = os.Getenv("NYDUS_MODEL_REGISTRY_AUTH")
var modelImageRef = os.Getenv("NYDUS_MODEL_IMAGE_REF")

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

func verify(t *testing.T, ctx tool.Context, ExternalBackendConfigPath string) {
	config := tool.NydusdConfig{
		EnablePrefetch:               ctx.Runtime.EnablePrefetch,
		NydusdPath:                   ctx.Binary.Nydusd,
		BootstrapPath:                ctx.Env.BootstrapPath,
		ConfigPath:                   filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		BackendType:                  "localfs",
		BackendConfig:                fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		ExternalBackendConfigPath:    ExternalBackendConfigPath,
		ExternalBackendProxyCacheDir: ctx.Env.CacheDir,
		BlobCacheDir:                 ctx.Env.CacheDir,
		APISockPath:                  filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		MountPath:                    ctx.Env.MountDir,
		CacheType:                    ctx.Runtime.CacheType,
		CacheCompressed:              ctx.Runtime.CacheCompressed,
		RafsMode:                     ctx.Runtime.RafsMode,
		DigestValidate:               false,
		AmplifyIO:                    ctx.Runtime.AmplifyIO,
	}

	nydusd, err := tool.NewNydusd(config)
	require.NoError(t, err)
	err = nydusd.Mount()
	require.NoError(t, err)

	fmt.Println("mountpoint:", ctx.Env.MountDir)
	time.Sleep(time.Second * 10000)

	// check(t, ctx, testModctlRepoDir, ctx.Env.MountDir)

	defer func() {
		if err := nydusd.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()
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

type ModctlTestConfig struct {
	Option    modctl.Option `json:"option"`
	TargetRef string        `json:"target_ref"`
}

func parseReference(ref string) (string, string, string, error) {
	refs, err := reference.Parse(ref)
	if err != nil {
		return "", "", "", errors.Wrapf(err, "invalid image reference: %s", ref)
	}

	if named, ok := refs.(reference.Named); ok {
		domain := reference.Domain(named)
		name := reference.Path(named)
		tag := ""
		if tagged, ok := named.(reference.Tagged); ok {
			tag = tagged.Tag()
		}
		return domain, name, tag, nil
	}

	return "", "", "", fmt.Errorf("invalid image reference: %s", ref)
}

// sudo WORK_DIR=/tmp \
// NYDUS_BUILDER=/home/imeoer/nydus-rs/target/release/nydus-image \
// NYDUS_NYDUSD=/home/imeoer/nydus-rs/target/release/nydusd \
// ./test -test.run ^TestExternal$
func TestModctlExternal(t *testing.T) {
	// Prepare work directory
	ctx := tool.DefaultContext(t)
	ctx.PrepareWorkDir(t)
	ctx.Build.FSVersion = "5"
	// defer ctx.Destroy(t)

	// Prepare backend meta file
	attributesPath := filepath.Join(ctx.Env.WorkDir, ".nydusattributes")
	backendMetaPath := filepath.Join(ctx.Env.WorkDir, "backend.meta")
	backendConfigPath := filepath.Join(ctx.Env.WorkDir, "build.backend.json")

	host, name, tag, err := parseReference(modelImageRef)
	require.NoError(t, err)
	repo := strings.SplitN(name, "/", 2)
	require.Len(t, repo, 2)

	opt := modctl.Option{
		Root:         modelctlWorkDir,
		RegistryHost: host,
		Namespace:    repo[0],
		ImageName:    repo[1],
		Tag:          tag,
	}
	handler, err := modctl.NewHandler(opt)
	require.NoError(t, err)
	err = external.Handle(context.Background(), external.Options{
		Dir:              modelctlWorkDir,
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
		FromDir:        modelctlContextDir,
		AttributesPath: attributesPath,
	}
	_, externalBlobDigest := packWithAttributes(t, packOption, ctx.Env.BlobDir, modelctlContextDir)

	externalBlobRa, err := local.OpenReader(filepath.Join(ctx.Env.BlobDir, externalBlobDigest.Hex()))
	require.NoError(t, err)

	bootstrapPath := filepath.Join(ctx.Env.WorkDir, "bootstrap")
	bootstrap, err := os.Create(filepath.Join(ctx.Env.WorkDir, "bootstrap"))
	require.NoError(t, err)
	defer bootstrap.Close()

	_, err = converter.UnpackEntry(externalBlobRa, converter.EntryBootstrap, bootstrap)
	require.NoError(t, err)

	fmt.Println("====================================== BOOTSTRAP", bootstrapPath)

	// Check bootstrap file
	err = tool.CheckBootstrap(tool.CheckOption{
		BuilderPath: ctx.Binary.Builder,
	}, bootstrapPath)
	require.NoError(t, err)

	// Prepare external backend config
	backendBytes, err := os.ReadFile(backendConfigPath)
	require.NoError(t, err)
	backend := backend.Backend{}
	err = json.Unmarshal(backendBytes, &backend)
	require.NoError(t, err)

	backend.Backends[0].Config = map[string]string{
		"scheme": "https",
		"host":   host,
		"repo":   name,
		"auth":   modelRegistryAuth,
	}

	backendBytes, err = json.MarshalIndent(backend, "", "  ")
	require.NoError(t, err)

	runtimeBackendConfigPath := filepath.Join(ctx.Env.WorkDir, "backend.json")
	err = os.WriteFile(runtimeBackendConfigPath, backendBytes, 0644)
	require.NoError(t, err)

	// Verify layer mounted by nydusd
	ctx.Env.BootstrapPath = bootstrapPath
	verify(t, *ctx, runtimeBackendConfigPath)
}
