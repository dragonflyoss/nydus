package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/distribution/reference"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/containerd/containerd/content/local"
	"github.com/containerd/log"

	"github.com/BraveY/snapshotter-converter/converter"
	checkerTool "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/tool"
	pkgConv "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/converter"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/external/modctl"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/viewer"
	"github.com/dragonflyoss/nydus/smoke/tests/tool"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var modelctlWorkDir = os.Getenv("NYDUS_MODELCTL_WORK_DIR")
var modelctlContextDir = os.Getenv("NYDUS_MODELCTL_CONTEXT_DIR")
var modelRegistryAuth = os.Getenv("NYDUS_MODEL_REGISTRY_AUTH")
var modelImageRef = os.Getenv("NYDUS_MODEL_IMAGE_REF")

type proxy struct {
	CacheDir       string `json:"cache_dir"`
	URL            string `json:"url"`
	Fallback       bool   `json:"fallback"`
	Timeout        int    `json:"timeout"`
	ConnectTimeout int    `json:"connect_timeout"`
}

func walk(t *testing.T, root string) map[string]*tool.File {
	tree := map[string]*tool.File{}

	err := filepath.WalkDir(root, func(path string, _ fs.DirEntry, err error) error {
		require.Nil(t, err)

		targetPath, err := filepath.Rel(root, path)
		require.NoError(t, err)
		if targetPath == "." {
			return nil
		}

		stat, err := os.Lstat(path)
		require.NoError(t, err)
		if stat.Size() > (1024<<10)*128 {
			t.Logf("skip large file verification: %s", targetPath)
			return nil
		}

		file := tool.NewFile(t, path, targetPath)
		tree[targetPath] = file

		return nil
	})
	require.NoError(t, err)

	return tree
}

func check(t *testing.T, source, target string) {
	sourceTree := walk(t, source)
	targetTree := walk(t, target)

	for targetPath, targetFile := range targetTree {
		if sourceFile := sourceTree[targetPath]; sourceFile != nil {
			sourceFile.Compare(t, targetFile)
		} else {
			t.Fatalf("not found file %s in source", targetPath)
		}
	}
}

func verify(t *testing.T, ctx tool.Context, externalBackendConfigPath string) {
	config := tool.NydusdConfig{
		EnablePrefetch:               ctx.Runtime.EnablePrefetch,
		NydusdPath:                   ctx.Binary.Nydusd,
		BootstrapPath:                ctx.Env.BootstrapPath,
		ConfigPath:                   filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		BackendType:                  "localfs",
		BackendConfig:                fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		ExternalBackendConfigPath:    externalBackendConfigPath,
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

	if os.Getenv("NYDUS_ONLY_MOUNT") == "true" {
		fmt.Printf("nydusd mounted: %s\n", ctx.Env.MountDir)
		time.Sleep(time.Hour * 5)
	}

	check(t, modelctlContextDir, ctx.Env.MountDir)

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

func TestModctlExternal(t *testing.T) {
	if modelImageRef == "" {
		t.Skip("skipping external test because no model image is specified")
	}
	// Prepare work directory
	ctx := tool.DefaultContext(t)
	ctx.PrepareWorkDir(t)
	ctx.Build.Compressor = "lz4_block"
	ctx.Build.FSVersion = "5"
	defer ctx.Destroy(t)

	host, name, tag, err := parseReference(modelImageRef)
	require.NoError(t, err)
	repo := strings.SplitN(name, "/", 2)
	require.Len(t, repo, 2)

	bootstrapPath := os.Getenv("NYDUS_BOOTSTRAP")
	backendConfigPath := os.Getenv("NYDUS_EXTERNAL_BACKEND_CONFIG")

	if bootstrapPath == "" {
		// Generate nydus attributes
		attributesPath := filepath.Join(ctx.Env.WorkDir, ".nydusattributes")
		backendMetaPath := filepath.Join(ctx.Env.WorkDir, "backend.meta")
		backendConfigPath = filepath.Join(ctx.Env.WorkDir, "build.backend.json")

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

		// Build external bootstrap
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

		bootstrapPath = filepath.Join(ctx.Env.WorkDir, "bootstrap")
		bootstrap, err := os.Create(filepath.Join(ctx.Env.WorkDir, "bootstrap"))
		require.NoError(t, err)
		defer bootstrap.Close()

		_, err = converter.UnpackEntry(externalBlobRa, converter.EntryBootstrap, bootstrap)
		require.NoError(t, err)

		// Check external bootstrap
		err = tool.CheckBootstrap(tool.CheckOption{
			BuilderPath: ctx.Binary.Builder,
		}, bootstrapPath)
		require.NoError(t, err)
	}

	// Prepare external backend config
	err = buildRuntimeExternalBackendConfig(ctx, host, name, backendConfigPath)
	assert.NoError(t, err)
	// Verify nydus filesystem with model context directory
	ctx.Env.BootstrapPath = bootstrapPath
	verify(t, *ctx, backendConfigPath)
}

func TestModctlExternalBinary(t *testing.T) {
	if modelImageRef == "" {
		t.Skip("skipping external test because no model image is specified")
	}
	nydusifyPath := os.Getenv("NYDUS_NYDUSIFY")
	if nydusifyPath == "" {
		t.Skip("skipping external test because nydusify binary is not specified")
	}

	// Prepare work directory
	ctx := tool.DefaultContext(t)
	ctx.PrepareWorkDir(t)
	ctx.Build.Compressor = "lz4_block"
	ctx.Build.FSVersion = "5"
	defer ctx.Destroy(t)
	source := modelImageRef
	target := modelImageRef + "_smoke_test_nydus_v2" + strconv.Itoa(int(time.Now().Unix()))

	t.Run("Convert with modelfile type", func(t *testing.T) {
		sourceBackendType := "modelfile"
		srcBkdCfg := pkgConv.SourceBackendConfig{
			Context: modelctlContextDir,
			WorkDir: modelctlWorkDir,
		}
		srcBkdCfgBytes, err := json.Marshal(srcBkdCfg)
		require.NoError(t, err)
		args := []string{
			"convert",
			"--source-backend-type",
			sourceBackendType,
			"--source-backend-config",
			string(srcBkdCfgBytes),
			"--source",
			source,
			"--target",
			target,
			"--nydus-image",
			ctx.Binary.Builder,
			"--fs-version",
			ctx.Build.FSVersion,
			"--compressor",
			ctx.Build.Compressor,
		}
		convertAndCheck(t, ctx, target, args)
	})

	t.Run("Convert with model-artifact type", func(t *testing.T) {
		sourceBackendType := "model-artifact"
		args := []string{
			"convert",
			"--log-level",
			"warn",
			"--source-backend-type",
			sourceBackendType,
			"--source",
			source,
			"--target",
			target,
			"--nydus-image",
			ctx.Binary.Builder,
			"--fs-version",
			ctx.Build.FSVersion,
			"--compressor",
			ctx.Build.Compressor,
		}
		convertAndCheck(t, ctx, target, args)
	})

}

// nydusify convert image to nydus
// nydus-image check bootstrap
// nydusd mount and compare file meta.
func convertAndCheck(t *testing.T, ctx *tool.Context, target string, args []string) {
	host, name, _, err := parseReference(modelImageRef)
	require.NoError(t, err)
	repo := strings.SplitN(name, "/", 2)
	require.Len(t, repo, 2)

	logger := logrus.NewEntry(logrus.New())
	logger.Infof("Command: %s %s", ctx.Binary.Nydusify, strings.Join(args, " "))
	nydusifyCmd := exec.CommandContext(context.Background(), ctx.Binary.Nydusify, args...)
	nydusifyCmd.Stdout = logger.WithField("module", "nydusify").Writer()
	nydusifyCmd.Stderr = logger.WithField("module", "nydusify").Writer()

	err = nydusifyCmd.Run()
	assert.NoError(t, err)

	// check bootstrap
	targetRemote, err := provider.DefaultRemote(target, false)
	assert.NoError(t, err)
	arch := runtime.GOARCH
	targetParser, err := parser.New(targetRemote, arch)
	assert.NoError(t, err)
	targetParsed, err := targetParser.Parse(context.Background())
	assert.NoError(t, err)

	bootstrapPath := filepath.Join(ctx.Env.WorkDir, "nydus_bootstrap")
	backendConfigPath := filepath.Join(ctx.Env.WorkDir, "nydus_backend.json")
	fsViewer := buildFsViewer(ctx, targetParser, bootstrapPath, backendConfigPath)
	err = fsViewer.PullBootstrap(context.Background(), targetParsed)
	assert.NoError(t, err)

	err = tool.CheckBootstrap(tool.CheckOption{
		BuilderPath: ctx.Binary.Builder,
	}, bootstrapPath)
	assert.NoError(t, err)

	// mount and compare file metadata
	err = buildRuntimeExternalBackendConfig(ctx, host, name, backendConfigPath)
	assert.NoError(t, err)
	ctx.Env.BootstrapPath = bootstrapPath
	verify(t, *ctx, backendConfigPath)
}

func buildFsViewer(ctx *tool.Context, targetParser *parser.Parser, bootstrapPath, backendConfigPath string) *viewer.FsViewer {
	return &viewer.FsViewer{
		Opt: viewer.Opt{
			WorkDir: ctx.Env.WorkDir,
		},
		NydusdConfig: checkerTool.NydusdConfig{
			BootstrapPath:             bootstrapPath,
			ExternalBackendConfigPath: backendConfigPath,
		},
		Parser: targetParser,
	}
}

func buildRuntimeExternalBackendConfig(ctx *tool.Context, host, name, backendConfigPath string) error {
	backendBytes, err := os.ReadFile(backendConfigPath)
	if err != nil {
		return errors.Wrap(err, "failed to read backend config file")
	}
	backend := backend.Backend{}
	if err = json.Unmarshal(backendBytes, &backend); err != nil {
		return errors.Wrap(err, "failed to unmarshal backend config file")
	}

	proxyURL := os.Getenv("NYDUS_EXTERNAL_PROXY_URL")
	cacheDir := os.Getenv("NYDUS_EXTERNAL_PROXY_CACHE_DIR")
	if cacheDir == "" {
		cacheDir = ctx.Env.CacheDir
	}
	backend.Backends[0].Config = map[string]interface{}{
		"scheme":          "https",
		"host":            host,
		"repo":            name,
		"auth":            modelRegistryAuth,
		"timeout":         30,
		"connect_timeout": 5,
		"proxy": proxy{
			CacheDir: cacheDir,
			URL:      proxyURL,
			Fallback: true,
		},
	}

	backendBytes, err = json.MarshalIndent(backend, "", "  ")
	if err != nil {
		return errors.Wrap(err, "failed to marshal backend config file")
	}
	return os.WriteFile(backendConfigPath, backendBytes, 0644)
}
