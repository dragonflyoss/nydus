package tests

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/log"
	"github.com/containerd/nydus-snapshotter/pkg/converter"
	"github.com/dragonflyoss/image-service/smoke/tests/texture"
	"github.com/dragonflyoss/image-service/smoke/tests/tool"
	"github.com/dragonflyoss/image-service/smoke/tests/tool/test"
	"github.com/stretchr/testify/require"
)

type LocalCASTestSuite struct{}

func (cas *LocalCASTestSuite) TestDeduplication(t *testing.T) {
	cacheSizeWithoutLocalCAS := cas.calculateCacheDirSize(t, false)
	cas.cleanWorkDir(t)
	cacheSizeWithLocalCAS := cas.calculateCacheDirSize(t, true)
	require.Greater(t, cacheSizeWithoutLocalCAS, cacheSizeWithLocalCAS)
}

func (cas *LocalCASTestSuite) cleanWorkDir(t *testing.T) error {
	ctx := tool.DefaultContext(t)
	entries, err := os.ReadDir(ctx.Env.WorkDir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		entryPath := filepath.Join(ctx.Env.WorkDir, entry.Name())

		err := os.RemoveAll(entryPath)
		if err != nil {
			return err
		}
	}

	return nil
}

func (cas *LocalCASTestSuite) calculateCacheDirSize(t *testing.T, enableDeduplication bool) float64 {
	ctx := tool.DefaultContext(t)

	ctx.PrepareWorkDir(t)
	defer ctx.Destroy(t)

	content := strings.Repeat("123456789abcdefghijklmnopqrstuvwxyz", 1024*1024)
	// Create nydusd1
	rootFs1 := texture.MakeLowerLayer(
		t,
		filepath.Join(ctx.Env.WorkDir, "root-fs-1"),
		texture.LargerFileWithCustomizedContentMaker("large-blob.bin", 1, content))

	rafs1 := cas.rootFsToRafs(t, ctx, rootFs1)
	mountDir1 := filepath.Join(ctx.Env.WorkDir, "/1")
	err := os.MkdirAll(mountDir1, 0755)
	require.NoError(t, err)

	var bootstrap1 string
	if enableDeduplication {
		bootstrap1 = rafs1 + ".boot.dedup"
	} else {
		bootstrap1 = rafs1
	}

	config1 := tool.NydusdConfig{
		BootstrapPath:       bootstrap1,
		NydusdPath:          ctx.Binary.Nydusd,
		MountPath:           mountDir1,
		APISockPath:         filepath.Join(ctx.Env.WorkDir, "nydusd-api-1.sock"),
		ConfigPath:          filepath.Join(ctx.Env.WorkDir, "nydusd-config-1.fusedev.json"),
		BackendType:         "localfs",
		BackendConfig:       fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		CacheType:           ctx.Runtime.CacheType,
		CacheCompressed:     ctx.Runtime.CacheCompressed,
		BlobCacheDir:        ctx.Env.CacheDir,
		RafsMode:            ctx.Runtime.RafsMode,
		DigestValidate:      false,
		EnablePrefetch:      true,
		PrefetchFiles:       []string{"/", "/large-blob.bin"},
		EnableDeduplication: enableDeduplication,
		DeduplicationDir:    ctx.Env.WorkDir,
	}

	nydusd1, err := tool.NewNydusd(config1)
	require.NoError(t, err)

	// If enable local CAS, exec "nydus-image dedup" for bootstrap.
	if enableDeduplication {
		tool.Run(t, fmt.Sprintf("%s  dedup --bootstrap %s --config %s",
			ctx.Binary.Builder, rafs1,
			filepath.Join(ctx.Env.WorkDir, "nydusd-config-1.fusedev.json")))
	}

	err = nydusd1.Mount()
	require.NoError(t, err)
	defer func() {
		if err := nydusd1.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()

	// Create nydusd2
	rootFs2 := texture.MakeLowerLayer(
		t,
		filepath.Join(ctx.Env.WorkDir, "root-fs-2"),
		texture.LargerFileWithCustomizedContentMaker("large-blob.bin", 1, content))

	rafs2 := cas.rootFsToRafs(t, ctx, rootFs2)

	mountDir2 := filepath.Join(ctx.Env.WorkDir, "/2")
	err = os.MkdirAll(mountDir2, 0755)
	require.NoError(t, err)

	var bootstrap2 string
	if enableDeduplication {
		bootstrap2 = rafs2 + ".boot.dedup"
	} else {
		bootstrap2 = rafs2
	}

	config2 := tool.NydusdConfig{
		BootstrapPath:       bootstrap2,
		NydusdPath:          ctx.Binary.Nydusd,
		MountPath:           mountDir2,
		APISockPath:         filepath.Join(ctx.Env.WorkDir, "nydusd-api-2.sock"),
		ConfigPath:          filepath.Join(ctx.Env.WorkDir, "nydusd-config-2.fusedev.json"),
		BackendType:         "localfs",
		BackendConfig:       fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		CacheType:           ctx.Runtime.CacheType,
		BlobCacheDir:        ctx.Env.CacheDir,
		CacheCompressed:     ctx.Runtime.CacheCompressed,
		RafsMode:            ctx.Runtime.RafsMode,
		DigestValidate:      false,
		EnablePrefetch:      true,
		PrefetchFiles:       []string{"/", "/large-blob.bin"},
		EnableDeduplication: enableDeduplication,
		DeduplicationDir:    ctx.Env.WorkDir,
	}

	nydusd2, err := tool.NewNydusd(config2)
	require.NoError(t, err)

	// If enable local CAS, exec "nydus-image dedup" for bootstrap.
	if enableDeduplication {
		tool.Run(t, fmt.Sprintf("%s  dedup --bootstrap %s --config %s",
			ctx.Binary.Builder, rafs2,
			filepath.Join(ctx.Env.WorkDir, "nydusd-config-1.fusedev.json")))
	}

	err = nydusd2.Mount()
	require.NoError(t, err)
	defer func() {
		if err := nydusd2.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()

	time.Sleep(time.Millisecond * 15)

	cacheDir := ctx.Env.CacheDir
	result, err := cas.calculateFolderSize(cacheDir)
	require.NoError(t, err)
	return result
}

func (cas *LocalCASTestSuite) calculateFolderSize(folderPath string) (float64, error) {
	cmd := exec.Command("du", "-sh", folderPath)

	output, err := cmd.Output()
	if err != nil {
		return 0.0, err
	}

	outputString := string(output)
	sizeFields := strings.Fields(outputString)
	if len(sizeFields) > 0 {
		folderSizeStr := sizeFields[0]
		folderSizeStr = strings.TrimSuffix(folderSizeStr, "M")
		folderSizeInMB, err := strconv.ParseFloat(folderSizeStr, 64)
		if err != nil {
			return 0.0, err
		}
		return folderSizeInMB, nil
	} else {
		return 0.0, nil
	}
}

func (cas *LocalCASTestSuite) rootFsToRafs(t *testing.T, ctx *tool.Context, rootFs *tool.Layer) string {
	digest := rootFs.Pack(t,
		converter.PackOption{
			BuilderPath: ctx.Binary.Builder,
			Compressor:  ctx.Build.Compressor,
			FsVersion:   ctx.Build.FSVersion,
			ChunkSize:   ctx.Build.ChunkSize,
		},
		ctx.Env.BlobDir)
	_, bootstrap := tool.MergeLayers(t, *ctx,
		converter.MergeOption{
			BuilderPath: ctx.Binary.Builder,
		},
		[]converter.Layer{
			{Digest: digest},
		})
	return bootstrap
}

func TestLocalCAS(t *testing.T) {
	test.Run(t, &LocalCASTestSuite{})
}
