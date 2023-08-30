package tests

import (
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/containerd/log"
	"github.com/dragonflyoss/image-service/smoke/tests/texture"
	"github.com/dragonflyoss/image-service/smoke/tests/tool"
	"github.com/dragonflyoss/image-service/smoke/tests/tool/test"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/require"
)

type BlobCacheTestSuite struct {
	T *testing.T
}

func (a *BlobCacheTestSuite) compareTwoFiles(t *testing.T, left, right string) {

	lf, err := os.Open(left)
	require.NoError(t, err)
	defer lf.Close()
	leftDigester, err := digest.FromReader(lf)
	require.NoError(t, err)

	rf, err := os.Open(right)
	require.NoError(t, err)
	defer rf.Close()
	rightDigester, err := digest.FromReader(rf)
	require.NoError(t, err)

	require.Equal(t, leftDigester, rightDigester)
}

func (a *BlobCacheTestSuite) prepareTestEnv(t *testing.T) (*tool.Context, string, digest.Digest) {
	ctx := tool.DefaultContext(t)
	ctx.PrepareWorkDir(t)

	rootFs := texture.MakeLowerLayer(t, filepath.Join(ctx.Env.WorkDir, "root-fs"))

	rootfsReader := rootFs.ToOCITar(t)

	ociBlobDigester := digest.Canonical.Digester()
	ociBlob, err := ioutil.TempFile(ctx.Env.BlobDir, "oci-blob-")
	require.NoError(t, err)

	_, err = io.Copy(io.MultiWriter(ociBlobDigester.Hash(), ociBlob), rootfsReader)
	require.NoError(t, err)

	ociBlobDigest := ociBlobDigester.Digest()
	err = os.Rename(ociBlob.Name(), filepath.Join(ctx.Env.BlobDir, ociBlobDigest.Hex()))
	require.NoError(t, err)

	// use to generate blob.data and blob.meta
	blobcacheDir := filepath.Join(ctx.Env.WorkDir, "blobcache")
	err = os.MkdirAll(blobcacheDir, 0755)
	require.NoError(t, err)

	ctx.Env.BootstrapPath = filepath.Join(ctx.Env.WorkDir, "bootstrap")
	return ctx, blobcacheDir, ociBlobDigest
}

func (a *BlobCacheTestSuite) TestCommandFlags(t *testing.T) {
	ctx, blobcacheDir, ociBlobDigest := a.prepareTestEnv(t)
	defer ctx.Destroy(t)

	testCases := []struct {
		name           string
		conversionType string
		bootstrap      string
		testArgs       string
		success        bool
		expectedOutput string
	}{
		{
			name:           "conflict with --blob-dir",
			conversionType: "targz-ref",
			bootstrap:      fmt.Sprintf("--bootstrap %s", ctx.Env.BootstrapPath),
			testArgs:       fmt.Sprintf("--blob-dir %s --blob-cache-dir %s", ctx.Env.BlobDir, blobcacheDir),
			success:        false,
			expectedOutput: "The argument '--blob-dir <blob-dir>' cannot be used with '--blob-cache-dir <blob-cache-dir>'",
		},
		{
			name:           "conflict with --blob",
			conversionType: "targz-ref",
			bootstrap:      fmt.Sprintf("--bootstrap %s", ctx.Env.BootstrapPath),
			testArgs:       fmt.Sprintf("--blob %s --blob-cache-dir %s", "xxxxxx", blobcacheDir),
			success:        false,
			expectedOutput: "The argument '--blob <blob>' cannot be used with '--blob-cache-dir <blob-cache-dir>'",
		},
		{
			name:           "conflict with --blob-inline-meta",
			conversionType: "targz-ref",
			bootstrap:      "",
			testArgs:       fmt.Sprintf("--blob-inline-meta --blob-cache-dir %s", blobcacheDir),
			success:        false,
			expectedOutput: "The argument '--blob-inline-meta' cannot be used with '--blob-cache-dir <blob-cache-dir>'",
		},
		{
			name:           "conflict with --compressor",
			conversionType: "targz-ref",
			bootstrap:      fmt.Sprintf("--bootstrap %s", ctx.Env.BootstrapPath),
			testArgs:       fmt.Sprintf("--compressor zstd --blob-cache-dir %s", blobcacheDir),
			success:        false,
			expectedOutput: "The argument '--compressor <compressor>' cannot be used with '--blob-cache-dir <blob-cache-dir>'",
		},

		{
			name:           "conflict with tar-tarfs conversion type",
			conversionType: "tar-tarfs",
			bootstrap:      fmt.Sprintf("--bootstrap %s", ctx.Env.BootstrapPath),
			testArgs:       fmt.Sprintf("--blob-cache-dir %s", blobcacheDir),
			success:        false,
			expectedOutput: "conversion type `tar-tarfs` conflicts with `--blob-cache-dir`",
		},

		{
			name:           "conflict with estargztoc-ref conversion type",
			conversionType: "estargztoc-ref",
			bootstrap:      fmt.Sprintf("--bootstrap %s", ctx.Env.BootstrapPath),
			testArgs:       fmt.Sprintf("--blob-id %s --blob-cache-dir %s", "xxxx", blobcacheDir),
			success:        false,
			expectedOutput: "conversion type `estargztoc-ref` conflicts with `--blob-cache-dir`",
		},

		{
			name:           "conflict with estargz-rafs conversion type",
			conversionType: "estargz-rafs",
			bootstrap:      fmt.Sprintf("--bootstrap %s", ctx.Env.BootstrapPath),
			testArgs:       fmt.Sprintf("--blob-cache-dir %s", blobcacheDir),
			success:        false,
			expectedOutput: "conversion type `estargz-rafs` conflicts with `--blob-cache-dir`",
		},

		{
			name:           "conflict with estargz-ref conversion type",
			conversionType: "estargz-ref",
			bootstrap:      fmt.Sprintf("--bootstrap %s", ctx.Env.BootstrapPath),
			testArgs:       fmt.Sprintf("--blob-cache-dir %s", blobcacheDir),
			success:        false,
			expectedOutput: "conversion type `estargz-ref` conflicts with `--blob-cache-dir`",
		},
	}

	for _, tc := range testCases {
		output, err := tool.RunWithCombinedOutput(fmt.Sprintf("%s  create -t %s %s %s %s",
			ctx.Binary.Builder, tc.conversionType, tc.bootstrap, tc.testArgs,
			filepath.Join(ctx.Env.BlobDir, ociBlobDigest.Hex())))

		if tc.success {
			require.NoError(t, err)
		} else {
			require.NotEqual(t, err, nil)
		}

		require.Contains(t, output, tc.expectedOutput)
	}
}

func (a *BlobCacheTestSuite) TestGenerateBlobcache(t *testing.T) {
	ctx, blobcacheDir, ociBlobDigest := a.prepareTestEnv(t)
	defer ctx.Destroy(t)

	tool.Run(t, fmt.Sprintf("%s  create -t targz-ref --bootstrap %s --blob-dir %s %s",
		ctx.Binary.Builder, ctx.Env.BootstrapPath, ctx.Env.BlobDir,
		filepath.Join(ctx.Env.BlobDir, ociBlobDigest.Hex())))

	nydusd, err := tool.NewNydusd(tool.NydusdConfig{
		NydusdPath:      ctx.Binary.Nydusd,
		BootstrapPath:   ctx.Env.BootstrapPath,
		ConfigPath:      filepath.Join(ctx.Env.WorkDir, "nydusd-config.fusedev.json"),
		MountPath:       ctx.Env.MountDir,
		APISockPath:     filepath.Join(ctx.Env.WorkDir, "nydusd-api.sock"),
		BackendType:     "localfs",
		BackendConfig:   fmt.Sprintf(`{"dir": "%s"}`, ctx.Env.BlobDir),
		EnablePrefetch:  ctx.Runtime.EnablePrefetch,
		BlobCacheDir:    ctx.Env.CacheDir,
		CacheType:       ctx.Runtime.CacheType,
		CacheCompressed: ctx.Runtime.CacheCompressed,
		RafsMode:        ctx.Runtime.RafsMode,
		DigestValidate:  false,
	})
	require.NoError(t, err)

	err = nydusd.Mount()
	require.NoError(t, err)
	defer func() {
		if err := nydusd.Umount(); err != nil {
			log.L.WithError(err).Errorf("umount")
		}
	}()

	// make sure blobcache ready
	err = filepath.WalkDir(ctx.Env.MountDir, func(path string, entry fs.DirEntry, err error) error {
		require.Nil(t, err)
		if entry.Type().IsRegular() {
			targetPath, err := filepath.Rel(ctx.Env.MountDir, path)
			require.NoError(t, err)
			_, _ = os.ReadFile(targetPath)
		}
		return nil
	})
	require.NoError(t, err)

	// Generate blobcache
	tool.Run(t, fmt.Sprintf("%s create -t targz-ref --bootstrap %s --blob-cache-dir %s %s",
		ctx.Binary.Builder, ctx.Env.BootstrapPath, blobcacheDir,
		filepath.Join(ctx.Env.BlobDir, ociBlobDigest.Hex())))

	a.compareTwoFiles(t, filepath.Join(blobcacheDir, fmt.Sprintf("%s.blob.data", ociBlobDigest.Hex())), filepath.Join(ctx.Env.CacheDir, fmt.Sprintf("%s.blob.data", ociBlobDigest.Hex())))
	a.compareTwoFiles(t, filepath.Join(blobcacheDir, fmt.Sprintf("%s.blob.meta", ociBlobDigest.Hex())), filepath.Join(ctx.Env.CacheDir, fmt.Sprintf("%s.blob.meta", ociBlobDigest.Hex())))
}

func TestBlobCache(t *testing.T) {
	test.Run(t, &BlobCacheTestSuite{T: t})
}
