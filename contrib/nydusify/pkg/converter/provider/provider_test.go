package provider

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	accelremote "github.com/goharbor/acceleration-service/pkg/remote"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func testHostFunc(ref string) (accelremote.CredentialFunc, bool, error) {
	return accelremote.NewDockerConfigCredFunc(), ref == "insecure-ref", nil
}

func TestProviderStateHelpers(t *testing.T) {
	pvd, err := New(t.TempDir(), testHostFunc, 8, "v2", platforms.OnlyStrict(ocispec.Platform{OS: "linux", Architecture: "amd64"}), 4096, nil)
	require.NoError(t, err)
	require.NotNil(t, pvd.ContentStore())
	require.Equal(t, 8, pvd.cacheSize)
	require.Equal(t, "v2", pvd.cacheVersion)
	require.Equal(t, int64(4096), pvd.chunkSize)

	pvd.UsePlainHTTP()
	require.True(t, pvd.usePlainHTTP)

	pvd.SetPushRetryConfig(5, 2*time.Second)
	require.Equal(t, 5, pvd.pushRetryCount)
	require.Equal(t, 2*time.Second, pvd.pushRetryDelay)

	pvd.WithLocalSource("source.tar")
	pvd.WithLocalTarget("target.tar")
	require.Equal(t, "source.tar", pvd.localSource)
	require.Equal(t, "target.tar", pvd.localTarget)

	resolver, err := pvd.Resolver("insecure-ref")
	require.NoError(t, err)
	require.NotNil(t, resolver)
}

func TestProviderImageLookupAndCache(t *testing.T) {
	pvd, err := New(t.TempDir(), testHostFunc, 4, "v1", platforms.OnlyStrict(ocispec.Platform{OS: "linux", Architecture: "amd64"}), 0, nil)
	require.NoError(t, err)

	_, err = pvd.Image(context.Background(), "missing")
	require.ErrorIs(t, err, errdefs.ErrNotFound)

	desc := &ocispec.Descriptor{Size: 128}
	pvd.images["present"] = desc
	got, err := pvd.Image(context.Background(), "present")
	require.NoError(t, err)
	require.Equal(t, desc, got)

	ctx := context.Background()
	ctx2, cache := pvd.NewRemoteCache(ctx, "cache-ref")
	require.NotNil(t, cache)
	require.NotNil(t, ctx2)

	ctx3, cache := pvd.NewRemoteCache(ctx, "")
	require.Nil(t, cache)
	require.Equal(t, ctx, ctx3)
}

func TestProviderLocalPathErrors(t *testing.T) {
	pvd, err := New(t.TempDir(), testHostFunc, 4, "v1", platforms.OnlyStrict(ocispec.Platform{OS: "linux", Architecture: "amd64"}), 0, nil)
	require.NoError(t, err)

	_, err = pvd.localPull(context.Background(), filepath.Join(t.TempDir(), "missing.tar"))
	require.Error(t, err)

	err = pvd.localPush(context.Background(), ocispec.Descriptor{}, "ref", filepath.Join(t.TempDir(), "missing", "target.tar"))
	require.Error(t, err)

	pvd.WithLocalSource(filepath.Join(t.TempDir(), "missing.tar"))
	err = pvd.Pull(context.Background(), "ref")
	require.Error(t, err)

	pvd.WithLocalSource("")
	pvd.WithLocalTarget(filepath.Join(t.TempDir(), "missing", "target.tar"))
	err = pvd.Push(context.Background(), ocispec.Descriptor{}, "ref")
	require.Error(t, err)

	filePath := filepath.Join(t.TempDir(), "target.tar")
	require.NoError(t, os.WriteFile(filePath, []byte("existing"), 0644))
}
