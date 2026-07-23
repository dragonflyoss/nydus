package copier

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/platforms"
	"github.com/goharbor/acceleration-service/pkg/remote"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	nydusifyUtils "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

func TestGetPlatform(t *testing.T) {
	require.Equal(t, platforms.DefaultString(), getPlatform(nil))
	require.Equal(t, "linux/arm64", getPlatform(&ocispec.Platform{OS: "linux", Architecture: "arm64"}))
	require.Equal(t, "windows/amd64", getPlatform(&ocispec.Platform{OS: "windows", Architecture: "amd64"}))
}

func TestGetLocalPath(t *testing.T) {
	isLocal, absPath, err := getLocalPath("docker.io/library/busybox:latest")
	require.NoError(t, err)
	require.False(t, isLocal)
	require.Empty(t, absPath)

	isLocal, absPath, err = getLocalPath("file://./testdata")
	require.NoError(t, err)
	require.True(t, isLocal)
	require.Equal(t, filepath.Join(filepath.Dir(absPath), "testdata"), absPath)

	isLocal, absPath, err = getLocalPath("file:///tmp/image.tar")
	require.NoError(t, err)
	require.True(t, isLocal)
	require.Equal(t, "/tmp/image.tar", absPath)
}

func TestGetLocalPathEmpty(t *testing.T) {
	isLocal, absPath, err := getLocalPath("")
	require.NoError(t, err)
	require.False(t, isLocal)
	require.Empty(t, absPath)
}

func TestGetLocalPathAbsolute(t *testing.T) {
	isLocal, absPath, err := getLocalPath("file:///var/data/image.tar")
	require.NoError(t, err)
	require.True(t, isLocal)
	require.Equal(t, "/var/data/image.tar", absPath)
}

func TestHosts(t *testing.T) {
	opt := Opt{
		Source:         "docker.io/library/busybox:latest",
		Target:         "registry.example.com/image:tag",
		SourceInsecure: true,
		TargetInsecure: false,
	}

	hostFunc := hosts(opt)

	credFunc, insecure, err := hostFunc(opt.Source)
	require.NoError(t, err)
	require.NotNil(t, credFunc)
	require.True(t, insecure)

	credFunc, insecure, err = hostFunc(opt.Target)
	require.NoError(t, err)
	require.NotNil(t, credFunc)
	require.False(t, insecure)

	// Unknown ref defaults to false
	credFunc, insecure, err = hostFunc("unknown.registry.io/image:tag")
	require.NoError(t, err)
	require.NotNil(t, credFunc)
	require.False(t, insecure)
}

func TestHostsCredentialFunc(t *testing.T) {
	opt := Opt{
		Source:         "source-ref",
		Target:         "target-ref",
		SourceInsecure: false,
		TargetInsecure: true,
	}
	hostFunc := hosts(opt)

	// Verify the credential function is a DockerConfigCredFunc
	credFunc, _, err := hostFunc("source-ref")
	require.NoError(t, err)
	require.IsType(t, (remote.CredentialFunc)(nil), credFunc)
}

func TestGetLocalPathEmptyFileScheme(t *testing.T) {
	// "file://" with no path after prefix → treated as relative empty path → cwd
	isLocal, absPath, err := getLocalPath("file://")
	require.NoError(t, err)
	require.True(t, isLocal)
	require.NotEmpty(t, absPath)
}

func TestGetLocalPathBareRelative(t *testing.T) {
	// "file://bare-relative" → treated as a relative path
	isLocal, absPath, err := getLocalPath("file://bare-relative")
	require.NoError(t, err)
	require.True(t, isLocal)
	require.True(t, filepath.IsAbs(absPath))
	require.True(t, strings.HasSuffix(absPath, "bare-relative"))
}

func TestHostsSameSourceAndTarget(t *testing.T) {
	ref := "docker.io/library/busybox:latest"
	opt := Opt{
		Source:         ref,
		Target:         ref,
		SourceInsecure: true,
		TargetInsecure: false,
	}
	hostFunc := hosts(opt)
	// When source and target are the same string, the second write in the map
	// clobbers the first; TargetInsecure (false) overwrites SourceInsecure (true).
	_, insecure, err := hostFunc(ref)
	require.NoError(t, err)
	require.False(t, insecure)
}

func TestCopyFailsWithUnsupportedBackendType(t *testing.T) {
	err := Copy(context.Background(), Opt{
		WorkDir:             t.TempDir(),
		Source:              "docker.io/library/busybox:latest",
		Target:              "registry.example.com/busybox:latest",
		SourceBackendType:   "no-such-backend",
		SourceBackendConfig: "{}",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "new backend")
}

func TestCopyFailsWithUnsupportedTargetBackendType(t *testing.T) {
	err := Copy(context.Background(), Opt{
		WorkDir:             t.TempDir(),
		Source:              "docker.io/library/busybox:latest",
		Target:              "registry.example.com/busybox:latest",
		TargetBackendType:   "no-such-backend",
		TargetBackendConfig: "{}",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "new target backend")
}

func TestPushBlobFromBackendRejectsUnsupportedMediaType(t *testing.T) {
	src := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageConfig,
		Digest:    digest.FromString("unsupported"),
	}

	blobs, target, err := pushBlobFromBackend(context.Background(), nil, nil, src, Opt{WorkDir: t.TempDir()})
	require.Nil(t, blobs)
	require.Nil(t, target)
	require.EqualError(t, err, "unsupported media type application/vnd.oci.image.config.v1+json")
}

func TestPushBlobToBackendRejectsUnsupportedMediaType(t *testing.T) {
	src := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageConfig,
		Digest:    digest.FromString("unsupported"),
	}

	blobs, target, err := pushBlobToBackend(context.Background(), nil, nil, nil, src, Opt{WorkDir: t.TempDir()})
	require.Nil(t, blobs)
	require.Nil(t, target)
	require.EqualError(t, err, "unsupported media type application/vnd.oci.image.config.v1+json")
}

func TestRemoveBootstrapBackendConfig(t *testing.T) {
	workDir := t.TempDir()
	backendConfigPath := filepath.Join(workDir, nydusifyUtils.BackendFileNameInLayer)
	require.NoError(t, os.MkdirAll(filepath.Dir(backendConfigPath), 0o755))
	require.NoError(t, os.WriteFile(backendConfigPath, []byte("secret"), 0o644))

	require.NoError(t, removeBootstrapBackendConfig(workDir))
	_, err := os.Stat(backendConfigPath)
	require.ErrorIs(t, err, os.ErrNotExist)

	require.NoError(t, removeBootstrapBackendConfig(workDir))
}

func TestRewriteManifestForTargetBackend(t *testing.T) {
	manifest := &ocispec.Manifest{
		Layers: []ocispec.Descriptor{
			{Digest: digest.FromString("blob-1")},
			{Digest: digest.FromString("blob-2")},
			{Digest: digest.FromString("bootstrap-old")},
		},
	}
	config := &ocispec.Image{
		RootFS: ocispec.RootFS{
			DiffIDs: []digest.Digest{
				digest.FromString("blob-1"),
				digest.FromString("blob-2"),
				digest.FromString("bootstrap-old"),
			},
		},
	}
	bootstrapDesc := ocispec.Descriptor{Digest: digest.FromString("bootstrap-new")}
	bootstrapDiffID := digest.FromString("bootstrap-diffid")

	rewriteManifestForTargetBackend(manifest, config, bootstrapDesc, bootstrapDiffID)

	require.Equal(t, []ocispec.Descriptor{bootstrapDesc}, manifest.Layers)
	require.Equal(t, []digest.Digest{bootstrapDiffID}, config.RootFS.DiffIDs)
}

func TestCopyFailsWithInvalidPlatforms(t *testing.T) {
	err := Copy(context.Background(), Opt{
		WorkDir:   t.TempDir(),
		Platforms: "invalid-platform-format!!!",
	})
	require.Error(t, err)
}

func TestCopyFailsWithInvalidSourceReference(t *testing.T) {
	err := Copy(context.Background(), Opt{
		WorkDir: t.TempDir(),
		Source:  "not a valid reference",
		Target:  "registry.example.com/ns/image:tag",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse source reference")
}

func TestGetLocalPathWithParentDirTraversal(t *testing.T) {
	isLocal, absPath, err := getLocalPath("file://../data/image.tar")
	require.NoError(t, err)
	require.True(t, isLocal)
	require.True(t, filepath.IsAbs(absPath))
	require.True(
		t,
		strings.HasSuffix(absPath, filepath.Join("data", "image.tar")),
	)
}

func TestGetPlatformWithPartialPlatform(t *testing.T) {
	require.Contains(t, getPlatform(&ocispec.Platform{OS: "darwin"}), "darwin")
	require.Equal(t, "unknown", getPlatform(&ocispec.Platform{Architecture: "arm64"}))
}

func TestHostsWithLocalRegistries(t *testing.T) {
	opt := Opt{
		Source:         "localhost:5000/image:tag",
		Target:         "127.0.0.1:5001/image:tag",
		SourceInsecure: true,
		TargetInsecure: true,
	}

	hostFunc := hosts(opt)

	credFunc, insecure, err := hostFunc(opt.Source)
	require.NoError(t, err)
	require.NotNil(t, credFunc)
	require.True(t, insecure)

	credFunc, insecure, err = hostFunc(opt.Target)
	require.NoError(t, err)
	require.NotNil(t, credFunc)
	require.True(t, insecure)

	credFunc, insecure, err = hostFunc("other.io/image:tag")
	require.NoError(t, err)
	require.NotNil(t, credFunc)
	require.False(t, insecure)
}
