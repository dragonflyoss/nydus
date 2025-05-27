package converter

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	snapConv "github.com/BraveY/snapshotter-converter/converter"
	modelspec "github.com/CloudNativeAI/model-spec/specs-go/v1"
	"github.com/agiledragon/gomonkey/v2"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/external/modctl"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	pkgPvd "github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external"
)

func TestConvert(t *testing.T) {
	t.Run("convert modelfile", func(t *testing.T) {
		opt := Opt{
			WorkDir:             "/tmp/nydusify",
			SourceBackendType:   "modelfile",
			ChunkSize:           "4MiB",
			SourceBackendConfig: "{}",
		}
		err := Convert(context.Background(), opt)
		assert.Error(t, err)

		opt.ChunkSize = "0x1000"
		opt.Source = "docker.io/library/busybox:latest"
		opt.Target = "docker.io/library/busybox:latest_nydus"
		err = Convert(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Convert model-artifact", func(t *testing.T) {
		opt := Opt{
			WorkDir:           "/tmp/nydusify",
			SourceBackendType: "model-artifact",
		}
		err := Convert(context.Background(), opt)
		assert.Error(t, err)
	})
}

func TestConvertModelFile(t *testing.T) {
	opt := Opt{
		WorkDir:             "/tmp/nydusify",
		SourceBackendConfig: "{}",
		Source:              "docker.io/library/busybox:latest",
		Target:              "docker.io/library/busybox:latest_nydus",
		ChunkSize:           "0x100000",
	}
	t.Run("Run normal", func(t *testing.T) {
		patches := gomonkey.ApplyFunc(modctl.NewHandler, func(modctl.Option) (*modctl.Handler, error) {
			return &modctl.Handler{}, nil
		})
		defer patches.Reset()
		extHandlePatches := gomonkey.ApplyFunc(external.Handle, func(context.Context, external.Options) error {
			return nil
		})
		defer extHandlePatches.Reset()

		packFinBootPatches := gomonkey.ApplyFunc(packFinalBootstrap, func(string, string, digest.Digest) (string, error) {
			return "", nil
		})
		defer packFinBootPatches.Reset()

		buildModelConfigPatches := gomonkey.ApplyFunc(buildModelConfig, func(*modctl.Handler) (*modelspec.Model, error) {
			return &modelspec.Model{}, nil
		})
		defer buildModelConfigPatches.Reset()

		pushManifestPatches := gomonkey.ApplyFunc(pushManifest, func(context.Context, Opt, modelspec.Model, []ocispec.Descriptor, parser.Image, string) error {
			return nil
		})
		defer pushManifestPatches.Reset()
		err := convertModelFile(context.Background(), opt)
		assert.NoError(t, err)
	})

	t.Run("Run newModctlHandler failed", func(t *testing.T) {
		patches := gomonkey.ApplyFunc(modctl.NewHandler, func(modctl.Option) (*modctl.Handler, error) {
			return nil, errors.New("new handler error")
		})
		defer patches.Reset()
		err := convertModelFile(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Run external handle failed", func(t *testing.T) {
		patches := gomonkey.ApplyFunc(modctl.NewHandler, func(modctl.Option) (*modctl.Handler, error) {
			return &modctl.Handler{}, nil
		})
		defer patches.Reset()
		extHandlePatches := gomonkey.ApplyFunc(external.Handle, func(context.Context, external.Options) error {
			return errors.New("external handle mock error")
		})
		defer extHandlePatches.Reset()
		err := convertModelFile(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Run packFinalBootstrap failed", func(t *testing.T) {
		patches := gomonkey.ApplyFunc(modctl.NewHandler, func(modctl.Option) (*modctl.Handler, error) {
			return &modctl.Handler{}, nil
		})
		defer patches.Reset()
		extHandlePatches := gomonkey.ApplyFunc(external.Handle, func(context.Context, external.Options) error {
			return nil
		})
		defer extHandlePatches.Reset()

		packFinBootPatches := gomonkey.ApplyFunc(packFinalBootstrap, func(string, string, digest.Digest) (string, error) {
			return "", errors.New("pack final bootstrap mock error")
		})
		defer packFinBootPatches.Reset()
		err := convertModelFile(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Run buildModelConfig failed", func(t *testing.T) {
		patches := gomonkey.ApplyFunc(modctl.NewHandler, func(modctl.Option) (*modctl.Handler, error) {
			return &modctl.Handler{}, nil
		})
		defer patches.Reset()
		extHandlePatches := gomonkey.ApplyFunc(external.Handle, func(context.Context, external.Options) error {
			return nil
		})
		defer extHandlePatches.Reset()

		packFinBootPatches := gomonkey.ApplyFunc(packFinalBootstrap, func(string, string, digest.Digest) (string, error) {
			return "", nil
		})
		defer packFinBootPatches.Reset()

		buildModelConfigPatches := gomonkey.ApplyFunc(buildModelConfig, func(*modctl.Handler) (*modelspec.Model, error) {
			return nil, errors.New("buildModelConfig mock error")
		})
		defer buildModelConfigPatches.Reset()
		err := convertModelFile(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Run pushManifest failed", func(t *testing.T) {
		patches := gomonkey.ApplyFunc(modctl.NewHandler, func(modctl.Option) (*modctl.Handler, error) {
			return &modctl.Handler{}, nil
		})
		defer patches.Reset()
		extHandlePatches := gomonkey.ApplyFunc(external.Handle, func(context.Context, external.Options) error {
			return nil
		})
		defer extHandlePatches.Reset()

		packFinBootPatches := gomonkey.ApplyFunc(packFinalBootstrap, func(string, string, digest.Digest) (string, error) {
			return "", nil
		})
		defer packFinBootPatches.Reset()

		buildModelConfigPatches := gomonkey.ApplyFunc(buildModelConfig, func(*modctl.Handler) (*modelspec.Model, error) {
			return &modelspec.Model{}, nil
		})
		defer buildModelConfigPatches.Reset()

		pushManifestPatches := gomonkey.ApplyFunc(pushManifest, func(context.Context, Opt, modelspec.Model, []ocispec.Descriptor, parser.Image, string) error {
			return errors.New("pushManifest mock error")
		})
		defer pushManifestPatches.Reset()
		err := convertModelFile(context.Background(), opt)
		assert.Error(t, err)
	})
}

func TestConvertModelArtifact(t *testing.T) {
	opt := Opt{
		WorkDir:   "/tmp/nydusify",
		Source:    "docker.io/library/busybox:latest",
		Target:    "docker.io/library/busybox:latest_nydus",
		ChunkSize: "0x100000",
	}

	t.Run("Run normal", func(t *testing.T) {
		mockRemoteHandler := &modctl.RemoteHandler{}
		patches := gomonkey.ApplyFunc(modctl.NewRemoteHandler, func(context.Context, string, bool) (*modctl.RemoteHandler, error) {
			return mockRemoteHandler, nil
		})
		defer patches.Reset()
		extHandlePatches := gomonkey.ApplyFunc(external.RemoteHandle, func(context.Context, external.Options) error {
			return nil
		})
		defer extHandlePatches.Reset()

		packWithAttributesPatches := gomonkey.ApplyFunc(packWithAttributes, func(context.Context, snapConv.PackOption, string) (digest.Digest, digest.Digest, error) {
			return "", "", nil
		})
		defer packWithAttributesPatches.Reset()

		packFinBootPatches := gomonkey.ApplyFunc(packFinalBootstrap, func(string, string, digest.Digest) (string, error) {
			return "", nil
		})
		defer packFinBootPatches.Reset()

		getModelConfigPaches := gomonkey.ApplyMethod(mockRemoteHandler, "GetModelConfig", func() (*modelspec.Model, error) {
			return &modelspec.Model{}, nil
		})
		defer getModelConfigPaches.Reset()

		pushManifestPatches := gomonkey.ApplyFunc(pushManifest, func(context.Context, Opt, modelspec.Model, []ocispec.Descriptor, parser.Image, string) error {
			return nil
		})
		defer pushManifestPatches.Reset()
		err := convertModelArtifact(context.Background(), opt)
		assert.NoError(t, err)
	})

	t.Run("Run RemoteHandle failed", func(t *testing.T) {
		patches := gomonkey.ApplyFunc(modctl.NewRemoteHandler, func(context.Context, string, bool) (*modctl.RemoteHandler, error) {
			return nil, errors.New("remote handler mock error")
		})
		defer patches.Reset()
		err := convertModelArtifact(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Run packWithAttributes failed", func(t *testing.T) {
		mockRemoteHandler := &modctl.RemoteHandler{}
		patches := gomonkey.ApplyFunc(modctl.NewRemoteHandler, func(context.Context, string, bool) (*modctl.RemoteHandler, error) {
			return mockRemoteHandler, nil
		})
		defer patches.Reset()
		extHandlePatches := gomonkey.ApplyFunc(external.RemoteHandle, func(context.Context, external.Options) error {
			return nil
		})
		defer extHandlePatches.Reset()

		packWithAttributesPatches := gomonkey.ApplyFunc(packWithAttributes, func(context.Context, snapConv.PackOption, string) (digest.Digest, digest.Digest, error) {
			return "", "", errors.New("pack with attributes failed mock error")
		})
		defer packWithAttributesPatches.Reset()
		err := convertModelArtifact(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Run packFinalBootstrap failed", func(t *testing.T) {
		mockRemoteHandler := &modctl.RemoteHandler{}
		patches := gomonkey.ApplyFunc(modctl.NewRemoteHandler, func(context.Context, string, bool) (*modctl.RemoteHandler, error) {
			return mockRemoteHandler, nil
		})
		defer patches.Reset()
		extHandlePatches := gomonkey.ApplyFunc(external.RemoteHandle, func(context.Context, external.Options) error {
			return nil
		})
		defer extHandlePatches.Reset()

		packWithAttributesPatches := gomonkey.ApplyFunc(packWithAttributes, func(context.Context, snapConv.PackOption, string) (digest.Digest, digest.Digest, error) {
			return "", "", nil
		})
		defer packWithAttributesPatches.Reset()

		packFinBootPatches := gomonkey.ApplyFunc(packFinalBootstrap, func(string, string, digest.Digest) (string, error) {
			return "", errors.New("packFinalBootstrap mock error")
		})
		defer packFinBootPatches.Reset()

		err := convertModelArtifact(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Run GetModelConfig failed", func(t *testing.T) {
		mockRemoteHandler := &modctl.RemoteHandler{}
		patches := gomonkey.ApplyFunc(modctl.NewRemoteHandler, func(context.Context, string, bool) (*modctl.RemoteHandler, error) {
			return mockRemoteHandler, nil
		})
		defer patches.Reset()
		extHandlePatches := gomonkey.ApplyFunc(external.RemoteHandle, func(context.Context, external.Options) error {
			return nil
		})
		defer extHandlePatches.Reset()

		packWithAttributesPatches := gomonkey.ApplyFunc(packWithAttributes, func(context.Context, snapConv.PackOption, string) (digest.Digest, digest.Digest, error) {
			return "", "", nil
		})
		defer packWithAttributesPatches.Reset()

		packFinBootPatches := gomonkey.ApplyFunc(packFinalBootstrap, func(string, string, digest.Digest) (string, error) {
			return "", nil
		})
		defer packFinBootPatches.Reset()

		getModelConfigPaches := gomonkey.ApplyMethod(mockRemoteHandler, "GetModelConfig", func() (*modelspec.Model, error) {
			return nil, errors.New("run getModelConfig mock error")
		})
		defer getModelConfigPaches.Reset()

		err := convertModelArtifact(context.Background(), opt)
		assert.Error(t, err)
	})

	t.Run("Run pushManifest failed", func(t *testing.T) {
		mockRemoteHandler := &modctl.RemoteHandler{}
		patches := gomonkey.ApplyFunc(modctl.NewRemoteHandler, func(context.Context, string, bool) (*modctl.RemoteHandler, error) {
			return mockRemoteHandler, nil
		})
		defer patches.Reset()
		extHandlePatches := gomonkey.ApplyFunc(external.RemoteHandle, func(context.Context, external.Options) error {
			return nil
		})
		defer extHandlePatches.Reset()

		packWithAttributesPatches := gomonkey.ApplyFunc(packWithAttributes, func(context.Context, snapConv.PackOption, string) (digest.Digest, digest.Digest, error) {
			return "", "", nil
		})
		defer packWithAttributesPatches.Reset()

		packFinBootPatches := gomonkey.ApplyFunc(packFinalBootstrap, func(string, string, digest.Digest) (string, error) {
			return "", nil
		})
		defer packFinBootPatches.Reset()

		getModelConfigPaches := gomonkey.ApplyMethod(mockRemoteHandler, "GetModelConfig", func() (*modelspec.Model, error) {
			return &modelspec.Model{}, nil
		})
		defer getModelConfigPaches.Reset()

		pushManifestPatches := gomonkey.ApplyFunc(pushManifest, func(context.Context, Opt, modelspec.Model, []ocispec.Descriptor, parser.Image, string) error {
			return errors.New("push manifest mock error")
		})
		defer pushManifestPatches.Reset()

		err := convertModelArtifact(context.Background(), opt)
		assert.Error(t, err)
	})
}

func TestPackWithAttributes(t *testing.T) {
	packOpt := snapConv.PackOption{
		BuilderPath: "/tmp/nydus-image",
	}
	blobDir := "/tmp/nydusify"
	os.MkdirAll(blobDir, 0755)
	defer os.RemoveAll(blobDir)
	_, _, err := packWithAttributes(context.Background(), packOpt, blobDir)
	assert.Nil(t, err)
}

type mockReaderAt struct{}

func (m *mockReaderAt) ReadAt([]byte, int64) (n int, err error) {
	return 0, errors.New("mock error")
}
func (m *mockReaderAt) Close() error {
	return nil
}

func (m *mockReaderAt) Size() int64 {
	return 0
}

func TestPackFinalBootstrap(t *testing.T) {
	workDir := "/tmp/nydusify"
	os.MkdirAll(workDir, 0755)
	defer os.RemoveAll(workDir)
	cfgPath := filepath.Join(workDir, "backend.json")
	os.Create(cfgPath)
	extDigest := digest.FromString("abc1234")
	mockReaderAt := &mockReaderAt{}

	t.Run("Run local OpenReader failed", func(t *testing.T) {
		_, err := packFinalBootstrap(workDir, cfgPath, extDigest)
		assert.Error(t, err)
	})

	t.Run("Run unpack entry failed", func(t *testing.T) {
		openReaderPatches := gomonkey.ApplyFunc(local.OpenReader, func(string) (content.ReaderAt, error) {
			return mockReaderAt, nil
		})
		defer openReaderPatches.Reset()
		_, err := packFinalBootstrap(workDir, cfgPath, extDigest)
		assert.Error(t, err)
	})

	t.Run("Run normal", func(t *testing.T) {
		openReaderPatches := gomonkey.ApplyFunc(local.OpenReader, func(string) (content.ReaderAt, error) {
			return mockReaderAt, nil
		})
		defer openReaderPatches.Reset()

		unpackEntryPatches := gomonkey.ApplyFunc(snapConv.UnpackEntry, func(content.ReaderAt, string, io.Writer) (*snapConv.TOCEntry, error) {
			return &snapConv.TOCEntry{}, nil
		})
		defer unpackEntryPatches.Reset()

		packToTarPaches := gomonkey.ApplyFunc(snapConv.PackToTar, func([]snapConv.File, bool) io.ReadCloser {
			var buff bytes.Buffer
			return io.NopCloser(&buff)
		})
		defer packToTarPaches.Reset()

		ioCopyPatches := gomonkey.ApplyFunc(io.Copy, func(io.Writer, io.Reader) (int64, error) {
			return 0, nil
		})
		defer ioCopyPatches.Reset()
		_, err := packFinalBootstrap(workDir, cfgPath, extDigest)
		assert.NoError(t, err)
	})

}

func TestBuildNydusImage(t *testing.T) {
	image := buildNydusImage()
	assert.NotNil(t, image)
}

func TestMakeDesc(t *testing.T) {
	input := "test"
	oldDesc := ocispec.Descriptor{
		MediaType: "test",
	}
	_, _, err := makeDesc(input, oldDesc)
	assert.NoError(t, err)
}

func TestBuildModelConfig(t *testing.T) {
	modctlHander := &modctl.Handler{}
	_, err := buildModelConfig(modctlHander)
	assert.Error(t, err)
}

func TestPushManifest(t *testing.T) {
	remoter := &remote.Remote{}
	t.Run("Run make desc failed", func(t *testing.T) {
		makeDescPatches := gomonkey.ApplyFunc(makeDesc, func(interface{}, ocispec.Descriptor) ([]byte, *ocispec.Descriptor, error) {
			return nil, nil, errors.New("make desc mock error")
		})
		defer makeDescPatches.Reset()
		err := pushManifest(context.Background(), Opt{}, modelspec.Model{}, nil, parser.Image{}, "")
		assert.Error(t, err)
	})

	t.Run("Run default remote failed", func(t *testing.T) {
		makeDescPatches := gomonkey.ApplyFunc(makeDesc, func(interface{}, ocispec.Descriptor) ([]byte, *ocispec.Descriptor, error) {
			return []byte{}, &ocispec.Descriptor{}, nil
		})
		defer makeDescPatches.Reset()

		defaultRemotePatches := gomonkey.ApplyFunc(pkgPvd.DefaultRemote, func(string, bool) (*remote.Remote, error) {
			return nil, errors.New("default remote failed mock error")
		})
		defer defaultRemotePatches.Reset()
		err := pushManifest(context.Background(), Opt{}, modelspec.Model{}, nil, parser.Image{}, "")
		assert.Error(t, err)
	})

	t.Run("Run push failed", func(t *testing.T) {
		makeDescPatches := gomonkey.ApplyFunc(makeDesc, func(interface{}, ocispec.Descriptor) ([]byte, *ocispec.Descriptor, error) {
			return []byte{}, &ocispec.Descriptor{}, nil
		})
		defer makeDescPatches.Reset()

		defaultRemotePatches := gomonkey.ApplyFunc(pkgPvd.DefaultRemote, func(string, bool) (*remote.Remote, error) {
			return remoter, nil
		})
		defer defaultRemotePatches.Reset()

		pushPatches := gomonkey.ApplyMethod(remoter, "Push", func(*remote.Remote, context.Context, ocispec.Descriptor, bool, io.Reader) error {
			return errors.New("push mock timeout error")
		})
		defer pushPatches.Reset()
		err := pushManifest(context.Background(), Opt{WithPlainHTTP: true}, modelspec.Model{}, nil, parser.Image{}, "")
		assert.Error(t, err)
	})

	t.Run("Run open failed", func(t *testing.T) {
		makeDescPatches := gomonkey.ApplyFunc(makeDesc, func(interface{}, ocispec.Descriptor) ([]byte, *ocispec.Descriptor, error) {
			return []byte{}, &ocispec.Descriptor{}, nil
		})
		defer makeDescPatches.Reset()

		defaultRemotePatches := gomonkey.ApplyFunc(pkgPvd.DefaultRemote, func(string, bool) (*remote.Remote, error) {
			return remoter, nil
		})
		defer defaultRemotePatches.Reset()

		pushPatches := gomonkey.ApplyMethod(remoter, "Push", func(*remote.Remote, context.Context, ocispec.Descriptor, bool, io.Reader) error {
			return nil
		})
		defer pushPatches.Reset()

		err := pushManifest(context.Background(), Opt{WithPlainHTTP: true}, modelspec.Model{}, nil, parser.Image{}, "")
		assert.Error(t, err)
	})

	t.Run("Run getSourceManifestSubject failed", func(t *testing.T) {
		makeDescPatches := gomonkey.ApplyFunc(makeDesc, func(interface{}, ocispec.Descriptor) ([]byte, *ocispec.Descriptor, error) {
			return []byte{}, &ocispec.Descriptor{}, nil
		})
		defer makeDescPatches.Reset()

		defaultRemotePatches := gomonkey.ApplyFunc(pkgPvd.DefaultRemote, func(string, bool) (*remote.Remote, error) {
			return remoter, nil
		})
		defer defaultRemotePatches.Reset()

		pushPatches := gomonkey.ApplyMethod(remoter, "Push", func(*remote.Remote, context.Context, ocispec.Descriptor, bool, io.Reader) error {
			return nil
		})
		defer pushPatches.Reset()

		bootstrapPath := "/tmp/nydusify/bootstrap"
		os.Mkdir("/tmp/nydusify/", 0755)
		os.Create(bootstrapPath)
		defer os.RemoveAll("/tmp/nydusify/")
		defer os.Remove(bootstrapPath)

		getSourceManifestSubjectPatches := gomonkey.ApplyFunc(getSourceManifestSubject, func(context.Context, string, bool, bool) (*ocispec.Descriptor, error) {
			return nil, errors.New("get source manifest subject mock error")
		})
		defer getSourceManifestSubjectPatches.Reset()
		err := pushManifest(context.Background(), Opt{WithPlainHTTP: true}, modelspec.Model{}, nil, parser.Image{}, bootstrapPath)
		assert.Error(t, err)
	})

	t.Run("Run normal", func(t *testing.T) {
		makeDescPatches := gomonkey.ApplyFunc(makeDesc, func(interface{}, ocispec.Descriptor) ([]byte, *ocispec.Descriptor, error) {
			return []byte{}, &ocispec.Descriptor{}, nil
		})
		defer makeDescPatches.Reset()

		defaultRemotePatches := gomonkey.ApplyFunc(pkgPvd.DefaultRemote, func(string, bool) (*remote.Remote, error) {
			return remoter, nil
		})
		defer defaultRemotePatches.Reset()

		pushPatches := gomonkey.ApplyMethod(remoter, "Push", func(*remote.Remote, context.Context, ocispec.Descriptor, bool, io.Reader) error {
			return nil
		})
		defer pushPatches.Reset()

		bootstrapPath := "/tmp/nydusify/bootstrap"
		os.Mkdir("/tmp/nydusify/", 0755)
		os.Create(bootstrapPath)
		defer os.RemoveAll("/tmp/nydusify/")
		defer os.Remove(bootstrapPath)

		getSourceManifestSubjectPatches := gomonkey.ApplyFunc(getSourceManifestSubject, func(context.Context, string, bool, bool) (*ocispec.Descriptor, error) {
			return &ocispec.Descriptor{}, nil
		})
		defer getSourceManifestSubjectPatches.Reset()
		err := pushManifest(context.Background(), Opt{WithPlainHTTP: true}, modelspec.Model{}, nil, parser.Image{}, bootstrapPath)
		assert.NoError(t, err)
	})
}

func TestGetSourceManifestSubject(t *testing.T) {
	remoter := &remote.Remote{}
	t.Run("Run default remote failed", func(t *testing.T) {
		defaultRemotePatches := gomonkey.ApplyFunc(pkgPvd.DefaultRemote, func(string, bool) (*remote.Remote, error) {
			return nil, errors.New("default remote failed mock error")
		})
		defer defaultRemotePatches.Reset()
		_, err := getSourceManifestSubject(context.Background(), "", false, false)
		assert.Error(t, err)
	})

	t.Run("Run resolve failed", func(t *testing.T) {
		defaultRemotePatches := gomonkey.ApplyFunc(pkgPvd.DefaultRemote, func(string, bool) (*remote.Remote, error) {
			return remoter, nil
		})
		defer defaultRemotePatches.Reset()

		remoterReolvePatches := gomonkey.ApplyMethod(remoter, "Resolve", func(*remote.Remote, context.Context) (*ocispec.Descriptor, error) {
			return nil, errors.New("resolve failed mock error timeout")
		})
		defer remoterReolvePatches.Reset()
		_, err := getSourceManifestSubject(context.Background(), "", false, false)
		assert.Error(t, err)
	})

	t.Run("Run normal", func(t *testing.T) {
		defaultRemotePatches := gomonkey.ApplyFunc(pkgPvd.DefaultRemote, func(string, bool) (*remote.Remote, error) {
			return remoter, nil
		})
		defer defaultRemotePatches.Reset()

		remoterReolvePatches := gomonkey.ApplyMethod(remoter, "Resolve", func(*remote.Remote, context.Context) (*ocispec.Descriptor, error) {
			return &ocispec.Descriptor{}, nil
		})
		defer remoterReolvePatches.Reset()
		desc, err := getSourceManifestSubject(context.Background(), "", false, false)
		assert.NoError(t, err)
		assert.NotNil(t, desc)
	})

}
