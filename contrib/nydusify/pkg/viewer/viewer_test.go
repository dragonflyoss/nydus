package viewer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/checker/tool"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type failingJSON struct{}

func (failingJSON) MarshalJSON() ([]byte, error) {
	return nil, errors.New("marshal failed")
}

func buildBootstrapArchive(t *testing.T, name string, data []byte) io.ReadCloser {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tarWriter := tar.NewWriter(gz)
	require.NoError(t, tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}))
	_, err := tarWriter.Write(data)
	require.NoError(t, err)
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gz.Close())
	return io.NopCloser(bytes.NewReader(buf.Bytes()))
}

func TestNewFsViewer(t *testing.T) {
	var remoter = remote.Remote{}
	defaultRemotePatches := gomonkey.ApplyFunc(provider.DefaultRemote, func(string, bool) (*remote.Remote, error) {
		return &remoter, nil
	})
	defer defaultRemotePatches.Reset()

	var targetParser = parser.Parser{}
	parserNewPatches := gomonkey.ApplyFunc(parser.New, func(*remote.Remote, string) (*parser.Parser, error) {
		return &targetParser, nil
	})
	defer parserNewPatches.Reset()
	opt := Opt{
		Target: "test",
	}
	fsViewer, err := New(opt)
	assert.NoError(t, err)
	assert.NotNil(t, fsViewer)
}

func TestNewFsViewerErrors(t *testing.T) {
	t.Run("missing target", func(t *testing.T) {
		fsViewer, err := New(Opt{})
		assert.Error(t, err)
		assert.Nil(t, fsViewer)
	})

	t.Run("default remote failed", func(t *testing.T) {
		defaultRemotePatches := gomonkey.ApplyFunc(provider.DefaultRemote, func(string, bool) (*remote.Remote, error) {
			return nil, errors.New("remote failed")
		})
		defer defaultRemotePatches.Reset()

		fsViewer, err := New(Opt{Target: "test"})
		assert.Error(t, err)
		assert.Nil(t, fsViewer)
	})

	t.Run("parser failed", func(t *testing.T) {
		defaultRemotePatches := gomonkey.ApplyFunc(provider.DefaultRemote, func(string, bool) (*remote.Remote, error) {
			return &remote.Remote{}, nil
		})
		defer defaultRemotePatches.Reset()

		parserNewPatches := gomonkey.ApplyFunc(parser.New, func(*remote.Remote, string) (*parser.Parser, error) {
			return nil, errors.New("parser failed")
		})
		defer parserNewPatches.Reset()

		fsViewer, err := New(Opt{Target: "test"})
		assert.Error(t, err)
		assert.Nil(t, fsViewer)
	})
}

func TestPrettyDump(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dump.json")
	require.NoError(t, prettyDump(map[string]string{"key": "value"}, path))
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(content), "\"key\": \"value\"")

	err = prettyDump(failingJSON{}, filepath.Join(t.TempDir(), "invalid.json"))
	require.ErrorContains(t, err, "marshal failed")
}

func TestPullBootstrap(t *testing.T) {
	opt := Opt{
		WorkDir: "/tmp/nydusify/fsviwer",
	}
	fsViwer := FsViewer{
		Opt: opt,
		NydusdConfig: tool.NydusdConfig{
			ExternalBackendConfigPath: "/tmp/backend.json",
		},
	}
	os.MkdirAll(fsViwer.WorkDir, 0755)
	defer os.RemoveAll(fsViwer.WorkDir)
	targetParsed := &parser.Parsed{
		NydusImage: &parser.Image{},
	}
	err := fsViwer.PullBootstrap(context.Background(), targetParsed)
	assert.Error(t, err)
	callCount := 0
	getBootstrapPatches := gomonkey.ApplyPrivateMethod(&fsViwer, "getBootstrapFile", func(context.Context, *parser.Image, string, string) error {
		if callCount == 0 {
			callCount++
			return nil
		}
		return errors.New("failed to pull Nydus bootstrap layer mock error")
	})
	defer getBootstrapPatches.Reset()
	err = fsViwer.PullBootstrap(context.Background(), targetParsed)
	assert.Error(t, err)
}

func TestPullBootstrapWithoutNydusImage(t *testing.T) {
	fsViewer := FsViewer{Opt: Opt{WorkDir: t.TempDir()}}
	require.NoError(t, fsViewer.PullBootstrap(context.Background(), &parser.Parsed{}))
}

func TestGetBootstrapFile(t *testing.T) {
	opt := Opt{
		WorkDir: "/tmp/nydusify/fsviwer",
	}
	fsViwer := FsViewer{
		Opt:    opt,
		Parser: &parser.Parser{},
		NydusdConfig: tool.NydusdConfig{
			ExternalBackendConfigPath: filepath.Join(opt.WorkDir, "backend.json"),
		},
	}
	t.Run("Run pull bootstrap failed", func(t *testing.T) {
		pullNydusBootstrapPatches := gomonkey.ApplyMethod(fsViwer.Parser, "PullNydusBootstrap", func(*parser.Parser, context.Context, *parser.Image) (io.ReadCloser, error) {
			return nil, errors.New("failed to pull Nydus bootstrap layer mock error")
		})
		defer pullNydusBootstrapPatches.Reset()
		image := &parser.Image{}
		err := fsViwer.getBootstrapFile(context.Background(), image, "", "")
		assert.Error(t, err)
	})

	t.Run("Run unpack failed", func(t *testing.T) {
		var buf bytes.Buffer
		pullNydusBootstrapPatches := gomonkey.ApplyMethod(fsViwer.Parser, "PullNydusBootstrap", func(*parser.Parser, context.Context, *parser.Image) (io.ReadCloser, error) {
			return io.NopCloser(&buf), nil
		})
		defer pullNydusBootstrapPatches.Reset()
		image := &parser.Image{}
		err := fsViwer.getBootstrapFile(context.Background(), image, "", "")
		assert.Error(t, err)
	})

	t.Run("Run normal", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "nydus_bootstrap")
		pullNydusBootstrapPatches := gomonkey.ApplyMethod(fsViwer.Parser, "PullNydusBootstrap", func(*parser.Parser, context.Context, *parser.Image) (io.ReadCloser, error) {
			return buildBootstrapArchive(t, utils.BootstrapFileNameInLayer, []byte("bootstrap-data")), nil
		})
		defer pullNydusBootstrapPatches.Reset()
		image := &parser.Image{}
		err := fsViwer.getBootstrapFile(context.Background(), image, utils.BootstrapFileNameInLayer, target)
		assert.NoError(t, err)
		content, err := os.ReadFile(target)
		require.NoError(t, err)
		require.Equal(t, "bootstrap-data", string(content))
	})
}

func TestHandleExternalBackendConfig(t *testing.T) {
	backend := &backend.Backend{
		Backends: []backend.Config{
			{
				Type: "registry",
			},
		},
	}
	bkdConfig, err := json.Marshal(backend)
	require.NoError(t, err)
	opt := Opt{
		WorkDir:       "/tmp/nydusify/fsviwer",
		BackendConfig: string(bkdConfig),
	}
	fsViwer := FsViewer{
		Opt:    opt,
		Parser: &parser.Parser{},
		NydusdConfig: tool.NydusdConfig{
			ExternalBackendConfigPath: filepath.Join(opt.WorkDir, "backend.json"),
		},
	}
	t.Run("Run not exist", func(t *testing.T) {
		err := fsViwer.handleExternalBackendConfig()
		assert.NoError(t, err)
	})

	t.Run("Run normal", func(t *testing.T) {
		require.NoError(t, os.MkdirAll(fsViwer.WorkDir, 0755))
		require.NoError(t, os.WriteFile(fsViwer.NydusdConfig.ExternalBackendConfigPath, []byte("{}"), 0644))

		buildExternalConfigPatches := gomonkey.ApplyFunc(utils.BuildRuntimeExternalBackendConfig, func(string, string) error {
			return nil
		})
		defer buildExternalConfigPatches.Reset()
		err := fsViwer.handleExternalBackendConfig()
		assert.NoError(t, err)
	})

	t.Run("Run build external backend config failed", func(t *testing.T) {
		require.NoError(t, os.MkdirAll(fsViwer.WorkDir, 0755))
		require.NoError(t, os.WriteFile(fsViwer.NydusdConfig.ExternalBackendConfigPath, []byte("{}"), 0644))

		buildExternalConfigPatches := gomonkey.ApplyFunc(utils.BuildRuntimeExternalBackendConfig, func(string, string) error {
			return errors.New("build external backend config failed")
		})
		defer buildExternalConfigPatches.Reset()

		err := fsViwer.handleExternalBackendConfig()
		assert.Error(t, err)
	})
}

func TestMountImage(t *testing.T) {
	t.Run("blob cache dir failed", func(t *testing.T) {
		workDir := t.TempDir()
		filePath := filepath.Join(workDir, "blob-cache-file")
		require.NoError(t, os.WriteFile(filePath, []byte("x"), 0644))

		fsViewer := FsViewer{
			NydusdConfig: tool.NydusdConfig{
				BlobCacheDir: filePath,
				MountPath:    filepath.Join(workDir, "mnt"),
			},
		}

		err := fsViewer.MountImage()
		assert.Error(t, err)
	})

	t.Run("mount path failed", func(t *testing.T) {
		workDir := t.TempDir()
		filePath := filepath.Join(workDir, "mount-file")
		require.NoError(t, os.WriteFile(filePath, []byte("x"), 0644))

		fsViewer := FsViewer{
			NydusdConfig: tool.NydusdConfig{
				BlobCacheDir: filepath.Join(workDir, "blob-cache"),
				MountPath:    filePath,
			},
		}

		err := fsViewer.MountImage()
		assert.Error(t, err)
	})

	t.Run("new nydusd failed", func(t *testing.T) {
		workDir := t.TempDir()
		fsViewer := FsViewer{
			NydusdConfig: tool.NydusdConfig{
				BlobCacheDir: filepath.Join(workDir, "blob-cache"),
				MountPath:    filepath.Join(workDir, "mnt"),
			},
		}

		newNydusdPatches := gomonkey.ApplyFunc(tool.NewNydusd, func(tool.NydusdConfig) (*tool.Nydusd, error) {
			return nil, errors.New("create daemon failed")
		})
		defer newNydusdPatches.Reset()

		err := fsViewer.MountImage()
		assert.Error(t, err)
	})

	t.Run("mount failed", func(t *testing.T) {
		workDir := t.TempDir()
		fsViewer := FsViewer{
			NydusdConfig: tool.NydusdConfig{
				BlobCacheDir: filepath.Join(workDir, "blob-cache"),
				MountPath:    filepath.Join(workDir, "mnt"),
			},
		}

		newNydusdPatches := gomonkey.ApplyFunc(tool.NewNydusd, func(conf tool.NydusdConfig) (*tool.Nydusd, error) {
			return &tool.Nydusd{NydusdConfig: conf}, nil
		})
		defer newNydusdPatches.Reset()

		mountPatches := gomonkey.ApplyMethod(&tool.Nydusd{}, "Mount", func(*tool.Nydusd) error {
			return errors.New("mount failed")
		})
		defer mountPatches.Reset()

		err := fsViewer.MountImage()
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		workDir := t.TempDir()
		fsViewer := FsViewer{
			NydusdConfig: tool.NydusdConfig{
				BlobCacheDir: filepath.Join(workDir, "blob-cache"),
				MountPath:    filepath.Join(workDir, "mnt"),
			},
		}

		newNydusdPatches := gomonkey.ApplyFunc(tool.NewNydusd, func(conf tool.NydusdConfig) (*tool.Nydusd, error) {
			return &tool.Nydusd{NydusdConfig: conf}, nil
		})
		defer newNydusdPatches.Reset()

		mountPatches := gomonkey.ApplyMethod(&tool.Nydusd{}, "Mount", func(*tool.Nydusd) error {
			return nil
		})
		defer mountPatches.Reset()

		assert.NoError(t, fsViewer.MountImage())
	})
}
