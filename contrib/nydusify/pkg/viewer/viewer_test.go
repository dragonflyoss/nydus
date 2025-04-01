package viewer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/provider"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestPullBootstrap(t *testing.T) {
	opt := Opt{
		WorkDir: "/tmp/nydusify/fsviwer",
	}
	fsViwer := FsViewer{
		Opt: opt,
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

func TestGetBootstrapFile(t *testing.T) {
	opt := Opt{
		WorkDir: "/tmp/nydusify/fsviwer",
	}
	fsViwer := FsViewer{
		Opt:    opt,
		Parser: &parser.Parser{},
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
		var buf bytes.Buffer
		pullNydusBootstrapPatches := gomonkey.ApplyMethod(fsViwer.Parser, "PullNydusBootstrap", func(*parser.Parser, context.Context, *parser.Image) (io.ReadCloser, error) {
			return io.NopCloser(&buf), nil
		})
		defer pullNydusBootstrapPatches.Reset()

		unpackPatches := gomonkey.ApplyFunc(utils.UnpackFile, func(io.Reader, string, string) error {
			return nil
		})
		defer unpackPatches.Reset()
		image := &parser.Image{}
		err := fsViwer.getBootstrapFile(context.Background(), image, "", "")
		assert.NoError(t, err)
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
	}
	t.Run("Run not exist", func(t *testing.T) {
		err := fsViwer.handleExternalBackendConfig()
		assert.NoError(t, err)
	})

	t.Run("Run normal", func(t *testing.T) {
		osStatPatches := gomonkey.ApplyFunc(os.Stat, func(string) (os.FileInfo, error) {
			return nil, nil
		})
		defer osStatPatches.Reset()

		buildExternalConfigPatches := gomonkey.ApplyFunc(utils.BuildRuntimeExternalBackendConfig, func(string, string) error {
			return nil
		})
		defer buildExternalConfigPatches.Reset()
		err := fsViwer.handleExternalBackendConfig()
		assert.NoError(t, err)
	})
}
