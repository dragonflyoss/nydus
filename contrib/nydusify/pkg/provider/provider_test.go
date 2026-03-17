// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

func TestExtractOsArch(t *testing.T) {
	tests := []struct {
		name     string
		platform string
		os       string
		arch     string
		err      string
	}{
		{name: "amd64", platform: "linux/amd64", os: "linux", arch: "amd64"},
		{name: "arm64", platform: "linux/arm64", os: "linux", arch: "arm64"},
		{name: "missing slash", platform: "linux-amd64", err: "invalid platform format"},
		{name: "too many parts", platform: "linux/amd64/v2", err: "invalid platform format"},
		{name: "unsupported os", platform: "windows/amd64", err: "not support os windows"},
		{name: "unsupported arch", platform: "linux/arm", err: "not support architecture arm"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			osName, arch, err := ExtractOsArch(test.platform)
			if test.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.os, osName)
			require.Equal(t, test.arch, arch)
		})
	}
}

func TestNewDefaultClient(t *testing.T) {
	client := newDefaultClient(true)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	require.Equal(t, 10, transport.MaxIdleConns)
	require.True(t, transport.DisableKeepAlives)
	require.Equal(t, 30*time.Second, transport.IdleConnTimeout)
	require.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)

	client = newDefaultClient(false)
	transport = client.Transport.(*http.Transport)
	require.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func TestDefaultRemoteWithAuthValid(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	var gotUser, gotPass string
	var gotErr error
	patches := gomonkey.ApplyFunc(withRemote, func(ref string, insecure bool, credFunc withCredentialFunc) (*remote.Remote, error) {
		gotUser, gotPass, gotErr = credFunc("registry.example.com")
		return &remote.Remote{Ref: ref}, nil
	})
	defer patches.Reset()

	resolver, err := DefaultRemoteWithAuth("example.com/repo:tag", true, encoded)
	require.NoError(t, err)
	require.NoError(t, gotErr)
	require.Equal(t, "user", gotUser)
	require.Equal(t, "pass", gotPass)
	require.Equal(t, "example.com/repo:tag", resolver.Ref)
}

func TestDefaultRemoteWithAuthEmpty(t *testing.T) {
	var gotUser, gotPass string
	var gotErr error
	patches := gomonkey.ApplyFunc(withRemote, func(ref string, insecure bool, credFunc withCredentialFunc) (*remote.Remote, error) {
		gotUser, gotPass, gotErr = credFunc("registry.example.com")
		return &remote.Remote{Ref: ref}, nil
	})
	defer patches.Reset()

	resolver, err := DefaultRemoteWithAuth("example.com/repo:tag", false, "   ")
	require.NoError(t, err)
	require.NoError(t, gotErr)
	require.Empty(t, gotUser)
	require.Empty(t, gotPass)
	require.Equal(t, "example.com/repo:tag", resolver.Ref)
}

func TestDefaultRemoteWithAuthInvalidBase64(t *testing.T) {
	resolver, err := DefaultRemoteWithAuth("example.com/repo:tag", false, "not-base64")
	require.Nil(t, resolver)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Decode base64 encoded auth string")
}

func TestDefaultRemoteWithAuthInvalidDecodedAuth(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("user-pass"))
	resolver, err := DefaultRemoteWithAuth("example.com/repo:tag", false, encoded)
	require.Nil(t, resolver)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid base64 encoded auth string")
}

func TestDefaultSourceProviderLayers(t *testing.T) {
	diffID1 := digest.FromString("layer1")
	diffID2 := digest.FromString("layer2")
	provider := &defaultSourceProvider{
		workDir: t.TempDir(),
		image: parser.Image{
			Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{{Digest: digest.FromString("blob1"), Size: 10}, {Digest: digest.FromString("blob2"), Size: 20}}},
			Config:   ocispec.Image{RootFS: ocispec.RootFS{DiffIDs: []digest.Digest{diffID1, diffID2}}},
		},
		remote: &remote.Remote{},
	}

	layers, err := provider.Layers(context.Background())
	require.NoError(t, err)
	require.Len(t, layers, 2)
	require.Equal(t, identity.ChainID([]digest.Digest{diffID1}), layers[0].ChainID())
	require.Nil(t, layers[0].ParentChainID())
	require.Equal(t, identity.ChainID([]digest.Digest{diffID1, diffID2}), layers[1].ChainID())
	require.NotNil(t, layers[1].ParentChainID())
	require.Equal(t, identity.ChainID([]digest.Digest{diffID1}), *layers[1].ParentChainID())

	provider.image.Config.RootFS.DiffIDs = []digest.Digest{diffID1}
	layers, err = provider.Layers(context.Background())
	require.Nil(t, layers)
	require.Error(t, err)
	require.Contains(t, err.Error(), "mismatched fs layers")
}

func TestDefaultLoggerClosure(t *testing.T) {
	logger := &defaultLogger{}
	fields := LoggerFields{"step": "convert"}
	inputErr := errors.New("boom")

	finish := logger.Log(context.Background(), "processing", fields)
	returnedErr := finish(inputErr)

	require.Equal(t, inputErr, returnedErr)
	require.Contains(t, fields, "Time")
	require.NotEmpty(t, fields["Time"])
}

func TestDefaultSource(t *testing.T) {
	t.Run("parser new error", func(t *testing.T) {
		patches := gomonkey.ApplyFunc(parser.New, func(*remote.Remote, string) (*parser.Parser, error) {
			return nil, errors.New("new parser failed")
		})
		defer patches.Reset()

		providers, err := DefaultSource(context.Background(), &remote.Remote{}, t.TempDir(), utils.SupportedOS+"/"+utils.PlatformArchAMD64)
		require.Nil(t, providers)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create parser")
	})

	t.Run("nydus only image", func(t *testing.T) {
		patches := gomonkey.NewPatches()
		patches.ApplyFunc(parser.New, func(*remote.Remote, string) (*parser.Parser, error) {
			return &parser.Parser{}, nil
		})
		patches.ApplyMethod(reflect.TypeOf(&parser.Parser{}), "Parse", func(*parser.Parser, context.Context) (*parser.Parsed, error) {
			return &parser.Parsed{NydusImage: &parser.Image{}}, nil
		})
		defer patches.Reset()

		providers, err := DefaultSource(context.Background(), &remote.Remote{}, t.TempDir(), utils.SupportedOS+"/"+utils.PlatformArchAMD64)
		require.Nil(t, providers)
		require.Error(t, err)
		require.Contains(t, err.Error(), "only included Nydus manifest")
	})

	t.Run("success", func(t *testing.T) {
		patches := gomonkey.NewPatches()
		patches.ApplyFunc(parser.New, func(*remote.Remote, string) (*parser.Parser, error) {
			return &parser.Parser{}, nil
		})
		patches.ApplyMethod(reflect.TypeOf(&parser.Parser{}), "Parse", func(*parser.Parser, context.Context) (*parser.Parsed, error) {
			return &parser.Parsed{OCIImage: &parser.Image{Desc: ocispec.Descriptor{Digest: digest.FromString("oci")}}}, nil
		})
		defer patches.Reset()

		providers, err := DefaultSource(context.Background(), &remote.Remote{}, t.TempDir(), utils.SupportedOS+"/"+utils.PlatformArchAMD64)
		require.NoError(t, err)
		require.Len(t, providers, 1)
	})
}

func TestDefaultSourceProviderManifestAndConfig(t *testing.T) {
	desc := ocispec.Descriptor{Digest: digest.FromString("manifest"), Size: 100}
	config := ocispec.Image{Author: "test-author"}
	sp := &defaultSourceProvider{
		image: parser.Image{
			Desc:   desc,
			Config: config,
		},
	}

	gotDesc, err := sp.Manifest(context.Background())
	require.NoError(t, err)
	require.Equal(t, desc.Digest, gotDesc.Digest)

	gotConfig, err := sp.Config(context.Background())
	require.NoError(t, err)
	require.Equal(t, "test-author", gotConfig.Author)
}

func TestDefaultSourceLayerGetters(t *testing.T) {
	parentID := digest.FromString("parent")
	layer := &defaultSourceLayer{
		desc:          ocispec.Descriptor{Digest: digest.FromString("layer1"), Size: 2048},
		chainID:       digest.FromString("chain1"),
		parentChainID: &parentID,
	}

	require.Equal(t, digest.FromString("layer1"), layer.Digest())
	require.Equal(t, int64(2048), layer.Size())
	require.Equal(t, digest.FromString("chain1"), layer.ChainID())
	require.NotNil(t, layer.ParentChainID())
	require.Equal(t, parentID, *layer.ParentChainID())

	// Test with nil parent
	layer2 := &defaultSourceLayer{
		desc:          ocispec.Descriptor{Digest: digest.FromString("first"), Size: 512},
		chainID:       digest.FromString("chain0"),
		parentChainID: nil,
	}
	require.Nil(t, layer2.ParentChainID())
	require.Equal(t, int64(512), layer2.Size())
}

func TestDefaultLoggerFactory(t *testing.T) {
	logger, err := DefaultLogger()
	require.NoError(t, err)
	require.NotNil(t, logger)
}

func TestDefaultRemote(t *testing.T) {
	patches := gomonkey.ApplyFunc(withRemote, func(ref string, insecure bool, credFunc withCredentialFunc) (*remote.Remote, error) {
		// Validate the credFunc handles docker hub
		user, pass, err := credFunc("registry-1.docker.io")
		_ = user
		_ = pass
		if err != nil {
			return nil, err
		}
		// Also test with a non-dockerhub host
		user, pass, err = credFunc("ghcr.io")
		_ = user
		_ = pass
		if err != nil {
			return nil, err
		}
		return &remote.Remote{Ref: ref}, nil
	})
	defer patches.Reset()

	r, err := DefaultRemote("docker.io/library/nginx:latest", false)
	require.NoError(t, err)
	require.NotNil(t, r)
	require.Equal(t, "docker.io/library/nginx:latest", r.Ref)
}

func TestDefaultRemoteWithAuthColonOnlyPass(t *testing.T) {
	// Test with auth that has three colons (user:pass:extra should fail)
	encoded := base64.StdEncoding.EncodeToString([]byte("u:p:extra"))
	_, err := DefaultRemoteWithAuth("example.com/repo:tag", false, encoded)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid base64 encoded auth string")
}
