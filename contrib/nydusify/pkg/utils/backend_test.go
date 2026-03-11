package utils

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/distribution/reference"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistryBackendConfig(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.example.com:8080")
	t.Setenv("HTTPS_PROXY", "")

	dockerConfigDir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", dockerConfigDir)
	auth := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	configJSON := `{"auths":{"example.com":{"auth":"` + auth + `"}}}`
	require.NoError(t, os.WriteFile(dockerConfigDir+"/config.json", []byte(configJSON), 0o644))

	parsed, err := reference.ParseDockerRef("example.com/team/image:latest")
	require.NoError(t, err)

	backendConfig, err := NewRegistryBackendConfig(parsed, true)
	require.NoError(t, err)
	assert.Equal(t, "https", backendConfig.Scheme)
	assert.Equal(t, "example.com", backendConfig.Host)
	assert.Equal(t, "team/image", backendConfig.Repo)
	assert.Equal(t, auth, backendConfig.Auth)
	assert.True(t, backendConfig.SkipVerify)
	assert.Equal(t, "http://proxy.example.com:8080", backendConfig.Proxy.URL)
	assert.True(t, backendConfig.Proxy.Fallback)
}

func TestNewRegistryBackendConfigUsesHTTPSProxyFallback(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("HTTPS_PROXY", "https://secure-proxy.example.com")
	t.Setenv("DOCKER_CONFIG", t.TempDir())

	parsed, err := reference.ParseDockerRef("registry.example.com/library/busybox:latest")
	require.NoError(t, err)

	backendConfig, err := NewRegistryBackendConfig(parsed, false)
	require.NoError(t, err)
	assert.Equal(t, "https://secure-proxy.example.com", backendConfig.Proxy.URL)
	assert.Empty(t, backendConfig.Auth)
	assert.False(t, backendConfig.SkipVerify)
}

func TestBuildExternalBackend(t *testing.T) {
	bkdCfg := RegistryBackendConfig{
		Host: "test.host",
	}
	bkdCfgBytes, err := json.Marshal(bkdCfg)
	require.NoError(t, err)

	oldExtCfg := backend.Backend{
		Version: "test.ver",
		Backends: []backend.Config{
			{Type: "registry"},
		},
	}

	t.Run("not exist", func(t *testing.T) {
		err = BuildRuntimeExternalBackendConfig(string(bkdCfgBytes), "not-exist")
		assert.Error(t, err)
	})

	t.Run("normal", func(t *testing.T) {
		extFile, err := os.CreateTemp("/tmp", "external-backend-config")
		require.NoError(t, err)
		defer os.Remove(extFile.Name())

		oldExtCfgBytes, err := json.Marshal(oldExtCfg)
		require.NoError(t, err)

		err = os.WriteFile(extFile.Name(), oldExtCfgBytes, 0644)
		require.NoError(t, err)

		err = BuildRuntimeExternalBackendConfig(string(bkdCfgBytes), extFile.Name())
		require.NoError(t, err)

		newExtCfg := backend.Backend{}
		newExtCfgBytes, err := os.ReadFile(extFile.Name())
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(newExtCfgBytes, &newExtCfg))
		assert.Equal(t, bkdCfg.Host, newExtCfg.Backends[0].Config["host"])
	})
}
