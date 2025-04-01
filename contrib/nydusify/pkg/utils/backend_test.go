package utils

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/snapshotter/external/backend"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
