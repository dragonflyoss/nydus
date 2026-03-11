package compactor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func createFakeCompactBinary(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nydus-image")
	require.NoError(t, os.WriteFile(path, []byte(script), 0755))
	return path
}

func TestCompactConfigRoundTrip(t *testing.T) {
	cfg := CompactConfig{
		MinUsedRatio:    "10",
		CompactBlobSize: "20",
		MaxCompactSize:  "30",
		LayersToCompact: "40",
		BlobsDir:        "/tmp/blobs",
	}
	configPath := filepath.Join(t.TempDir(), "compact.json")
	require.NoError(t, cfg.Dumps(configPath))

	loaded, err := loadCompactConfig(configPath)
	require.NoError(t, err)
	require.Equal(t, cfg, loaded)
}

func TestNewCompactor(t *testing.T) {
	t.Run("default config", func(t *testing.T) {
		workDir := t.TempDir()
		compactor, err := NewCompactor("/usr/bin/nydus-image", workDir, "")
		require.NoError(t, err)
		require.Equal(t, workDir, compactor.workdir)
		require.Equal(t, workDir, compactor.cfg.BlobsDir)
		require.Equal(t, defaultCompactConfig.MinUsedRatio, compactor.cfg.MinUsedRatio)
	})

	t.Run("load config error", func(t *testing.T) {
		_, err := NewCompactor("/usr/bin/nydus-image", t.TempDir(), filepath.Join(t.TempDir(), "missing.json"))
		require.ErrorContains(t, err, "compact config err")
	})
}

func TestCompactorCompact(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		workDir := t.TempDir()
		argsFile := filepath.Join(workDir, "args.txt")
		builderPath := createFakeCompactBinary(t, "#!/bin/sh\nprintf '%s\n' \"$@\" > \""+argsFile+"\"\n")

		compactor, err := NewCompactor(builderPath, workDir, "")
		require.NoError(t, err)

		bootstrapPath := filepath.Join(workDir, "bootstrap")
		require.NoError(t, os.WriteFile(bootstrapPath, []byte("bootstrap"), 0644))
		require.NoError(t, os.WriteFile(bootstrapPath+".compact", []byte("old"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(workDir, "compact-result.json"), []byte("old"), 0644))

		targetPath, err := compactor.Compact(bootstrapPath, "chunk.dict", "registry", "backend.json")
		require.NoError(t, err)
		require.Equal(t, bootstrapPath+".compact", targetPath)

		args, err := os.ReadFile(argsFile)
		require.NoError(t, err)
		argsText := string(args)
		require.Contains(t, argsText, "compact")
		require.Contains(t, argsText, bootstrapPath)
		require.Contains(t, argsText, "chunk.dict")
		require.Contains(t, argsText, "backend.json")
	})

	t.Run("builder failure", func(t *testing.T) {
		workDir := t.TempDir()
		builderPath := createFakeCompactBinary(t, "#!/bin/sh\nexit 1\n")
		compactor, err := NewCompactor(builderPath, workDir, "")
		require.NoError(t, err)

		bootstrapPath := filepath.Join(workDir, "bootstrap")
		require.NoError(t, os.WriteFile(bootstrapPath, []byte("bootstrap"), 0644))
		_, err = compactor.Compact(bootstrapPath, "", "registry", "backend.json")
		require.ErrorContains(t, err, "failed to run compact command")
	})
}
