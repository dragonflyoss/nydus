package tool

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBlobInfoString(t *testing.T) {
	info := &BlobInfo{BlobID: "blob", CompressedSize: 10, DecompressedSize: 20, ReadaheadOffset: 1, ReadaheadSize: 2}
	text := info.String()
	require.JSONEq(t, `{"blob_id":"blob","compressed_size":10,"decompressed_size":20,"readahead_offset":1,"readahead_size":2}`, text)
}

func TestBlobInfoListString(t *testing.T) {
	infos := BlobInfoList{{BlobID: "blob-a"}, {BlobID: "blob-b"}}
	text := infos.String()

	var decoded []map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(text), &decoded))
	require.Len(t, decoded, 2)
	require.Equal(t, "blob-a", decoded[0]["blob_id"])
	require.Equal(t, "blob-b", decoded[1]["blob_id"])
}

func TestNewInspector(t *testing.T) {
	inspector := NewInspector("/usr/bin/nydus-image")
	require.NotNil(t, inspector)
	require.Equal(t, "/usr/bin/nydus-image", inspector.binaryPath)
}

func TestInspectorInspect(t *testing.T) {
	t.Run("unsupported operation", func(t *testing.T) {
		inspector := NewInspector("/usr/bin/nydus-image")
		result, err := inspector.Inspect(InspectOption{Operation: 99})
		require.Nil(t, result)
		require.ErrorContains(t, err, "not support method 99")
	})

	t.Run("success", func(t *testing.T) {
		workDir := t.TempDir()
		scriptPath := filepath.Join(workDir, "inspect.sh")
		script := "#!/bin/sh\necho '[{\"blob_id\":\"blob-a\",\"compressed_size\":1,\"decompressed_size\":2,\"readahead_offset\":3,\"readahead_size\":4}]'\n"
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0755))

		inspector := NewInspector(scriptPath)
		result, err := inspector.Inspect(InspectOption{Operation: GetBlobs, Bootstrap: "/tmp/bootstrap"})
		require.NoError(t, err)

		blobs, ok := result.(BlobInfoList)
		require.True(t, ok)
		require.Len(t, blobs, 1)
		require.Equal(t, "blob-a", blobs[0].BlobID)
		require.EqualValues(t, 1, blobs[0].CompressedSize)
	})

	t.Run("command failed", func(t *testing.T) {
		workDir := t.TempDir()
		scriptPath := filepath.Join(workDir, "inspect.sh")
		script := "#!/bin/sh\necho stderr-message\nexit 1\n"
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0755))

		inspector := NewInspector(scriptPath)
		result, err := inspector.Inspect(InspectOption{Operation: GetBlobs, Bootstrap: "/tmp/bootstrap"})
		require.Nil(t, result)
		require.ErrorContains(t, err, "stderr-message")
	})

	t.Run("invalid json", func(t *testing.T) {
		workDir := t.TempDir()
		scriptPath := filepath.Join(workDir, "inspect.sh")
		script := "#!/bin/sh\necho invalid-json\n"
		require.NoError(t, os.WriteFile(scriptPath, []byte(script), 0755))

		inspector := NewInspector(scriptPath)
		result, err := inspector.Inspect(InspectOption{Operation: GetBlobs, Bootstrap: "/tmp/bootstrap"})
		require.Nil(t, result)
		require.Error(t, err)
	})
}
