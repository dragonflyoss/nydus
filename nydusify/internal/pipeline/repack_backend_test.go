package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

func TestRepackBackendSourceFailures(t *testing.T) {
	work := t.TempDir()
	blobs := filepath.Join(work, "blobs")
	require.NoError(t, os.Mkdir(blobs, 0700))
	id := digest.FromString("blob")
	opt := ArtifactOption{OpenCompactBlob: func(context.Context, ocispec.Descriptor, string) (io.ReadSeekCloser, error) {
		return nil, errors.New("source unavailable")
	}}
	config, closeServer, err := startRepackBackend(context.Background(), opt, blobs, work)
	require.NoError(t, err)
	defer closeServer()
	data, err := os.ReadFile(config)
	require.NoError(t, err)
	var cfg struct {
		Backend struct {
			Config struct{ Addr, Repository string }
		}
	}
	require.NoError(t, json.Unmarshal(data, &cfg))
	path := filepath.Join(blobs, id.Encoded())
	url := cfg.Backend.Config.Addr + "/v2/" + cfg.Backend.Config.Repository + "/blobs/" + id.String()
	for _, tc := range []struct {
		name   string
		status int
	}{{"local open failure", 500}, {"remote open failure", 502}} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.status == 500 {
				require.NoError(t, os.Symlink(path, path))
			} else {
				require.NoError(t, os.Remove(path))
				data, err := json.Marshal(ocispec.Descriptor{Digest: id, Size: 4})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path+".descriptor.json", data, 0600))
			}
			resp, err := http.Get(url)
			require.NoError(t, err)
			require.Equal(t, tc.status, resp.StatusCode)
			require.NoError(t, resp.Body.Close())
		})
	}
	blocked := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(blocked, "backend.json"), 0700))
	_, _, err = startRepackBackend(context.Background(), opt, blobs, blocked)
	require.Error(t, err)
}

func TestRepackBackendServesOnlyPreparedRanges(t *testing.T) {
	ctx := context.Background()
	work := t.TempDir()
	blobs := filepath.Join(work, "blobs")
	require.NoError(t, os.Mkdir(blobs, 0700))
	data := bytes.Repeat([]byte("a"), 1024*1024)
	remote := digest.FromBytes(data)
	local := digest.FromString("local")
	path := filepath.Join(t.TempDir(), "local")
	require.NoError(t, os.WriteFile(path, []byte("local"), 0600))
	var downloaded atomic.Int64
	opt := ArtifactOption{
		OpenCompactBlob: func(_ context.Context, desc ocispec.Descriptor, _ string) (io.ReadSeekCloser, error) {
			require.Equal(t, remote, desc.Digest)
			return countedBlobReader{testBlobReader{bytes.NewReader(data)}, &downloaded}, nil
		},
	}
	config, closeServer, err := startRepackBackend(ctx, opt, blobs, work)
	require.NoError(t, err)
	defer closeServer()
	raw, err := os.ReadFile(config)
	require.NoError(t, err)
	var cfg struct {
		Backend struct {
			Config struct{ Addr, Repository string }
		}
	}
	require.NoError(t, json.Unmarshal(raw, &cfg))
	url := cfg.Backend.Config.Addr + "/v2/" + cfg.Backend.Config.Repository + "/blobs/sha256:"
	response, err := http.Get(url + remote.Encoded())
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, response.StatusCode)
	require.NoError(t, response.Body.Close())
	require.Zero(t, downloaded.Load())
	require.NoError(t, stageRepackBlobs(opt, []ocispec.Descriptor{
		{Digest: remote, Size: int64(len(data))}, {Digest: local, Size: 5},
	}, map[digest.Digest]string{local: path}, blobs, []nydus.BlobMetaFile{
		{Name: remote.Encoded() + ".blob.meta", Data: []byte("remote metadata")},
		{Name: local.Encoded() + ".blob.meta", Data: []byte("local metadata")},
		{Name: "../unused.blob.meta", Data: []byte("unused")},
	}))
	for _, id := range []digest.Digest{remote, local} {
		meta, err := os.ReadFile(filepath.Join(work, "output", "cache", id.Encoded()+".blob.meta"))
		require.NoError(t, err)
		require.Contains(t, string(meta), "metadata")
	}
	_, err = os.Stat(filepath.Join(work, "output", "unused.blob.meta"))
	require.True(t, os.IsNotExist(err))
	response, err = http.Get(cfg.Backend.Config.Addr + "/v2/repack/blobs/sha256:" + remote.Encoded())
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, response.StatusCode)
	require.NoError(t, response.Body.Close())
	require.Zero(t, downloaded.Load())
	for _, tc := range []struct {
		id         digest.Digest
		start, end int
		expected   string
	}{
		{remote, 4096, 4103, "aaaaaaaa"}, {local, 1, 3, "oca"},
	} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url+tc.id.Encoded(), nil)
		require.NoError(t, err)
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", tc.start, tc.end))
		response, err := http.DefaultClient.Do(request)
		require.NoError(t, err)
		body, err := io.ReadAll(response.Body)
		require.NoError(t, response.Body.Close())
		require.NoError(t, err)
		require.Equal(t, http.StatusPartialContent, response.StatusCode)
		require.Equal(t, tc.expected, string(body))
	}
	require.Equal(t, int64(8), downloaded.Load())
	_, err = os.Stat(filepath.Join(blobs, remote.Encoded()))
	require.True(t, os.IsNotExist(err), "remote data must not be materialized")
}
