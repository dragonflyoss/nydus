package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

type mockBlobReader struct {
	*bytes.Reader
}

func (mockBlobReader) Close() error { return nil }

type mockCountedBlobReader struct {
	io.ReadSeekCloser
	read *atomic.Int64
}

func (r mockCountedBlobReader) Read(b []byte) (int, error) {
	n, err := r.ReadSeekCloser.Read(b)
	r.read.Add(int64(n))
	return n, err
}

func mockUnavailableBlob(context.Context, ocispec.Descriptor, string) (io.ReadSeekCloser, error) {
	return nil, errors.New("blob unavailable")
}

func readRepackBackend(t *testing.T, config string) (string, string) {
	t.Helper()
	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}

	var cfg struct {
		Backend struct {
			Config struct{ Addr, Repository string }
		}
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}

	return cfg.Backend.Config.Addr, cfg.Backend.Config.Repository
}

func fetchRepackBlob(t *testing.T, url, byteRange string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", byteRange)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}

	return resp.StatusCode, string(body)
}

func TestStartRepackBackend(t *testing.T) {
	data := bytes.Repeat([]byte("a"), 1024*1024)
	remote := digest.FromBytes(data)
	local := digest.FromString("local")
	var downloaded atomic.Int64

	tests := []struct {
		name   string
		open   func(ctx context.Context, desc ocispec.Descriptor, byteRange string) (io.ReadSeekCloser, error)
		mock   func(t *testing.T, work, blobs string)
		expect func(t *testing.T, opt ArtifactOption, work, blobs, config string, err error)
	}{
		{
			name: "fail to open local blob",
			open: mockUnavailableBlob,
			mock: func(t *testing.T, work, blobs string) {
				path := filepath.Join(blobs, mockBlobDigest.Encoded())
				if err := os.Symlink(path, path); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, opt ArtifactOption, work, blobs, config string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				addr, repository := readRepackBackend(t, config)
				status, _ := fetchRepackBlob(t, addr+"/v2/"+repository+"/blobs/"+mockBlobDigest.String(), "")
				assert.Equal(http.StatusInternalServerError, status)
			},
		},
		{
			name: "fail to open remote blob",
			open: mockUnavailableBlob,
			mock: func(t *testing.T, work, blobs string) {
				desc, err := json.Marshal(ocispec.Descriptor{Digest: mockBlobDigest, Size: int64(len(mockBlobData))})
				if err != nil {
					t.Fatal(err)
				}
				mockFile(t, filepath.Join(blobs, mockBlobDigest.Encoded()+".descriptor.json"), desc)
			},
			expect: func(t *testing.T, opt ArtifactOption, work, blobs, config string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				addr, repository := readRepackBackend(t, config)
				status, _ := fetchRepackBlob(t, addr+"/v2/"+repository+"/blobs/"+mockBlobDigest.String(), "")
				assert.Equal(http.StatusBadGateway, status)
			},
		},
		{
			name: "fail to write backend config",
			open: mockUnavailableBlob,
			mock: func(t *testing.T, work, blobs string) {
				if err := os.Mkdir(filepath.Join(work, "backend.json"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			expect: func(t *testing.T, opt ArtifactOption, work, blobs, config string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "is a directory")
				assert.Empty(config)
			},
		},
		{
			name: "serve only prepared ranges",
			open: func(_ context.Context, desc ocispec.Descriptor, _ string) (io.ReadSeekCloser, error) {
				if desc.Digest != remote {
					return nil, errors.New("unexpected blob " + desc.Digest.String())
				}

				return mockCountedBlobReader{ReadSeekCloser: mockBlobReader{Reader: bytes.NewReader(data)}, read: &downloaded}, nil
			},
			mock: func(t *testing.T, work, blobs string) {},
			expect: func(t *testing.T, opt ArtifactOption, work, blobs, config string, err error) {
				assert := assert.New(t)
				assert.NoError(err)

				addr, repository := readRepackBackend(t, config)
				url := addr + "/v2/" + repository + "/blobs/sha256:"
				status, _ := fetchRepackBlob(t, url+remote.Encoded(), "")
				assert.Equal(http.StatusNotFound, status)
				assert.Zero(downloaded.Load())

				source := mockFile(t, filepath.Join(t.TempDir(), "local"), []byte("local"))
				assert.NoError(stageRepackBlobs(opt, []ocispec.Descriptor{
					{Digest: remote, Size: int64(len(data))},
					{Digest: local, Size: 5},
				}, map[digest.Digest]string{local: source}, blobs, []nydus.BlobMetaFile{
					{Name: remote.Encoded() + ".blob.meta", Data: []byte("remote metadata")},
					{Name: local.Encoded() + ".blob.meta", Data: []byte("local metadata")},
					{Name: "../unused.blob.meta", Data: []byte("unused")},
				}))
				for _, id := range []digest.Digest{remote, local} {
					meta, err := os.ReadFile(filepath.Join(work, "output", "cache", id.Encoded()+".blob.meta"))
					assert.NoError(err)
					assert.Contains(string(meta), "metadata")
				}
				assert.NoFileExists(filepath.Join(work, "output", "unused.blob.meta"))

				status, _ = fetchRepackBlob(t, addr+"/v2/repack/blobs/sha256:"+remote.Encoded(), "")
				assert.Equal(http.StatusNotFound, status)
				assert.Zero(downloaded.Load())

				status, body := fetchRepackBlob(t, url+remote.Encoded(), "bytes=4096-4103")
				assert.Equal(http.StatusPartialContent, status)
				assert.Equal("aaaaaaaa", body)

				status, body = fetchRepackBlob(t, url+local.Encoded(), "bytes=1-3")
				assert.Equal(http.StatusPartialContent, status)
				assert.Equal("oca", body)
				assert.Equal(int64(8), downloaded.Load())
				assert.NoFileExists(filepath.Join(blobs, remote.Encoded()))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			blobs := filepath.Join(work, "blobs")
			if err := os.Mkdir(blobs, 0o700); err != nil {
				t.Fatal(err)
			}

			tc.mock(t, work, blobs)
			opt := ArtifactOption{OpenCompactBlob: tc.open}
			config, closeServer, err := startRepackBackend(context.Background(), opt, blobs, work)
			if closeServer != nil {
				defer closeServer()
			}

			tc.expect(t, opt, work, blobs, config, err)
		})
	}
}
