/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/registrytest"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

var (
	mockImageConfig = ocispec.Image{Platform: ocispec.Platform{Architecture: "amd64", OS: "linux"}}

	mockImageConfigBlob, _ = json.Marshal(mockImageConfig)

	mockImageConfigDesc = mockDescriptor(ocispec.MediaTypeImageConfig, mockImageConfigBlob)

	mockOCILayer = []byte("oci layer")

	mockOCILayerDesc = mockDescriptor(ocispec.MediaTypeImageLayerGzip, mockOCILayer)

	mockNydusBlob = []byte("nydus blob")

	mockNydusBlobDesc = mockDescriptor(nydus.MediaTypeNydusBlob, mockNydusBlob)

	mockBootstrap = []byte("nydus bootstrap")

	mockBootstrapDesc = ocispec.Descriptor{
		MediaType:   ocispec.MediaTypeImageLayerGzip,
		Digest:      digest.FromBytes(mockBootstrap),
		Size:        int64(len(mockBootstrap)),
		Annotations: map[string]string{nydus.LayerAnnotationNydusBootstrap: "true"},
	}

	mockManifest, _ = json.Marshal(ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    mockImageConfigDesc,
		Layers:    []ocispec.Descriptor{mockOCILayerDesc, mockNydusBlobDesc, mockBootstrapDesc},
	})

	mockManifestDesc = mockDescriptor(ocispec.MediaTypeImageManifest, mockManifest)

	mockImageBlobs = map[digest.Digest][]byte{
		mockImageConfigDesc.Digest: mockImageConfigBlob,
		mockOCILayerDesc.Digest:    mockOCILayer,
		mockNydusBlobDesc.Digest:   mockNydusBlob,
		mockBootstrapDesc.Digest:   mockBootstrap,
		mockManifestDesc.Digest:    mockManifest,
	}

	mockBlobFile = []byte("local blob file")

	mockBlobFileDesc = mockDescriptor(nydus.MediaTypeNydusBlob, mockBlobFile)

	mockRangeBlob = []byte("abcdefgh")

	mockRangeBlobDesc = ocispec.Descriptor{Digest: digest.FromBytes(mockRangeBlob), Size: int64(len(mockRangeBlob))}

	mockBlobFetcherKey = struct {
		side Side
		ref  string
	}{side: Target, ref: mockRef}
)

func mockProvider(t *testing.T) *Provider {
	t.Helper()
	mockDockerConfig(t, `{}`)
	provider, err := NewProvider(Option{WorkDir: t.TempDir(), TargetPlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}

	for dgst, data := range mockImageBlobs {
		if err := content.WriteBlob(context.Background(), provider.ContentStore(), dgst.String(), bytes.NewReader(data), ocispec.Descriptor{Digest: dgst, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
	}

	return provider
}

func mockRangeRegistry(t *testing.T, upstreamRange string) (string, *atomic.Int32) {
	t.Helper()
	transferred := &atomic.Int32{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, upstreamRange, r.Header.Get("Range"))
		assert.Equal(t, "identity", r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, "blob", time.Time{}, bytes.NewReader(mockRangeBlob))
		transferred.Add(1)
	}))
	t.Cleanup(origin.Close)

	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "user" || pass != "pass" {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		http.Redirect(w, r, origin.URL+"/object", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(registry.Close)

	return strings.TrimPrefix(registry.URL, "http://") + "/test:v1", transferred
}

// mockFlakyRegistry fronts the registry at host with a server that answers the
// first GET of dgst with a 503, and returns its host:port.
func mockFlakyRegistry(t *testing.T, host string, dgst digest.Digest) string {
	t.Helper()
	failed := &atomic.Bool{}
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: host})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, dgst.String()) && failed.CompareAndSwap(false, true) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}

		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "http://")
}

func requestMethods(reg *registrytest.Registry, dgst digest.Digest) []string {
	var methods []string
	for _, req := range reg.Requests() {
		if strings.Contains(req.URL, dgst.String()) {
			methods = append(methods, req.Method)
		}
	}

	return methods
}

func TestSameRepository(t *testing.T) {
	tests := []struct {
		name   string
		left   string
		right  string
		expect func(t *testing.T, same bool, err error)
	}{
		{
			name:  "same explicit repository",
			left:  "localhost:5000/repo/image:parent",
			right: "localhost:5000/repo/image:child",
			expect: func(t *testing.T, same bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(same)
			},
		},
		{
			name:  "different repository",
			left:  "localhost:5000/repo/image:parent",
			right: "localhost:5000/repo/other:child",
			expect: func(t *testing.T, same bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.False(same)
			},
		},
		{
			name:  "docker hub shorthand",
			left:  "busybox:1.36",
			right: "docker.io/library/busybox:latest",
			expect: func(t *testing.T, same bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(same)
			},
		},
		{
			name:  "digest reference",
			left:  "localhost:5000/repo/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			right: "localhost:5000/repo/image:tag",
			expect: func(t *testing.T, same bool, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.True(same)
			},
		},
		{
			name:  "invalid left reference",
			left:  "not a valid reference",
			right: "localhost:5000/repo/image:tag",
			expect: func(t *testing.T, same bool, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
		{
			name:  "invalid right reference",
			left:  "localhost:5000/repo/image:tag",
			right: "not a valid reference",
			expect: func(t *testing.T, same bool, err error) {
				assert := assert.New(t)
				assert.Error(err)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			same, err := SameRepository(tc.left, tc.right)

			tc.expect(t, same, err)
		})
	}
}

func TestProvider_Pull(t *testing.T) {
	tests := []struct {
		name   string
		ref    string
		opt    PullOption
		opts   []registrytest.Option
		flaky  digest.Digest
		expect func(t *testing.T, reg *registrytest.Registry, cs content.Store, desc ocispec.Descriptor, err error)
	}{
		{
			name: "pull every layer",
			ref:  "repo/image:v1",
			opt:  PullAll,
			expect: func(t *testing.T, reg *registrytest.Registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockManifestDesc.Digest, desc.Digest)
				for dgst, data := range mockImageBlobs {
					stored, err := content.ReadBlob(context.Background(), cs, ocispec.Descriptor{Digest: dgst})
					assert.NoError(err)
					assert.Equal(data, stored)
				}
			},
		},
		{
			name: "data layers are skipped",
			ref:  "repo/image:v1",
			expect: func(t *testing.T, reg *registrytest.Registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				for _, layer := range []ocispec.Descriptor{mockManifestDesc, mockImageConfigDesc, mockBootstrapDesc} {
					_, err := cs.Info(context.Background(), layer.Digest)
					assert.NoError(err)
				}

				for _, layer := range []ocispec.Descriptor{mockOCILayerDesc, mockNydusBlobDesc} {
					_, err := cs.Info(context.Background(), layer.Digest)
					assert.ErrorIs(err, errdefs.ErrNotFound)
					assert.NotContains(requestMethods(reg, layer.Digest), http.MethodGet)
				}
			},
		},
		{
			name: "only nydus blobs are pulled",
			ref:  "repo/image:v1",
			opt:  PullOption{PullNydusBlobs: true},
			expect: func(t *testing.T, reg *registrytest.Registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, err = cs.Info(context.Background(), mockNydusBlobDesc.Digest)
				assert.NoError(err)
				_, err = cs.Info(context.Background(), mockOCILayerDesc.Digest)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "only oci layers are pulled",
			ref:  "repo/image:v1",
			opt:  PullOption{PullOCILayers: true},
			expect: func(t *testing.T, reg *registrytest.Registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				_, err = cs.Info(context.Background(), mockOCILayerDesc.Digest)
				assert.NoError(err)
				_, err = cs.Info(context.Background(), mockNydusBlobDesc.Digest)
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "docker config credentials are sent",
			ref:  "repo/image:v1",
			opt:  PullAll,
			opts: []registrytest.Option{registrytest.WithBasicAuth("user", "secret")},
			expect: func(t *testing.T, reg *registrytest.Registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockManifestDesc.Digest, desc.Digest)
			},
		},
		{
			name:  "retry a layer the registry answers with a transient status",
			ref:   "repo/image:v1",
			opt:   PullAll,
			flaky: mockOCILayerDesc.Digest,
			expect: func(t *testing.T, reg *registrytest.Registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				stored, err := content.ReadBlob(context.Background(), cs, mockOCILayerDesc)
				assert.NoError(err)
				assert.Equal(mockOCILayer, stored)
				assert.Equal([]string{http.MethodGet}, requestMethods(reg, mockOCILayerDesc.Digest))
			},
		},
		{
			name: "corrupt manifest",
			ref:  "repo/broken:v1",
			expect: func(t *testing.T, reg *registrytest.Registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "fetch")
				assert.Empty(desc)
			},
		},
		{
			name: "missing tag",
			ref:  "repo/image:missing",
			expect: func(t *testing.T, reg *registrytest.Registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve")
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "invalid reference",
			ref:  "repo/Image:v1",
			expect: func(t *testing.T, reg *registrytest.Registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse reference")
				assert.Empty(reg.Requests())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := registrytest.New(t, tc.opts...)
			for _, data := range [][]byte{mockOCILayer, mockNydusBlob, mockBootstrap} {
				reg.Store("repo/image", "", "", data)
			}

			reg.StoreImage(t, "repo/image", "v1", mockImageConfig, mockOCILayerDesc, mockNydusBlobDesc, mockBootstrapDesc)
			reg.Store("repo/broken", "v1", ocispec.MediaTypeImageManifest, []byte("{"))
			mockDockerConfig(t, `{"auths":{"`+reg.Host+`":{"auth":"`+mockAuth+`"}}}`)
			provider, err := NewProvider(Option{WorkDir: t.TempDir(), SourcePlainHTTP: true})
			if err != nil {
				t.Fatal(err)
			}

			host := reg.Host
			if tc.flaky != "" {
				host = mockFlakyRegistry(t, reg.Host, tc.flaky)
			}

			desc, err := provider.Pull(context.Background(), host+"/"+tc.ref, tc.opt, Source)

			tc.expect(t, reg, provider.ContentStore(), desc, err)
		})
	}
}

func TestProvider_Push(t *testing.T) {
	tests := []struct {
		name   string
		ref    string
		expect func(t *testing.T, reg *registrytest.Registry, err error)
	}{
		{
			name: "push image",
			ref:  "repo/image:v1",
			expect: func(t *testing.T, reg *registrytest.Registry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				for dgst, data := range mockImageBlobs {
					stored, _ := reg.Load("repo/image", dgst.String())
					assert.Equal(data, stored)
				}

				manifest, _ := reg.Load("repo/image", "v1")
				assert.Equal(mockManifest, manifest)
			},
		},
		{
			name: "invalid reference",
			ref:  "Repo/Image:v1",
			expect: func(t *testing.T, reg *registrytest.Registry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse reference")
				assert.Empty(reg.Requests())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := registrytest.New(t)
			provider := mockProvider(t)

			tc.expect(t, reg, provider.Push(context.Background(), mockManifestDesc, reg.Host+"/"+tc.ref))
		})
	}
}

func TestProvider_PushSkipping(t *testing.T) {
	tests := []struct {
		name   string
		ref    string
		skip   map[digest.Digest]struct{}
		expect func(t *testing.T, reg *registrytest.Registry, err error)
	}{
		{
			name: "skip parent blob",
			ref:  "repo/image:v1",
			skip: map[digest.Digest]struct{}{mockNydusBlobDesc.Digest: {}},
			expect: func(t *testing.T, reg *registrytest.Registry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				manifest, _ := reg.Load("repo/image", "v1")
				assert.Equal(mockManifest, manifest)
				layer, _ := reg.Load("repo/image", mockOCILayerDesc.Digest.String())
				assert.Equal(mockOCILayer, layer)
				_, ok := reg.Load("repo/image", mockNydusBlobDesc.Digest.String())
				assert.False(ok)
				assert.NotContains(requestMethods(reg, mockNydusBlobDesc.Digest), http.MethodHead)
			},
		},
		{
			name: "no skipped blobs",
			ref:  "repo/image:v1",
			expect: func(t *testing.T, reg *registrytest.Registry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				for dgst, data := range mockImageBlobs {
					stored, _ := reg.Load("repo/image", dgst.String())
					assert.Equal(data, stored)
				}
			},
		},
		{
			name: "invalid reference",
			ref:  "Repo/Image:v1",
			expect: func(t *testing.T, reg *registrytest.Registry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse reference")
				assert.Empty(reg.Requests())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := registrytest.New(t)
			provider := mockProvider(t)

			tc.expect(t, reg, provider.PushSkipping(context.Background(), mockManifestDesc, reg.Host+"/"+tc.ref, tc.skip))
		})
	}
}

func TestProvider_EnsureParentBlobs(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, provider *Provider, reg *registrytest.Registry)
	}{
		{
			name: "mount parent blobs without download",
			expect: func(t *testing.T, provider *Provider, reg *registrytest.Registry) {
				assert := assert.New(t)
				reg.Store("ns/parent", "", "", mockOCILayer)
				reg.Store("ns/parent", "", "", mockNydusBlob)
				err := provider.EnsureParentBlobs(context.Background(), []ocispec.Descriptor{mockOCILayerDesc, mockNydusBlobDesc}, reg.Ref("ns/parent", "v1"), reg.Ref("ns/child", "v2"))
				assert.NoError(err)
				assert.Equal([]string{http.MethodHead, http.MethodPost}, requestMethods(reg, mockOCILayerDesc.Digest))
				assert.Equal([]string{http.MethodHead, http.MethodPost}, requestMethods(reg, mockNydusBlobDesc.Digest))
			},
		},
		{
			name: "invalid parent reference",
			expect: func(t *testing.T, provider *Provider, reg *registrytest.Registry) {
				assert := assert.New(t)
				err := provider.EnsureParentBlobs(context.Background(), []ocispec.Descriptor{mockNydusBlobDesc}, "Parent/Image:v1", "registry.test/ns/child:v1")
				assert.ErrorContains(err, `parse reference "Parent/Image:v1"`)
			},
		},
		{
			name: "invalid target reference",
			expect: func(t *testing.T, provider *Provider, reg *registrytest.Registry) {
				assert := assert.New(t)
				err := provider.EnsureParentBlobs(context.Background(), []ocispec.Descriptor{mockNydusBlobDesc}, "registry.test/ns/parent:v1", "Child/Image:v1")
				assert.ErrorContains(err, `parse reference "Child/Image:v1"`)
			},
		},
		{
			name: "parent on another registry",
			expect: func(t *testing.T, provider *Provider, reg *registrytest.Registry) {
				assert := assert.New(t)
				err := provider.EnsureParentBlobs(context.Background(), []ocispec.Descriptor{mockNydusBlobDesc}, "source.test/ns/parent:v1", "target.test/ns/child:v1")
				assert.ErrorContains(err, "make parent blob "+mockNydusBlobDesc.Digest.String()+" available in target repository")
				assert.ErrorContains(err, "must use the same registry")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := registrytest.New(t)
			provider := mockProvider(t)

			tc.expect(t, provider, reg)
		})
	}
}

func TestProvider_PushBlob(t *testing.T) {
	tests := []struct {
		name   string
		ref    string
		expect func(t *testing.T, reg *registrytest.Registry, err error)
	}{
		{
			name: "push single blob",
			ref:  "repo/image:v1",
			expect: func(t *testing.T, reg *registrytest.Registry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				layer, _ := reg.Load("repo/image", mockOCILayerDesc.Digest.String())
				assert.Equal(mockOCILayer, layer)
				_, ok := reg.Load("repo/image", mockManifestDesc.Digest.String())
				assert.False(ok)
				_, ok = reg.Load("repo/image", "v1")
				assert.False(ok)
			},
		},
		{
			name: "invalid reference",
			ref:  "Repo/Image:v1",
			expect: func(t *testing.T, reg *registrytest.Registry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse reference")
				assert.Empty(reg.Requests())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := registrytest.New(t)
			provider := mockProvider(t)

			tc.expect(t, reg, provider.PushBlob(context.Background(), mockOCILayerDesc, reg.Host+"/"+tc.ref))
		})
	}
}

func TestProvider_PushBlobFile(t *testing.T) {
	tests := []struct {
		name   string
		ref    string
		expect func(t *testing.T, reg *registrytest.Registry, err error)
	}{
		{
			name: "push blob file",
			ref:  "repo/image:v1",
			expect: func(t *testing.T, reg *registrytest.Registry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				stored, _ := reg.Load("repo/image", mockBlobFileDesc.Digest.String())
				assert.Equal(mockBlobFile, stored)
			},
		},
		{
			name: "invalid reference",
			ref:  "Repo/Image:v1",
			expect: func(t *testing.T, reg *registrytest.Registry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse reference")
				assert.Empty(reg.Requests())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := registrytest.New(t)
			provider := mockProvider(t)
			path := filepath.Join(t.TempDir(), "blob")
			if err := os.WriteFile(path, mockBlobFile, 0o600); err != nil {
				t.Fatal(err)
			}

			tc.expect(t, reg, provider.PushBlobFile(context.Background(), path, mockBlobFileDesc, reg.Host+"/"+tc.ref))
		})
	}
}

func TestMemoryLabelStore_Update(t *testing.T) {
	tests := []struct {
		name   string
		update map[string]string
		expect func(t *testing.T, store *memoryLabelStore, labels map[string]string)
	}{
		{
			name:   "new label is added",
			update: map[string]string{"added": "value"},
			expect: func(t *testing.T, store *memoryLabelStore, labels map[string]string) {
				assert := assert.New(t)
				assert.Equal(map[string]string{"kept": "label", "removed": "label", "added": "value"}, labels)
			},
		},
		{
			name:   "empty value removes label",
			update: map[string]string{"removed": ""},
			expect: func(t *testing.T, store *memoryLabelStore, labels map[string]string) {
				assert := assert.New(t)
				assert.Equal(map[string]string{"kept": "label"}, labels)
				stored, err := store.Get(mockOCILayerDesc.Digest)
				assert.NoError(err)
				assert.Equal(map[string]string{"kept": "label"}, stored)
			},
		},
		{
			name:   "returned labels are a copy",
			update: map[string]string{"kept": "updated"},
			expect: func(t *testing.T, store *memoryLabelStore, labels map[string]string) {
				assert := assert.New(t)
				labels["kept"] = "mutated"
				stored, err := store.Get(mockOCILayerDesc.Digest)
				assert.NoError(err)
				assert.Equal("updated", stored["kept"])
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemoryLabelStore()
			if err := store.Set(mockOCILayerDesc.Digest, map[string]string{"kept": "label", "removed": "label"}); err != nil {
				t.Fatal(err)
			}

			labels, err := store.Update(mockOCILayerDesc.Digest, tc.update)
			assert.NoError(t, err)

			tc.expect(t, store, labels)
		})
	}
}

func TestProvider_OpenBlob(t *testing.T) {
	tests := []struct {
		name   string
		expect func(t *testing.T, provider *Provider)
	}{
		{
			name: "invalid blob size",
			expect: func(t *testing.T, provider *Provider) {
				assert := assert.New(t)
				_, err := provider.OpenBlob(context.Background(), ocispec.Descriptor{}, mockRef, Target, "")
				assert.ErrorContains(err, "invalid blob size")
			},
		},
		{
			name: "invalid reference",
			expect: func(t *testing.T, provider *Provider) {
				assert := assert.New(t)
				_, err := provider.OpenBlob(context.Background(), mockRangeBlobDesc, "://invalid", Target, "")
				assert.ErrorContains(err, "parse reference")
			},
		},
		{
			name: "fetch failure",
			expect: func(t *testing.T, provider *Provider) {
				assert := assert.New(t)
				provider.blobFetchers.Store(mockBlobFetcherKey, &mockFetcher{err: errMock})
				_, err := provider.OpenBlob(context.Background(), mockRangeBlobDesc, mockBlobFetcherKey.ref, Target, "")
				assert.ErrorIs(err, errMock)
			},
		},
		{
			name: "close non-seekable reader",
			expect: func(t *testing.T, provider *Provider) {
				assert := assert.New(t)
				fetcher := &mockFetcher{Reader: bytes.NewReader(mockRangeBlob)}
				provider.blobFetchers.Store(mockBlobFetcherKey, fetcher)
				_, err := provider.OpenBlob(context.Background(), mockRangeBlobDesc, mockBlobFetcherKey.ref, Target, "")
				assert.ErrorContains(err, "does not support seeking")
				assert.Equal(1, fetcher.closes)
			},
		},
		{
			name: "defer transfer until read",
			expect: func(t *testing.T, provider *Provider) {
				assert := assert.New(t)
				ref, transferred := mockRangeRegistry(t, "bytes=4-5")
				reader, err := provider.OpenBlob(context.Background(), mockRangeBlobDesc, ref, Target, "bytes=4-5")
				assert.NoError(err)
				assert.Zero(transferred.Load())
				_, err = reader.Seek(4, io.SeekStart)
				assert.NoError(err)
				data, err := io.ReadAll(reader)
				assert.NoError(err)
				assert.Equal("ef", string(data))
				assert.Equal(int32(1), transferred.Load())
				assert.NoError(reader.Close())
			},
		},
		{
			name: "bound middle range",
			expect: func(t *testing.T, provider *Provider) {
				assert := assert.New(t)
				ref, transferred := mockRangeRegistry(t, "bytes=2-4")
				reader, err := provider.OpenBlob(context.Background(), mockRangeBlobDesc, ref, Target, "bytes=2-4")
				assert.NoError(err)
				_, err = reader.Seek(2, io.SeekStart)
				assert.NoError(err)
				data, err := io.ReadAll(reader)
				assert.NoError(err)
				assert.Equal("cde", string(data))
				assert.Equal(int32(1), transferred.Load())
				assert.NoError(reader.Close())
			},
		},
		{
			name: "bound start range",
			expect: func(t *testing.T, provider *Provider) {
				assert := assert.New(t)
				ref, transferred := mockRangeRegistry(t, "bytes=0-1")
				reader, err := provider.OpenBlob(context.Background(), mockRangeBlobDesc, ref, Target, "bytes=0-1")
				assert.NoError(err)
				_, err = reader.Seek(0, io.SeekStart)
				assert.NoError(err)
				data, err := io.ReadAll(reader)
				assert.NoError(err)
				assert.Equal("ab", string(data))
				assert.Equal(int32(1), transferred.Load())
				assert.NoError(reader.Close())
			},
		},
		{
			name: "bound suffix range",
			expect: func(t *testing.T, provider *Provider) {
				assert := assert.New(t)
				ref, transferred := mockRangeRegistry(t, "bytes=6-7")
				reader, err := provider.OpenBlob(context.Background(), mockRangeBlobDesc, ref, Target, "bytes=-2")
				assert.NoError(err)
				_, err = reader.Seek(6, io.SeekStart)
				assert.NoError(err)
				data, err := io.ReadAll(reader)
				assert.NoError(err)
				assert.Equal("gh", string(data))
				assert.Equal(int32(1), transferred.Load())
				assert.NoError(reader.Close())
			},
		},
		{
			name: "reject ignored range",
			expect: func(t *testing.T, provider *Provider) {
				assert := assert.New(t)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write(mockRangeBlob)
				}))
				defer server.Close()
				reader, err := provider.OpenBlob(context.Background(), mockRangeBlobDesc, strings.TrimPrefix(server.URL, "http://")+"/test:v1", Target, "bytes=0-1")
				assert.NoError(err)
				_, err = io.ReadAll(reader)
				assert.ErrorContains(err, "did not honor compact range")
				assert.NoError(reader.Close())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider := mockProvider(t)
			provider.credFunc = func(string) (string, string, error) {
				return "user", "pass", nil
			}

			tc.expect(t, provider)
		})
	}
}
