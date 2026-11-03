/*
 * Copyright (c) 2026. Nydus Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package remote

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	dockerconfig "github.com/docker/cli/cli/config"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"

	"github.com/dragonflyoss/nydus/nydusify/internal/registrytest"
	"github.com/dragonflyoss/nydus/nydusify/pkg/nydus"
)

func TestSameRepository(t *testing.T) {
	tests := []struct {
		name      string
		left      string
		right     string
		want      bool
		wantError bool
	}{
		{
			name:  "same explicit repository",
			left:  "localhost:5000/repo/image:parent",
			right: "localhost:5000/repo/image:child",
			want:  true,
		},
		{
			name:  "different repository",
			left:  "localhost:5000/repo/image:parent",
			right: "localhost:5000/repo/other:child",
			want:  false,
		},
		{
			name:  "docker hub shorthand",
			left:  "busybox:1.36",
			right: "docker.io/library/busybox:latest",
			want:  true,
		},
		{
			name:  "digest reference",
			left:  "localhost:5000/repo/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			right: "localhost:5000/repo/image:tag",
			want:  true,
		},
		{
			name:      "invalid reference",
			left:      "not a valid reference",
			right:     "localhost:5000/repo/image:tag",
			wantError: true,
		},
		{
			name:      "invalid right reference",
			left:      "localhost:5000/repo/image:tag",
			right:     "not a valid reference",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SameRepository(tt.left, tt.right)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("SameRepository returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("SameRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}

var (
	mockImageConfig = []byte(`{"architecture":"amd64","os":"linux"}`)

	mockImageConfigDesc = contentTestDescriptor(ocispec.MediaTypeImageConfig, mockImageConfig)

	mockOCILayer = []byte("oci layer")

	mockOCILayerDesc = contentTestDescriptor(ocispec.MediaTypeImageLayerGzip, mockOCILayer)

	mockNydusBlob = []byte("nydus blob")

	mockNydusBlobDesc = contentTestDescriptor(nydus.MediaTypeNydusBlob, mockNydusBlob)

	mockBootstrap = []byte("nydus bootstrap")

	mockBootstrapDesc = ocispec.Descriptor{
		MediaType:   ocispec.MediaTypeImageLayerGzip,
		Digest:      digest.FromBytes(mockBootstrap),
		Size:        int64(len(mockBootstrap)),
		Annotations: map[string]string{nydus.LayerAnnotationNydusBootstrap: "true"},
	}

	mockManifest = newMockManifest(mockImageConfigDesc, mockOCILayerDesc, mockNydusBlobDesc, mockBootstrapDesc)

	mockManifestDesc = contentTestDescriptor(ocispec.MediaTypeImageManifest, mockManifest)

	mockImageBlobs = map[digest.Digest][]byte{
		mockImageConfigDesc.Digest: mockImageConfig,
		mockOCILayerDesc.Digest:    mockOCILayer,
		mockNydusBlobDesc.Digest:   mockNydusBlob,
		mockBootstrapDesc.Digest:   mockBootstrap,
		mockManifestDesc.Digest:    mockManifest,
	}
)

func newMockManifest(config ocispec.Descriptor, layers ...ocispec.Descriptor) []byte {
	manifest := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Config: config, Layers: layers}
	manifest.SchemaVersion = 2
	data, _ := json.Marshal(manifest)
	return data
}

type registry struct {
	*registrytest.Registry
}

func newRegistry(t *testing.T, opts ...registrytest.Option) *registry {
	return &registry{registrytest.New(t, opts...)}
}

func (r *registry) storeImage(repo, tag string) {
	for _, data := range mockImageBlobs {
		r.Store(repo, "", "", data)
	}

	r.Store(repo, tag, ocispec.MediaTypeImageManifest, mockManifest)
}

func (r *registry) requested(method string, dgst digest.Digest) bool {
	return slices.ContainsFunc(r.Requests(), func(req registrytest.Request) bool {
		return req.Method == method && strings.Contains(req.URL, dgst.String())
	})
}

func mockDockerConfig(t *testing.T, config string) {
	dir := t.TempDir()
	if !assert.NoError(t, os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o600)) {
		t.FailNow()
	}
	previous := dockerconfig.Dir()
	dockerconfig.SetDir(dir)
	t.Cleanup(func() { dockerconfig.SetDir(previous) })
}

func TestProvider_Pull(t *testing.T) {
	mockAuth := base64.StdEncoding.EncodeToString([]byte("user:secret"))
	tests := []struct {
		name   string
		ref    string
		opt    PullOption
		auth   bool
		setup  func(reg *registry)
		expect func(t *testing.T, reg *registry, cs content.Store, desc ocispec.Descriptor, err error)
	}{
		{
			name: "pull every layer",
			ref:  "repo/image:v1",
			opt:  PullAll,
			expect: func(t *testing.T, reg *registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
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
			expect: func(t *testing.T, reg *registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				for _, layer := range []ocispec.Descriptor{mockManifestDesc, mockImageConfigDesc, mockBootstrapDesc} {
					_, err := cs.Info(context.Background(), layer.Digest)
					assert.NoError(err)
				}
				for _, layer := range []ocispec.Descriptor{mockOCILayerDesc, mockNydusBlobDesc} {
					_, err := cs.Info(context.Background(), layer.Digest)
					assert.True(errdefs.IsNotFound(err))
					assert.False(reg.requested(http.MethodGet, layer.Digest))
				}
			},
		},
		{
			name: "only nydus blobs are pulled",
			ref:  "repo/image:v1",
			opt:  PullOption{PullNydusBlobs: true},
			expect: func(t *testing.T, reg *registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				_, err = cs.Info(context.Background(), mockNydusBlobDesc.Digest)
				assert.NoError(err)
				_, err = cs.Info(context.Background(), mockOCILayerDesc.Digest)
				assert.True(errdefs.IsNotFound(err))
			},
		},
		{
			name: "only oci layers are pulled",
			ref:  "repo/image:v1",
			opt:  PullOption{PullOCILayers: true},
			expect: func(t *testing.T, reg *registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				if !assert.NoError(err) {
					t.FailNow()
				}
				_, err = cs.Info(context.Background(), mockOCILayerDesc.Digest)
				assert.NoError(err)
				_, err = cs.Info(context.Background(), mockNydusBlobDesc.Digest)
				assert.True(errdefs.IsNotFound(err))
			},
		},
		{
			name: "docker config credentials are sent",
			ref:  "repo/image:v1",
			opt:  PullAll,
			auth: true,
			expect: func(t *testing.T, reg *registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal(mockManifestDesc.Digest, desc.Digest)
			},
		},
		{
			name: "corrupt manifest",
			ref:  "repo/broken:v1",
			setup: func(reg *registry) {
				reg.Store("repo/broken", "v1", ocispec.MediaTypeImageManifest, []byte("{"))
			},
			expect: func(t *testing.T, reg *registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "fetch")
				assert.Empty(desc)
			},
		},
		{
			name: "missing tag",
			ref:  "repo/image:missing",
			expect: func(t *testing.T, reg *registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "resolve")
				assert.ErrorIs(err, errdefs.ErrNotFound)
			},
		},
		{
			name: "invalid reference",
			ref:  "repo/Image:v1",
			expect: func(t *testing.T, reg *registry, cs content.Store, desc ocispec.Descriptor, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse reference")
				assert.Empty(reg.Requests())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var opts []registrytest.Option
			if tc.auth {
				opts = append(opts, registrytest.WithBasicAuth("user", "secret"))
			}
			reg := newRegistry(t, opts...)
			reg.storeImage("repo/image", "v1")
			if tc.setup != nil {
				tc.setup(reg)
			}
			mockDockerConfig(t, `{"auths":{"`+reg.Host+`":{"auth":"`+mockAuth+`"}}}`)
			provider, err := NewProvider(Option{WorkDir: t.TempDir(), SourcePlainHTTP: true})
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			desc, err := provider.Pull(context.Background(), reg.Host+"/"+tc.ref, tc.opt, Source)
			tc.expect(t, reg, provider.ContentStore(), desc, err)
		})
	}
}

func TestProvider_Push(t *testing.T) {
	tests := []struct {
		name   string
		push   func(t *testing.T, p *Provider, ref string) error
		expect func(t *testing.T, reg *registry, err error)
	}{
		{
			name: "push uploads image",
			push: func(t *testing.T, p *Provider, ref string) error {
				return p.Push(context.Background(), mockManifestDesc, ref)
			},
			expect: func(t *testing.T, reg *registry, err error) {
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
			name: "push skipping parent blob",
			push: func(t *testing.T, p *Provider, ref string) error {
				return p.PushSkipping(context.Background(), mockManifestDesc, ref, map[digest.Digest]struct{}{mockNydusBlobDesc.Digest: {}})
			},
			expect: func(t *testing.T, reg *registry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				manifest, _ := reg.Load("repo/image", "v1")
				assert.Equal(mockManifest, manifest)
				layer, _ := reg.Load("repo/image", mockOCILayerDesc.Digest.String())
				assert.Equal(mockOCILayer, layer)
				_, ok := reg.Load("repo/image", mockNydusBlobDesc.Digest.String())
				assert.False(ok)
				assert.False(reg.requested(http.MethodHead, mockNydusBlobDesc.Digest))
			},
		},
		{
			name: "push skipping without skipped blobs",
			push: func(t *testing.T, p *Provider, ref string) error {
				return p.PushSkipping(context.Background(), mockManifestDesc, ref, nil)
			},
			expect: func(t *testing.T, reg *registry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				for dgst, data := range mockImageBlobs {
					stored, _ := reg.Load("repo/image", dgst.String())
					assert.Equal(data, stored)
				}
			},
		},
		{
			name: "push single blob",
			push: func(t *testing.T, p *Provider, ref string) error {
				return p.PushBlob(context.Background(), mockOCILayerDesc, ref)
			},
			expect: func(t *testing.T, reg *registry, err error) {
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
			name: "push blob file",
			push: func(t *testing.T, p *Provider, ref string) error {
				path := filepath.Join(t.TempDir(), "blob")
				if !assert.NoError(t, os.WriteFile(path, []byte("local blob file"), 0o600)) {
					t.FailNow()
				}
				return p.PushBlobFile(context.Background(), path, contentTestDescriptor(nydus.MediaTypeNydusBlob, []byte("local blob file")), ref)
			},
			expect: func(t *testing.T, reg *registry, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				stored, _ := reg.Load("repo/image", digest.FromString("local blob file").String())
				assert.Equal([]byte("local blob file"), stored)
			},
		},
		{
			name: "push rejects invalid reference",
			push: func(t *testing.T, p *Provider, ref string) error {
				return p.Push(context.Background(), mockManifestDesc, "Repo/Image:v1")
			},
			expect: func(t *testing.T, reg *registry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse reference")
				assert.Empty(reg.Requests())
			},
		},
		{
			name: "push skipping rejects invalid reference",
			push: func(t *testing.T, p *Provider, ref string) error {
				return p.PushSkipping(context.Background(), mockManifestDesc, "Repo/Image:v1", nil)
			},
			expect: func(t *testing.T, reg *registry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse reference")
				assert.Empty(reg.Requests())
			},
		},
		{
			name: "push blob rejects invalid reference",
			push: func(t *testing.T, p *Provider, ref string) error {
				return p.PushBlob(context.Background(), mockOCILayerDesc, "Repo/Image:v1")
			},
			expect: func(t *testing.T, reg *registry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse reference")
				assert.Empty(reg.Requests())
			},
		},
		{
			name: "push blob file rejects invalid reference",
			push: func(t *testing.T, p *Provider, ref string) error {
				return p.PushBlobFile(context.Background(), "blob", mockOCILayerDesc, "Repo/Image:v1")
			},
			expect: func(t *testing.T, reg *registry, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "parse reference")
				assert.Empty(reg.Requests())
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reg := newRegistry(t)
			mockDockerConfig(t, `{}`)
			provider, err := NewProvider(Option{WorkDir: t.TempDir(), TargetPlainHTTP: true})
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			for dgst, data := range mockImageBlobs {
				desc := ocispec.Descriptor{Digest: dgst, Size: int64(len(data))}
				if !assert.NoError(t, content.WriteBlob(context.Background(), provider.ContentStore(), dgst.String(), bytes.NewReader(data), desc)) {
					t.FailNow()
				}
			}
			tc.expect(t, reg, tc.push(t, provider, reg.Ref("repo/image", "v1")))
		})
	}
}

func TestProvider_EnsureParentBlobs(t *testing.T) {
	tests := []struct {
		name   string
		parent string
		target string
		expect func(t *testing.T, err error)
	}{
		{
			name:   "invalid parent reference",
			parent: "Parent/Image:v1",
			target: "registry.test/ns/child:v1",
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `parse reference "Parent/Image:v1"`)
			},
		},
		{
			name:   "invalid target reference",
			parent: "registry.test/ns/parent:v1",
			target: "Child/Image:v1",
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `parse reference "Child/Image:v1"`)
			},
		},
		{
			name:   "parent on another registry",
			parent: "source.test/ns/parent:v1",
			target: "target.test/ns/child:v1",
			expect: func(t *testing.T, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, "make parent blob "+mockNydusBlobDesc.Digest.String()+" available in target repository")
				assert.ErrorContains(err, "must use the same registry")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := NewProvider(Option{WorkDir: t.TempDir()})
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			tc.expect(t, provider.EnsureParentBlobs(context.Background(), []ocispec.Descriptor{mockNydusBlobDesc}, tc.parent, tc.target))
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
			if !assert.NoError(t, store.Set(mockOCILayerDesc.Digest, map[string]string{"kept": "label", "removed": "label"})) {
				t.FailNow()
			}
			labels, err := store.Update(mockOCILayerDesc.Digest, tc.update)
			assert.NoError(t, err)
			tc.expect(t, store, labels)
		})
	}
}

func TestNewDockerConfigCredFunc(t *testing.T) {
	tests := []struct {
		name   string
		config string
		host   string
		expect func(t *testing.T, username, password string, err error)
	}{
		{
			name:   "registry credentials",
			config: `{"auths":{"registry.test":{"auth":"` + base64.StdEncoding.EncodeToString([]byte("user:secret")) + `"}}}`,
			host:   "registry.test",
			expect: func(t *testing.T, username, password string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("user", username)
				assert.Equal("secret", password)
			},
		},
		{
			name:   "docker hub uses legacy key",
			config: `{"auths":{"https://index.docker.io/v1/":{"auth":"` + base64.StdEncoding.EncodeToString([]byte("hub:token")) + `"}}}`,
			host:   "registry-1.docker.io",
			expect: func(t *testing.T, username, password string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Equal("hub", username)
				assert.Equal("token", password)
			},
		},
		{
			name:   "unknown registry is anonymous",
			config: `{"auths":{}}`,
			host:   "registry.test",
			expect: func(t *testing.T, username, password string, err error) {
				assert := assert.New(t)
				assert.NoError(err)
				assert.Empty(username)
				assert.Empty(password)
			},
		},
		{
			name:   "credential helper failure",
			config: `{"credsStore":"nydusify-missing-helper"}`,
			host:   "registry.test",
			expect: func(t *testing.T, username, password string, err error) {
				assert := assert.New(t)
				assert.ErrorContains(err, `get auth config for "registry.test"`)
				assert.Empty(username)
				assert.Empty(password)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockDockerConfig(t, tc.config)
			username, password, err := NewDockerConfigCredFunc()(tc.host)
			tc.expect(t, username, password, err)
		})
	}
}
