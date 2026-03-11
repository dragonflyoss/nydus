// Copyright 2026 Nydus Developers. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/remote"
	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/utils"
)

type testResolver struct {
	resolve func(context.Context, string) (string, ocispec.Descriptor, error)
	fetcher func(context.Context, string) (remotes.Fetcher, error)
}

func (r *testResolver) Resolve(ctx context.Context, ref string) (string, ocispec.Descriptor, error) {
	return r.resolve(ctx, ref)
}

func (r *testResolver) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	return r.fetcher(ctx, ref)
}

func (r *testResolver) Pusher(context.Context, string) (remotes.Pusher, error) {
	return nil, errors.New("pusher not implemented")
}

func (r *testResolver) PusherInChunked(context.Context, string) (remotes.PusherInChunked, error) {
	return nil, errors.New("chunked pusher not implemented")
}

func newTestParser(
	t *testing.T,
	arch string,
	resolve func(context.Context, string) (string, ocispec.Descriptor, error),
	fetch func(context.Context, ocispec.Descriptor) (io.ReadCloser, error),
) *Parser {
	t.Helper()
	remoter, err := remote.New("docker.io/library/busybox:latest", func(bool) remotes.Resolver {
		return &testResolver{
			resolve: resolve,
			fetcher: func(ctx context.Context, _ string) (remotes.Fetcher, error) {
				return remotes.FetcherFunc(func(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
					return fetch(ctx, desc)
				}), nil
			},
		}
	})
	require.NoError(t, err)
	parser, err := New(remoter, arch)
	require.NoError(t, err)
	return parser
}

func TestNewRejectsUnsupportedArch(t *testing.T) {
	parser, err := New(nil, "riscv64")
	require.Error(t, err)
	require.Nil(t, parser)
	require.Contains(t, err.Error(), "invalid arch riscv64")
}

func TestFindNydusBootstrapDesc(t *testing.T) {
	manifest := &ocispec.Manifest{
		Layers: []ocispec.Descriptor{
			{
				MediaType: ocispec.MediaTypeImageLayerGzip,
				Digest:    digest.FromString("regular"),
			},
			{
				MediaType: images.MediaTypeDockerSchema2LayerGzip,
				Digest:    digest.FromString("bootstrap"),
				Annotations: map[string]string{
					utils.LayerAnnotationNydusBootstrap: "true",
				},
			},
		},
	}

	desc := FindNydusBootstrapDesc(manifest)
	require.NotNil(t, desc)
	require.Equal(t, digest.FromString("bootstrap"), desc.Digest)

	manifest.Layers[len(manifest.Layers)-1].Annotations[utils.LayerAnnotationNydusBootstrap] = "false"
	require.Nil(t, FindNydusBootstrapDesc(manifest))
}

func TestMatchImagePlatform(t *testing.T) {
	parser, err := New(nil, utils.PlatformArchAMD64)
	require.NoError(t, err)

	require.True(t, parser.matchImagePlatform(&ocispec.Descriptor{
		Platform: &ocispec.Platform{OS: "linux", Architecture: utils.PlatformArchAMD64},
	}))
	require.False(t, parser.matchImagePlatform(&ocispec.Descriptor{
		Platform: &ocispec.Platform{OS: "linux", Architecture: utils.PlatformArchARM64},
	}))
	require.False(t, parser.matchImagePlatform(&ocispec.Descriptor{
		Platform: &ocispec.Platform{OS: "windows", Architecture: utils.PlatformArchAMD64},
	}))
}

func TestParseImageIgnoresMismatchedArchWhenRequested(t *testing.T) {
	configDesc := ocispec.Descriptor{Digest: digest.FromString("config")}
	manifest := &ocispec.Manifest{Config: configDesc}
	parser := newTestParser(
		t,
		utils.PlatformArchAMD64,
		func(_ context.Context, _ string) (string, ocispec.Descriptor, error) {
			return "", ocispec.Descriptor{}, nil
		},
		func(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
			require.Equal(t, configDesc.Digest, desc.Digest)
			payload := []byte(`{"os":"linux","architecture":"arm64"}`)
			return io.NopCloser(bytes.NewReader(payload)), nil
		},
	)

	image, err := parser.parseImage(context.Background(), &ocispec.Descriptor{Digest: digest.FromString("manifest")}, manifest, true)
	require.NoError(t, err)
	require.Equal(t, "arm64", image.Config.Architecture)
	require.Equal(t, configDesc.Digest, image.Manifest.Config.Digest)

	_, err = parser.parseImage(context.Background(), &ocispec.Descriptor{}, manifest, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "specified target arch")
}

func TestPullNydusBootstrap(t *testing.T) {
	bootstrapDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    digest.FromString("bootstrap"),
		Annotations: map[string]string{
			utils.LayerAnnotationNydusBootstrap: "true",
		},
	}
	parser := newTestParser(
		t,
		utils.PlatformArchAMD64,
		func(_ context.Context, _ string) (string, ocispec.Descriptor, error) {
			return "", ocispec.Descriptor{}, nil
		},
		func(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
			require.Equal(t, bootstrapDesc.Digest, desc.Digest)
			return io.NopCloser(bytes.NewBufferString("bootstrap-data")), nil
		},
	)

	reader, err := parser.PullNydusBootstrap(context.Background(), &Image{
		Manifest: ocispec.Manifest{Layers: []ocispec.Descriptor{bootstrapDesc}},
	})
	require.NoError(t, err)
	defer reader.Close()

	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "bootstrap-data", string(data))

	_, err = parser.PullNydusBootstrap(context.Background(), &Image{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found Nydus bootstrap layer")
}

func TestParseResolveCertificateError(t *testing.T) {
	parser := newTestParser(
		t,
		utils.PlatformArchAMD64,
		func(_ context.Context, _ string) (string, ocispec.Descriptor, error) {
			return "", ocispec.Descriptor{}, errors.New("x509: certificate signed by unknown authority")
		},
		func(_ context.Context, _ ocispec.Descriptor) (io.ReadCloser, error) {
			return nil, errors.New("unexpected fetch")
		},
	)

	parsed, err := parser.Parse(context.Background())
	require.Nil(t, parsed)
	require.Error(t, err)
	require.Contains(t, err.Error(), "resolve image")
}

func TestParseSingleManifestOCIMode(t *testing.T) {
	manifestDesc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("single-manifest")}
	configDesc := ocispec.Descriptor{Digest: digest.FromString("single-config")}
	manifest := ocispec.Manifest{Config: configDesc}
	config := ocispec.Image{Platform: ocispec.Platform{OS: "linux", Architecture: utils.PlatformArchAMD64}}
	parser := newTestParser(
		t,
		utils.PlatformArchAMD64,
		func(_ context.Context, _ string) (string, ocispec.Descriptor, error) {
			return "docker.io/library/busybox:latest", manifestDesc, nil
		},
		func(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
			switch desc.Digest {
			case manifestDesc.Digest:
				payload, _ := json.Marshal(manifest)
				return io.NopCloser(bytes.NewReader(payload)), nil
			case configDesc.Digest:
				payload, _ := json.Marshal(config)
				return io.NopCloser(bytes.NewReader(payload)), nil
			default:
				return nil, errors.New("unexpected descriptor")
			}
		},
	)

	parsed, err := parser.Parse(context.Background())
	require.NoError(t, err)
	require.NotNil(t, parsed.OCIImage)
	require.Nil(t, parsed.NydusImage)
	require.Equal(t, manifestDesc.Digest, parsed.OCIImage.Desc.Digest)
}

func TestParseIndexScenarios(t *testing.T) {
	t.Run("artifact type detects nydus image", func(t *testing.T) {
		indexDesc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("index")}
		ociManifestDesc := ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    digest.FromString("oci-manifest"),
			Platform:  &ocispec.Platform{OS: "linux", Architecture: utils.PlatformArchAMD64},
		}
		nydusManifestDesc := ocispec.Descriptor{
			MediaType:    ocispec.MediaTypeImageManifest,
			Digest:       digest.FromString("nydus-manifest"),
			Platform:     &ocispec.Platform{OS: "linux", Architecture: utils.PlatformArchAMD64},
			ArtifactType: utils.ArtifactTypeNydusImageManifest,
		}
		index := ocispec.Index{Manifests: []ocispec.Descriptor{ociManifestDesc, nydusManifestDesc}}
		ociConfigDesc := ocispec.Descriptor{Digest: digest.FromString("oci-config")}
		nydusConfigDesc := ocispec.Descriptor{Digest: digest.FromString("nydus-config")}
		ociManifest := ocispec.Manifest{Config: ociConfigDesc}
		nydusManifest := ocispec.Manifest{Config: nydusConfigDesc}
		ociConfig := ocispec.Image{Platform: ocispec.Platform{OS: "linux", Architecture: utils.PlatformArchAMD64}}
		nydusConfig := ocispec.Image{Platform: ocispec.Platform{OS: "linux", Architecture: utils.PlatformArchAMD64}}
		parser := newTestParser(
			t,
			utils.PlatformArchAMD64,
			func(_ context.Context, _ string) (string, ocispec.Descriptor, error) {
				return "docker.io/library/busybox:latest", indexDesc, nil
			},
			func(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
				var payload []byte
				switch desc.Digest {
				case indexDesc.Digest:
					payload, _ = json.Marshal(index)
				case ociManifestDesc.Digest:
					payload, _ = json.Marshal(ociManifest)
				case nydusManifestDesc.Digest:
					payload, _ = json.Marshal(nydusManifest)
				case ociConfigDesc.Digest:
					payload, _ = json.Marshal(ociConfig)
				case nydusConfigDesc.Digest:
					payload, _ = json.Marshal(nydusConfig)
				default:
					return nil, errors.New("unexpected descriptor")
				}
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
		)

		parsed, err := parser.Parse(context.Background())
		require.NoError(t, err)
		require.NotNil(t, parsed.Index)
		require.NotNil(t, parsed.OCIImage)
		require.NotNil(t, parsed.NydusImage)
		require.Equal(t, ociManifestDesc.Digest, parsed.OCIImage.Desc.Digest)
		require.Equal(t, nydusManifestDesc.Digest, parsed.NydusImage.Desc.Digest)
	})

	t.Run("index without matching arch returns empty images", func(t *testing.T) {
		indexDesc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("index-no-match")}
		index := ocispec.Index{Manifests: []ocispec.Descriptor{{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    digest.FromString("arm64-manifest"),
			Platform:  &ocispec.Platform{OS: "linux", Architecture: utils.PlatformArchARM64},
		}}}
		parser := newTestParser(
			t,
			utils.PlatformArchAMD64,
			func(_ context.Context, _ string) (string, ocispec.Descriptor, error) {
				return "docker.io/library/busybox:latest", indexDesc, nil
			},
			func(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
				require.Equal(t, indexDesc.Digest, desc.Digest)
				payload, _ := json.Marshal(index)
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
		)

		parsed, err := parser.Parse(context.Background())
		require.NoError(t, err)
		require.NotNil(t, parsed.Index)
		require.Nil(t, parsed.OCIImage)
		require.Nil(t, parsed.NydusImage)
	})

	t.Run("index manifest pull failure bubbles up", func(t *testing.T) {
		indexDesc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("index-error")}
		manifestDesc := ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    digest.FromString("manifest-error"),
			Platform:  &ocispec.Platform{OS: "linux", Architecture: utils.PlatformArchAMD64},
		}
		index := ocispec.Index{Manifests: []ocispec.Descriptor{manifestDesc}}
		parser := newTestParser(
			t,
			utils.PlatformArchAMD64,
			func(_ context.Context, _ string) (string, ocispec.Descriptor, error) {
				return "docker.io/library/busybox:latest", indexDesc, nil
			},
			func(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
				if desc.Digest == indexDesc.Digest {
					payload, _ := json.Marshal(index)
					return io.NopCloser(bytes.NewReader(payload)), nil
				}
				return nil, errors.New("pull failed")
			},
		)

		parsed, err := parser.Parse(context.Background())
		require.Nil(t, parsed)
		require.Error(t, err)
		require.Contains(t, err.Error(), "pull image manifest")
	})

	t.Run("config missing architecture returns parse oci error", func(t *testing.T) {
		indexDesc := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromString("index-missing-arch")}
		manifestDesc := ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    digest.FromString("manifest-missing-arch"),
			Platform:  &ocispec.Platform{OS: "linux", Architecture: utils.PlatformArchAMD64},
		}
		configDesc := ocispec.Descriptor{Digest: digest.FromString("config-missing-arch")}
		index := ocispec.Index{Manifests: []ocispec.Descriptor{manifestDesc}}
		manifest := ocispec.Manifest{Config: configDesc}
		config := ocispec.Image{Platform: ocispec.Platform{OS: "linux"}}
		parser := newTestParser(
			t,
			utils.PlatformArchAMD64,
			func(_ context.Context, _ string) (string, ocispec.Descriptor, error) {
				return "docker.io/library/busybox:latest", indexDesc, nil
			},
			func(_ context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
				var payload []byte
				switch desc.Digest {
				case indexDesc.Digest:
					payload, _ = json.Marshal(index)
				case manifestDesc.Digest:
					payload, _ = json.Marshal(manifest)
				case configDesc.Digest:
					payload, _ = json.Marshal(config)
				default:
					return nil, errors.New("unexpected descriptor")
				}
				return io.NopCloser(bytes.NewReader(payload)), nil
			},
		)

		parsed, err := parser.Parse(context.Background())
		require.Nil(t, parsed)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Parse OCI image")
	})
}
